//! `POST /organizations/{org_id}/environments` (#38 slice 3) — port of
//! `createEnvironment` in environment_routes.go plus the preset /
//! insert helpers from environment_db.go.
//!
//! Environment intent has one authority: [`codewire_project::ProjectSpec`].
//! Presets and saved repository configuration may fill omitted canonical
//! fields, but no parallel setup representation is accepted or persisted.

use std::sync::atomic::{AtomicBool, Ordering};

use axum::http::StatusCode;
use codewire_server_core::auth::AuthUser;
use codewire_server_core::org_deletion::{
    OrganizationRuntimeMutationError, run_organization_runtime_mutation,
};
use codewire_server_core::{AppError, AppResult};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};

use super::ApiState;
use super::environments::{
    ENV_SELECT_COLS, ENV_SELECT_JOINS, Environment, check_quota, check_rate_limit, coded,
    require_org_member, scan_environment, trigger_environment,
};
use crate::confidential_storage::require_interactive_access;
use crate::repository_mount::validate_repository_mounts;

const CONFIDENTIAL_PERSISTENT_VOLUME_MAX_GIB: i32 = 50;

// ── Shared body types (environment_types.go) ────────────────────────────

/// Placement envelope plus the sole canonical workspace configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateEnvironmentBody {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preset_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<i32>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub isolation_tier: String,
    #[serde(default)]
    #[schemars(with = "serde_json::Value")]
    pub project_spec: codewire_project::ProjectSpec,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_profile_revision: Option<u64>,
    #[serde(default)]
    pub confirm_personal_credentials: bool,
    #[serde(default)]
    pub confirm_personal_secrets: bool,
    #[serde(default)]
    pub omit_application_previews: bool,
}

/// Mirrors `api.Preset` (the slice the create flow consumes; the full
/// wire shape comes with the presets endpoints).
#[derive(Debug, Clone, Default)]
pub struct Preset {
    pub id: String,
    pub org_id: Option<String>,
    pub official: bool,
    pub default_ttl_seconds: Option<i32>,
    pub project_spec: codewire_project::ProjectSpec,
}

#[derive(sqlx::FromRow)]
struct PresetRow {
    id: String,
    org_id: Option<String>,
    official: bool,
    default_ttl_seconds: Option<i32>,
    project_spec: serde_json::Value,
}

impl PresetRow {
    fn into_preset(self) -> anyhow::Result<Preset> {
        if !preset_scope_is_well_formed(self.org_id.as_deref(), self.official) {
            anyhow::bail!("preset scope is invalid");
        }
        let project_spec: codewire_project::ProjectSpec = serde_json::from_value(self.project_spec)
            .map_err(|error| anyhow::anyhow!("decode preset project_spec: {error}"))?;
        project_spec
            .validate()
            .map_err(|error| anyhow::anyhow!("invalid preset project_spec: {error}"))?;
        Ok(Preset {
            id: self.id,
            org_id: self.org_id,
            official: self.official,
            default_ttl_seconds: self.default_ttl_seconds,
            project_spec,
        })
    }
}

pub(crate) fn preset_scope_is_well_formed(org_id: Option<&str>, official: bool) -> bool {
    official == org_id.is_none()
}

pub(crate) fn preset_is_visible_to_org(
    preset_org_id: Option<&str>,
    official: bool,
    requested_org_id: &str,
) -> bool {
    preset_scope_is_well_formed(preset_org_id, official)
        && (preset_org_id == Some(requested_org_id) || official)
}

fn secret_source_selection(project: bool, organization: bool, user: bool) -> AppResult<()> {
    let field = if project {
        Some("secrets.project")
    } else if organization {
        Some("secrets.organization")
    } else if user {
        Some("secrets.user")
    } else {
        None
    };
    let Some(field) = field else {
        return Ok(());
    };
    Err(super::environments::coded_owned(
        StatusCode::BAD_REQUEST,
        "secret_delivery_pending",
        format!(
            "application-secret source {field} is not yet available for platform environment delivery"
        ),
    ))
}

/// Stored defaults cannot select application-secret authority. Explicit create
/// requests are resolved and admitted transactionally after the environment row
/// is inserted.
pub(crate) fn ensure_no_secret_delivery(spec: &codewire_project::ProjectSpec) -> AppResult<()> {
    secret_source_selection(
        !spec.secrets.project.is_empty(),
        spec.secrets.organization,
        spec.secrets.user.is_some(),
    )
}

fn ensure_no_preset_secret_delivery(preset: &Preset) -> AppResult<()> {
    ensure_no_secret_delivery(&preset.project_spec)
}

/// Validate the one canonical request representation.
pub(crate) fn apply_project_spec_defaults(body: &mut CreateEnvironmentBody) -> AppResult<()> {
    if body.omit_application_previews && !body.project_spec.application_ports.is_empty() {
        return Err(coded(
            StatusCode::BAD_REQUEST,
            "conflicting_preview_selection",
            "omit_application_previews requires an empty application_ports list",
        ));
    }
    body.project_spec
        .ensure_platform_compatible()
        .map_err(invalid_project_spec)?;
    if body
        .expected_profile_revision
        .is_some_and(|revision| revision == 0 || revision > i64::MAX as u64)
        || (body.project_spec.credentials.is_none() && body.expected_profile_revision.is_some())
    {
        return Err(coded(
            StatusCode::BAD_REQUEST,
            "invalid_profile_revision",
            "profile revision requires a selected credential profile and a positive revision",
        ));
    }
    if body
        .preset_id
        .as_deref()
        .is_some_and(|preset_id| preset_id.trim().is_empty())
    {
        return Err(coded(
            StatusCode::BAD_REQUEST,
            "invalid_preset_selection",
            "preset_id must be non-empty when provided",
        ));
    }
    if body.preset_id.is_some() && !body.project_spec.preset.is_empty() {
        return Err(coded(
            StatusCode::BAD_REQUEST,
            "invalid_preset_selection",
            "preset_id and project_spec.preset are mutually exclusive",
        ));
    }
    Ok(())
}

/// Fill omitted canonical fields without creating a second representation.
/// The first argument is the explicit request and therefore wins.
pub(crate) fn merge_project_spec_defaults(
    explicit: &mut codewire_project::ProjectSpec,
    defaults: &codewire_project::ProjectSpec,
) -> AppResult<()> {
    explicit.validate().map_err(invalid_project_spec)?;
    defaults.validate().map_err(invalid_project_spec)?;
    let explicit_repositories_were_empty = explicit.repositories.is_empty();
    if explicit.preset.is_empty() {
        explicit.preset = defaults.preset.clone();
    }
    if explicit.image.is_empty() {
        explicit.image = defaults.image.clone();
    }
    if explicit_repositories_were_empty {
        explicit.repositories = defaults.repositories.clone();
        explicit.working_directory = defaults.working_directory.clone();
    }
    if explicit.install_command.is_empty() {
        explicit.install_command = defaults.install_command.clone();
    }
    if explicit.startup_script.is_empty() {
        explicit.startup_script = defaults.startup_script.clone();
    }
    if explicit.environment.is_empty() {
        explicit.environment = defaults.environment.clone();
    }
    if explicit.agents.install.is_none() {
        explicit.agents.install = defaults.agents.install;
    }
    if explicit.agents.tools.is_empty() {
        explicit.agents.tools = defaults.agents.tools.clone();
    }
    if explicit.skills.is_empty() {
        explicit.skills = defaults.skills.clone();
    }
    if explicit.application_ports.is_empty() {
        explicit.application_ports = defaults.application_ports.clone();
    }
    if explicit.resources.cpu_millicores.is_none() {
        explicit.resources.cpu_millicores = defaults.resources.cpu_millicores;
    }
    if explicit.resources.memory_mib.is_none() {
        explicit.resources.memory_mib = defaults.resources.memory_mib;
    }
    if explicit.resources.disk_gib.is_none() {
        explicit.resources.disk_gib = defaults.resources.disk_gib;
    }
    // Secret sources and provider capability are authority, not convenience
    // defaults. Detection, repository configuration, and presets may fill
    // workload configuration, but only the explicit environment request may
    // select stored-secret sources or a credential profile. Omission therefore
    // remains no secret selection and no provider capability.
    explicit.validate().map_err(invalid_project_spec)
}

pub(crate) fn merge_environment_defaults(
    body: &mut CreateEnvironmentBody,
    defaults: &codewire_project::ProjectSpec,
) -> AppResult<()> {
    if body.omit_application_previews {
        // Suppress only preview defaults. Other workload defaults and explicit
        // provider/application-secret selection rules remain unchanged.
        let mut defaults = defaults.clone();
        defaults.application_ports.clear();
        merge_project_spec_defaults(&mut body.project_spec, &defaults)
    } else {
        merge_project_spec_defaults(&mut body.project_spec, defaults)
    }
}

pub(crate) fn ensure_current_platform_runtime_support(
    body: &CreateEnvironmentBody,
) -> AppResult<()> {
    let spec = &body.project_spec;
    super::ports::validate_application_previews(spec)?;
    for repository in &spec.repositories {
        if codewire_project::parse_repository_ssh_host(&repository.source)
            .map_err(invalid_project_spec)?
            .is_some()
            && spec.credentials.is_none()
        {
            return Err(coded(
                StatusCode::BAD_REQUEST,
                "repository_credentials_required",
                "SSH repository checkout requires an explicitly selected credential profile containing an SSH identity",
            ));
        }
    }
    let pending = if spec
        .repositories
        .iter()
        .any(|repository| !repository.revision.is_empty())
    {
        Some("repositories.revision")
    } else if !spec.skills.is_empty() {
        Some("skills")
    } else {
        let destinations = codewire_project::validate_repository_destinations(
            spec.repositories
                .iter()
                .map(|repository| (repository.source.as_str(), repository.destination.as_str())),
        )
        .map_err(invalid_project_spec)?;
        let current_working_directory = match destinations.as_slice() {
            [destination] => destination.as_str(),
            _ => "/workspace",
        };
        (spec.working_directory != current_working_directory).then_some("working_directory")
    };
    if let Some(field) = pending {
        return Err(super::environments::coded_owned(
            StatusCode::BAD_REQUEST,
            "project_feature_pending",
            format!(
                "project field {field} is represented but is not executable by the current platform workspace runtime"
            ),
        ));
    }
    Ok(())
}

fn invalid_project_spec(error: codewire_project::ProjectError) -> AppError {
    super::environments::coded_owned(
        StatusCode::BAD_REQUEST,
        "invalid_project_spec",
        error.to_string(),
    )
}

pub(crate) fn repository_analysis_pending() -> AppError {
    coded(
        StatusCode::BAD_REQUEST,
        "project_feature_pending",
        "automatic repository analysis requires the platform typed repository executor",
    )
}

fn validate_environment_repository_mounts(
    repositories: &[codewire_project::RepositorySpec],
) -> AppResult<()> {
    validate_repository_mounts(
        repositories
            .iter()
            .map(|repo| (repo.source.as_str(), repo.destination.as_str())),
    )
    .map(|_| ())
    .map_err(|error| {
        super::environments::coded_owned(
            StatusCode::BAD_REQUEST,
            "invalid_repo_mount_path",
            error.to_string(),
        )
    })
}

fn validate_environment_resources(
    cpu_millicores: Option<u32>,
    memory_mib: Option<u64>,
    disk_gib: Option<u64>,
    ttl_seconds: Option<i32>,
) -> AppResult<()> {
    if cpu_millicores == Some(0) {
        return Err(coded(
            StatusCode::BAD_REQUEST,
            "invalid_resources",
            "project_spec.resources.cpu_millicores must be greater than zero",
        ));
    }
    if memory_mib == Some(0) {
        return Err(coded(
            StatusCode::BAD_REQUEST,
            "invalid_resources",
            "project_spec.resources.memory_mib must be greater than zero",
        ));
    }
    if disk_gib == Some(0) {
        return Err(coded(
            StatusCode::BAD_REQUEST,
            "invalid_resources",
            "project_spec.resources.disk_gib must be greater than zero",
        ));
    }
    if ttl_seconds.is_some_and(|value| value <= 0) {
        return Err(coded(
            StatusCode::BAD_REQUEST,
            "invalid_resources",
            "ttl_seconds must be greater than zero",
        ));
    }
    Ok(())
}

fn validate_confidential_storage_size(isolation_tier: &str, disk_gib: u64) -> AppResult<()> {
    if isolation_tier == "confidential"
        && disk_gib > u64::try_from(CONFIDENTIAL_PERSISTENT_VOLUME_MAX_GIB).unwrap_or_default()
    {
        return Err(coded(
            StatusCode::BAD_REQUEST,
            "confidential_disk_limit_exceeded",
            "confidential persistent volumes currently support at most 50 GiB",
        ));
    }
    Ok(())
}

/// Mirrors `worker.ValidAgentType` via the shared agent registry.
fn valid_agent_type(agent: &str) -> bool {
    crate::worker::agents::is_supported_agent(agent)
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
        "workspace"
        | "codewiresh/workspace"
        | "ghcr.io/codewiresh/workspace"
        | "registry.example.invalid/codewire/workspace"
        | crate::sandbox::LEGACY_GHCR_CANONICAL_WORKSPACE_RUNTIME_IMAGE => {
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

async fn get_preset(pool: &PgPool, preset_id: &str) -> anyhow::Result<Preset> {
    let row = sqlx::query_as::<_, PresetRow>(
        r#"SELECT et.id, et.org_id, et.official,
                  et.default_ttl_seconds, et.project_spec
           FROM environment_presets et WHERE et.id = $1"#,
    )
    .bind(preset_id)
    .fetch_one(pool)
    .await?;
    row.into_preset()
}

/// Mirrors `getPresetBySlug` (org presets first, then official).
async fn get_preset_by_slug(pool: &PgPool, org_id: &str, slug: &str) -> anyhow::Result<Preset> {
    let row = sqlx::query_as::<_, PresetRow>(
        r#"SELECT et.id, et.org_id, et.official,
                  et.default_ttl_seconds, et.project_spec
           FROM environment_presets et
           WHERE et.slug = $1 AND (et.org_id = $2 OR (et.official = true AND et.org_id IS NULL))
           ORDER BY CASE WHEN et.org_id = $2 THEN 0 ELSE 1 END
           LIMIT 1"#,
    )
    .bind(slug)
    .bind(org_id)
    .fetch_one(pool)
    .await?;
    row.into_preset()
}

/// Resolve one saved canonical repository configuration. Invalid stored intent
/// fails closed rather than silently falling back to repository analysis.
async fn resolve_from_repo_config(
    pool: &PgPool,
    org_id: &str,
    repo_url: &str,
) -> AppResult<Option<(Option<Preset>, codewire_project::ProjectSpec)>> {
    let row: Option<(serde_json::Value,)> =
        sqlx::query_as("SELECT project_spec FROM repo_configs WHERE org_id = $1 AND repo_url = $2")
            .bind(org_id)
            .bind(repo_url)
            .fetch_optional(pool)
            .await?;
    let Some((project_spec,)) = row else {
        return Ok(None);
    };
    let project_spec: codewire_project::ProjectSpec = serde_json::from_value(project_spec)
        .map_err(|error| {
            tracing::error!(%error, "decode repository project_spec");
            coded(
                StatusCode::INTERNAL_SERVER_ERROR,
                "invalid_repo_config",
                "saved repository configuration is invalid",
            )
        })?;
    project_spec.validate().map_err(|error| {
        tracing::error!(%error, "validate repository project_spec");
        coded(
            StatusCode::INTERNAL_SERVER_ERROR,
            "invalid_repo_config",
            "saved repository configuration is invalid",
        )
    })?;
    ensure_no_secret_delivery(&project_spec)?;
    let preset = match (!project_spec.preset.is_empty()).then_some(project_spec.preset.as_str()) {
        Some(preset_slug) => Some(
            get_preset_by_slug(pool, org_id, preset_slug)
                .await
                .map_err(|error| {
                    tracing::error!(%error, "load repository preset");
                    coded(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "invalid_repo_config",
                        "saved repository preset is invalid",
                    )
                })?,
        ),
        None => None,
    };
    Ok(Some((preset, project_spec)))
}

async fn find_or_create_preset_by_image(
    pool: &PgPool,
    org_id: &str,
    image_ref: &str,
) -> anyhow::Result<String> {
    let image_ref = normalize_image_ref(image_ref);
    let mut transaction = pool.begin().await?;

    if let Some(id) = sqlx::query_scalar::<_, String>(
        r#"SELECT et.id FROM environment_presets et
           JOIN sandbox_template_config stc ON stc.preset_id = et.id
           WHERE et.auto_image_ref = $1 AND stc.image_ref = $1 AND et.org_id = $2"#,
    )
    .bind(&image_ref)
    .bind(org_id)
    .fetch_optional(&mut *transaction)
    .await?
    {
        transaction.commit().await?;
        return Ok(id);
    }

    let sandbox_name = sanitize_image_name(&image_ref);
    let project_spec = codewire_project::ProjectSpec {
        image: image_ref.clone(),
        ..Default::default()
    };
    project_spec.validate()?;
    let project_spec = serde_json::to_value(project_spec)?;
    let id: String = sqlx::query_scalar(
        r#"INSERT INTO environment_presets
              (org_id, name, slug, description, default_ttl_seconds, project_spec,
               auto_image_ref)
           VALUES ($1, $2, NULL, NULL, NULL, $3, $4)
           ON CONFLICT (org_id, auto_image_ref) WHERE auto_image_ref IS NOT NULL
           DO UPDATE SET auto_image_ref = EXCLUDED.auto_image_ref
           RETURNING id"#,
    )
    .bind(org_id)
    .bind(&sandbox_name)
    .bind(project_spec)
    .bind(&image_ref)
    .fetch_one(&mut *transaction)
    .await
    .map_err(|e| anyhow::anyhow!("auto-create preset: {e}"))?;

    sqlx::query(
        r#"INSERT INTO sandbox_template_config (preset_id, image_ref, sandbox_template_name)
           VALUES ($1, $2, $3)
           ON CONFLICT (preset_id) DO UPDATE
           SET image_ref = EXCLUDED.image_ref,
               sandbox_template_name = EXCLUDED.sandbox_template_name"#,
    )
    .bind(&id)
    .bind(&image_ref)
    .bind(&sandbox_name)
    .execute(&mut *transaction)
    .await
    .map_err(|e| anyhow::anyhow!("auto-create sandbox_template_config: {e}"))?;

    transaction.commit().await?;
    Ok(id)
}

// ── Insert (environment_db.go::insertEnvironment) ───────────────────────

struct InsertEnvironmentParams<'a> {
    org_id: &'a str,
    user: &'a AuthUser,
    preset_id: &'a str,
    env_type: &'a str,
    name: Option<String>,
    cpu_millicores: i32,
    memory_mb: i32,
    disk_gb: i32,
    isolation_tier: &'a str,
    ttl_seconds: Option<i32>,
    body: &'a CreateEnvironmentBody,
}

async fn insert_environment(
    pool: &PgPool,
    p: InsertEnvironmentParams<'_>,
) -> AppResult<Environment> {
    let project_spec = serde_json::to_value(&p.body.project_spec).map_err(|error| {
        tracing::error!(%error, "serialize environment project spec");
        coded(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "failed to serialize environment project specification",
        )
    })?;

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
                 cpu_millicores, memory_mb, disk_gb, isolation_tier, ttl_seconds,
                 shutdown_at, project_spec)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
                 CASE WHEN $11::int IS NOT NULL THEN NOW() + make_interval(secs => $11::int) END,
                 $12)
             RETURNING *
         )
         SELECT {ENV_SELECT_COLS}
         FROM ins e
         {ENV_SELECT_JOINS}"#
    );
    let profiles = codewire_platform_credentials::PlatformAccessProfileStore::new(
        pool.clone(),
        codewire_access::builtin_provider_catalog(),
    );
    let mut transaction = profiles
        .begin_transaction()
        .await
        .map_err(crate::access_profiles::profile_error)?;
    super::environment_sources::lock_source_owners_in(&mut transaction, p.user, p.org_id).await?;
    if p.isolation_tier == "confidential" {
        reserve_confidential_capacity(&mut transaction, p.org_id).await?;
    }
    let row = sqlx::query(&sql)
        .bind(p.org_id)
        .bind(&p.user.user_id)
        .bind(preset_id)
        .bind(p.env_type)
        .bind(&name)
        .bind(p.cpu_millicores)
        .bind(p.memory_mb)
        .bind(p.disk_gb)
        .bind(p.isolation_tier)
        .bind(p.ttl_seconds)
        .bind(p.ttl_seconds)
        .bind(project_spec)
        .fetch_one(&mut *transaction)
        .await?;
    let environment_id: String = row.try_get("id")?;
    let mut admitted = p.body.clone();
    super::environment_sources::admit_create_sources_in(
        &mut transaction,
        &profiles,
        p.user,
        p.org_id,
        &environment_id,
        &mut admitted,
    )
    .await?;
    // Admission has resolved exact source IDs and created the immutable profile
    // pin. Only this final, same-transaction read describes the published row.
    let sql =
        format!("SELECT {ENV_SELECT_COLS} FROM environments e {ENV_SELECT_JOINS} WHERE e.id=$1");
    let row = sqlx::query(&sql)
        .bind(&environment_id)
        .fetch_one(&mut *transaction)
        .await?;
    let environment = scan_environment(&row)?;
    transaction.commit().await?;
    Ok(environment)
}

/// Checks the catalog entitlement and concurrent capacity while holding an
/// organization-row lock. The new environment row is inserted in the same
/// transaction, so a successful check is a reservation and a failed check
/// creates no environment.
async fn reserve_confidential_capacity(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    org_id: &str,
) -> AppResult<()> {
    sqlx::query("SELECT id FROM organizations WHERE id = $1 FOR UPDATE")
        .bind(org_id)
        .fetch_optional(&mut **transaction)
        .await?
        .ok_or_else(|| {
            coded(
                StatusCode::NOT_FOUND,
                "org_not_found",
                "organization not found",
            )
        })?;

    let plan: String = sqlx::query_scalar(
        r#"SELECT COALESCE(
              (SELECT plan FROM environment_subscriptions
                WHERE org_id = $1 AND status IN ('active', 'trialing', 'past_due')
                ORDER BY updated_at DESC LIMIT 1),
              (SELECT plan FROM org_subscriptions
                WHERE org_id = $1 AND status IN ('active', 'trialing', 'past_due')
                ORDER BY updated_at DESC LIMIT 1),
              (SELECT billing_plan FROM organizations
                WHERE id = $1 AND billing_plan NOT IN ('', 'none')
                  AND billing_status IN ('active', 'trialing', 'past_due')),
              '')"#,
    )
    .bind(org_id)
    .fetch_one(&mut **transaction)
    .await?;

    let catalog: Option<(i32, f64, f64)> = sqlx::query_as(
        r#"SELECT max_concurrent_ws, cpu_overage_cents, mem_overage_cents
           FROM billing_catalog_plans
           WHERE resource_type = 'confidential_sandbox' AND plan_key = $1
             AND archived_at IS NULL"#,
    )
    .bind(&plan)
    .fetch_optional(&mut **transaction)
    .await?;
    let Some((max_concurrent, cpu_rate, memory_rate)) = catalog else {
        return Err(coded(
            StatusCode::CONFLICT,
            "CONFIDENTIAL_CAPACITY_UNAVAILABLE",
            "confidential environments are not available for this plan",
        ));
    };
    if cpu_rate <= 0.0 || memory_rate <= 0.0 || max_concurrent == 0 {
        return Err(coded(
            StatusCode::CONFLICT,
            "CONFIDENTIAL_CAPACITY_UNAVAILABLE",
            "confidential environments are currently unavailable",
        ));
    }
    let active: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*) FROM environments
           WHERE org_id = $1 AND isolation_tier = 'confidential'
             AND state NOT IN ('destroyed', 'destroying', 'error', 'archived')
             AND NOT (state = 'stopped' AND desired_state = 'stopped')"#,
    )
    .bind(org_id)
    .fetch_one(&mut **transaction)
    .await?;
    if max_concurrent != -1 && active >= i64::from(max_concurrent) {
        return Err(coded(
            StatusCode::CONFLICT,
            "CONFIDENTIAL_CAPACITY_UNAVAILABLE",
            "confidential environment capacity is currently unavailable",
        ));
    }
    Ok(())
}

// A create that names no resources gets 2 vCPU, 8 GiB and 10 GiB (owner,
// 2026-10-04): the same shape as a Dev warm pool, so it can start warm.
const DEFAULT_CPU_MILLICORES: u32 = 2_000;
const DEFAULT_MEMORY_MIB: u64 = 8_192;
const DEFAULT_DISK_GIB: u64 = 10;

fn apply_environment_resource_defaults(spec: &mut codewire_project::ProjectSpec) {
    spec.resources
        .cpu_millicores
        .get_or_insert(DEFAULT_CPU_MILLICORES);
    spec.resources.memory_mib.get_or_insert(DEFAULT_MEMORY_MIB);
    spec.resources.disk_gib.get_or_insert(DEFAULT_DISK_GIB);
}

fn resource_i32(value: u64, field: &'static str) -> AppResult<i32> {
    i32::try_from(value).map_err(|_| {
        super::environments::coded_owned(
            StatusCode::BAD_REQUEST,
            "invalid_resources",
            format!("project_spec.resources.{field} exceeds the platform limit"),
        )
    })
}

fn validate_preset_scope(preset: &Preset, org_id: &str) -> AppResult<()> {
    if preset_is_visible_to_org(preset.org_id.as_deref(), preset.official, org_id) {
        Ok(())
    } else {
        Err(coded(
            StatusCode::BAD_REQUEST,
            "preset_not_found",
            "preset does not belong to this organization",
        ))
    }
}

async fn resolve_project_preset(
    pool: &PgPool,
    org_id: &str,
    spec: &codewire_project::ProjectSpec,
) -> AppResult<Preset> {
    if !spec.preset.is_empty() {
        // `image` may explicitly override a resolved preset's image, but it
        // must never turn a missing preset into a different image-only path.
        return get_preset_by_slug(pool, org_id, &spec.preset)
            .await
            .map_err(|_| {
                super::environments::coded_owned(
                    StatusCode::BAD_REQUEST,
                    "preset_not_found",
                    format!("preset not found: {}", spec.preset),
                )
            });
    }
    if spec.image.is_empty() {
        return Err(coded(
            StatusCode::BAD_REQUEST,
            "missing_input",
            "project_spec must select a preset, image, or repository",
        ));
    }
    let preset_id = find_or_create_preset_by_image(pool, org_id, &spec.image)
        .await
        .map_err(|error| {
            tracing::error!(%error, "find or create preset by image");
            coded(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "failed to resolve preset for image",
            )
        })?;
    get_preset(pool, &preset_id).await.map_err(|error| {
        tracing::error!(%error, "load image preset");
        coded(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "failed to load image preset",
        )
    })
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
    let isolation_tier = match body.isolation_tier.trim() {
        "" | "standard" => "standard",
        "confidential" => "confidential",
        _ => {
            return Err(coded(
                StatusCode::BAD_REQUEST,
                "invalid_isolation_tier",
                "isolation_tier must be standard or confidential",
            ));
        }
    };
    crate::confidential_storage::refuse_confidential_isolation(isolation_tier)?;
    require_interactive_access(state.confidential_storage_flags, user, isolation_tier)?;
    apply_project_spec_defaults(&mut body)?;
    if !body.project_spec.image.is_empty() {
        body.project_spec.image = normalize_image_ref(&body.project_spec.image);
    }

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

    ensure_current_platform_runtime_support(&body)?;
    validate_environment_repository_mounts(&body.project_spec.repositories)?;
    // Reject explicit bad values before preset lookup or auto-creation can
    // write preset state. The effective values are checked again after
    // preset resolution so invalid stored defaults cannot reach quota or the
    // environment insert.
    validate_environment_resources(
        body.project_spec.resources.cpu_millicores,
        body.project_spec.resources.memory_mib,
        body.project_spec.resources.disk_gib,
        body.ttl_seconds,
    )?;

    let dispatch_ambiguous = AtomicBool::new(false);
    // The admitted operation outlives a dropped request, so it owns its inputs.
    let owned_state = state.clone();
    let owned_user = user.clone();
    let owned_org_id = org_id.to_owned();
    run_organization_runtime_mutation(pool, org_id, async move {
        let (state, user, org_id) = (&owned_state, &owned_user, owned_org_id.as_str());
        let pool = &state.pool;
        let result: AppResult<Environment> = async {
            let preset: Preset = if body.preset_id.as_deref().is_some_and(|s| !s.is_empty()) {
                let preset_id = body.preset_id.clone().unwrap();
                let preset = get_preset(pool, &preset_id).await.map_err(|_| {
                    coded(
                        StatusCode::BAD_REQUEST,
                        "preset_not_found",
                        "preset not found",
                    )
                })?;
                validate_preset_scope(&preset, org_id)?;
                preset
            } else if !body.project_spec.preset.is_empty() || !body.project_spec.image.is_empty() {
                resolve_project_preset(pool, org_id, &body.project_spec).await?
            } else if let Some(repository_source) = body
                .project_spec
                .repositories
                .first()
                .map(|repository| repository.source.clone())
            {
                match resolve_from_repo_config(pool, org_id, &repository_source).await? {
                    Some((saved_preset, saved_spec)) => {
                        tracing::info!(
                            repo_url = repository_source,
                            "smart create: using saved repo config"
                        );
                        merge_environment_defaults(&mut body, &saved_spec)?;
                        match saved_preset {
                            Some(preset) => {
                                validate_preset_scope(&preset, org_id)?;
                                preset
                            }
                            None if body.project_spec.image.is_empty()
                                && body.project_spec.preset.is_empty() =>
                            {
                                return Err(repository_analysis_pending());
                            }
                            None => {
                                // Saved workload defaults must be executable
                                // before image resolution can write a preset.
                                ensure_current_platform_runtime_support(&body)?;
                                resolve_project_preset(pool, org_id, &body.project_spec).await?
                            }
                        }
                    }
                    None => return Err(repository_analysis_pending()),
                }
            } else {
                return Err(coded(
                    StatusCode::BAD_REQUEST,
                    "missing_input",
                    "project_spec must select a preset, image, or repository",
                ));
            };

            ensure_no_preset_secret_delivery(&preset)?;
            merge_environment_defaults(&mut body, &preset.project_spec)?;
            apply_environment_resource_defaults(&mut body.project_spec);
            body.project_spec.validate().map_err(invalid_project_spec)?;
            ensure_current_platform_runtime_support(&body)?;
            validate_environment_repository_mounts(&body.project_spec.repositories)?;

            let cpu = body.project_spec.resources.cpu_millicores.unwrap();
            let memory_mib = body.project_spec.resources.memory_mib.unwrap();
            let disk_gib = body.project_spec.resources.disk_gib.unwrap();
            let ttl = match body.ttl_seconds {
                Some(t) => Some(t),
                None => preset.default_ttl_seconds,
            };

            validate_environment_resources(Some(cpu), Some(memory_mib), Some(disk_gib), ttl)?;
            validate_confidential_storage_size(isolation_tier, disk_gib)?;
            let cpu = resource_i32(u64::from(cpu), "cpu_millicores")?;
            let memory_mib = resource_i32(memory_mib, "memory_mib")?;
            let disk_gib = resource_i32(disk_gib, "disk_gib")?;
            check_quota(pool, org_id, "sandbox", cpu, memory_mib).await?;

            for agent in &body.project_spec.agents.tools {
                if !valid_agent_type(agent) {
                    return Err(super::environments::coded_owned(
                        StatusCode::BAD_REQUEST,
                        "unsupported_agent",
                        format!("unsupported agent: {agent}"),
                    ));
                }
            }

            let env = insert_environment(
                pool,
                InsertEnvironmentParams {
                    org_id,
                    user,
                    preset_id: &preset.id,
                    env_type: "sandbox",
                    name: body.name.clone(),
                    cpu_millicores: cpu,
                    memory_mb: memory_mib,
                    disk_gb: disk_gib,
                    isolation_tier,
                    ttl_seconds: ttl,
                    body: &body,
                },
            )
            .await?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use codewire_server_core::AppError;
    use codewire_server_core::validation::validate_value;
    use sqlx::postgres::PgPoolOptions;

    fn image_project_spec(
        image: &str,
        cpu_millicores: Option<u32>,
        memory_mib: Option<u64>,
        disk_gib: Option<u64>,
    ) -> codewire_project::ProjectSpec {
        codewire_project::ProjectSpec {
            image: image.to_owned(),
            resources: codewire_project::ResourceSpec {
                cpu_millicores,
                memory_mib,
                disk_gib,
            },
            ..Default::default()
        }
    }

    fn materialize_image_caller(
        mut caller: codewire_project::ProjectSpec,
        preset: &Preset,
    ) -> codewire_project::ProjectSpec {
        merge_project_spec_defaults(&mut caller, &preset.project_spec).unwrap();
        apply_environment_resource_defaults(&mut caller);
        caller
    }

    #[test]
    fn repository_mounts_are_safe_and_non_overlapping() {
        let invalid = [
            vec![codewire_project::RepositorySpec {
                source: "https://github.com/x/y".into(),
                destination: "/workspace/../outside".into(),
                ..Default::default()
            }],
            vec![
                codewire_project::RepositorySpec {
                    source: "https://github.com/x/y".into(),
                    destination: "/workspace/app".into(),
                    ..Default::default()
                },
                codewire_project::RepositorySpec {
                    source: "https://github.com/x/z".into(),
                    destination: "/workspace/app/docs".into(),
                    ..Default::default()
                },
            ],
        ];
        for repos in invalid {
            let error = validate_environment_repository_mounts(&repos).unwrap_err();
            assert!(matches!(
                error,
                AppError::Coded {
                    code: "invalid_repo_mount_path",
                    ..
                }
            ));
        }
    }

    #[test]
    fn canonical_defaults_fill_only_omitted_project_fields() {
        let mut explicit = codewire_project::parse_project_yaml(
            r#"
repositories:
  - source: https://example.test/org/explicit.git
    destination: /workspace/explicit
working_directory: /workspace/explicit
install_command: caller-install
environment: {CALLER: set}
agents: {install: false}
cpu: "1"
"#,
        )
        .unwrap()
        .spec;
        let defaults = codewire_project::parse_project_yaml(
            r#"
image: ghcr.io/example/workspace:1
repositories:
  - source: https://example.test/org/default.git
    destination: /workspace/default
working_directory: /workspace/default
install_command: default-install
startup_script: cargo test
environment: {DEFAULT_ONLY: ignored}
agents: {install: true, tools: [codex]}
skills: [{source: repository, path: .agents/skills/rust}]
ports: [{port: 8080, label: api, access: private}]
cpu: "4"
memory: "16Gi"
disk: "40Gi"
credentials: {profile: user/work}
"#,
        )
        .unwrap()
        .spec;

        merge_project_spec_defaults(&mut explicit, &defaults).unwrap();

        assert_eq!(explicit.image, "ghcr.io/example/workspace:1");
        assert_eq!(
            explicit.repositories[0].source,
            "https://example.test/org/explicit.git"
        );
        assert_eq!(explicit.working_directory, "/workspace/explicit");
        assert_eq!(explicit.install_command, "caller-install");
        assert_eq!(explicit.startup_script, "cargo test");
        assert_eq!(explicit.environment.len(), 1);
        assert_eq!(explicit.environment["CALLER"], "set");
        assert_eq!(explicit.agents.install, Some(false));
        assert_eq!(explicit.agents.tools, ["codex"]);
        assert_eq!(explicit.application_ports[0].port, 8080);
        assert_eq!(explicit.resources.cpu_millicores, Some(1_000));
        assert_eq!(explicit.resources.memory_mib, Some(16 * 1_024));
        assert_eq!(explicit.resources.disk_gib, Some(40));
        assert!(explicit.credentials.is_none());
        explicit.validate().unwrap();
    }

    #[test]
    fn stored_defaults_cannot_grant_provider_access() {
        let access_default = codewire_project::parse_project_yaml(
            "image: ghcr.io/example/workspace:1\ncredentials: {profile: user/work}\n",
        )
        .unwrap()
        .spec;

        for source in ["saved repository configuration", "preset"] {
            let mut merged = codewire_project::ProjectSpec::default();
            merge_project_spec_defaults(&mut merged, &access_default).unwrap();
            assert!(
                merged.credentials.is_none(),
                "{source} granted provider access"
            );
        }

        let explicit_access =
            codewire_project::parse_project_yaml("credentials: {profile: organization/approved}\n")
                .unwrap()
                .spec;
        let mut requested = explicit_access.clone();
        merge_project_spec_defaults(&mut requested, &codewire_project::ProjectSpec::default())
            .unwrap();
        assert_eq!(requested.credentials, explicit_access.credentials);
    }

    #[test]
    fn defaults_cannot_select_stored_secret_sources() {
        let secret_defaults = codewire_project::parse_project_yaml(
            "secrets: {user: platform, organization: true, project: development}\n",
        )
        .unwrap()
        .spec;

        for source in ["saved repository configuration", "preset"] {
            let mut merged = codewire_project::ProjectSpec::default();
            merge_project_spec_defaults(&mut merged, &secret_defaults).unwrap();
            assert_eq!(
                merged.secrets,
                codewire_project::SecretBindings::default(),
                "{source} selected stored-secret sources"
            );
        }

        let explicit_secrets =
            codewire_project::parse_project_yaml("secrets: {user: platform, project: explicit}\n")
                .unwrap()
                .spec;
        let mut requested = explicit_secrets.clone();
        merge_project_spec_defaults(&mut requested, &codewire_project::ProjectSpec::default())
            .unwrap();
        assert_eq!(requested.secrets, explicit_secrets.secrets);
    }

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

    #[test]
    fn explicit_canonical_secret_sources_pass_initial_validation() {
        for yaml in [
            "secrets: {project: platform:development}\n",
            "secrets: {organization: true}\n",
            "secrets: {user: platform}\n",
        ] {
            let mut body = CreateEnvironmentBody {
                project_spec: codewire_project::parse_project_yaml(yaml).unwrap().spec,
                ..Default::default()
            };
            apply_project_spec_defaults(&mut body).unwrap();
        }

        ensure_no_secret_delivery(
            &codewire_project::parse_project_yaml("secrets: {organization: false}\n")
                .unwrap()
                .spec,
        )
        .unwrap();
    }

    #[test]
    fn preset_secret_sources_fail_closed_without_disclosing_bindings() {
        ensure_no_preset_secret_delivery(&Preset::default()).unwrap();
        let preset = Preset {
            project_spec: codewire_project::parse_project_yaml(
                "secrets: {project: preset-project-secret-value}\n",
            )
            .unwrap()
            .spec,
            ..Default::default()
        };
        assert_secret_delivery_pending(
            ensure_no_preset_secret_delivery(&preset).unwrap_err(),
            Some("preset-project-secret-value"),
        );
    }

    #[test]
    fn automatic_repository_analysis_is_value_blind_and_has_no_fetch_implementation() {
        let canary = "https://synthetic-user:synthetic-secret@arbitrary.example.test/org/repo";
        let error = repository_analysis_pending();
        let AppError::Coded {
            status,
            code,
            detail,
        } = error
        else {
            panic!("repository analysis did not return a typed error");
        };
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(code, "project_feature_pending");
        assert!(!detail.contains(canary));

        for source in [include_str!("create.rs"), include_str!("prepare.rs")] {
            for forbidden in [
                concat!("fetch_repo_", "context"),
                concat!("call_claude_", "detect"),
                concat!("parse_repo_", "url"),
            ] {
                assert!(
                    !source.contains(forbidden),
                    "server-side repository network implementation remains: {forbidden}"
                );
            }
        }
    }

    #[test]
    fn represented_unsupported_project_features_fail_closed() {
        for yaml in [
            "repositories: [{source: https://example.test/app.git, revision: deadbeef}]\n",
            "skills: [{source: repository, path: .agents/skills/rust}]\n",
            "repositories: [{source: https://example.test/app.git}]\nworking_directory: /workspace/app/subdir\n",
        ] {
            let spec = codewire_project::parse_project_yaml(yaml).unwrap().spec;
            let error = ensure_current_platform_runtime_support(&CreateEnvironmentBody {
                project_spec: spec,
                ..Default::default()
            })
            .unwrap_err();
            assert!(
                matches!(
                    error,
                    AppError::Coded {
                        code: "project_feature_pending",
                        ..
                    }
                ),
                "unexpected result for {yaml:?}: {error}"
            );
        }
        let credentials =
            codewire_project::parse_project_yaml("credentials: {profile: platform:user/work}\n")
                .unwrap()
                .spec;
        ensure_current_platform_runtime_support(&CreateEnvironmentBody {
            project_spec: credentials,
            ..Default::default()
        })
        .unwrap();
    }

    fn ssh_project(source: &str) -> codewire_project::ProjectSpec {
        let host = codewire_project::parse_repository_ssh_host(source)
            .unwrap()
            .unwrap();
        codewire_project::ProjectSpec {
            repositories: vec![codewire_project::RepositorySpec {
                source: source.into(),
                destination: "/workspace/app".into(),
                known_hosts: vec![format!(
                    "{} ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAx",
                    host.known_hosts_name()
                )],
                ..Default::default()
            }],
            working_directory: "/workspace/app".into(),
            ..Default::default()
        }
    }

    #[test]
    fn ssh_checkout_requires_an_explicit_profile_without_echoing_repository_data() {
        for source in [
            "git@example.test:private-canary/app.git",
            "ssh://git@example.test:2222/private-canary/app.git",
        ] {
            let mut body = CreateEnvironmentBody {
                project_spec: ssh_project(source),
                ..Default::default()
            };
            apply_project_spec_defaults(&mut body).unwrap();
            let AppError::Coded {
                status,
                code,
                detail,
            } = ensure_current_platform_runtime_support(&body).unwrap_err()
            else {
                panic!("SSH without a profile was not rejected with a typed error");
            };
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert_eq!(code, "repository_credentials_required");
            assert!(detail.contains("SSH identity"));
            assert!(!detail.contains("private-canary"));
            assert!(!detail.contains(source));
            body.project_spec.credentials = Some(codewire_project::CredentialBinding {
                profile: "platform:user/work".into(),
            });
            // Profile ownership/revision and the actual SSH slot remain the
            // existing source-admission and worker checks, not this presence check.
            ensure_current_platform_runtime_support(&body).unwrap();
        }
        let body = CreateEnvironmentBody {
            project_spec: codewire_project::parse_project_yaml(
                "repositories: [{source: https://example.test/org/app.git}]\n",
            )
            .unwrap()
            .spec,
            ..Default::default()
        };
        ensure_current_platform_runtime_support(&body).unwrap();
    }

    #[test]
    fn inherited_ssh_repositories_cannot_inherit_profile_authority() {
        let mut defaults = ssh_project("git@example.test:org/app.git");
        defaults.credentials = Some(codewire_project::CredentialBinding {
            profile: "platform:user/default-must-not-grant".into(),
        });
        let mut body = CreateEnvironmentBody::default();
        merge_environment_defaults(&mut body, &defaults).unwrap();
        assert!(body.project_spec.credentials.is_none());
        assert!(matches!(
            ensure_current_platform_runtime_support(&body),
            Err(AppError::Coded {
                code: "repository_credentials_required",
                ..
            })
        ));
        body.project_spec.application_ports =
            codewire_project::parse_project_yaml("ports: [{port: 2222, label: ssh}]\n")
                .unwrap()
                .spec
                .application_ports;
        let error = ensure_current_platform_runtime_support(&body).unwrap_err();
        assert!(
            !matches!(
                error,
                AppError::Coded {
                    code: "repository_credentials_required",
                    ..
                }
            ),
            "preview validation must retain priority over SSH profile presence"
        );
    }

    #[test]
    fn explicit_no_previews_suppresses_only_inherited_preview_defaults() {
        let defaults = codewire_project::parse_project_yaml(
            "image: example.test/workspace\nports: [{port: 3000, label: web}]\n",
        )
        .unwrap()
        .spec;
        let mut legacy = CreateEnvironmentBody::default();
        merge_environment_defaults(&mut legacy, &defaults).unwrap();
        assert_eq!(legacy.project_spec.application_ports.len(), 1);

        let mut explicit = CreateEnvironmentBody {
            omit_application_previews: true,
            ..Default::default()
        };
        apply_project_spec_defaults(&mut explicit).unwrap();
        // Both repository and preset default stages use this helper.
        for _ in 0..2 {
            merge_environment_defaults(&mut explicit, &defaults).unwrap();
            assert!(explicit.project_spec.application_ports.is_empty());
            assert_eq!(explicit.project_spec.image, "example.test/workspace");
        }
        ensure_current_platform_runtime_support(&explicit).unwrap();
        explicit.project_spec.application_ports = defaults.application_ports;
        assert!(matches!(
            apply_project_spec_defaults(&mut explicit),
            Err(AppError::Coded {
                code: "conflicting_preview_selection",
                ..
            })
        ));
    }

    #[test]
    fn inherited_preview_defaults_are_checked_before_platform_setup() {
        for yaml in [
            "ports: [{port: 3000, label: web}, {port: 3001, label: web}]\n",
            "ports: [{port: 2222, label: ssh}]\n",
            "ports: [{port: 3000, label: web, access: private}]\n",
            "ports: [{port: 3000}]\n",
        ] {
            let defaults = codewire_project::parse_project_yaml(yaml).unwrap().spec;
            // These are valid generic project/local-VM specifications. The
            // platform must reject unsupported previews after preset merging,
            // rather than silently dropping them during environment setup.
            let mut caller = codewire_project::ProjectSpec::default();
            merge_project_spec_defaults(&mut caller, &defaults).unwrap();
            assert!(
                ensure_current_platform_runtime_support(&CreateEnvironmentBody {
                    project_spec: caller,
                    ..Default::default()
                })
                .is_err(),
                "inherited preview was admitted: {yaml:?}"
            );
        }

        let defaults = codewire_project::parse_project_yaml("ports: [{port: 3000, label: 9web}]\n")
            .unwrap()
            .spec;
        let mut caller = codewire_project::ProjectSpec::default();
        merge_project_spec_defaults(&mut caller, &defaults).unwrap();
        ensure_current_platform_runtime_support(&CreateEnvironmentBody {
            project_spec: caller,
            ..Default::default()
        })
        .unwrap();
    }

    #[test]
    fn isolation_tier_is_an_explicit_product_choice() {
        let body = CreateEnvironmentBody {
            isolation_tier: "confidential".into(),
            ..Default::default()
        };
        assert_eq!(body.isolation_tier, "confidential");
    }

    #[test]
    fn confidential_persistent_volume_size_is_bounded_by_the_runtime_contract() {
        validate_confidential_storage_size("standard", 51).unwrap();
        validate_confidential_storage_size("confidential", 50).unwrap();
        let error = validate_confidential_storage_size("confidential", 51).unwrap_err();
        assert!(matches!(
            error,
            AppError::Coded {
                code: "confidential_disk_limit_exceeded",
                ..
            }
        ));
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL"]
    async fn db_confidential_capacity_is_atomic_and_plan_scoped() {
        let database_url =
            std::env::var("TEST_DATABASE_URL").expect("ignored DB test requires TEST_DATABASE_URL");
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .connect(&database_url)
            .await
            .unwrap();
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let user_id = format!("user_confidential_{suffix}");
        let org_id = format!("org_confidential_{suffix}");
        let preset_id = format!("preset_confidential_{suffix}");
        let environment_id = format!("env_confidential_{suffix}");
        let plan_key = format!("confidential_{suffix}");

        sqlx::query("INSERT INTO users (id, email) VALUES ($1, $2)")
            .bind(&user_id)
            .bind(format!("{user_id}@example.test"))
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO organizations (id, name, slug, created_by, billing_plan, billing_status) VALUES ($1, $2, $3, $4, $5, 'active')",
        )
        .bind(&org_id)
        .bind(format!("Confidential {suffix}"))
        .bind(format!("confidential-{suffix}"))
        .bind(&user_id)
        .bind(&plan_key)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO billing_catalog_plans (resource_type, plan_key, display_name, price_cents, max_concurrent_ws, cpu_overage_cents, mem_overage_cents) VALUES ('confidential_sandbox', $1, 'Confidential test', 0, 1, 1, 1)",
        )
        .bind(&plan_key)
        .execute(&pool)
        .await
        .unwrap();

        sqlx::query(
            r#"INSERT INTO environment_presets (id, org_id, name, build_status, project_spec)
               VALUES ($1, $2, 'Confidential test', 'ready',
                       '{"schema_version":1,"working_directory":"/workspace"}'::jsonb)"#,
        )
        .bind(&preset_id)
        .bind(&org_id)
        .execute(&pool)
        .await
        .unwrap();
        let mut transaction = pool.begin().await.unwrap();
        reserve_confidential_capacity(&mut transaction, &org_id)
            .await
            .unwrap();
        sqlx::query(
            r#"INSERT INTO environments
                 (id, org_id, created_by, type, preset_id, state, desired_state,
                  isolation_tier, project_spec)
               VALUES ($1, $2, $3, 'sandbox', $4, 'pending', 'started',
                       'confidential',
                       '{"schema_version":1,"working_directory":"/workspace"}'::jsonb)"#,
        )
        .bind(&environment_id)
        .bind(&org_id)
        .bind(&user_id)
        .bind(&preset_id)
        .execute(&mut *transaction)
        .await
        .unwrap();
        transaction.commit().await.unwrap();

        let mut transaction = pool.begin().await.unwrap();
        let error = reserve_confidential_capacity(&mut transaction, &org_id)
            .await
            .expect_err("the second active confidential environment must be rejected");
        transaction.rollback().await.unwrap();
        assert!(matches!(
            error,
            AppError::Coded {
                code: "CONFIDENTIAL_CAPACITY_UNAVAILABLE",
                ..
            }
        ));

        sqlx::query(
            "UPDATE environments SET state = 'stopped', desired_state = 'stopped' WHERE id = $1",
        )
        .bind(&environment_id)
        .execute(&pool)
        .await
        .unwrap();
        let mut transaction = pool.begin().await.unwrap();
        reserve_confidential_capacity(&mut transaction, &org_id)
            .await
            .expect("a fully stopped environment must release confidential capacity");
        transaction.rollback().await.unwrap();

        crate::lifecycle::Service::for_pool(pool.clone())
            .admit_confidential_start(&environment_id, &org_id, "confidential")
            .await
            .expect("a stopped environment can atomically reserve confidential capacity");
        let mut transaction = pool.begin().await.unwrap();
        let error = reserve_confidential_capacity(&mut transaction, &org_id)
            .await
            .expect_err("a stopped environment with start intent must reserve capacity");
        transaction.rollback().await.unwrap();
        assert!(matches!(
            error,
            AppError::Coded {
                code: "CONFIDENTIAL_CAPACITY_UNAVAILABLE",
                ..
            }
        ));

        sqlx::query(
            "UPDATE environments SET state = 'error', desired_state = 'stopped' WHERE id = $1",
        )
        .bind(&environment_id)
        .execute(&pool)
        .await
        .unwrap();
        crate::lifecycle::Service::for_pool(pool.clone())
            .retry_confidential_start(&environment_id, &org_id)
            .await
            .expect("an errored environment must reacquire capacity before retry");
        let retried: (String, String) =
            sqlx::query_as("SELECT state, desired_state FROM environments WHERE id = $1")
                .bind(&environment_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(retried, ("pending".to_owned(), "started".to_owned()));

        sqlx::query("DELETE FROM environments WHERE id = $1")
            .bind(&environment_id)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM environment_presets WHERE id = $1")
            .bind(&preset_id)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "DELETE FROM billing_catalog_plans WHERE resource_type = 'confidential_sandbox' AND plan_key = $1",
        )
        .bind(&plan_key)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(&org_id)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(&user_id)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL"]
    async fn db_auto_image_preset_is_resource_neutral_for_sequential_callers() {
        let database_url =
            std::env::var("TEST_DATABASE_URL").expect("ignored DB test requires TEST_DATABASE_URL");
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .connect(&database_url)
            .await
            .unwrap();
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let user_id = format!("user_auto_preset_sequential_{suffix}");
        let org_id = format!("org_auto_preset_sequential_{suffix}");
        let image = format!("ghcr.io/example/sequential-{suffix}:1");

        sqlx::query("INSERT INTO users (id, email) VALUES ($1, $2)")
            .bind(&user_id)
            .bind(format!("{user_id}@example.test"))
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO organizations (id, name, slug, created_by) VALUES ($1, $2, $3, $4)",
        )
        .bind(&org_id)
        .bind(format!("Sequential auto preset {suffix}"))
        .bind(format!("sequential-auto-preset-{suffix}"))
        .bind(&user_id)
        .execute(&pool)
        .await
        .unwrap();

        let first_caller = image_project_spec(&image, Some(1_000), Some(2_048), Some(20));
        let second_caller = image_project_spec(&image, Some(6_000), Some(8_192), Some(30));
        let first_preset = resolve_project_preset(&pool, &org_id, &first_caller)
            .await
            .unwrap();
        let second_preset = resolve_project_preset(&pool, &org_id, &second_caller)
            .await
            .unwrap();

        assert_eq!(first_preset.id, second_preset.id);
        assert_eq!(
            first_preset.project_spec.resources,
            codewire_project::ResourceSpec::default()
        );
        assert_eq!(
            second_preset.project_spec.resources,
            codewire_project::ResourceSpec::default()
        );
        assert_eq!(
            materialize_image_caller(first_caller, &first_preset).resources,
            codewire_project::ResourceSpec {
                cpu_millicores: Some(1_000),
                memory_mib: Some(2_048),
                disk_gib: Some(20),
            }
        );
        assert_eq!(
            materialize_image_caller(second_caller, &second_preset).resources,
            codewire_project::ResourceSpec {
                cpu_millicores: Some(6_000),
                memory_mib: Some(8_192),
                disk_gib: Some(30),
            }
        );
        assert_eq!(
            materialize_image_caller(image_project_spec(&image, None, None, None), &first_preset,)
                .resources,
            codewire_project::ResourceSpec {
                cpu_millicores: Some(DEFAULT_CPU_MILLICORES),
                memory_mib: Some(DEFAULT_MEMORY_MIB),
                disk_gib: Some(DEFAULT_DISK_GIB),
            }
        );

        sqlx::query("DELETE FROM environment_presets WHERE org_id = $1")
            .bind(&org_id)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(&org_id)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(&user_id)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL"]
    async fn db_auto_image_preset_is_resource_neutral_atomic_and_unique_under_concurrency() {
        let database_url =
            std::env::var("TEST_DATABASE_URL").expect("ignored DB test requires TEST_DATABASE_URL");
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .connect(&database_url)
            .await
            .unwrap();
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let user_id = format!("user_auto_preset_{suffix}");
        let org_id = format!("org_auto_preset_{suffix}");
        let image = format!("ghcr.io/example/concurrent-{suffix}:1");
        let failing_image = format!("ghcr.io/example/failing-{suffix}:1");
        let function_name = format!("cw_fail_auto_projection_{suffix}");
        let trigger_name = format!("cw_fail_auto_projection_{suffix}");

        sqlx::query("INSERT INTO users (id, email) VALUES ($1, $2)")
            .bind(&user_id)
            .bind(format!("{user_id}@example.test"))
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO organizations (id, name, slug, created_by) VALUES ($1, $2, $3, $4)",
        )
        .bind(&org_id)
        .bind(format!("Auto preset {suffix}"))
        .bind(format!("auto-preset-{suffix}"))
        .bind(&user_id)
        .execute(&pool)
        .await
        .unwrap();

        let first_caller = image_project_spec(&image, Some(1_000), Some(2_048), Some(20));
        let second_caller = image_project_spec(&image, Some(6_000), Some(8_192), Some(30));
        let first = resolve_project_preset(&pool, &org_id, &first_caller);
        let second = resolve_project_preset(&pool, &org_id, &second_caller);
        let (first, second) = tokio::join!(first, second);
        let first = first.unwrap();
        let second = second.unwrap();
        let canonical_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM environment_presets WHERE org_id = $1 AND auto_image_ref = $2",
        )
        .bind(&org_id)
        .bind(&image)
        .fetch_one(&pool)
        .await
        .unwrap();
        let projection_count: i64 = sqlx::query_scalar(
            r#"SELECT COUNT(*)
               FROM sandbox_template_config stc
               JOIN environment_presets ep ON ep.id = stc.preset_id
               WHERE ep.org_id = $1 AND stc.image_ref = $2"#,
        )
        .bind(&org_id)
        .bind(&image)
        .fetch_one(&pool)
        .await
        .unwrap();

        sqlx::query(&format!(
            r#"CREATE FUNCTION {function_name}() RETURNS trigger
               LANGUAGE plpgsql AS $function$
               BEGIN
                   IF NEW.image_ref = '{failing_image}' THEN
                       RAISE EXCEPTION 'synthetic auto projection failure';
                   END IF;
                   RETURN NEW;
               END
               $function$"#,
        ))
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(&format!(
            r#"CREATE TRIGGER {trigger_name}
               BEFORE INSERT OR UPDATE ON sandbox_template_config
               FOR EACH ROW EXECUTE FUNCTION {function_name}()"#,
        ))
        .execute(&pool)
        .await
        .unwrap();
        let failure = find_or_create_preset_by_image(&pool, &org_id, &failing_image)
            .await
            .expect_err("projection failure must roll back the auto-created preset");
        let failed_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM environment_presets WHERE org_id = $1 AND auto_image_ref = $2",
        )
        .bind(&org_id)
        .bind(&failing_image)
        .fetch_one(&pool)
        .await
        .unwrap();

        sqlx::query(&format!(
            "DROP TRIGGER {trigger_name} ON sandbox_template_config",
        ))
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(&format!("DROP FUNCTION {function_name}()"))
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM environment_presets WHERE org_id = $1")
            .bind(&org_id)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(&org_id)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(&user_id)
            .execute(&pool)
            .await
            .unwrap();

        assert_eq!(first.id, second.id);
        assert_eq!(
            first.project_spec.resources,
            codewire_project::ResourceSpec::default()
        );
        assert_eq!(
            second.project_spec.resources,
            codewire_project::ResourceSpec::default()
        );
        assert_eq!(
            materialize_image_caller(first_caller, &first)
                .resources
                .cpu_millicores,
            Some(1_000)
        );
        assert_eq!(
            materialize_image_caller(second_caller, &second)
                .resources
                .cpu_millicores,
            Some(6_000)
        );
        assert_eq!(canonical_count, 1);
        assert_eq!(projection_count, 1);
        assert!(
            failure
                .to_string()
                .contains("synthetic auto projection failure")
        );
        assert_eq!(failed_count, 0);
    }

    #[test]
    fn create_accepts_every_curated_workspace_agent() {
        for agent in [
            "claude-code",
            "codex",
            "gemini-cli",
            "kimi-code",
            "pi",
            "aider",
        ] {
            assert!(valid_agent_type(agent), "{agent}");
        }
        assert!(!valid_agent_type("not-an-agent"));
    }

    #[test]
    fn image_name_sanitization_is_stable_and_bounded() {
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
    fn canonical_and_explicit_image_references_are_stable() {
        assert_eq!(
            normalize_image_ref(crate::sandbox::CANONICAL_WORKSPACE_RUNTIME_IMAGE),
            crate::sandbox::CANONICAL_WORKSPACE_RUNTIME_IMAGE
        );
        assert_eq!(normalize_image_ref("python:3.12"), "python:3.12");
        // The former public GHCR location of the same digest resolves to the
        // Harbor reference deployments pull, as do the short workspace names.
        for legacy in [
            crate::sandbox::LEGACY_GHCR_CANONICAL_WORKSPACE_RUNTIME_IMAGE,
            "ghcr.io/codewiresh/workspace",
            "registry.example.invalid/codewire/workspace",
            " workspace ",
        ] {
            assert_eq!(
                normalize_image_ref(legacy),
                crate::sandbox::CANONICAL_WORKSPACE_RUNTIME_IMAGE
            );
        }
        assert!(
            crate::sandbox::CANONICAL_WORKSPACE_RUNTIME_IMAGE
                .starts_with("registry.example.invalid/codewire/workspace@sha256:")
        );
        assert!(crate::sandbox::is_canonical_workspace_runtime_image(
            crate::sandbox::LEGACY_GHCR_CANONICAL_WORKSPACE_RUNTIME_IMAGE
        ));
        assert!(!crate::sandbox::is_canonical_workspace_runtime_image(
            "ghcr.io/codewiresh/workspace@sha256:2058b7f1fd76f6f77b1dba596a9b54c698c049380e5ace6a0493f10a9d41e1b4"
        ));
    }

    #[test]
    fn canonical_project_spec_serialization_contains_bindings_but_no_resolved_values() {
        let project_spec = codewire_project::parse_project_yaml(
            r#"
repositories:
  - source: https://example.test/org/app.git
    revision: deadbeef
credentials: {profile: user/work}
"#,
        )
        .unwrap()
        .spec;
        let value = serde_json::to_value(project_spec).unwrap();

        assert_eq!(value["schema_version"], 1);
        assert_eq!(value["credentials"]["profile"], "user/work");
        let encoded = value.to_string();
        for forbidden in ["host_path", "token", "secret_value", "backend_socket"] {
            assert!(!encoded.contains(forbidden), "unexpected {forbidden}");
        }
    }

    #[test]
    fn create_environment_schema_exposes_only_placement_and_project_spec() {
        let schema = serde_json::to_value(schemars::schema_for!(CreateEnvironmentBody)).unwrap();
        let properties = schema["properties"].as_object().unwrap();
        assert_eq!(
            properties.keys().map(String::as_str).collect::<Vec<_>>(),
            [
                "confirm_personal_credentials",
                "confirm_personal_secrets",
                "expected_profile_revision",
                "isolation_tier",
                "name",
                "omit_application_previews",
                "preset_id",
                "project_spec",
                "ttl_seconds"
            ]
        );
    }

    #[test]
    fn create_environment_validation_defaults_to_an_empty_canonical_project_spec() {
        let parsed =
            validate_value::<CreateEnvironmentBody>(serde_json::json!({})).expect("empty body");

        assert!(parsed.preset_id.is_none());
        assert_eq!(
            parsed.project_spec,
            codewire_project::ProjectSpec::default()
        );
    }

    #[test]
    fn create_environment_rejects_removed_parallel_configuration_fields() {
        for field in [
            "repo_url",
            "repos",
            "image",
            "env_vars",
            "agent_env",
            "secret_project",
            "include_org_secrets",
        ] {
            let value = serde_json::Value::Object(
                [(field.to_owned(), serde_json::Value::Null)]
                    .into_iter()
                    .collect(),
            );
            assert!(
                validate_value::<CreateEnvironmentBody>(value).is_err(),
                "removed field {field} was accepted"
            );
        }
    }

    #[test]
    fn create_environment_validation_rejects_nested_project_type_errors() {
        let Err(AppError::Validation { errors }) =
            validate_value::<CreateEnvironmentBody>(serde_json::json!({
                "project_spec": {
                    "schema_version": 1,
                    "working_directory": "/workspace",
                    "resources": {"cpu_millicores": "2000"}
                }
            }))
        else {
            panic!("expected type-invalid CPU to be rejected");
        };

        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].path, "/");
        assert!(errors[0].message.contains("u32"));
    }

    #[test]
    fn create_environment_rejects_noncanonical_typed_project_spec() {
        let mut body = CreateEnvironmentBody::default();
        body.project_spec.schema_version = 0;
        let error = apply_project_spec_defaults(&mut body).unwrap_err();
        assert!(matches!(
            error,
            AppError::Coded {
                code: "invalid_project_spec",
                ..
            }
        ));
    }

    #[test]
    fn create_environment_requires_one_unambiguous_preset_selector() {
        for mut body in [
            CreateEnvironmentBody {
                preset_id: Some(String::new()),
                ..Default::default()
            },
            CreateEnvironmentBody {
                preset_id: Some("preset_exact".to_owned()),
                project_spec: codewire_project::parse_project_yaml("preset: rust\n")
                    .unwrap()
                    .spec,
                ..Default::default()
            },
        ] {
            let error = apply_project_spec_defaults(&mut body).unwrap_err();
            assert!(matches!(
                error,
                AppError::Coded {
                    code: "invalid_preset_selection",
                    ..
                }
            ));
        }
    }

    #[test]
    fn preset_scope_rejects_malformed_or_cross_organization_rows() {
        assert!(preset_is_visible_to_org(Some("org-a"), false, "org-a"));
        assert!(preset_is_visible_to_org(None, true, "org-a"));
        assert!(!preset_is_visible_to_org(Some("org-b"), false, "org-a"));
        assert!(!preset_is_visible_to_org(Some("org-a"), true, "org-a"));
        assert!(!preset_is_visible_to_org(None, false, "org-a"));
    }

    #[test]
    fn a_preset_with_an_image_override_remains_one_canonical_selection() {
        let mut body = CreateEnvironmentBody {
            project_spec: codewire_project::parse_project_yaml(
                "preset: rust\nimage: ghcr.io/example/rust@sha256:abc\n",
            )
            .unwrap()
            .spec,
            ..Default::default()
        };

        apply_project_spec_defaults(&mut body).unwrap();
        assert_eq!(body.project_spec.preset, "rust");
        assert_eq!(body.project_spec.image, "ghcr.io/example/rust@sha256:abc");
    }

    #[test]
    fn environment_resource_validation_rejects_each_non_positive_effective_value() {
        let cases = [
            (
                (Some(0), Some(4096), Some(10), Some(3600)),
                "project_spec.resources.cpu_millicores must be greater than zero",
            ),
            (
                (Some(2000), Some(0), Some(10), Some(3600)),
                "project_spec.resources.memory_mib must be greater than zero",
            ),
            (
                (Some(2000), Some(4096), Some(0), Some(3600)),
                "project_spec.resources.disk_gib must be greater than zero",
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
