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

use axum::http::StatusCode;
use codewire_server_core::auth::AuthUser;
use codewire_server_core::org_deletion::{
    OrganizationRuntimeMutationError, run_organization_runtime_mutation,
};
use codewire_server_core::{AppError, AppResult};
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
use crate::confidential_storage::require_interactive_access;
use crate::repository_mount::validate_repository_mounts;

const CONFIDENTIAL_PERSISTENT_VOLUME_MAX_GIB: i32 = 50;

// ── Shared body types (environment_types.go) ────────────────────────────

/// Mirrors `api.RepoEntry`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct RepoEntry {
    #[serde(default)]
    pub url: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub branch: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub mount_path: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub revision: String,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option<serde_json::Value>")]
    pub project_spec: Option<codewire_project::ProjectSpec>,
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
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub isolation_tier: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option<serde_json::Value>")]
    pub project_spec: Option<codewire_project::ProjectSpec>,
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
    pub default_setup_config: Option<SetupConfig>,
    pub default_secret_project_id: Option<String>,
}

#[derive(sqlx::FromRow)]
struct PresetRow {
    id: String,
    org_id: Option<String>,
    official: bool,
    default_cpu_millicores: i32,
    default_memory_mb: i32,
    default_disk_gb: i32,
    default_ttl_seconds: Option<i32>,
    default_setup_config: Option<serde_json::Value>,
    default_secret_project_id: Option<String>,
}

impl PresetRow {
    fn into_preset(self) -> Preset {
        Preset {
            id: self.id,
            org_id: self.org_id,
            official: self.official,
            default_cpu_millicores: self.default_cpu_millicores,
            default_memory_mb: self.default_memory_mb,
            default_disk_gb: self.default_disk_gb,
            default_ttl_seconds: self.default_ttl_seconds,
            default_setup_config: self
                .default_setup_config
                .and_then(|value| serde_json::from_value::<SetupConfig>(value).ok()),
            default_secret_project_id: self.default_secret_project_id,
        }
    }
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
            "secret source {field} requires an explicit protected delivery mode that is not available for platform environments"
        ),
    ))
}

fn project_secret_source_selection(
    spec: Option<&codewire_project::ProjectSpec>,
) -> (bool, bool, bool) {
    spec.map_or((false, false, false), |spec| {
        (
            !spec.secrets.project.is_empty(),
            spec.secrets.organization,
            spec.secrets.user,
        )
    })
}

/// Reject every represented legacy secret source before compatibility fields
/// can overwrite one another. Selecting protected material does not choose a
/// delivery mode, and the platform runtime does not yet provide a secret-blind
/// one for these environment bindings.
pub(crate) fn ensure_no_legacy_secret_delivery(body: &CreateEnvironmentBody) -> AppResult<()> {
    let (project, organization, user) = project_secret_source_selection(body.project_spec.as_ref());
    secret_source_selection(
        !body.secret_project.is_empty() || project,
        body.include_org_secrets == Some(true) || organization,
        body.include_user_secrets == Some(true) || user,
    )
}

pub(crate) fn ensure_no_legacy_setup_secret_delivery(config: &SetupConfig) -> AppResult<()> {
    let (project, organization, user) =
        project_secret_source_selection(config.project_spec.as_ref());
    secret_source_selection(
        project,
        config.include_org_secrets == Some(true) || organization,
        config.include_user_secrets == Some(true) || user,
    )
}

fn ensure_no_legacy_detection_secret_delivery(detection: &DetectionResult) -> AppResult<()> {
    let (project, organization, user) =
        project_secret_source_selection(detection.project_spec.as_ref());
    secret_source_selection(
        !detection.secret_project.is_empty() || project,
        detection.include_org_secrets == Some(true) || organization,
        detection.include_user_secrets == Some(true) || user,
    )
}

pub(crate) fn ensure_no_legacy_preset_secret_delivery(
    default_secret_project_id: Option<&str>,
) -> AppResult<()> {
    if default_secret_project_id.is_none() {
        return Ok(());
    }
    Err(super::environments::coded_owned(
        StatusCode::BAD_REQUEST,
        "secret_delivery_pending",
        "preset secret source requires an explicit protected delivery mode that is not available for platform environments".to_owned(),
    ))
}

fn ensure_no_legacy_preset_defaults(preset: &Preset) -> AppResult<()> {
    if let Some(config) = preset.default_setup_config.as_ref() {
        ensure_no_legacy_setup_secret_delivery(config)?;
    }
    ensure_no_legacy_preset_secret_delivery(preset.default_secret_project_id.as_deref())
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
            mount_path: String::new(),
            revision: String::new(),
        }];
    }
}

/// Validate portable project intent for platform placement, then expose fields
/// understood by the existing setup worker through its compatibility view.
/// Fields already supplied by the caller remain explicit placement overrides.
pub(crate) fn apply_project_spec_defaults(body: &mut CreateEnvironmentBody) -> AppResult<()> {
    ensure_no_legacy_secret_delivery(body)?;
    let Some(spec) = body.project_spec.as_ref() else {
        return Ok(());
    };
    spec.validate().map_err(invalid_project_spec)?;
    if body.preset_slug.is_empty() && !spec.preset.is_empty() {
        body.preset_slug = spec.preset.clone();
    }
    if body.image.is_empty() && !spec.image.is_empty() {
        body.image = spec.image.clone();
    }
    if body.repos.is_empty() && !spec.repositories.is_empty() {
        body.repos = spec
            .repositories
            .iter()
            .map(|repository| RepoEntry {
                url: repository.source.clone(),
                branch: repository.branch.clone(),
                mount_path: repository.destination.clone(),
                revision: repository.revision.clone(),
            })
            .collect();
    }
    if body.install_command.is_empty() {
        body.install_command = spec.install_command.clone();
    }
    if body.startup_script.is_empty() {
        body.startup_script = spec.startup_script.clone();
    }
    if body.env_vars.is_empty() {
        body.env_vars = spec.environment.clone();
    }
    if body.agents.is_empty() {
        body.agents = spec
            .agents
            .tools
            .iter()
            .map(|agent_type| SetupAgent {
                agent_type: agent_type.clone(),
            })
            .collect();
    }
    if body.install_agents.is_none() {
        body.install_agents = spec.agents.install;
    }
    if body.agent_env.is_empty() {
        body.agent_env = spec.agent_environment.clone();
    }
    if body.app_ports.is_empty() {
        body.app_ports = spec
            .application_ports
            .iter()
            .map(|port| AppPort {
                port: i32::from(port.port),
                label: port.label.clone(),
                access: port.access.clone(),
            })
            .collect();
    }
    if body.cpu_millicores.is_none() {
        body.cpu_millicores = spec.resources.cpu_millicores.map(|value| value as i32);
    }
    if body.memory_mb.is_none() {
        body.memory_mb = spec.resources.memory_mib.map(|value| value as i32);
    }
    if body.disk_gb.is_none() {
        body.disk_gb = spec.resources.disk_gib.map(|value| value as i32);
    }
    if body.secret_project.is_empty() {
        body.secret_project = spec.secrets.project.clone();
    }
    if body.include_org_secrets.is_none() {
        body.include_org_secrets = Some(spec.secrets.organization);
    }
    if body.include_user_secrets.is_none() {
        body.include_user_secrets = Some(spec.secrets.user);
    }
    Ok(())
}

/// Merge an in-repository project document beneath explicit request values.
/// The repository list declared by codewire.yaml replaces the repository used
/// to discover that file; extended fields that have no legacy compatibility
/// field retain an explicit caller value when one was supplied.
pub(crate) fn apply_detected_project_spec(
    body: &mut CreateEnvironmentBody,
    detected: Option<&codewire_project::ProjectSpec>,
) -> AppResult<()> {
    let Some(detected) = detected else {
        return Ok(());
    };
    let current = body.project_spec.take();
    let mut merged = detected.clone();
    if let Some(current) = current {
        if !current.skills.is_empty() {
            merged.skills = current.skills;
        }
        if current.access.is_some() {
            merged.access = current.access;
        }
        if current.working_directory != default_project_working_directory(&current.repositories) {
            merged.working_directory = current.working_directory;
        }
    }
    if !detected.repositories.is_empty() {
        body.repo_url.clear();
        body.branch.clear();
        body.repos.clear();
    }
    body.project_spec = Some(merged);
    apply_project_spec_defaults(body)?;
    normalize_create_environment_body(body);
    Ok(())
}

/// Rebuild the compatibility fields of the portable spec from the effective
/// request while preserving fields owned only by the portable model. This
/// prevents mixed old/new clients and detection defaults from persisting two
/// conflicting descriptions of the workspace.
pub(crate) fn synchronize_project_spec(body: &mut CreateEnvironmentBody) -> AppResult<()> {
    let Some(mut spec) = body.project_spec.take() else {
        return Ok(());
    };
    let prior_default = default_project_working_directory(&spec.repositories);
    let custom_working_directory =
        (spec.working_directory != prior_default).then(|| spec.working_directory.clone());

    let destinations = codewire_project::validate_repository_destinations(
        body.repos
            .iter()
            .map(|repository| (repository.url.as_str(), repository.mount_path.as_str())),
    )
    .map_err(invalid_project_spec)?;
    spec.repositories = body
        .repos
        .iter()
        .zip(destinations)
        .map(
            |(repository, destination)| codewire_project::RepositorySpec {
                source: repository.url.clone(),
                revision: repository.revision.clone(),
                branch: repository.branch.clone(),
                destination,
            },
        )
        .collect();
    spec.working_directory = custom_working_directory
        .unwrap_or_else(|| default_project_working_directory(&spec.repositories));
    spec.preset = body.preset_slug.clone();
    spec.image = body.image.clone();
    spec.install_command = body.install_command.clone();
    spec.startup_script = body.startup_script.clone();
    spec.environment = body.env_vars.clone();
    spec.agents = codewire_project::AgentsSpec {
        install: body.install_agents,
        tools: body
            .agents
            .iter()
            .map(|agent| agent.agent_type.clone())
            .collect(),
    };
    spec.agent_environment = body.agent_env.clone();
    spec.application_ports = body
        .app_ports
        .iter()
        .map(|port| {
            Ok(codewire_project::ApplicationPort {
                port: u16::try_from(port.port).map_err(|_| {
                    invalid_project_spec_error("ports.port", "must be from 1 through 65535")
                })?,
                label: port.label.clone(),
                access: port.access.clone(),
            })
        })
        .collect::<AppResult<Vec<_>>>()?;
    spec.resources = codewire_project::ResourceSpec {
        cpu_millicores: optional_u32(body.cpu_millicores, "cpu")?,
        memory_mib: optional_u64(body.memory_mb, "memory")?,
        disk_gib: optional_u64(body.disk_gb, "disk")?,
    };
    spec.secrets = codewire_project::SecretBindings {
        project: body.secret_project.clone(),
        organization: body.include_org_secrets.unwrap_or(false),
        user: body.include_user_secrets.unwrap_or(false),
    };
    spec.validate().map_err(invalid_project_spec)?;
    body.project_spec = Some(spec);
    Ok(())
}

pub(crate) fn ensure_synchronized_project_spec(body: &mut CreateEnvironmentBody) -> AppResult<()> {
    body.project_spec
        .get_or_insert_with(codewire_project::ProjectSpec::default);
    synchronize_project_spec(body)
}

pub(crate) fn apply_detection_defaults(
    body: &mut CreateEnvironmentBody,
    detection: &DetectionResult,
) -> AppResult<()> {
    ensure_no_legacy_secret_delivery(body)?;
    ensure_no_legacy_detection_secret_delivery(detection)?;
    apply_detected_project_spec(body, detection.project_spec.as_ref())?;
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
    ensure_synchronized_project_spec(body)
}

fn default_project_working_directory(repositories: &[codewire_project::RepositorySpec]) -> String {
    match repositories {
        [repository] => repository.destination.clone(),
        _ => "/workspace".to_string(),
    }
}

fn optional_u32(value: Option<i32>, field: &'static str) -> AppResult<Option<u32>> {
    value
        .map(|value| {
            u32::try_from(value)
                .map_err(|_| invalid_project_spec_error(field, "must be greater than zero"))
        })
        .transpose()
}

fn optional_u64(value: Option<i32>, field: &'static str) -> AppResult<Option<u64>> {
    value
        .map(|value| {
            u64::try_from(value)
                .map_err(|_| invalid_project_spec_error(field, "must be greater than zero"))
        })
        .transpose()
}

fn invalid_project_spec_error(field: &'static str, detail: &'static str) -> AppError {
    invalid_project_spec(codewire_project::ProjectError::InvalidField {
        field,
        detail: detail.to_string(),
    })
}

fn ensure_current_platform_runtime_support(body: &CreateEnvironmentBody) -> AppResult<()> {
    let spec = body.project_spec.as_ref();
    let pending = if body
        .repos
        .iter()
        .any(|repository| !repository.revision.is_empty())
        || spec.is_some_and(|project| {
            project
                .repositories
                .iter()
                .any(|repository| !repository.revision.is_empty())
        }) {
        Some("repositories.revision")
    } else {
        let Some(spec) = spec else {
            return Ok(());
        };
        if !spec.skills.is_empty() {
            Some("skills")
        } else if spec.access.is_some() {
            Some("access")
        } else {
            let destinations =
                codewire_project::validate_repository_destinations(spec.repositories.iter().map(
                    |repository| (repository.source.as_str(), repository.destination.as_str()),
                ))
                .map_err(invalid_project_spec)?;
            let current_working_directory = match destinations.as_slice() {
                [destination] => destination.as_str(),
                _ => "/workspace",
            };
            (spec.working_directory != current_working_directory).then_some("working_directory")
        }
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

fn validate_environment_repository_mounts(repos: &[RepoEntry]) -> AppResult<()> {
    validate_repository_mounts(
        repos
            .iter()
            .map(|repo| (repo.url.as_str(), repo.mount_path.as_str())),
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

fn validate_confidential_storage_size(isolation_tier: &str, disk_gb: i32) -> AppResult<()> {
    if isolation_tier == "confidential" && disk_gb > CONFIDENTIAL_PERSISTENT_VOLUME_MAX_GIB {
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
    let row = sqlx::query_as::<_, PresetRow>(
        r#"SELECT et.id, et.org_id, et.official,
                  et.default_cpu_millicores, et.default_memory_mb, et.default_disk_gb,
                  et.default_ttl_seconds, et.default_setup_config,
                  et.default_secret_project_id
           FROM environment_presets et WHERE et.id = $1"#,
    )
    .bind(preset_id)
    .fetch_one(pool)
    .await?;
    Ok(row.into_preset())
}

/// Mirrors `getPresetBySlug` (org presets first, then official).
async fn get_preset_by_slug(
    pool: &PgPool,
    org_id: &str,
    slug: &str,
) -> Result<Preset, sqlx::Error> {
    let row = sqlx::query_as::<_, PresetRow>(
        r#"SELECT et.id, et.org_id, et.official,
                  et.default_cpu_millicores, et.default_memory_mb, et.default_disk_gb,
                  et.default_ttl_seconds, et.default_setup_config,
                  et.default_secret_project_id
           FROM environment_presets et
           WHERE et.slug = $1 AND (et.org_id = $2 OR (et.official = true AND et.org_id IS NULL))
           ORDER BY CASE WHEN et.org_id = $2 THEN 0 ELSE 1 END
           LIMIT 1"#,
    )
    .bind(slug)
    .bind(org_id)
    .fetch_one(pool)
    .await?;
    Ok(row.into_preset())
}

fn resolved_repo_config_preset_id(
    preset_id: Option<String>,
    setup_config: Option<serde_json::Value>,
) -> AppResult<Option<String>> {
    if let Some(config) =
        setup_config.and_then(|value| serde_json::from_value::<SetupConfig>(value).ok())
    {
        ensure_no_legacy_setup_secret_delivery(&config)?;
    }
    Ok(preset_id.filter(|preset_id| !preset_id.is_empty()))
}

/// Mirrors `resolveFromRepoConfig`: validate the saved setup intent, then
/// resolve its preset. Lookup failures preserve the legacy detection fallback.
async fn resolve_from_repo_config(
    pool: &PgPool,
    org_id: &str,
    repo_url: &str,
) -> AppResult<Option<Preset>> {
    let row: Option<(Option<String>, Option<serde_json::Value>)> = sqlx::query_as(
        "SELECT preset_id, setup_config FROM repo_configs WHERE org_id = $1 AND repo_url = $2",
    )
    .bind(org_id)
    .bind(repo_url)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten();
    let Some((preset_id, setup_config)) = row else {
        return Ok(None);
    };
    let Some(preset_id) = resolved_repo_config_preset_id(preset_id, setup_config)? else {
        return Ok(None);
    };
    Ok(get_preset(pool, &preset_id).await.ok())
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
    isolation_tier: &'a str,
    ttl_seconds: Option<i32>,
    setup_config: Option<&'a SetupConfig>,
}

async fn insert_environment(
    pool: &PgPool,
    p: InsertEnvironmentParams<'_>,
) -> AppResult<Environment> {
    let setup_json = match p.setup_config {
        Some(cfg) => Some(serde_json::to_value(cfg).map_err(|error| {
            tracing::error!(%error, "serialize environment setup config");
            coded(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "failed to serialize environment setup",
            )
        })?),
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
                 cpu_millicores, memory_mb, disk_gb, isolation_tier, ttl_seconds,
                 shutdown_at, auth_token, setup_config, secret_project_id)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
                 CASE WHEN $11::int IS NOT NULL THEN NOW() + make_interval(secs => $11::int) END,
                 gen_random_uuid()::text, $12, NULL)
             RETURNING *
         )
         SELECT {ENV_SELECT_COLS}
         FROM ins e
         {ENV_SELECT_JOINS}"#
    );
    let mut transaction = pool.begin().await?;
    if p.isolation_tier == "confidential" {
        reserve_confidential_capacity(&mut transaction, p.org_id).await?;
    }
    let row = sqlx::query(&sql)
        .bind(p.org_id)
        .bind(p.created_by)
        .bind(preset_id)
        .bind(p.env_type)
        .bind(&name)
        .bind(p.cpu_millicores)
        .bind(p.memory_mb)
        .bind(p.disk_gb)
        .bind(p.isolation_tier)
        .bind(p.ttl_seconds)
        .bind(p.ttl_seconds)
        .bind(setup_json)
        .fetch_one(&mut *transaction)
        .await?;
    transaction.commit().await?;
    Ok(scan_environment(&row)?)
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

fn int_or_default(v: Option<i32>, default: i32) -> i32 {
    v.unwrap_or(default)
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
    require_interactive_access(state.confidential_storage_flags, user, isolation_tier)?;
    ensure_no_legacy_secret_delivery(&body)?;

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

    apply_project_spec_defaults(&mut body)?;
    normalize_create_environment_body(&mut body);
    synchronize_project_spec(&mut body)?;
    ensure_current_platform_runtime_support(&body)?;
    validate_environment_repository_mounts(&body.repos)?;
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
                match resolve_from_repo_config(pool, org_id, &body.repo_url).await? {
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

            ensure_no_legacy_preset_defaults(&preset)?;

            let cpu = body.cpu_millicores.unwrap_or(preset.default_cpu_millicores);
            let mem = body.memory_mb.unwrap_or(preset.default_memory_mb);
            let disk = body.disk_gb.unwrap_or(preset.default_disk_gb);
            let ttl = match body.ttl_seconds {
                Some(t) => Some(t),
                None => preset.default_ttl_seconds,
            };

            validate_environment_resources(Some(cpu), Some(mem), Some(disk), ttl)?;
            validate_confidential_storage_size(isolation_tier, disk)?;
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
            let needs_setup_cfg = create_needs_setup_config(&body);
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
                project_spec: body.project_spec.clone(),
            });

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
                    isolation_tier,
                    ttl_seconds: ttl,
                    setup_config: setup_cfg.as_ref(),
                },
            )
            .await?;

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

fn create_needs_setup_config(body: &CreateEnvironmentBody) -> bool {
    !body.repo_url.is_empty()
        || !body.repos.is_empty()
        || !body.install_command.is_empty()
        || !body.startup_script.is_empty()
        || !body.env_vars.is_empty()
        || !body.agents.is_empty()
        || body.install_agents.is_some()
        || !body.agent.is_empty()
        || !body.agent_env.is_empty()
        || !body.app_ports.is_empty()
        || body.include_org_secrets.is_some()
        || body.include_user_secrets.is_some()
        || body.project_spec.is_some()
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

    apply_detection_defaults(body, &result)?;
    ensure_current_platform_runtime_support(body)?;
    validate_environment_repository_mounts(&body.repos)?;

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
    use sqlx::postgres::PgPoolOptions;

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
                    revision: String::new(),
                    mount_path: "/workspace/api".into(),
                },
                RepoEntry {
                    url: "https://github.com/x/z".into(),
                    branch: String::new(),
                    revision: String::new(),
                    mount_path: "/workspace/web".into(),
                },
            ],
            ..Default::default()
        };
        normalize_create_environment_body(&mut b);
        assert_eq!(b.repo_url, "https://github.com/x/y");
        assert_eq!(b.branch, "dev");
        assert_eq!(b.repos.len(), 2);
        validate_environment_repository_mounts(&b.repos).unwrap();
    }

    #[test]
    fn repository_mounts_are_safe_and_non_overlapping() {
        let invalid = [
            vec![RepoEntry {
                url: "https://github.com/x/y".into(),
                mount_path: "/workspace/../outside".into(),
                ..Default::default()
            }],
            vec![
                RepoEntry {
                    url: "https://github.com/x/y".into(),
                    mount_path: "/workspace/app".into(),
                    ..Default::default()
                },
                RepoEntry {
                    url: "https://github.com/x/z".into(),
                    mount_path: "/workspace/app/docs".into(),
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
    fn project_spec_defaults_are_explicit_and_direct_mode_is_typed_local_only() {
        let spec = codewire_project::parse_project_yaml(
            r#"
image: ghcr.io/example/workspace:1
repositories:
  - source: https://example.test/org/app.git
    branch: main
    destination: /workspace/app
install: cargo fetch
startup: cargo test
env: {RUST_LOG: info}
agents: {install: false, tools: [claude]}
ports: [{port: 8080, label: api, access: private}]
cpu: 2
memory: 4Gi
disk: 40Gi
secrets: {organization: false, user: false}
"#,
        )
        .unwrap()
        .spec;
        let mut body = CreateEnvironmentBody {
            project_spec: Some(spec.clone()),
            ..Default::default()
        };

        apply_project_spec_defaults(&mut body).unwrap();
        assert_eq!(body.image, spec.image);
        assert_eq!(body.repos[0].url, spec.repositories[0].source);
        assert_eq!(body.repos[0].branch, "main");
        assert_eq!(body.install_command, "cargo fetch");
        assert_eq!(body.startup_script, "cargo test");
        assert_eq!(body.env_vars["RUST_LOG"], "info");
        assert_eq!(body.agents[0].agent_type, "claude-code");
        assert_eq!(body.install_agents, Some(false));
        assert_eq!(body.app_ports[0].port, 8080);
        assert_eq!(body.cpu_millicores, Some(2000));
        assert_eq!(body.memory_mb, Some(4096));
        assert_eq!(body.disk_gb, Some(40));
        assert!(body.secret_project.is_empty());
        assert_eq!(body.include_org_secrets, Some(false));
        assert_eq!(body.include_user_secrets, Some(false));
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
    fn direct_and_project_secret_sources_fail_closed_before_synchronization() {
        for body in [
            CreateEnvironmentBody {
                secret_project: "project-secret-value".to_owned(),
                ..Default::default()
            },
            CreateEnvironmentBody {
                include_org_secrets: Some(true),
                ..Default::default()
            },
            CreateEnvironmentBody {
                include_user_secrets: Some(true),
                ..Default::default()
            },
        ] {
            assert_secret_delivery_pending(
                ensure_no_legacy_secret_delivery(&body).unwrap_err(),
                Some("project-secret-value"),
            );
        }

        for yaml in [
            "secrets: {project: nested-project-secret-value}\n",
            "secrets: {organization: true}\n",
            "secrets: {user: true}\n",
        ] {
            let mut body = CreateEnvironmentBody {
                include_org_secrets: Some(false),
                include_user_secrets: Some(false),
                project_spec: Some(codewire_project::parse_project_yaml(yaml).unwrap().spec),
                ..Default::default()
            };
            assert_secret_delivery_pending(
                apply_project_spec_defaults(&mut body).unwrap_err(),
                Some("nested-project-secret-value"),
            );
        }

        ensure_no_legacy_secret_delivery(&CreateEnvironmentBody {
            include_org_secrets: Some(false),
            include_user_secrets: Some(false),
            project_spec: Some(
                codewire_project::parse_project_yaml(
                    "secrets: {organization: false, user: false}\n",
                )
                .unwrap()
                .spec,
            ),
            ..Default::default()
        })
        .unwrap();
    }

    #[test]
    fn detection_secret_sources_fail_closed_before_explicit_false_can_mask_them() {
        let detections = [
            DetectionResult {
                secret_project: "detected-project-secret-value".to_owned(),
                ..Default::default()
            },
            DetectionResult {
                include_org_secrets: Some(true),
                ..Default::default()
            },
            DetectionResult {
                include_user_secrets: Some(true),
                ..Default::default()
            },
            DetectionResult {
                project_spec: Some(
                    codewire_project::parse_project_yaml("secrets: {organization: true}\n")
                        .unwrap()
                        .spec,
                ),
                ..Default::default()
            },
        ];
        for detection in detections {
            let mut body = CreateEnvironmentBody {
                include_org_secrets: Some(false),
                include_user_secrets: Some(false),
                ..Default::default()
            };
            assert_secret_delivery_pending(
                apply_detection_defaults(&mut body, &detection).unwrap_err(),
                Some("detected-project-secret-value"),
            );
        }

        let mut body = CreateEnvironmentBody {
            include_org_secrets: Some(false),
            include_user_secrets: Some(false),
            ..Default::default()
        };
        apply_detection_defaults(
            &mut body,
            &DetectionResult {
                include_org_secrets: Some(false),
                include_user_secrets: Some(false),
                ..Default::default()
            },
        )
        .unwrap();
    }

    #[test]
    fn preset_secret_defaults_fail_closed_without_rendering_identifiers() {
        ensure_no_legacy_preset_defaults(&Preset::default()).unwrap();
        assert_secret_delivery_pending(
            ensure_no_legacy_preset_defaults(&Preset {
                default_secret_project_id: Some("preset-project-secret-value".to_owned()),
                ..Default::default()
            })
            .unwrap_err(),
            Some("preset-project-secret-value"),
        );
        assert_secret_delivery_pending(
            ensure_no_legacy_preset_defaults(&Preset {
                default_setup_config: Some(SetupConfig {
                    include_user_secrets: Some(true),
                    ..Default::default()
                }),
                ..Default::default()
            })
            .unwrap_err(),
            None,
        );
    }

    #[test]
    fn saved_repo_config_secret_sources_fail_before_preset_resolution() {
        for config in [
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
        ] {
            assert_secret_delivery_pending(
                resolved_repo_config_preset_id(
                    Some("preset-test".to_owned()),
                    Some(serde_json::to_value(config).unwrap()),
                )
                .unwrap_err(),
                Some("saved-project-secret-value"),
            );
        }

        assert_eq!(
            resolved_repo_config_preset_id(
                Some("preset-test".to_owned()),
                Some(
                    serde_json::to_value(SetupConfig {
                        include_org_secrets: Some(false),
                        include_user_secrets: Some(false),
                        ..Default::default()
                    })
                    .unwrap(),
                ),
            )
            .unwrap()
            .as_deref(),
            Some("preset-test")
        );
    }

    #[test]
    fn explicit_false_secret_selection_persists_setup_config() {
        let mut body = CreateEnvironmentBody::default();
        assert!(!create_needs_setup_config(&body));

        body.include_user_secrets = Some(false);
        assert!(create_needs_setup_config(&body));

        body.include_user_secrets = None;
        body.include_org_secrets = Some(false);
        assert!(create_needs_setup_config(&body));
    }

    #[test]
    fn detected_project_spec_and_explicit_request_resolve_to_one_canonical_plan() {
        let requested = codewire_project::parse_project_yaml(
            "repositories: [{source: https://example.test/org/discovery.git}]\ninstall: caller-install\n",
        )
        .unwrap()
        .spec;
        let detected = codewire_project::parse_project_yaml(
            r#"
image: ghcr.io/example/workspace@sha256:abc
repositories:
  - source: https://example.test/org/api.git
    destination: /workspace/api
skills: [.agents/skills/rust]
cpu: 2
memory: 16Gi
"#,
        )
        .unwrap()
        .spec;
        let mut body = CreateEnvironmentBody {
            repo_url: "https://example.test/org/discovery.git".to_string(),
            repos: vec![RepoEntry {
                url: "https://example.test/org/discovery.git".to_string(),
                ..Default::default()
            }],
            install_command: "caller-install".to_string(),
            project_spec: Some(requested),
            ..Default::default()
        };
        apply_detection_defaults(
            &mut body,
            &DetectionResult {
                preset_image: detected.image.clone(),
                install_command: "detected-install".to_string(),
                project_spec: Some(detected),
                ..Default::default()
            },
        )
        .unwrap();

        assert_eq!(body.repo_url, "https://example.test/org/api.git");
        assert_eq!(body.repos[0].mount_path, "/workspace/api");
        assert_eq!(body.install_command, "caller-install");
        assert_eq!(body.cpu_millicores, Some(2000));
        assert_eq!(body.memory_mb, Some(16 * 1024));
        let project = body.project_spec.expect("synchronized project spec");
        assert_eq!(project.repositories[0].source, body.repos[0].url);
        assert_eq!(project.working_directory, "/workspace/api");
        assert_eq!(project.install_command, body.install_command);
        assert_eq!(project.skills[0].reference, ".agents/skills/rust");
        project.validate().unwrap();
    }

    #[test]
    fn legacy_detection_builds_a_portable_spec_and_mixed_fields_cannot_diverge() {
        let mut body = CreateEnvironmentBody {
            repo_url: "codewiresh/codewire".to_string(),
            repos: vec![RepoEntry {
                url: "codewiresh/codewire".to_string(),
                ..Default::default()
            }],
            image: "ghcr.io/example/explicit:1".to_string(),
            project_spec: Some(codewire_project::ProjectSpec {
                image: "ghcr.io/example/stale:1".to_string(),
                ..Default::default()
            }),
            ..Default::default()
        };
        apply_project_spec_defaults(&mut body).unwrap();
        normalize_create_environment_body(&mut body);
        synchronize_project_spec(&mut body).unwrap();
        assert_eq!(
            body.project_spec.as_ref().unwrap().image,
            "ghcr.io/example/explicit:1"
        );

        body.project_spec = None;
        apply_detection_defaults(
            &mut body,
            &DetectionResult {
                startup_script: "cargo test".to_string(),
                agents: vec![SetupAgent {
                    agent_type: "codex".to_string(),
                }],
                ..Default::default()
            },
        )
        .unwrap();
        let project = body.project_spec.expect("legacy request migration spec");
        assert_eq!(project.repositories[0].source, "codewiresh/codewire");
        assert_eq!(project.working_directory, "/workspace/codewire");
        assert_eq!(project.startup_script, "cargo test");
        assert_eq!(project.agents.tools, ["codex"]);
        project.validate().unwrap();
    }

    #[test]
    fn represented_project_features_fail_closed_until_the_platform_runtime_owns_them() {
        for yaml in [
            "repositories: [{source: https://example.test/app.git, revision: deadbeef}]\n",
            "skills: [.agents/skills/rust]\n",
            "access: {profile: user/work}\n",
            "repositories: [{source: https://example.test/app.git}]\nworking_directory: /workspace/app/subdir\n",
        ] {
            let spec = codewire_project::parse_project_yaml(yaml).unwrap().spec;
            let error = ensure_current_platform_runtime_support(&CreateEnvironmentBody {
                project_spec: Some(spec),
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

        let error = ensure_current_platform_runtime_support(&CreateEnvironmentBody {
            repos: vec![RepoEntry {
                url: "https://example.test/app.git".to_string(),
                revision: "deadbeef".to_string(),
                ..Default::default()
            }],
            ..Default::default()
        })
        .unwrap_err();
        assert!(matches!(
            error,
            AppError::Coded {
                code: "project_feature_pending",
                ..
            }
        ));
    }

    #[test]
    fn isolation_tier_is_an_explicit_product_choice() {
        let mut body = CreateEnvironmentBody {
            isolation_tier: "confidential".into(),
            ..Default::default()
        };
        normalize_create_environment_body(&mut body);
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
            "INSERT INTO environment_presets (id, org_id, name, build_status) VALUES ($1, $2, 'Confidential test', 'ready')",
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
            "INSERT INTO environments (id, org_id, created_by, type, preset_id, state, desired_state, isolation_tier) VALUES ($1, $2, $3, 'sandbox', $4, 'pending', 'started', 'confidential')",
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
                revision: String::new(),
                mount_path: String::new(),
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
    fn setup_config_persists_the_versioned_project_spec_without_values() {
        let project_spec = codewire_project::parse_project_yaml(
            r#"
repositories:
  - source: https://example.test/org/app.git
    revision: deadbeef
access: {profile: user/work}
"#,
        )
        .unwrap()
        .spec;
        let value = serde_json::to_value(SetupConfig {
            project_spec: Some(project_spec),
            ..Default::default()
        })
        .unwrap();

        assert_eq!(value["project_spec"]["schema_version"], 1);
        assert_eq!(value["project_spec"]["access"]["profile"], "user/work");
        let encoded = value.to_string();
        for forbidden in ["host_path", "token", "secret_value", "backend_socket"] {
            assert!(!encoded.contains(forbidden), "unexpected {forbidden}");
        }
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
