//! Connect-RPC adapter for organization and official presets.
//!
//! This module maps the shared preset service logic to protobuf, validates
//! pagination, and renders Connect errors.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::sync::Arc;

use buffa_types::Timestamp;
use chrono::DateTime;
use codewire_proto::codewire::v1::{
    AppPort as ProtoAppPort, CreatePresetRequest, CreatePresetResponse, DeletePresetRequest,
    DeletePresetResponse, GetPresetRequest, GetPresetResponse, ListPresetsRequest,
    ListPresetsResponse, Preset, PresetService, RepoEntry as ProtoRepoEntry,
    SetupAgent as ProtoSetupAgent, SetupConfig as ProtoSetupConfig, UpdatePresetRequest,
    UpdatePresetResponse,
};
use codewire_server_core::connect::{auth_user, rpc_app_error};
use codewire_server_core::{AppError, AppResult, ValidationIssue};
use connectrpc::{RequestContext, ServiceRequest, ServiceResult};

use crate::api::ApiState;
use crate::api::create::{AppPort, RepoEntry, SetupAgent, SetupConfig};
use crate::api::prepare::PresetWire;
use crate::api::presets::{
    CreatePresetBody, SecretProjectSelection, UpdatePresetBody, create_preset_core,
    delete_preset_core, get_preset_core, list_presets_core, update_preset_core,
};

/// Registers all five PresetService RPCs on their generated Connect routes.
pub fn router(state: ApiState) -> connectrpc::Router {
    connectrpc::Router::new().add_service(Arc::new(PresetConnectService { state }))
}

struct PresetConnectService {
    state: ApiState,
}

#[allow(refining_impl_trait)]
impl PresetService for PresetConnectService {
    async fn list_presets(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ListPresetsRequest>,
    ) -> ServiceResult<ListPresetsResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();
        validate_pagination(request.page_token).map_err(|error| rpc_app_error(&error, &ctx))?;
        let presets = list_presets_core(&self.state, &user, request.org_id)
            .await
            .map_err(|error| rpc_app_error(&error, &ctx))?
            .into_iter()
            .map(proto_preset)
            .collect::<AppResult<Vec<_>>>()
            .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(ListPresetsResponse {
            presets,
            next_page_token: String::new(),
            ..Default::default()
        })
    }

    async fn create_preset(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, CreatePresetRequest>,
    ) -> ServiceResult<CreatePresetResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.to_owned_message();
        let name_missing = request.name.trim().is_empty();
        let org_id = request.org_id.clone();
        let (body, secret_project) = create_body(request);
        let preset = create_preset_core(&self.state, &user, &org_id, body, secret_project)
            .await
            .map_err(|error| {
                let error = create_preset_validation(error, name_missing);
                rpc_app_error(&error, &ctx)
            })?;
        connectrpc::Response::ok(CreatePresetResponse {
            preset: Some(proto_preset(preset).map_err(|error| rpc_app_error(&error, &ctx))?).into(),
            ..Default::default()
        })
    }

    async fn get_preset(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, GetPresetRequest>,
    ) -> ServiceResult<GetPresetResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();
        let preset = get_preset_core(&self.state, &user, request.org_id, request.preset_id)
            .await
            .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(GetPresetResponse {
            preset: Some(proto_preset(preset).map_err(|error| rpc_app_error(&error, &ctx))?).into(),
            ..Default::default()
        })
    }

    async fn update_preset(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, UpdatePresetRequest>,
    ) -> ServiceResult<UpdatePresetResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.to_owned_message();
        let org_id = request.org_id.clone();
        let preset_id = request.preset_id.clone();
        let (body, secret_project) = update_body(request);
        let preset = update_preset_core(
            &self.state,
            &user,
            &org_id,
            &preset_id,
            body,
            secret_project,
        )
        .await
        .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(UpdatePresetResponse {
            preset: Some(proto_preset(preset).map_err(|error| rpc_app_error(&error, &ctx))?).into(),
            ..Default::default()
        })
    }

    async fn delete_preset(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, DeletePresetRequest>,
    ) -> ServiceResult<DeletePresetResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();
        delete_preset_core(&self.state, &user, request.org_id, request.preset_id)
            .await
            .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(DeletePresetResponse::default())
    }
}

fn create_body(request: CreatePresetRequest) -> (CreatePresetBody, Option<SecretProjectSelection>) {
    let secret_project = request
        .secret_project_id
        .filter(|id| !id.is_empty())
        .map(SecretProjectSelection::Id);
    (
        CreatePresetBody {
            name: request.name,
            slug: request.slug,
            description: request.description,
            default_cpu_millicores: request.default_cpu_millicores,
            default_memory_mb: request.default_memory_mb,
            default_disk_gb: request.default_disk_gb,
            default_ttl_seconds: request.default_ttl_seconds,
            image: request.image,
            install_command: request.install_command,
            startup_script: request.startup_script,
            env_vars: string_map(request.env_vars),
            agents: request.agents.into_iter().map(api_setup_agent).collect(),
            install_agents: request.install_agents,
            agent: request.agent,
            agent_env: string_map(request.agent_env),
            app_ports: request.app_ports.into_iter().map(api_app_port).collect(),
            include_org_secrets: request.include_org_secrets,
            include_user_secrets: request.include_user_secrets,
            secret_project: String::new(),
        },
        secret_project,
    )
}

fn update_body(request: UpdatePresetRequest) -> (UpdatePresetBody, Option<SecretProjectSelection>) {
    let secret_project = request.secret_project_id.map(|id| {
        if id.is_empty() {
            SecretProjectSelection::Clear
        } else {
            SecretProjectSelection::Id(id)
        }
    });
    (
        UpdatePresetBody {
            name: request.name,
            description: request.description,
            slug: request.slug,
            default_cpu_millicores: request.default_cpu_millicores,
            default_memory_mb: request.default_memory_mb,
            default_disk_gb: request.default_disk_gb,
            default_ttl_seconds: request.default_ttl_seconds,
            image: request.image,
            install_command: request.install_command,
            startup_script: request.startup_script,
            env_vars: request
                .env_vars
                .into_option()
                .map(|map| string_map(map.values)),
            agents: request
                .agents
                .into_option()
                .map(|list| list.values.into_iter().map(api_setup_agent).collect()),
            install_agents: request.install_agents,
            agent: request.agent,
            agent_env: request
                .agent_env
                .into_option()
                .map(|map| string_map(map.values)),
            app_ports: request
                .app_ports
                .into_option()
                .map(|list| list.values.into_iter().map(api_app_port).collect()),
            include_org_secrets: request.include_org_secrets,
            include_user_secrets: request.include_user_secrets,
            secret_project: None,
        },
        secret_project,
    )
}

fn string_map(values: impl IntoIterator<Item = (String, String)>) -> BTreeMap<String, String> {
    values.into_iter().collect()
}

fn api_setup_agent(agent: ProtoSetupAgent) -> SetupAgent {
    SetupAgent {
        agent_type: agent.r#type,
    }
}

fn api_app_port(port: ProtoAppPort) -> AppPort {
    AppPort {
        port: port.port,
        label: port.label,
        access: port.access,
    }
}

fn validate_pagination(page_token: &str) -> AppResult<()> {
    if page_token.is_empty() {
        Ok(())
    } else {
        Err(AppError::BadRequest("unrecognized page_token".into()))
    }
}

fn create_preset_validation(error: AppError, name_missing: bool) -> AppError {
    if name_missing
        && matches!(
            &error,
            AppError::Coded {
                code: "name_required",
                ..
            }
        )
    {
        AppError::Validation {
            errors: vec![ValidationIssue {
                path: Cow::Borrowed("/name"),
                message: Cow::Borrowed("name is required"),
            }],
        }
    } else {
        error
    }
}

pub(crate) fn proto_preset(preset: PresetWire) -> AppResult<Preset> {
    Ok(Preset {
        id: preset.id,
        org_id: preset.org_id,
        name: preset.name,
        slug: preset.slug,
        language: preset.language,
        official: preset.official,
        description: preset.description,
        build_status: preset.build_status,
        build_error: preset.build_error,
        default_cpu_millicores: preset.default_cpu_millicores,
        default_memory_mb: preset.default_memory_mb,
        default_disk_gb: preset.default_disk_gb,
        default_ttl_seconds: preset.default_ttl_seconds,
        image: preset.image,
        default_setup_config: preset.default_setup_config.map(proto_setup_config).into(),
        secret_project_id: preset.secret_project_id,
        created_at: Some(proto_timestamp(&preset.created_at)?).into(),
        ..Default::default()
    })
}

fn proto_setup_config(config: SetupConfig) -> ProtoSetupConfig {
    ProtoSetupConfig {
        repo_url: config.repo_url,
        branch: config.branch,
        repos: config.repos.into_iter().map(proto_repo_entry).collect(),
        install_command: config.install_command,
        startup_script: config.startup_script,
        env_vars: config.env_vars.into_iter().collect(),
        agents: config.agents.into_iter().map(proto_setup_agent).collect(),
        install_agents: config.install_agents,
        agent: config.agent,
        agent_env: config.agent_env.into_iter().collect(),
        app_ports: config.app_ports.into_iter().map(proto_app_port).collect(),
        include_org_secrets: config.include_org_secrets,
        include_user_secrets: config.include_user_secrets,
        ..Default::default()
    }
}

fn proto_repo_entry(entry: RepoEntry) -> ProtoRepoEntry {
    ProtoRepoEntry {
        url: entry.url,
        branch: entry.branch,
        mount_path: entry.mount_path,
        ..Default::default()
    }
}

fn proto_setup_agent(agent: SetupAgent) -> ProtoSetupAgent {
    ProtoSetupAgent {
        r#type: agent.agent_type,
        ..Default::default()
    }
}

fn proto_app_port(port: AppPort) -> ProtoAppPort {
    ProtoAppPort {
        port: port.port,
        label: port.label,
        access: port.access,
        ..Default::default()
    }
}

fn proto_timestamp(value: &str) -> AppResult<Timestamp> {
    let value = DateTime::parse_from_rfc3339(value).map_err(|error| {
        tracing::error!(%error, created_at = value, "preset timestamp invalid");
        AppError::InternalMsg("failed to map preset timestamp".into())
    })?;
    Ok(Timestamp::from_unix(
        value.timestamp(),
        value.timestamp_subsec_nanos() as i32,
    ))
}

#[cfg(test)]
mod tests {
    use codewire_proto::codewire::v1::{AgentEnvMap, AgentList, AppPortList, EnvVarMap};

    use super::*;
    use codewire_server_core::connect_error::{ConnectCode, ConnectError, ConnectErrorDetail};

    #[test]
    fn update_mapping_preserves_absent_and_present_empty_collections() {
        let (absent, selection) = update_body(UpdatePresetRequest::default());
        assert!(absent.slug.is_none());
        assert!(absent.env_vars.is_none());
        assert!(absent.agents.is_none());
        assert!(absent.agent_env.is_none());
        assert!(absent.app_ports.is_none());
        assert!(selection.is_none());

        let (empty, selection) = update_body(UpdatePresetRequest {
            slug: Some(String::new()),
            env_vars: Some(EnvVarMap::default()).into(),
            agents: Some(AgentList::default()).into(),
            agent_env: Some(AgentEnvMap::default()).into(),
            app_ports: Some(AppPortList::default()).into(),
            secret_project_id: Some(String::new()),
            ..Default::default()
        });
        assert_eq!(empty.slug.as_deref(), Some(""));
        assert_eq!(empty.env_vars, Some(BTreeMap::new()));
        assert!(empty.agents.is_some_and(|agents| agents.is_empty()));
        assert_eq!(empty.agent_env, Some(BTreeMap::new()));
        assert!(empty.app_ports.is_some_and(|ports| ports.is_empty()));
        assert_eq!(selection, Some(SecretProjectSelection::Clear));
    }

    #[test]
    fn update_mapping_preserves_present_values_and_project_id() {
        let (body, selection) = update_body(UpdatePresetRequest {
            env_vars: Some(EnvVarMap {
                values: [("RUST_LOG".into(), "debug".into())].into_iter().collect(),
                ..Default::default()
            })
            .into(),
            agents: Some(AgentList {
                values: vec![ProtoSetupAgent {
                    r#type: "claude".into(),
                    ..Default::default()
                }],
                ..Default::default()
            })
            .into(),
            secret_project_id: Some("project_123".into()),
            ..Default::default()
        });
        assert_eq!(body.env_vars.unwrap()["RUST_LOG"], "debug");
        assert_eq!(body.agents.unwrap()[0].agent_type, "claude");
        assert_eq!(
            selection,
            Some(SecretProjectSelection::Id("project_123".into()))
        );
    }

    #[test]
    fn preset_mapping_keeps_presence_and_proto_json_names() {
        let preset = proto_preset(PresetWire {
            id: "preset_123".into(),
            org_id: Some("org_123".into()),
            name: "Rust".into(),
            slug: Some("rust".into()),
            language: Some("rust".into()),
            official: false,
            description: None,
            build_status: "ready".into(),
            build_error: None,
            default_cpu_millicores: 2_000,
            default_memory_mb: 4_096,
            default_disk_gb: 10,
            default_ttl_seconds: Some(3_600),
            image: None,
            default_setup_config: Some(SetupConfig {
                env_vars: [("RUST_LOG".into(), "info".into())].into_iter().collect(),
                ..Default::default()
            }),
            secret_project_id: Some("project_123".into()),
            created_at: "2026-07-18T03:10:02Z".into(),
        })
        .unwrap();
        let json = serde_json::to_value(preset).unwrap();
        assert_eq!(json["orgId"], "org_123");
        assert_eq!(json["defaultSetupConfig"]["envVars"]["RUST_LOG"], "info");
        assert_eq!(json["secretProjectId"], "project_123");
        assert_eq!(json["createdAt"], "2026-07-18T03:10:02Z");
        assert!(json.get("description").is_none());
    }

    #[test]
    fn pagination_rejects_unknown_tokens() {
        assert!(validate_pagination("").is_ok());
        assert!(matches!(
            validate_pagination("future"),
            Err(AppError::BadRequest(_))
        ));
    }

    #[test]
    fn missing_preset_name_names_the_name_proto_field() {
        let error = create_preset_validation(
            AppError::Coded {
                status: axum::http::StatusCode::BAD_REQUEST,
                code: "name_required",
                detail: "name is required".into(),
            },
            true,
        );
        let rendered = ConnectError::from_app_error(&error, None);
        assert_eq!(rendered.code, ConnectCode::InvalidArgument);
        let ConnectErrorDetail::BadRequest(detail) = &rendered.details[0] else {
            panic!("missing BadRequest detail");
        };
        assert_eq!(detail.field_violations[0].field, "name");
        assert!(!detail.field_violations[0].description.is_empty());
    }
}
