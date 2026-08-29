use std::time::Duration;

use chrono::{DateTime, SecondsFormat, Utc};
use codewire_client::{self as rpc, ClientConfig, ClientError, CodewireClient, ErrorCode};
use serde::{Deserialize, Serialize};

use crate::CLI_VERSION;
use crate::config::ResolvedPlatformConfig;
use crate::organization_client::legacy_preset;
use crate::presentation::*;

/// Typed EnvironmentService facade preserving the CLI's established
/// presentation shapes over the shared Connect client.
///
/// The CLI keeps its existing presentation DTOs until their owning commands
/// are migrated. This facade is the only place that translates those DTOs to
/// and from the shared generated Connect client.
#[derive(Clone)]
pub struct EnvironmentClient {
    inner: CodewireClient,
}

impl EnvironmentClient {
    pub fn new(config: &ResolvedPlatformConfig) -> anyhow::Result<Self> {
        Ok(Self {
            inner: connect_client(config)?,
        })
    }

    pub async fn list_environments(&self, org_id: &str) -> anyhow::Result<Vec<Environment>> {
        let response = self
            .inner
            .list_environments(rpc::ListEnvironmentsRequest {
                org_id: org_id.to_string(),
                ..Default::default()
            })
            .await
            .map_err(display_client_error)?;
        Ok(response
            .environments
            .into_iter()
            .map(legacy_environment)
            .collect())
    }

    pub async fn create_environment(
        &self,
        org_id: &str,
        request: &CreateEnvironmentRequest,
    ) -> anyhow::Result<Environment> {
        let response = self
            .inner
            .create_environment(proto_create_environment_request(org_id, request))
            .await
            .map_err(display_client_error)?;
        response
            .environment
            .into_option()
            .map(legacy_environment)
            .ok_or_else(|| anyhow::anyhow!("CreateEnvironment returned no environment"))
    }

    pub async fn prepare_environment_create(
        &self,
        org_id: &str,
        request: &PrepareEnvironmentRequest,
    ) -> anyhow::Result<PrepareEnvironmentResponse> {
        let events = self
            .inner
            .watch_environment_create(rpc::WatchEnvironmentCreateRequest {
                org_id: org_id.to_string(),
                draft: Some(proto_create_environment_request(org_id, &request.draft)).into(),
                analyze: request.analyze,
                ..Default::default()
            })
            .await
            .map_err(display_client_error)?;
        let complete = events
            .into_iter()
            .filter_map(|event| event.event)
            .find_map(|event| match event {
                rpc::watch_environment_create_response::Event::Complete(complete) => {
                    Some(*complete)
                }
                rpc::watch_environment_create_response::Event::Progress(_)
                | rpc::watch_environment_create_response::Event::RepoFetched(_) => None,
            })
            .ok_or_else(|| {
                anyhow::anyhow!("WatchEnvironmentCreate ended without a complete event")
            })?;
        legacy_prepare_complete(complete)
    }

    pub async fn get_environment(
        &self,
        org_id: &str,
        environment_id: &str,
    ) -> anyhow::Result<Environment> {
        Ok(self
            .get_environment_with_poll_interval(org_id, environment_id)
            .await?
            .0)
    }

    pub async fn get_environment_with_poll_interval(
        &self,
        org_id: &str,
        environment_id: &str,
    ) -> anyhow::Result<(Environment, Option<Duration>)> {
        let response = self
            .inner
            .get_environment(rpc::GetEnvironmentRequest {
                org_id: org_id.to_string(),
                environment_id: environment_id.to_string(),
                ..Default::default()
            })
            .await
            .map_err(display_client_error)?;
        let poll_interval = response
            .poll_interval
            .into_option()
            .and_then(proto_duration_to_std);
        let environment = response
            .environment
            .into_option()
            .map(legacy_environment)
            .ok_or_else(|| anyhow::anyhow!("GetEnvironment returned no environment"))?;
        Ok((environment, poll_interval))
    }

    pub async fn resize_environment(
        &self,
        org_id: &str,
        environment_id: &str,
        desired: &EnvironmentResizeResources,
        request_id: &str,
        force: bool,
        allow_restart: bool,
    ) -> anyhow::Result<(EnvironmentResizeResult, Option<Duration>)> {
        let response = self
            .inner
            .resize_environment(rpc::ResizeEnvironmentRequest {
                org_id: org_id.to_string(),
                environment_id: environment_id.to_string(),
                cpu_millicores: desired.cpu_millicores,
                memory_mb: desired.memory_mb,
                disk_gb: desired.disk_gb,
                request_id: request_id.to_string(),
                force,
                disruption_policy: if allow_restart {
                    rpc::EnvironmentResizeDisruptionPolicy::AllowRestart
                } else {
                    rpc::EnvironmentResizeDisruptionPolicy::LiveOnly
                }
                .into(),
                ..Default::default()
            })
            .await
            .map_err(display_client_error)?;
        legacy_environment_resize_response(
            response.operation.into_option(),
            response.environment.into_option(),
            response.poll_interval.into_option(),
        )
    }

    pub async fn plan_environment_resize(
        &self,
        org_id: &str,
        environment_id: &str,
        desired: &EnvironmentResizeResources,
    ) -> anyhow::Result<EnvironmentResizePlan> {
        let response = self
            .inner
            .plan_environment_resize(rpc::PlanEnvironmentResizeRequest {
                org_id: org_id.to_string(),
                environment_id: environment_id.to_string(),
                cpu_millicores: desired.cpu_millicores,
                memory_mb: desired.memory_mb,
                disk_gb: desired.disk_gb,
                ..Default::default()
            })
            .await
            .map_err(display_client_error)?;
        response
            .plan
            .into_option()
            .map(legacy_environment_resize_plan)
            .ok_or_else(|| anyhow::anyhow!("PlanEnvironmentResize returned no plan"))
    }

    pub async fn get_environment_resize_operation(
        &self,
        org_id: &str,
        environment_id: &str,
        operation_id: &str,
    ) -> anyhow::Result<(EnvironmentResizeResult, Option<Duration>)> {
        let response = self
            .inner
            .get_environment_resize_operation(rpc::GetEnvironmentResizeOperationRequest {
                org_id: org_id.to_string(),
                environment_id: environment_id.to_string(),
                operation_id: operation_id.to_string(),
                ..Default::default()
            })
            .await
            .map_err(display_client_error)?;
        legacy_environment_resize_response(
            response.operation.into_option(),
            response.environment.into_option(),
            response.poll_interval.into_option(),
        )
    }

    pub async fn get_environment_trust_report(
        &self,
        org_id: &str,
        environment_id: &str,
    ) -> anyhow::Result<EnvironmentTrustReport> {
        let response = self
            .inner
            .get_environment_trust_report(rpc::GetEnvironmentTrustReportRequest {
                org_id: org_id.to_string(),
                environment_id: environment_id.to_string(),
                ..Default::default()
            })
            .await
            .map_err(display_client_error)?;
        response
            .trust_report
            .into_option()
            .map(legacy_environment_trust_report)
            .ok_or_else(|| anyhow::anyhow!("GetEnvironmentTrustReport returned no trust report"))
    }

    pub async fn get_environment_daemon_status(
        &self,
        org_id: &str,
        environment_id: &str,
    ) -> anyhow::Result<EnvironmentDaemonStatus> {
        let response = self
            .inner
            .get_environment_daemon_status(rpc::GetEnvironmentDaemonStatusRequest {
                org_id: org_id.to_string(),
                environment_id: environment_id.to_string(),
                ..Default::default()
            })
            .await
            .map_err(display_client_error)?;
        response
            .status
            .into_option()
            .map(legacy_environment_daemon_status)
            .ok_or_else(|| anyhow::anyhow!("GetEnvironmentDaemonStatus returned no status"))
    }

    pub async fn get_environment_daemon_logs(
        &self,
        org_id: &str,
        environment_id: &str,
    ) -> anyhow::Result<Vec<u8>> {
        let mut data = Vec::new();
        self.inner
            .stream_environment_daemon_logs(
                rpc::StreamEnvironmentDaemonLogsRequest {
                    org_id: org_id.to_string(),
                    environment_id: environment_id.to_string(),
                    ..Default::default()
                },
                |message| {
                    data.extend_from_slice(&message.data);
                    true
                },
            )
            .await
            .map_err(display_client_error)?;
        Ok(data)
    }

    pub async fn repair_environment_daemon(
        &self,
        org_id: &str,
        environment_id: &str,
    ) -> anyhow::Result<EnvironmentDaemonRepair> {
        let response = self
            .inner
            .repair_environment_daemon(rpc::RepairEnvironmentDaemonRequest {
                org_id: org_id.to_string(),
                environment_id: environment_id.to_string(),
                ..Default::default()
            })
            .await
            .map_err(display_client_error)?;
        let status = response
            .status
            .into_option()
            .map(legacy_environment_daemon_status)
            .ok_or_else(|| anyhow::anyhow!("RepairEnvironmentDaemon returned no status"))?;
        Ok(EnvironmentDaemonRepair {
            status,
            replaced_pod_name: response.replaced_pod_name,
        })
    }

    pub async fn stop_environment(
        &self,
        org_id: &str,
        environment_id: &str,
    ) -> anyhow::Result<StatusResponse> {
        let response = self
            .inner
            .stop_environment(rpc::StopEnvironmentRequest {
                org_id: org_id.to_string(),
                environment_id: environment_id.to_string(),
                ..Default::default()
            })
            .await
            .map_err(display_client_error)?;
        Ok(StatusResponse {
            status: response.status,
        })
    }

    pub async fn start_environment(
        &self,
        org_id: &str,
        environment_id: &str,
    ) -> anyhow::Result<StatusResponse> {
        let response = self
            .inner
            .start_environment(rpc::StartEnvironmentRequest {
                org_id: org_id.to_string(),
                environment_id: environment_id.to_string(),
                ..Default::default()
            })
            .await
            .map_err(display_client_error)?;
        Ok(StatusResponse {
            status: response.status,
        })
    }

    pub async fn delete_environment(
        &self,
        org_id: &str,
        environment_id: &str,
    ) -> anyhow::Result<()> {
        self.inner
            .delete_environment(rpc::DeleteEnvironmentRequest {
                org_id: org_id.to_string(),
                environment_id: environment_id.to_string(),
                ..Default::default()
            })
            .await
            .map_err(display_client_error)?;
        Ok(())
    }

    pub async fn protect_environment(
        &self,
        org_id: &str,
        environment_id: &str,
    ) -> anyhow::Result<StatusResponse> {
        let response = self
            .inner
            .protect_environment(rpc::ProtectEnvironmentRequest {
                org_id: org_id.to_string(),
                environment_id: environment_id.to_string(),
                ..Default::default()
            })
            .await
            .map_err(display_client_error)?;
        Ok(StatusResponse {
            status: response.status,
        })
    }

    pub async fn unprotect_environment(
        &self,
        org_id: &str,
        environment_id: &str,
    ) -> anyhow::Result<StatusResponse> {
        let response = self
            .inner
            .unprotect_environment(rpc::UnprotectEnvironmentRequest {
                org_id: org_id.to_string(),
                environment_id: environment_id.to_string(),
                ..Default::default()
            })
            .await
            .map_err(display_client_error)?;
        Ok(StatusResponse {
            status: response.status,
        })
    }

    pub async fn cancel_environment_deletion(
        &self,
        org_id: &str,
        environment_id: &str,
    ) -> anyhow::Result<StatusResponse> {
        let response = self
            .inner
            .cancel_environment_deletion(rpc::CancelEnvironmentDeletionRequest {
                org_id: org_id.to_string(),
                environment_id: environment_id.to_string(),
                ..Default::default()
            })
            .await
            .map_err(display_client_error)?;
        Ok(StatusResponse {
            status: response.status,
        })
    }

    pub async fn extend_environment_ttl(
        &self,
        org_id: &str,
        environment_id: &str,
        request: &ExtendTtlRequest,
    ) -> anyhow::Result<StatusResponse> {
        let response = self
            .inner
            .extend_environment_ttl(rpc::ExtendEnvironmentTtlRequest {
                org_id: org_id.to_string(),
                environment_id: environment_id.to_string(),
                additional_seconds: request.additional_seconds,
                ..Default::default()
            })
            .await
            .map_err(display_client_error)?;
        Ok(StatusResponse {
            status: response.status,
        })
    }

    pub async fn list_environment_access(
        &self,
        org_id: &str,
        environment_id: &str,
    ) -> anyhow::Result<Vec<EnvironmentAccessGrant>> {
        let response = self
            .inner
            .list_environment_access(rpc::ListEnvironmentAccessRequest {
                org_id: org_id.to_string(),
                environment_id: environment_id.to_string(),
                ..Default::default()
            })
            .await
            .map_err(display_client_error)?;
        Ok(response
            .access_grants
            .into_iter()
            .map(legacy_environment_access_grant)
            .collect())
    }

    pub async fn grant_environment_access(
        &self,
        org_id: &str,
        environment_id: &str,
        request: &GrantEnvironmentAccessRequest,
    ) -> anyhow::Result<EnvironmentAccessGrant> {
        let permission = match request.permission.as_str() {
            "viewer" => rpc::AccessPermission::Viewer,
            "operator" => rpc::AccessPermission::Operator,
            "owner" => rpc::AccessPermission::Owner,
            value => anyhow::bail!("invalid environment access permission {value:?}"),
        };
        let response = self
            .inner
            .grant_environment_access(rpc::GrantEnvironmentAccessRequest {
                org_id: org_id.to_string(),
                environment_id: environment_id.to_string(),
                user_id: request.user_id.clone(),
                permission: permission.into(),
                ..Default::default()
            })
            .await
            .map_err(display_client_error)?;
        response
            .access_grant
            .into_option()
            .map(legacy_environment_access_grant)
            .ok_or_else(|| anyhow::anyhow!("GrantEnvironmentAccess returned no access grant"))
    }

    pub async fn revoke_environment_access(
        &self,
        org_id: &str,
        environment_id: &str,
        user_id: &str,
    ) -> anyhow::Result<()> {
        self.inner
            .revoke_environment_access(rpc::RevokeEnvironmentAccessRequest {
                org_id: org_id.to_string(),
                environment_id: environment_id.to_string(),
                user_id: user_id.to_string(),
                ..Default::default()
            })
            .await
            .map_err(display_client_error)?;
        Ok(())
    }

    pub async fn create_environment_port(
        &self,
        org_id: &str,
        environment_id: &str,
        request: &CreateEnvironmentPortRequest,
    ) -> anyhow::Result<EnvironmentPort> {
        let access = match request.access.as_str() {
            "" => rpc::PortAccess::Unspecified,
            "public" => rpc::PortAccess::Public,
            "org_members" => rpc::PortAccess::OrgMembers,
            "creator" => rpc::PortAccess::Creator,
            value => anyhow::bail!("invalid environment port access {value:?}"),
        };
        let response = self
            .inner
            .create_port(rpc::CreatePortRequest {
                org_id: org_id.to_string(),
                environment_id: environment_id.to_string(),
                port: request.port,
                label: request.label.clone(),
                access: access.into(),
                ..Default::default()
            })
            .await
            .map_err(display_client_error)?;
        response
            .port
            .into_option()
            .map(legacy_environment_port)
            .ok_or_else(|| anyhow::anyhow!("CreatePort returned no port"))
    }

    pub async fn list_environment_ports(
        &self,
        org_id: &str,
        environment_id: &str,
    ) -> anyhow::Result<Vec<EnvironmentPort>> {
        let response = self
            .inner
            .list_ports(rpc::ListPortsRequest {
                org_id: org_id.to_string(),
                environment_id: environment_id.to_string(),
                ..Default::default()
            })
            .await
            .map_err(display_client_error)?;
        Ok(response
            .ports
            .into_iter()
            .map(legacy_environment_port)
            .collect())
    }

    pub async fn delete_environment_port(
        &self,
        org_id: &str,
        environment_id: &str,
        port_id: &str,
    ) -> anyhow::Result<()> {
        self.inner
            .delete_port(rpc::DeletePortRequest {
                org_id: org_id.to_string(),
                environment_id: environment_id.to_string(),
                port_id: port_id.to_string(),
                ..Default::default()
            })
            .await
            .map_err(display_client_error)?;
        Ok(())
    }

    pub async fn get_environment_logs(
        &self,
        org_id: &str,
        environment_id: &str,
    ) -> anyhow::Result<Vec<EnvironmentLog>> {
        let mut logs = Vec::new();
        let mut conversion_error = None;
        self.inner
            .stream_logs(
                rpc::StreamLogsRequest {
                    org_id: org_id.to_string(),
                    environment_id: environment_id.to_string(),
                    follow: false,
                    ..Default::default()
                },
                |message| match legacy_stream_log(message) {
                    Ok(Some(log)) => {
                        logs.push(log);
                        true
                    }
                    Ok(None) => true,
                    Err(error) => {
                        conversion_error = Some(error);
                        false
                    }
                },
            )
            .await
            .map_err(display_client_error)?;
        if let Some(error) = conversion_error {
            return Err(error);
        }
        Ok(logs)
    }

    pub async fn stream_environment_logs<F>(
        &self,
        org_id: &str,
        environment_id: &str,
        mut on_event: F,
    ) -> anyhow::Result<()>
    where
        F: FnMut(EnvironmentLog) -> bool,
    {
        let mut conversion_error = None;
        self.inner
            .stream_logs(
                rpc::StreamLogsRequest {
                    org_id: org_id.to_string(),
                    environment_id: environment_id.to_string(),
                    follow: true,
                    ..Default::default()
                },
                |message| match legacy_stream_log(message) {
                    Ok(Some(log)) => on_event(log),
                    Ok(None) => true,
                    Err(error) => {
                        conversion_error = Some(error);
                        false
                    }
                },
            )
            .await
            .map_err(display_client_error)?;
        if let Some(error) = conversion_error {
            return Err(error);
        }
        Ok(())
    }

    pub async fn upload_environment_file(
        &self,
        org_id: &str,
        environment_id: &str,
        remote_path: &str,
        data: Vec<u8>,
    ) -> anyhow::Result<()> {
        let mut requests = vec![rpc::UploadFileRequest {
            payload: Some(rpc::upload_file_request::Payload::Header(Box::new(
                rpc::UploadFileHeader {
                    org_id: org_id.to_string(),
                    environment_id: environment_id.to_string(),
                    path: remote_path.to_string(),
                    ..Default::default()
                },
            ))),
            ..Default::default()
        }];
        if !data.is_empty() {
            requests.push(rpc::UploadFileRequest {
                payload: Some(rpc::upload_file_request::Payload::Chunk(data)),
                ..Default::default()
            });
        }
        self.inner
            .upload_file(requests)
            .await
            .map_err(display_client_error)?;
        Ok(())
    }

    pub async fn download_environment_file(
        &self,
        org_id: &str,
        environment_id: &str,
        remote_path: &str,
    ) -> anyhow::Result<Vec<u8>> {
        let responses = self
            .inner
            .download_file(rpc::DownloadFileRequest {
                org_id: org_id.to_string(),
                environment_id: environment_id.to_string(),
                path: remote_path.to_string(),
                ..Default::default()
            })
            .await
            .map_err(display_client_error)?;
        Ok(responses
            .into_iter()
            .filter_map(|response| match response.payload {
                Some(rpc::download_file_response::Payload::Chunk(chunk)) => Some(chunk),
                Some(rpc::download_file_response::Payload::Info(_)) | None => None,
            })
            .flatten()
            .collect())
    }
}

pub(crate) fn connect_client(config: &ResolvedPlatformConfig) -> anyhow::Result<CodewireClient> {
    let client_config = ClientConfig::new(&config.server_url)?
        .with_user_agent(format!("codewire-cli/{CLI_VERSION}"))?;
    CodewireClient::with_token_provider(client_config, config.token_provider()?).map_err(Into::into)
}

pub(crate) fn display_client_error(error: ClientError) -> anyhow::Error {
    if error.code() == ErrorCode::Unauthenticated {
        return anyhow::anyhow!("session expired or invalid");
    }
    error.into()
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
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

#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct CreateEnvironmentPortRequest {
    pub port: i32,
    pub label: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub access: String,
}

fn proto_create_environment_request(
    org_id: &str,
    request: &CreateEnvironmentRequest,
) -> rpc::CreateEnvironmentRequest {
    rpc::CreateEnvironmentRequest {
        org_id: org_id.to_string(),
        preset_id: request.preset_id.clone(),
        name: request.name.clone(),
        cpu_millicores: request.cpu_millicores,
        memory_mb: request.memory_mb,
        disk_gb: request.disk_gb,
        ttl_seconds: request.ttl_seconds,
        preset_slug: request.preset_slug.clone(),
        repo_url: request.repo_url.clone(),
        branch: request.branch.clone(),
        repos: request
            .repos
            .iter()
            .map(|repo| rpc::RepoEntry {
                url: repo.url.clone(),
                branch: repo.branch.clone(),
                mount_path: repo.mount_path.clone(),
                revision: repo.revision.clone(),
                ..Default::default()
            })
            .collect(),
        image: request.image.clone(),
        install_command: request.install_command.clone(),
        startup_script: request.startup_script.clone(),
        env_vars: request.env_vars.clone().into_iter().collect(),
        agents: request
            .agents
            .iter()
            .map(|agent| rpc::SetupAgent {
                r#type: agent.agent_type.clone(),
                ..Default::default()
            })
            .collect(),
        install_agents: request.install_agents,
        agent: request.agent.clone(),
        agent_env: request.agent_env.clone().into_iter().collect(),
        secret_project: request.secret_project.clone(),
        app_ports: request
            .app_ports
            .iter()
            .map(|port| rpc::AppPort {
                port: port.port,
                label: port.label.clone(),
                access: port.access.clone(),
                ..Default::default()
            })
            .collect(),
        include_org_secrets: request.include_org_secrets,
        include_user_secrets: request.include_user_secrets,
        isolation_tier: match request.isolation_tier.as_str() {
            "" | "standard" => rpc::IsolationTier::Standard.into(),
            "confidential" => rpc::IsolationTier::Confidential.into(),
            _ => rpc::IsolationTier::Unspecified.into(),
        },
        project_spec: request
            .project_spec
            .clone()
            .map(codewire_project_proto::to_proto)
            .into(),
        ..Default::default()
    }
}

fn legacy_stream_log(message: rpc::StreamLogsResponse) -> anyhow::Result<Option<EnvironmentLog>> {
    match message.event {
        Some(rpc::stream_logs_response::Event::Log(log)) => legacy_environment_log(*log).map(Some),
        Some(rpc::stream_logs_response::Event::Heartbeat(_)) | None => Ok(None),
    }
}

fn legacy_environment_log(value: rpc::EnvironmentLog) -> anyhow::Result<EnvironmentLog> {
    Ok(EnvironmentLog {
        id: value.id,
        environment_id: value.environment_id,
        phase: value.phase,
        status: value.status,
        message: value.message,
        metadata: value
            .metadata
            .into_option()
            .map(serde_json::to_value)
            .transpose()?,
        created_at: value
            .created_at
            .into_option()
            .map(timestamp_to_rfc3339)
            .unwrap_or_default(),
    })
}

fn legacy_prepare_complete(
    complete: rpc::PrepareComplete,
) -> anyhow::Result<PrepareEnvironmentResponse> {
    Ok(PrepareEnvironmentResponse {
        draft: complete
            .draft
            .into_option()
            .map(legacy_create_environment_request)
            .transpose()?
            .ok_or_else(|| anyhow::anyhow!("WatchEnvironmentCreate complete event had no draft"))?,
        detection: complete
            .detection
            .into_option()
            .map(legacy_detection)
            .transpose()?,
        resolved_preset: complete
            .resolved_preset
            .into_option()
            .map(legacy_preset)
            .transpose()?,
        repo_config: complete
            .repo_config
            .into_option()
            .map(legacy_repo_config)
            .transpose()?,
    })
}

fn legacy_create_environment_request(
    value: rpc::CreateEnvironmentRequest,
) -> anyhow::Result<CreateEnvironmentRequest> {
    let project_spec = value
        .project_spec
        .into_option()
        .map(codewire_project_proto::from_proto)
        .transpose()?;
    Ok(CreateEnvironmentRequest {
        preset_id: value.preset_id,
        name: value.name,
        cpu_millicores: value.cpu_millicores,
        memory_mb: value.memory_mb,
        disk_gb: value.disk_gb,
        ttl_seconds: value.ttl_seconds,
        preset_slug: value.preset_slug,
        repo_url: value.repo_url,
        branch: value.branch,
        repos: value
            .repos
            .into_iter()
            .map(|repo| RepoEntry {
                url: repo.url,
                branch: repo.branch,
                mount_path: repo.mount_path,
                revision: repo.revision,
            })
            .collect(),
        image: value.image,
        install_command: value.install_command,
        startup_script: value.startup_script,
        env_vars: value.env_vars.into_iter().collect(),
        agents: value
            .agents
            .into_iter()
            .map(|agent| SetupAgent {
                agent_type: agent.r#type,
            })
            .collect(),
        install_agents: value.install_agents,
        agent: value.agent,
        agent_env: value.agent_env.into_iter().collect(),
        secret_project: value.secret_project,
        app_ports: value
            .app_ports
            .into_iter()
            .map(|port| AppPort {
                port: port.port,
                label: port.label,
                access: port.access,
            })
            .collect(),
        include_org_secrets: value.include_org_secrets,
        include_user_secrets: value.include_user_secrets,
        isolation_tier: match value.isolation_tier.as_known() {
            Some(rpc::IsolationTier::Confidential) => "confidential".into(),
            Some(rpc::IsolationTier::Standard) | Some(rpc::IsolationTier::Unspecified) | None => {
                String::new()
            }
        },
        project_spec,
    })
}

fn legacy_detection(value: rpc::DetectionResult) -> anyhow::Result<DetectionResult> {
    let project_spec = value
        .project_spec
        .into_option()
        .map(codewire_project_proto::from_proto)
        .transpose()?;
    Ok(DetectionResult {
        project_type: value.project_type,
        preset_slug: value.preset_slug,
        preset_image: value.preset_image,
        install_command: value.install_command,
        startup_script: value.startup_script,
        language: value.language,
        framework: value.framework,
        suggested_name: value.suggested_name,
        needs_docker: value.needs_docker,
        has_compose: value.has_compose,
        app_ports: value
            .app_ports
            .into_iter()
            .map(|port| AppPort {
                port: port.port,
                label: port.label,
                access: port.access,
            })
            .collect(),
        agents: value
            .agents
            .into_iter()
            .map(|agent| SetupAgent {
                agent_type: agent.r#type,
            })
            .collect(),
        install_agents: value.install_agents,
        secret_project: value.secret_project,
        include_org_secrets: value.include_org_secrets,
        include_user_secrets: value.include_user_secrets,
        cpu: value.cpu,
        memory: value.memory,
        setup_notes: value.setup_notes,
        project_spec,
    })
}

fn legacy_repo_config(value: rpc::RepoConfig) -> anyhow::Result<RepoConfig> {
    Ok(RepoConfig {
        id: value.id,
        org_id: value.org_id,
        repo_url: value.repo_url,
        preset_id: value.preset_id,
        setup_config: value
            .setup_config
            .into_option()
            .map(serde_json::to_value)
            .transpose()?
            .unwrap_or(serde_json::Value::Null),
        created_by: value.created_by,
        updated_at: value.updated_at,
    })
}

fn legacy_environment_daemon_status(
    value: rpc::EnvironmentDaemonStatus,
) -> EnvironmentDaemonStatus {
    let state = match value.state.as_known() {
        Some(rpc::EnvironmentDaemonState::Unspecified) => "unspecified",
        Some(rpc::EnvironmentDaemonState::Unsupported) => "unsupported",
        Some(rpc::EnvironmentDaemonState::Starting) => "starting",
        Some(rpc::EnvironmentDaemonState::Ready) => "ready",
        Some(rpc::EnvironmentDaemonState::Unhealthy) => "unhealthy",
        Some(rpc::EnvironmentDaemonState::UpgradeRequired) => "upgrade_required",
        None => "unknown",
    };
    EnvironmentDaemonStatus {
        state: state.to_string(),
        protocol_version: value.protocol_version,
        minimum_protocol_version: value.minimum_protocol_version,
        daemon_version: value.daemon_version,
        capabilities: value.capabilities,
        message: value.message,
        diagnostics: value
            .diagnostics
            .into_iter()
            .map(|diagnostic| EnvironmentDaemonDiagnostic {
                name: diagnostic.name,
                healthy: diagnostic.healthy,
                message: diagnostic.message,
            })
            .collect(),
        pod_name: value.pod_name,
    }
}

fn legacy_environment(value: rpc::Environment) -> Environment {
    let state = match value.state.as_known() {
        Some(rpc::EnvironmentState::Unspecified) => "",
        Some(rpc::EnvironmentState::Pending) => "pending",
        Some(rpc::EnvironmentState::PendingBuild) => "pending_build",
        Some(rpc::EnvironmentState::Building) => "building",
        Some(rpc::EnvironmentState::BuildFailed) => "build_failed",
        Some(rpc::EnvironmentState::PullingSnapshot) => "pulling_snapshot",
        Some(rpc::EnvironmentState::Creating) => "creating",
        Some(rpc::EnvironmentState::Starting) => "starting",
        Some(rpc::EnvironmentState::Running) => "running",
        Some(rpc::EnvironmentState::Stopping) => "stopping",
        Some(rpc::EnvironmentState::Stopped) => "stopped",
        Some(rpc::EnvironmentState::Archiving) => "archiving",
        Some(rpc::EnvironmentState::Archived) => "archived",
        Some(rpc::EnvironmentState::Restoring) => "restoring",
        Some(rpc::EnvironmentState::Resizing) => "resizing",
        Some(rpc::EnvironmentState::Destroying) => "destroying",
        Some(rpc::EnvironmentState::Destroyed) => "destroyed",
        Some(rpc::EnvironmentState::Error) => "error",
        Some(rpc::EnvironmentState::Unknown) | None => "unknown",
    };
    let desired_state = match value.desired_state.as_known() {
        Some(rpc::DesiredState::Unspecified) => "",
        Some(rpc::DesiredState::Started) => "started",
        Some(rpc::DesiredState::Stopped) => "stopped",
        Some(rpc::DesiredState::Destroyed) => "destroyed",
        Some(rpc::DesiredState::Archived) => "archived",
        Some(rpc::DesiredState::Resized) => "resized",
        None => "unknown",
    };
    Environment {
        id: value.id,
        org_id: value.org_id,
        created_by: value.created_by,
        preset_id: value.preset_id,
        environment_type: value.r#type,
        isolation_tier: match value.isolation_tier.as_known() {
            Some(rpc::IsolationTier::Confidential) => "confidential".into(),
            Some(rpc::IsolationTier::Standard) | Some(rpc::IsolationTier::Unspecified) | None => {
                "standard".into()
            }
        },
        name: empty_to_none(value.name),
        state: state.to_string(),
        desired_state: desired_state.to_string(),
        error_reason: empty_to_none(value.error_reason),
        recoverable: value.recoverable,
        state_changed_at: value
            .state_changed_at
            .into_option()
            .map(timestamp_to_rfc3339)
            .unwrap_or_default(),
        retry_count: value.retry_count,
        ttl_seconds: value.ttl_seconds,
        shutdown_at: value.shutdown_at.into_option().map(timestamp_to_rfc3339),
        cpu_millicores: value.cpu_millicores,
        memory_mb: value.memory_mb,
        disk_gb: value.disk_gb,
        total_running_seconds: value.total_running_seconds,
        created_at: value
            .created_at
            .into_option()
            .map(timestamp_to_rfc3339)
            .unwrap_or_default(),
        started_at: value.started_at.into_option().map(timestamp_to_rfc3339),
        stopped_at: value.stopped_at.into_option().map(timestamp_to_rfc3339),
        destroyed_at: value.destroyed_at.into_option().map(timestamp_to_rfc3339),
        protected: value.protected,
        deletion_requested_at: value
            .deletion_requested_at
            .into_option()
            .map(timestamp_to_rfc3339),
        deletion_grace_until: value
            .deletion_grace_until
            .into_option()
            .map(timestamp_to_rfc3339),
        network: empty_to_none(value.network),
    }
}

fn legacy_environment_resize_response(
    operation: Option<rpc::EnvironmentResizeOperation>,
    environment: Option<rpc::Environment>,
    poll_interval: Option<rpc::ProtoDuration>,
) -> anyhow::Result<(EnvironmentResizeResult, Option<Duration>)> {
    let operation = operation
        .map(legacy_environment_resize_operation)
        .ok_or_else(|| anyhow::anyhow!("EnvironmentService returned no resize operation"))?;
    let environment = environment
        .map(legacy_environment)
        .ok_or_else(|| anyhow::anyhow!("EnvironmentService returned no environment"))?;
    Ok((
        EnvironmentResizeResult {
            operation,
            environment,
        },
        poll_interval.and_then(proto_duration_to_std),
    ))
}

fn legacy_environment_resize_operation(
    value: rpc::EnvironmentResizeOperation,
) -> EnvironmentResizeOperation {
    let state = match value.state.as_known() {
        Some(rpc::EnvironmentResizeOperationState::Pending) => "pending",
        Some(rpc::EnvironmentResizeOperationState::Applying) => "applying",
        Some(rpc::EnvironmentResizeOperationState::Restarting) => "restarting",
        Some(rpc::EnvironmentResizeOperationState::Completed) => "completed",
        Some(rpc::EnvironmentResizeOperationState::Failed) => "failed",
        Some(rpc::EnvironmentResizeOperationState::Unspecified) => "unspecified",
        None => "unknown",
    };
    EnvironmentResizeOperation {
        id: value.id,
        environment_id: value.environment_id,
        request_id: value.request_id,
        previous_resources: value
            .previous_resources
            .into_option()
            .map(legacy_environment_resize_resources)
            .unwrap_or_default(),
        desired_resources: value
            .desired_resources
            .into_option()
            .map(legacy_environment_resize_resources)
            .unwrap_or_default(),
        last_applied_resources: value
            .last_applied_resources
            .into_option()
            .map(legacy_environment_resize_resources)
            .unwrap_or_default(),
        state: state.to_string(),
        disruption_policy: resize_disruption_policy(value.disruption_policy).to_string(),
        planned_mode: resize_execution_mode(value.planned_mode).to_string(),
        applied_mode: resize_execution_mode(value.applied_mode).to_string(),
        pod_replaced: value.pod_replaced,
        failure: value
            .failure
            .into_option()
            .map(|failure| EnvironmentResizeFailure {
                code: failure.code,
                message: failure.message,
            }),
        created_at: value
            .created_at
            .into_option()
            .map(timestamp_to_rfc3339)
            .unwrap_or_default(),
        updated_at: value
            .updated_at
            .into_option()
            .map(timestamp_to_rfc3339)
            .unwrap_or_default(),
        completed_at: value.completed_at.into_option().map(timestamp_to_rfc3339),
    }
}

fn legacy_environment_resize_plan(value: rpc::EnvironmentResizePlan) -> EnvironmentResizePlan {
    EnvironmentResizePlan {
        previous_resources: value
            .previous_resources
            .into_option()
            .map(legacy_environment_resize_resources)
            .unwrap_or_default(),
        desired_resources: value
            .desired_resources
            .into_option()
            .map(legacy_environment_resize_resources)
            .unwrap_or_default(),
        execution_mode: resize_execution_mode(value.execution_mode).to_string(),
        active_session_count: value.active_session_count,
        active_sessions_will_be_terminated: value.active_sessions_will_be_terminated,
        reason: value.reason,
        warnings: value.warnings,
    }
}

fn resize_disruption_policy(
    value: rpc::EnumValue<rpc::EnvironmentResizeDisruptionPolicy>,
) -> &'static str {
    match value.as_known() {
        Some(rpc::EnvironmentResizeDisruptionPolicy::LiveOnly) => "live_only",
        Some(rpc::EnvironmentResizeDisruptionPolicy::AllowRestart) => "allow_restart",
        Some(rpc::EnvironmentResizeDisruptionPolicy::Unspecified) => "unspecified",
        None => "unknown",
    }
}

fn resize_execution_mode(
    value: rpc::EnumValue<rpc::EnvironmentResizeExecutionMode>,
) -> &'static str {
    match value.as_known() {
        Some(rpc::EnvironmentResizeExecutionMode::Noop) => "noop",
        Some(rpc::EnvironmentResizeExecutionMode::ApplyOnStart) => "apply_on_start",
        Some(rpc::EnvironmentResizeExecutionMode::InPlace) => "in_place",
        Some(rpc::EnvironmentResizeExecutionMode::Restart) => "restart",
        Some(rpc::EnvironmentResizeExecutionMode::Unspecified) => "unspecified",
        None => "unknown",
    }
}

fn legacy_environment_resize_resources(
    value: rpc::EnvironmentResources,
) -> EnvironmentResizeResources {
    EnvironmentResizeResources {
        cpu_millicores: value.cpu_millicores,
        memory_mb: value.memory_mb,
        disk_gb: value.disk_gb,
    }
}

fn legacy_environment_access_grant(value: rpc::AccessGrant) -> EnvironmentAccessGrant {
    let permission = match value.permission.as_known() {
        Some(rpc::AccessPermission::Unspecified) => "",
        Some(rpc::AccessPermission::Viewer) => "viewer",
        Some(rpc::AccessPermission::Operator) => "operator",
        Some(rpc::AccessPermission::Owner) => "owner",
        None => "unknown",
    };
    EnvironmentAccessGrant {
        id: value.id,
        environment_id: value.environment_id,
        user_id: value.user_id,
        permission: permission.to_string(),
        granted_by: value.granted_by,
        created_at: value
            .created_at
            .into_option()
            .map(timestamp_to_postgres_text)
            .unwrap_or_default(),
    }
}

fn legacy_environment_port(value: rpc::Port) -> EnvironmentPort {
    let access = match value.access.as_known() {
        Some(rpc::PortAccess::Unspecified) => "",
        Some(rpc::PortAccess::Public) => "public",
        Some(rpc::PortAccess::OrgMembers) => "org_members",
        Some(rpc::PortAccess::Creator) => "creator",
        None => "unknown",
    };
    EnvironmentPort {
        id: value.id,
        environment_id: value.environment_id,
        port: value.port,
        label: value.label,
        access: access.to_string(),
        preview_url: value.preview_url.unwrap_or_default(),
        created_at: value
            .created_at
            .into_option()
            .map(timestamp_to_rfc3339)
            .unwrap_or_default(),
    }
}

fn legacy_environment_trust_report(value: rpc::EnvironmentTrustReport) -> EnvironmentTrustReport {
    let environment = value.environment.into_option().unwrap_or_default();
    let runtime = value.runtime.into_option().unwrap_or_default();
    let placement = value.placement.into_option().unwrap_or_default();
    let images = value.images.into_option().unwrap_or_default();
    let provenance = value.provenance.into_option().unwrap_or_default();
    let attestation = value.attestation.into_option().unwrap_or_default();
    let trustee = value.trustee.into_option().unwrap_or_default();
    let summary = value.summary.into_option().unwrap_or_default();
    EnvironmentTrustReport {
        environment: TrustReportEnvironment {
            id: environment.id,
            org_id: environment.org_id,
            environment_type: environment.r#type,
            state: environment.state,
            isolation_tier: match environment.isolation_tier.as_known() {
                Some(rpc::IsolationTier::Confidential) => "confidential".to_owned(),
                _ => "standard".to_owned(),
            },
        },
        runtime: TrustReportRuntime {
            profile: runtime.profile,
            runtime_class: runtime.runtime_class,
            handler: runtime.handler,
            confidential: runtime.confidential,
        },
        placement: TrustReportPlacement {
            namespace: empty_to_none(placement.namespace),
            workspace_pod: empty_to_none(placement.workspace_pod),
            pod_ip: empty_to_none(placement.pod_ip),
            node: empty_to_none(placement.node),
            zone: empty_to_none(placement.zone),
            region: empty_to_none(placement.region),
        },
        images: TrustReportImages {
            workspace_image: empty_to_none(images.workspace_image),
            workspace_image_id: empty_to_none(images.workspace_image_id),
            gateway_image: empty_to_none(images.gateway_image),
            gateway_image_id: empty_to_none(images.gateway_image_id),
            dind_image: empty_to_none(images.dind_image),
            dind_image_id: empty_to_none(images.dind_image_id),
            daemon_init_image: empty_to_none(images.daemon_init_image),
            daemon_init_image_id: empty_to_none(images.daemon_init_image_id),
        },
        provenance: TrustReportProvenance {
            status: provenance.status,
            guest_kernel: empty_to_none(provenance.guest_kernel),
            guest_initrd: empty_to_none(provenance.guest_initrd),
            guest_image: empty_to_none(provenance.guest_image),
            firmware: empty_to_none(provenance.firmware),
            source: empty_to_none(provenance.source),
            notes: provenance.notes,
        },
        attestation: TrustReportAttestation {
            status: attestation.status,
            tee: attestation.tee,
            report_available: attestation.report_available,
            report_source: empty_to_none(attestation.report_source),
            metadata: attestation.metadata.into_iter().collect(),
        },
        trustee: TrustReportTrustee {
            status: trustee.status,
            resource_uri: empty_to_none(trustee.resource_uri),
            reference_values: empty_to_none(trustee.reference_values),
            policy: empty_to_none(trustee.policy),
            evidence_issues: trustee.evidence_issues,
        },
        summary: TrustReportSummary {
            trust_level: summary.trust_level,
            production_verified: summary.production_verified,
            warnings: summary.warnings,
        },
    }
}

fn empty_to_none(value: String) -> Option<String> {
    (!value.is_empty()).then_some(value)
}

fn timestamp_to_rfc3339(timestamp: rpc::Timestamp) -> String {
    DateTime::<Utc>::from_timestamp(timestamp.seconds, timestamp.nanos as u32)
        .map(|timestamp| timestamp.to_rfc3339_opts(SecondsFormat::Secs, true))
        .unwrap_or_default()
}

fn timestamp_to_postgres_text(timestamp: rpc::Timestamp) -> String {
    DateTime::<Utc>::from_timestamp(timestamp.seconds, timestamp.nanos as u32)
        .map(|timestamp| timestamp.format("%Y-%m-%d %H:%M:%S%.f+00").to_string())
        .unwrap_or_default()
}

fn proto_duration_to_std(duration: rpc::ProtoDuration) -> Option<Duration> {
    let seconds = u64::try_from(duration.seconds).ok()?;
    let nanos = u32::try_from(duration.nanos).ok()?;
    let duration = Duration::new(seconds, nanos);
    (!duration.is_zero()).then_some(duration)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::time::Duration;

    use super::*;

    #[test]
    fn environment_connect_adapter_preserves_cli_request_and_output_shapes() {
        let request = CreateEnvironmentRequest {
            preset_id: Some("preset_123".to_string()),
            name: Some("builder".to_string()),
            repo_url: "https://git.example/codewire".to_string(),
            branch: "main".to_string(),
            env_vars: BTreeMap::from([("RUST_LOG".to_string(), "info".to_string())]),
            agents: vec![SetupAgent {
                agent_type: "codex".to_string(),
            }],
            app_ports: vec![AppPort {
                port: 8080,
                label: "web".to_string(),
                access: "public".to_string(),
            }],
            project_spec: Some(
                codewire_project::parse_project_yaml(
                    "version: 1\nimage: ghcr.io/example/workspace@sha256:abc\nworkspace: clone\n",
                )
                .unwrap()
                .spec,
            ),
            ..CreateEnvironmentRequest::default()
        };
        let round_trip = legacy_create_environment_request(proto_create_environment_request(
            "org_123", &request,
        ))
        .unwrap();
        assert_eq!(round_trip, request);

        let environment = legacy_environment(rpc::Environment {
            id: "env_123".into(),
            org_id: "org_123".into(),
            created_by: "user_123".into(),
            r#type: "sandbox".into(),
            name: "builder".into(),
            state: rpc::EnvironmentState::Running.into(),
            desired_state: rpc::DesiredState::Started.into(),
            state_changed_at: Some(rpc::Timestamp {
                seconds: 1_767_225_600,
                ..Default::default()
            })
            .into(),
            created_at: Some(rpc::Timestamp {
                seconds: 1_767_225_600,
                ..Default::default()
            })
            .into(),
            ..Default::default()
        });
        let value = serde_json::to_value(environment).unwrap();
        assert_eq!(value["id"], "env_123");
        assert_eq!(value["org_id"], "org_123");
        assert_eq!(value["name"], "builder");
        assert_eq!(value["state"], "running");
        assert_eq!(value["desired_state"], "started");
        assert_eq!(value["created_at"], "2026-01-01T00:00:00Z");
        assert_eq!(
            proto_duration_to_std(rpc::ProtoDuration {
                seconds: 2,
                nanos: 500_000_000,
                ..Default::default()
            }),
            Some(Duration::new(2, 500_000_000))
        );
        assert_eq!(proto_duration_to_std(rpc::ProtoDuration::default()), None);

        let grant = legacy_environment_access_grant(rpc::AccessGrant {
            id: "grant_123".into(),
            created_at: Some(rpc::Timestamp {
                seconds: 1_767_225_600,
                nanos: 123_456_000,
                ..Default::default()
            })
            .into(),
            ..Default::default()
        });
        assert_eq!(grant.created_at, "2026-01-01 00:00:00.123456+00");
    }

    #[test]
    fn log_adapter_preserves_cli_output_shape() {
        let log = legacy_stream_log(rpc::StreamLogsResponse {
            event: Some(rpc::stream_logs_response::Event::Log(Box::new(
                rpc::EnvironmentLog {
                    id: "log_123".to_string(),
                    environment_id: "env_123".to_string(),
                    phase: "setup".to_string(),
                    status: "running".to_string(),
                    message: "installing dependencies".to_string(),
                    created_at: Some(rpc::Timestamp {
                        seconds: 1_767_225_600,
                        ..Default::default()
                    })
                    .into(),
                    ..Default::default()
                },
            ))),
            ..Default::default()
        })
        .unwrap()
        .unwrap();
        assert_eq!(log.id, "log_123");
        assert_eq!(log.message, "installing dependencies");
        assert_eq!(log.created_at, "2026-01-01T00:00:00Z");
        assert_eq!(log.metadata, None);
        assert!(
            legacy_stream_log(rpc::StreamLogsResponse {
                event: Some(rpc::stream_logs_response::Event::Heartbeat(
                    Default::default()
                )),
                ..Default::default()
            })
            .unwrap()
            .is_none()
        );
    }

    #[test]
    fn port_adapter_preserves_cli_json_shape() {
        let port = legacy_environment_port(rpc::Port {
            id: "port_123".into(),
            environment_id: "env_123".into(),
            port: 8080,
            label: "web".into(),
            access: rpc::PortAccess::Public.into(),
            preview_url: Some("https://preview.example".into()),
            created_at: Some(rpc::Timestamp {
                seconds: 1_767_225_600,
                ..Default::default()
            })
            .into(),
            ..Default::default()
        });
        assert_eq!(
            serde_json::to_value(port).expect("port JSON"),
            serde_json::json!({
                "id": "port_123",
                "environment_id": "env_123",
                "port": 8080,
                "label": "web",
                "access": "public",
                "preview_url": "https://preview.example",
                "created_at": "2026-01-01T00:00:00Z"
            })
        );
    }
}
