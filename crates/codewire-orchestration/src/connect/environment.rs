//! Connect-RPC adapter for environment resources and lifecycle operations.
//!
//! This module maps shared environment service logic to protobuf, validates
//! pagination, supplies polling hints and typed outcomes, and renders Connect
//! errors.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration as StdDuration;

use buffa::EnumValue;
use buffa_types::{Duration, Struct, Timestamp};
use chrono::{DateTime, NaiveDateTime};
use codewire_proto::codewire::v1 as proto;
use codewire_server_core::connect::{auth_user, wire_error};
use codewire_server_core::connect_error::ConnectError as RenderedConnectError;
use codewire_server_core::{AppError, AppResult, ValidationIssue};
use connectrpc::{RequestContext, ServiceRequest, ServiceResult, ServiceStream};

use crate::api::ApiState;
use crate::api::create::{
    AppPort, CreateEnvironmentBody, RepoEntry, SetupAgent, create_environment_core,
};
use crate::api::env_access::{
    AccessGrant, GrantAccessBody, grant_environment_access_core, list_environment_access_core,
    revoke_environment_access_core,
};
use crate::api::environment_daemon::{
    EnvironmentDaemonDiagnostic as ApiEnvironmentDaemonDiagnostic,
    EnvironmentDaemonRepair as ApiEnvironmentDaemonRepair,
    EnvironmentDaemonStatus as ApiEnvironmentDaemonStatus, get_environment_daemon_logs_core,
    get_environment_daemon_status_core, repair_environment_daemon_core,
};
use crate::api::environments::{
    Environment, EnvironmentPort, ListEnvironmentsQuery, StartOutcomeCore,
    cancel_environment_deletion_core, delete_environment_core, extend_environment_ttl_core,
    get_environment_core, list_environments_core, protect_environment_core, require_org_member,
    start_environment_core, stop_environment_core, unprotect_environment_core,
};
use crate::api::logs::{
    EnvironmentLog as ApiEnvironmentLog, LogStreamEvent, open_environment_log_stream,
};
use crate::api::prepare::{PrepareResponse, PrepareStreamEvent, RepoConfig, start_prepare_stream};
use crate::api::trust_report::{EnvironmentTrustReport, get_environment_trust_report_core};
use crate::connect::presets::proto_preset;

/// Registers the EnvironmentService unary and streaming RPCs on generated routes.
pub fn router(state: ApiState) -> connectrpc::Router {
    connectrpc::Router::new().add_service(Arc::new(EnvironmentConnectService { state }))
}

struct EnvironmentConnectService {
    state: ApiState,
}

#[allow(refining_impl_trait)]
impl proto::EnvironmentService for EnvironmentConnectService {
    async fn list_environments(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, proto::ListEnvironmentsRequest>,
    ) -> ServiceResult<proto::ListEnvironmentsResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();
        validate_pagination(request.page_token)
            .map_err(|error| environment_rpc_error(&error, &ctx))?;
        let state = api_environment_state(request.state)
            .map_err(|error| environment_rpc_error(&error, &ctx))?;
        let environments = list_environments_core(
            &self.state,
            &user,
            request.org_id,
            ListEnvironmentsQuery {
                env_type: request.r#type.to_owned(),
                state,
                include_destroyed: request.include_destroyed,
            },
        )
        .await
        .map_err(|error| environment_rpc_error(&error, &ctx))?;
        let poll_interval = environments
            .iter()
            .filter_map(poll_interval_seconds)
            .min()
            .map(Duration::from_secs);
        let environments = environments
            .into_iter()
            .map(proto_environment)
            .collect::<AppResult<Vec<_>>>()
            .map_err(|error| environment_rpc_error(&error, &ctx))?;

        connectrpc::Response::ok(proto::ListEnvironmentsResponse {
            environments,
            next_page_token: String::new(),
            poll_interval: poll_interval.into(),
            ..Default::default()
        })
    }

    async fn create_environment(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, proto::CreateEnvironmentRequest>,
    ) -> ServiceResult<proto::CreateEnvironmentResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.to_owned_message();
        let org_id = request.org_id.clone();
        let environment =
            create_environment_core(&self.state, &user, &org_id, create_body(request))
                .await
                .map_err(|error| environment_rpc_error(&error, &ctx))?;

        connectrpc::Response::ok(proto::CreateEnvironmentResponse {
            environment: Some(
                proto_environment(environment)
                    .map_err(|error| environment_rpc_error(&error, &ctx))?,
            )
            .into(),
            ..Default::default()
        })
    }

    async fn get_environment(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, proto::GetEnvironmentRequest>,
    ) -> ServiceResult<proto::GetEnvironmentResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();
        let environment =
            get_environment_core(&self.state, &user, request.org_id, request.environment_id)
                .await
                .map_err(|error| environment_rpc_error(&error, &ctx))?;
        let poll_interval = poll_interval_seconds(&environment).map(Duration::from_secs);

        connectrpc::Response::ok(proto::GetEnvironmentResponse {
            environment: Some(
                proto_environment(environment)
                    .map_err(|error| environment_rpc_error(&error, &ctx))?,
            )
            .into(),
            poll_interval: poll_interval.into(),
            ..Default::default()
        })
    }

    async fn delete_environment(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, proto::DeleteEnvironmentRequest>,
    ) -> ServiceResult<proto::DeleteEnvironmentResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();
        delete_environment_core(&self.state, &user, request.org_id, request.environment_id)
            .await
            .map_err(|error| environment_rpc_error(&error, &ctx))?;
        connectrpc::Response::ok(proto::DeleteEnvironmentResponse::default())
    }

    async fn stop_environment(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, proto::StopEnvironmentRequest>,
    ) -> ServiceResult<proto::StopEnvironmentResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();
        let result =
            stop_environment_core(&self.state, &user, request.org_id, request.environment_id)
                .await
                .map_err(|error| environment_rpc_error(&error, &ctx))?;
        connectrpc::Response::ok(proto::StopEnvironmentResponse {
            status: result.status.into(),
            ..Default::default()
        })
    }

    async fn start_environment(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, proto::StartEnvironmentRequest>,
    ) -> ServiceResult<proto::StartEnvironmentResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();
        let result =
            start_environment_core(&self.state, &user, request.org_id, request.environment_id)
                .await
                .map_err(|error| environment_rpc_error(&error, &ctx))?;
        connectrpc::Response::ok(proto::StartEnvironmentResponse {
            status: result.status.into(),
            outcome: proto_start_outcome(result.outcome).into(),
            ..Default::default()
        })
    }

    async fn protect_environment(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, proto::ProtectEnvironmentRequest>,
    ) -> ServiceResult<proto::ProtectEnvironmentResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();
        let result =
            protect_environment_core(&self.state, &user, request.org_id, request.environment_id)
                .await
                .map_err(|error| environment_rpc_error(&error, &ctx))?;
        connectrpc::Response::ok(proto::ProtectEnvironmentResponse {
            status: result.status.into(),
            ..Default::default()
        })
    }

    async fn unprotect_environment(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, proto::UnprotectEnvironmentRequest>,
    ) -> ServiceResult<proto::UnprotectEnvironmentResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();
        let result =
            unprotect_environment_core(&self.state, &user, request.org_id, request.environment_id)
                .await
                .map_err(|error| environment_rpc_error(&error, &ctx))?;
        connectrpc::Response::ok(proto::UnprotectEnvironmentResponse {
            status: result.status.into(),
            ..Default::default()
        })
    }

    async fn cancel_environment_deletion(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, proto::CancelEnvironmentDeletionRequest>,
    ) -> ServiceResult<proto::CancelEnvironmentDeletionResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();
        let result = cancel_environment_deletion_core(
            &self.state,
            &user,
            request.org_id,
            request.environment_id,
        )
        .await
        .map_err(|error| environment_rpc_error(&error, &ctx))?;
        connectrpc::Response::ok(proto::CancelEnvironmentDeletionResponse {
            status: result.status.into(),
            ..Default::default()
        })
    }

    async fn extend_environment_ttl(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, proto::ExtendEnvironmentTtlRequest>,
    ) -> ServiceResult<proto::ExtendEnvironmentTtlResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();
        validate_additional_seconds(request.additional_seconds)
            .map_err(|error| environment_rpc_error(&error, &ctx))?;
        let result = extend_environment_ttl_core(
            &self.state,
            &user,
            request.org_id,
            request.environment_id,
            request.additional_seconds,
        )
        .await
        .map_err(|error| environment_rpc_error(&error, &ctx))?;
        connectrpc::Response::ok(proto::ExtendEnvironmentTtlResponse {
            status: result.status.into(),
            ..Default::default()
        })
    }

    async fn get_environment_trust_report(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, proto::GetEnvironmentTrustReportRequest>,
    ) -> ServiceResult<proto::GetEnvironmentTrustReportResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();
        let report = get_environment_trust_report_core(
            &self.state,
            &user,
            request.org_id,
            request.environment_id,
        )
        .await
        .map_err(|error| environment_rpc_error(&error, &ctx))?;
        connectrpc::Response::ok(proto::GetEnvironmentTrustReportResponse {
            trust_report: Some(proto_trust_report(report)).into(),
            ..Default::default()
        })
    }

    async fn get_environment_daemon_status(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, proto::GetEnvironmentDaemonStatusRequest>,
    ) -> ServiceResult<proto::GetEnvironmentDaemonStatusResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();
        let status = get_environment_daemon_status_core(
            &self.state,
            &user,
            request.org_id,
            request.environment_id,
        )
        .await
        .map_err(|error| environment_rpc_error(&error, &ctx))?;
        connectrpc::Response::ok(proto::GetEnvironmentDaemonStatusResponse {
            status: Some(proto_environment_daemon_status(status)).into(),
            ..Default::default()
        })
    }

    async fn stream_environment_daemon_logs(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, proto::StreamEnvironmentDaemonLogsRequest>,
    ) -> ServiceResult<ServiceStream<proto::StreamEnvironmentDaemonLogsResponse>> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();
        let data = get_environment_daemon_logs_core(
            &self.state,
            &user,
            request.org_id,
            request.environment_id,
        )
        .await
        .map_err(|error| environment_rpc_error(&error, &ctx))?;
        let stream = futures::stream::iter([Ok(proto::StreamEnvironmentDaemonLogsResponse {
            data,
            ..Default::default()
        })]);
        connectrpc::Response::stream_ok(stream)
    }

    async fn repair_environment_daemon(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, proto::RepairEnvironmentDaemonRequest>,
    ) -> ServiceResult<proto::RepairEnvironmentDaemonResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();
        let repair = repair_environment_daemon_core(
            &self.state,
            &user,
            request.org_id,
            request.environment_id,
        )
        .await
        .map_err(|error| environment_rpc_error(&error, &ctx))?;
        connectrpc::Response::ok(proto_environment_daemon_repair(repair))
    }

    async fn list_environment_access(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, proto::ListEnvironmentAccessRequest>,
    ) -> ServiceResult<proto::ListEnvironmentAccessResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();
        validate_pagination(request.page_token)
            .map_err(|error| environment_rpc_error(&error, &ctx))?;
        let grants = list_environment_access_core(
            &self.state,
            &user,
            request.org_id,
            request.environment_id,
        )
        .await
        .map_err(|error| environment_rpc_error(&error, &ctx))?
        .into_iter()
        .map(proto_access_grant)
        .collect::<AppResult<Vec<_>>>()
        .map_err(|error| environment_rpc_error(&error, &ctx))?;
        connectrpc::Response::ok(proto::ListEnvironmentAccessResponse {
            access_grants: grants,
            next_page_token: String::new(),
            ..Default::default()
        })
    }

    async fn grant_environment_access(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, proto::GrantEnvironmentAccessRequest>,
    ) -> ServiceResult<proto::GrantEnvironmentAccessResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();
        let grant = grant_environment_access_core(
            &self.state,
            &user,
            request.org_id,
            request.environment_id,
            GrantAccessBody {
                user_id: request.user_id.to_owned(),
                permission: api_access_permission(request.permission),
            },
        )
        .await
        .map_err(|error| environment_rpc_error(&error, &ctx))?;
        connectrpc::Response::ok(proto::GrantEnvironmentAccessResponse {
            access_grant: Some(
                proto_access_grant(grant).map_err(|error| environment_rpc_error(&error, &ctx))?,
            )
            .into(),
            ..Default::default()
        })
    }

    async fn revoke_environment_access(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, proto::RevokeEnvironmentAccessRequest>,
    ) -> ServiceResult<proto::RevokeEnvironmentAccessResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();
        revoke_environment_access_core(
            &self.state,
            &user,
            request.org_id,
            request.environment_id,
            request.user_id,
        )
        .await
        .map_err(|error| environment_rpc_error(&error, &ctx))?;
        connectrpc::Response::ok(proto::RevokeEnvironmentAccessResponse::default())
    }

    async fn watch_environment_create(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, proto::WatchEnvironmentCreateRequest>,
    ) -> ServiceResult<ServiceStream<proto::WatchEnvironmentCreateResponse>> {
        let user = auth_user(&ctx)?.clone();
        let request = request.to_owned_message();
        let draft = request.draft.into_option().ok_or_else(|| {
            environment_rpc_error(
                &AppError::Validation {
                    errors: vec![ValidationIssue {
                        path: Cow::Borrowed("/draft"),
                        message: Cow::Borrowed("is required"),
                    }],
                },
                &ctx,
            )
        })?;
        if draft.org_id != request.org_id {
            return Err(environment_rpc_error(
                &AppError::Validation {
                    errors: vec![ValidationIssue {
                        path: Cow::Borrowed("/draft/org_id"),
                        message: Cow::Borrowed("must match org_id"),
                    }],
                },
                &ctx,
            ));
        }
        require_org_member(&self.state.pool, &user, &request.org_id)
            .await
            .map_err(|error| environment_rpc_error(&error, &ctx))?;

        let org_id = request.org_id;
        let events = start_prepare_stream(
            self.state.clone(),
            org_id.clone(),
            user.user_id,
            create_body(draft),
            request.analyze,
        );
        let request_id = request_id(&ctx).map(str::to_owned);
        let stream = futures::stream::unfold(events, move |mut events| {
            let org_id = org_id.clone();
            let request_id = request_id.clone();
            async move {
                let item = events.recv().await?;
                let message = match item {
                    Ok(event) => proto_prepare_event(event, &org_id)
                        .map_err(|error| environment_connect_error(&error, request_id.as_deref())),
                    Err(error) => Err(environment_connect_error(&error, request_id.as_deref())),
                };
                Some((message, events))
            }
        });
        connectrpc::Response::stream_ok(stream)
    }

    async fn stream_logs(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, proto::StreamLogsRequest>,
    ) -> ServiceResult<ServiceStream<proto::StreamLogsResponse>> {
        let user = auth_user(&ctx)?.clone();
        let request = request.to_owned_message();
        let events = open_environment_log_stream(
            &self.state,
            &user,
            &request.org_id,
            &request.environment_id,
            &request.after_log_id,
            request.follow,
        )
        .await
        .map_err(|error| environment_rpc_error(&error, &ctx))?;
        let request_id = request_id(&ctx).map(str::to_owned);
        let stream = futures::stream::unfold(events, move |mut events| {
            let request_id = request_id.clone();
            async move {
                let item = events.recv().await?;
                let message = match item {
                    Ok(event) => proto_log_event(event)
                        .map_err(|error| environment_connect_error(&error, request_id.as_deref())),
                    Err(error) => Err(environment_connect_error(&error, request_id.as_deref())),
                };
                Some((message, events))
            }
        });
        connectrpc::Response::stream_ok(stream)
    }
}

fn create_body(request: proto::CreateEnvironmentRequest) -> CreateEnvironmentBody {
    CreateEnvironmentBody {
        preset_id: request.preset_id,
        name: request.name,
        cpu_millicores: request.cpu_millicores,
        memory_mb: request.memory_mb,
        disk_gb: request.disk_gb,
        ttl_seconds: request.ttl_seconds,
        preset_slug: request.preset_slug,
        repo_url: request.repo_url,
        branch: request.branch,
        repos: request
            .repos
            .into_iter()
            .map(|repo| RepoEntry {
                url: repo.url,
                branch: repo.branch,
            })
            .collect(),
        image: request.image,
        install_command: request.install_command,
        startup_script: request.startup_script,
        env_vars: ordered_map(request.env_vars),
        agents: request
            .agents
            .into_iter()
            .map(|agent| SetupAgent {
                agent_type: agent.r#type,
            })
            .collect(),
        install_agents: request.install_agents,
        agent: request.agent,
        agent_env: ordered_map(request.agent_env),
        secret_project: request.secret_project,
        app_ports: request
            .app_ports
            .into_iter()
            .map(|port| AppPort {
                port: port.port,
                label: port.label,
                access: port.access,
            })
            .collect(),
        include_org_secrets: request.include_org_secrets,
        include_user_secrets: request.include_user_secrets,
        isolation_tier: match request.isolation_tier.as_known() {
            Some(proto::IsolationTier::Unspecified) | Some(proto::IsolationTier::Standard) => {
                String::new()
            }
            Some(proto::IsolationTier::Confidential) => "confidential".to_string(),
            None => format!("unknown-enum-value-{}", request.isolation_tier.to_i32()),
        },
    }
}

fn proto_prepare_event(
    event: PrepareStreamEvent,
    org_id: &str,
) -> AppResult<proto::WatchEnvironmentCreateResponse> {
    use proto::watch_environment_create_response::Event;

    let event = match event {
        PrepareStreamEvent::Progress {
            phase,
            message,
            total,
            repo,
        } => Event::Progress(Box::new(proto::PrepareProgress {
            phase,
            message,
            total: total.unwrap_or_default(),
            repo: repo.unwrap_or_default(),
            ..Default::default()
        })),
        PrepareStreamEvent::RepoFetched { index, repo, ok } => {
            Event::RepoFetched(Box::new(proto::RepoFetched {
                index,
                repo,
                ok,
                ..Default::default()
            }))
        }
        PrepareStreamEvent::Complete(response) => {
            Event::Complete(Box::new(proto_prepare_complete(*response, org_id)?))
        }
    };
    Ok(proto::WatchEnvironmentCreateResponse {
        event: Some(event),
        ..Default::default()
    })
}

fn proto_log_event(event: LogStreamEvent) -> AppResult<proto::StreamLogsResponse> {
    use proto::stream_logs_response::Event;

    let event = match event {
        LogStreamEvent::Log(log) => Event::Log(Box::new(proto_environment_log(log)?)),
        LogStreamEvent::Heartbeat(sent_at) => Event::Heartbeat(Box::new(proto::StreamHeartbeat {
            sent_at: Some(Timestamp::from_unix(
                sent_at.timestamp(),
                sent_at.timestamp_subsec_nanos() as i32,
            ))
            .into(),
            ..Default::default()
        })),
    };
    Ok(proto::StreamLogsResponse {
        event: Some(event),
        ..Default::default()
    })
}

fn proto_environment_log(log: ApiEnvironmentLog) -> AppResult<proto::EnvironmentLog> {
    let metadata = match log.metadata {
        None => None,
        Some(metadata) if metadata.get() == "null" => None,
        Some(metadata) => Some(serde_json::from_str::<Struct>(metadata.get()).map_err(
            |error| {
                tracing::error!(%error, "environment log metadata is not a JSON object");
                AppError::InternalMsg("failed to map environment log metadata".into())
            },
        )?),
    };
    Ok(proto::EnvironmentLog {
        id: log.id,
        environment_id: log.environment_id,
        phase: log.phase,
        status: log.status,
        message: log.message,
        metadata: metadata.into(),
        created_at: Some(proto_timestamp(&log.created_at)?).into(),
        ..Default::default()
    })
}

fn proto_environment_daemon_repair(
    repair: ApiEnvironmentDaemonRepair,
) -> proto::RepairEnvironmentDaemonResponse {
    proto::RepairEnvironmentDaemonResponse {
        status: Some(proto_environment_daemon_status(repair.status)).into(),
        replaced_pod_name: repair.replaced_pod_name,
        ..Default::default()
    }
}

fn proto_environment_daemon_status(
    status: ApiEnvironmentDaemonStatus,
) -> proto::EnvironmentDaemonStatus {
    proto::EnvironmentDaemonStatus {
        state: proto_environment_daemon_state(status.state).into(),
        protocol_version: status.protocol_version,
        minimum_protocol_version: status.minimum_protocol_version,
        daemon_version: status.daemon_version,
        capabilities: status.capabilities,
        message: status.message,
        diagnostics: status
            .diagnostics
            .into_iter()
            .map(proto_environment_daemon_diagnostic)
            .collect(),
        pod_name: status.pod_name,
        ..Default::default()
    }
}

fn proto_environment_daemon_diagnostic(
    diagnostic: ApiEnvironmentDaemonDiagnostic,
) -> proto::EnvironmentDaemonDiagnostic {
    proto::EnvironmentDaemonDiagnostic {
        name: diagnostic.name,
        healthy: diagnostic.healthy,
        message: diagnostic.message,
        ..Default::default()
    }
}

fn proto_environment_daemon_state(
    state: codewire_gateway_proto::daemon::v1::DaemonState,
) -> proto::EnvironmentDaemonState {
    use codewire_gateway_proto::daemon::v1::DaemonState as Internal;
    match state {
        Internal::Unspecified => proto::EnvironmentDaemonState::Unspecified,
        Internal::Unsupported => proto::EnvironmentDaemonState::Unsupported,
        Internal::Starting => proto::EnvironmentDaemonState::Starting,
        Internal::Ready => proto::EnvironmentDaemonState::Ready,
        Internal::Unhealthy => proto::EnvironmentDaemonState::Unhealthy,
        Internal::UpgradeRequired => proto::EnvironmentDaemonState::UpgradeRequired,
    }
}

fn proto_prepare_complete(
    response: PrepareResponse,
    org_id: &str,
) -> AppResult<proto::PrepareComplete> {
    Ok(proto::PrepareComplete {
        draft: Some(proto_create_request(response.draft, org_id)).into(),
        detection: response.detection.map(proto_detection).into(),
        resolved_preset: response
            .resolved_preset
            .map(proto_preset)
            .transpose()?
            .into(),
        repo_config: response
            .repo_config
            .map(proto_repo_config)
            .transpose()?
            .into(),
        ..Default::default()
    })
}

fn proto_create_request(
    body: CreateEnvironmentBody,
    org_id: &str,
) -> proto::CreateEnvironmentRequest {
    proto::CreateEnvironmentRequest {
        org_id: org_id.to_owned(),
        preset_id: body.preset_id,
        name: body.name,
        cpu_millicores: body.cpu_millicores,
        memory_mb: body.memory_mb,
        disk_gb: body.disk_gb,
        ttl_seconds: body.ttl_seconds,
        preset_slug: body.preset_slug,
        repo_url: body.repo_url,
        branch: body.branch,
        repos: body
            .repos
            .into_iter()
            .map(|repo| proto::RepoEntry {
                url: repo.url,
                branch: repo.branch,
                ..Default::default()
            })
            .collect(),
        image: body.image,
        install_command: body.install_command,
        startup_script: body.startup_script,
        env_vars: body.env_vars.into_iter().collect(),
        agents: body
            .agents
            .into_iter()
            .map(|agent| proto::SetupAgent {
                r#type: agent.agent_type,
                ..Default::default()
            })
            .collect(),
        install_agents: body.install_agents,
        agent: body.agent,
        agent_env: body.agent_env.into_iter().collect(),
        secret_project: body.secret_project,
        app_ports: body
            .app_ports
            .into_iter()
            .map(|port| proto::AppPort {
                port: port.port,
                label: port.label,
                access: port.access,
                ..Default::default()
            })
            .collect(),
        include_org_secrets: body.include_org_secrets,
        include_user_secrets: body.include_user_secrets,
        ..Default::default()
    }
}

pub(crate) fn proto_detection(
    value: crate::api::detect::DetectionResult,
) -> proto::DetectionResult {
    proto::DetectionResult {
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
            .map(|port| proto::AppPort {
                port: port.port,
                label: port.label,
                access: port.access,
                ..Default::default()
            })
            .collect(),
        agents: value
            .agents
            .into_iter()
            .map(|agent| proto::SetupAgent {
                r#type: agent.agent_type,
                ..Default::default()
            })
            .collect(),
        install_agents: value.install_agents,
        secret_project: value.secret_project,
        include_org_secrets: value.include_org_secrets,
        include_user_secrets: value.include_user_secrets,
        cpu: value.cpu,
        memory: value.memory,
        setup_notes: value.setup_notes,
        ..Default::default()
    }
}

fn proto_repo_config(value: RepoConfig) -> AppResult<proto::RepoConfig> {
    let setup_config = if value.setup_config.is_null() {
        Default::default()
    } else {
        serde_json::from_value(value.setup_config)
            .map_err(|error| AppError::Internal(anyhow::Error::new(error)))?
    };
    Ok(proto::RepoConfig {
        id: value.id,
        org_id: value.org_id,
        repo_url: value.repo_url,
        preset_id: value.preset_id,
        setup_config: Some(setup_config).into(),
        created_by: value.created_by,
        updated_at: value.updated_at,
        ..Default::default()
    })
}

fn ordered_map(values: impl IntoIterator<Item = (String, String)>) -> BTreeMap<String, String> {
    values.into_iter().collect()
}

fn validate_pagination(page_token: &str) -> AppResult<()> {
    if page_token.is_empty() {
        Ok(())
    } else {
        Err(AppError::BadRequest("unrecognized page_token".into()))
    }
}

fn validate_additional_seconds(additional_seconds: i32) -> AppResult<()> {
    if (60..=86_400).contains(&additional_seconds) {
        Ok(())
    } else {
        Err(AppError::Validation {
            errors: vec![ValidationIssue {
                path: Cow::Borrowed("/additional_seconds"),
                message: Cow::Borrowed("must be between 60 and 86400"),
            }],
        })
    }
}

fn api_environment_state(state: EnumValue<proto::EnvironmentState>) -> AppResult<String> {
    let value = match state.as_known() {
        Some(proto::EnvironmentState::Unspecified) => "",
        Some(proto::EnvironmentState::Pending) => "pending",
        Some(proto::EnvironmentState::PendingBuild) => "pending_build",
        Some(proto::EnvironmentState::Building) => "building",
        Some(proto::EnvironmentState::BuildFailed) => "build_failed",
        Some(proto::EnvironmentState::PullingSnapshot) => "pulling_snapshot",
        Some(proto::EnvironmentState::Creating) => "creating",
        Some(proto::EnvironmentState::Starting) => "starting",
        Some(proto::EnvironmentState::Running) => "running",
        Some(proto::EnvironmentState::Stopping) => "stopping",
        Some(proto::EnvironmentState::Stopped) => "stopped",
        Some(proto::EnvironmentState::Archiving) => "archiving",
        Some(proto::EnvironmentState::Archived) => "archived",
        Some(proto::EnvironmentState::Restoring) => "restoring",
        Some(proto::EnvironmentState::Resizing) => "resizing",
        Some(proto::EnvironmentState::Destroying) => "destroying",
        Some(proto::EnvironmentState::Destroyed) => "destroyed",
        Some(proto::EnvironmentState::Error) => "error",
        Some(proto::EnvironmentState::Unknown) => "unknown",
        None => return Err(AppError::BadRequest("unknown environment state".into())),
    };
    Ok(value.into())
}

fn proto_environment_state(state: &str) -> AppResult<proto::EnvironmentState> {
    match state {
        "pending" => Ok(proto::EnvironmentState::Pending),
        "pending_build" => Ok(proto::EnvironmentState::PendingBuild),
        "building" => Ok(proto::EnvironmentState::Building),
        "build_failed" => Ok(proto::EnvironmentState::BuildFailed),
        "pulling_snapshot" => Ok(proto::EnvironmentState::PullingSnapshot),
        "creating" => Ok(proto::EnvironmentState::Creating),
        "starting" => Ok(proto::EnvironmentState::Starting),
        "running" => Ok(proto::EnvironmentState::Running),
        "stopping" => Ok(proto::EnvironmentState::Stopping),
        "stopped" => Ok(proto::EnvironmentState::Stopped),
        "archiving" => Ok(proto::EnvironmentState::Archiving),
        "archived" => Ok(proto::EnvironmentState::Archived),
        "restoring" => Ok(proto::EnvironmentState::Restoring),
        "resizing" => Ok(proto::EnvironmentState::Resizing),
        "destroying" => Ok(proto::EnvironmentState::Destroying),
        "destroyed" => Ok(proto::EnvironmentState::Destroyed),
        "error" => Ok(proto::EnvironmentState::Error),
        "unknown" => Ok(proto::EnvironmentState::Unknown),
        unexpected => invalid_stored_value("environment state", unexpected),
    }
}

fn proto_desired_state(state: &str) -> AppResult<proto::DesiredState> {
    match state {
        "started" => Ok(proto::DesiredState::Started),
        "stopped" => Ok(proto::DesiredState::Stopped),
        "destroyed" => Ok(proto::DesiredState::Destroyed),
        "archived" => Ok(proto::DesiredState::Archived),
        "resized" => Ok(proto::DesiredState::Resized),
        unexpected => invalid_stored_value("desired environment state", unexpected),
    }
}

fn api_access_permission(permission: EnumValue<proto::AccessPermission>) -> String {
    match permission.as_known() {
        Some(proto::AccessPermission::Unspecified) => String::new(),
        Some(proto::AccessPermission::Viewer) => "viewer".into(),
        Some(proto::AccessPermission::Operator) => "operator".into(),
        Some(proto::AccessPermission::Owner) => "owner".into(),
        None => format!("unknown-enum-value-{}", permission.to_i32()),
    }
}

fn proto_access_permission(permission: &str) -> AppResult<proto::AccessPermission> {
    match permission {
        "viewer" => Ok(proto::AccessPermission::Viewer),
        "operator" => Ok(proto::AccessPermission::Operator),
        "owner" => Ok(proto::AccessPermission::Owner),
        unexpected => invalid_stored_value("environment access permission", unexpected),
    }
}

fn proto_start_outcome(outcome: StartOutcomeCore) -> proto::StartOutcome {
    match outcome {
        StartOutcomeCore::Started => proto::StartOutcome::Started,
        StartOutcomeCore::Retried => proto::StartOutcome::Retried,
    }
}

fn poll_interval_seconds(environment: &Environment) -> Option<i64> {
    match environment.state.as_str() {
        "pending" => Some(5),
        "creating" => Some(3),
        "running" if !environment.setup_complete => Some(2),
        _ => None,
    }
}

fn proto_environment(environment: Environment) -> AppResult<proto::Environment> {
    Ok(proto::Environment {
        id: environment.id,
        org_id: environment.org_id,
        created_by: environment.created_by,
        preset_id: environment.preset_id.unwrap_or_default(),
        r#type: environment.env_type,
        name: environment.name.unwrap_or_default(),
        state: proto_environment_state(&environment.state)?.into(),
        desired_state: proto_desired_state(&environment.desired_state)?.into(),
        error_reason: environment.error_reason.unwrap_or_default(),
        recoverable: environment.recoverable,
        state_changed_at: Some(proto_timestamp(&environment.state_changed_at)?).into(),
        retry_count: environment.retry_count,
        setup_phase: environment.setup_phase,
        setup_complete: environment.setup_complete,
        setup_error: environment.setup_error.unwrap_or_default(),
        ttl_seconds: environment.ttl_seconds,
        shutdown_at: optional_timestamp(environment.shutdown_at)?,
        cpu_millicores: environment.cpu_millicores,
        memory_mb: environment.memory_mb,
        disk_gb: environment.disk_gb,
        total_running_seconds: environment.total_running_seconds,
        created_at: Some(proto_timestamp(&environment.created_at)?).into(),
        started_at: optional_timestamp(environment.started_at)?,
        stopped_at: optional_timestamp(environment.stopped_at)?,
        destroyed_at: optional_timestamp(environment.destroyed_at)?,
        protected: environment.protected,
        deletion_requested_at: optional_timestamp(environment.deletion_requested_at)?,
        deletion_grace_until: optional_timestamp(environment.deletion_grace_until)?,
        preset_name: environment.preset_name.unwrap_or_default(),
        network: environment.network.unwrap_or_default(),
        ports: environment
            .ports
            .into_iter()
            .map(proto_port)
            .collect::<AppResult<Vec<_>>>()?,
        isolation_tier: match environment.isolation_tier.as_str() {
            "standard" => proto::IsolationTier::Standard.into(),
            "confidential" => proto::IsolationTier::Confidential.into(),
            unexpected => return invalid_stored_value("environment isolation tier", unexpected),
        },
        ..Default::default()
    })
}

fn proto_port(port: EnvironmentPort) -> AppResult<proto::Port> {
    Ok(proto::Port {
        id: port.id,
        environment_id: port.environment_id,
        port: port.port,
        label: port.label,
        access: match port.access.as_str() {
            "public" => proto::PortAccess::Public,
            "org_members" => proto::PortAccess::OrgMembers,
            "creator" => proto::PortAccess::Creator,
            unexpected => return invalid_stored_value("port access", unexpected),
        }
        .into(),
        preview_url: (!port.preview_url.is_empty()).then_some(port.preview_url),
        created_at: Some(proto_timestamp(&port.created_at)?).into(),
        ..Default::default()
    })
}

fn proto_access_grant(grant: AccessGrant) -> AppResult<proto::AccessGrant> {
    Ok(proto::AccessGrant {
        id: grant.id,
        environment_id: grant.environment_id,
        user_id: grant.user_id,
        permission: proto_access_permission(&grant.permission)?.into(),
        granted_by: grant.granted_by,
        created_at: Some(proto_postgres_timestamp(&grant.created_at)?).into(),
        ..Default::default()
    })
}

fn proto_timestamp(value: &str) -> AppResult<Timestamp> {
    let value = DateTime::parse_from_rfc3339(value).map_err(|error| {
        tracing::error!(%error, timestamp = value, "environment timestamp invalid");
        AppError::InternalMsg("failed to map environment timestamp".into())
    })?;
    Ok(Timestamp::from_unix(
        value.timestamp(),
        value.timestamp_subsec_nanos() as i32,
    ))
}

fn proto_postgres_timestamp(value: &str) -> AppResult<Timestamp> {
    let value = NaiveDateTime::parse_from_str(value, "%Y-%m-%d %H:%M:%S%.f").map_err(|error| {
        tracing::error!(%error, timestamp = value, "environment access timestamp invalid");
        AppError::InternalMsg("failed to map environment access timestamp".into())
    })?;
    let value = value.and_utc();
    Ok(Timestamp::from_unix(
        value.timestamp(),
        value.timestamp_subsec_nanos() as i32,
    ))
}

fn optional_timestamp(value: Option<String>) -> AppResult<buffa::MessageField<Timestamp>> {
    Ok(value.as_deref().map(proto_timestamp).transpose()?.into())
}

fn proto_trust_report(report: EnvironmentTrustReport) -> proto::EnvironmentTrustReport {
    proto::EnvironmentTrustReport {
        environment: Some(proto::TrustReportEnvironment {
            id: report.environment.id,
            org_id: report.environment.org_id,
            r#type: report.environment.env_type,
            state: report.environment.state,
            isolation_tier: match report.environment.isolation_tier.as_str() {
                "standard" => proto::IsolationTier::Standard.into(),
                "confidential" => proto::IsolationTier::Confidential.into(),
                _ => proto::IsolationTier::Unspecified.into(),
            },
            ..Default::default()
        })
        .into(),
        runtime: Some(proto::TrustReportRuntime {
            profile: report.runtime.profile,
            runtime_class: report.runtime.runtime_class,
            handler: report.runtime.handler,
            confidential: report.runtime.confidential,
            ..Default::default()
        })
        .into(),
        placement: Some(proto::TrustReportPlacement {
            namespace: report.placement.namespace.unwrap_or_default(),
            workspace_pod: report.placement.workspace_pod.unwrap_or_default(),
            pod_ip: report.placement.pod_ip.unwrap_or_default(),
            node: report.placement.node.unwrap_or_default(),
            zone: report.placement.zone.unwrap_or_default(),
            region: report.placement.region.unwrap_or_default(),
            ..Default::default()
        })
        .into(),
        images: Some(proto::TrustReportImages {
            workspace_image: report.images.workspace_image.unwrap_or_default(),
            workspace_image_id: report.images.workspace_image_id.unwrap_or_default(),
            gateway_image: report.images.gateway_image.unwrap_or_default(),
            gateway_image_id: report.images.gateway_image_id.unwrap_or_default(),
            dind_image: report.images.dind_image.unwrap_or_default(),
            dind_image_id: report.images.dind_image_id.unwrap_or_default(),
            daemon_init_image: report.images.daemon_init_image.unwrap_or_default(),
            daemon_init_image_id: report.images.daemon_init_image_id.unwrap_or_default(),
            ..Default::default()
        })
        .into(),
        provenance: Some(proto::TrustReportProvenance {
            status: report.provenance.status,
            guest_kernel: report.provenance.guest_kernel.unwrap_or_default(),
            guest_initrd: report.provenance.guest_initrd.unwrap_or_default(),
            guest_image: report.provenance.guest_image.unwrap_or_default(),
            firmware: report.provenance.firmware.unwrap_or_default(),
            source: report.provenance.source.unwrap_or_default(),
            notes: report.provenance.notes,
            ..Default::default()
        })
        .into(),
        attestation: Some(proto::TrustReportAttestation {
            status: report.attestation.status,
            tee: report.attestation.tee,
            report_available: report.attestation.report_available,
            report_source: report.attestation.report_source.unwrap_or_default(),
            metadata: report.attestation.metadata.into_iter().collect(),
            ..Default::default()
        })
        .into(),
        trustee: Some(proto::TrustReportTrustee {
            status: report.trustee.status,
            resource_uri: report.trustee.resource_uri.unwrap_or_default(),
            reference_values: report.trustee.reference_values.unwrap_or_default(),
            policy: report.trustee.policy.unwrap_or_default(),
            evidence_issues: report.trustee.evidence_issues,
            ..Default::default()
        })
        .into(),
        summary: Some(proto::TrustReportSummary {
            trust_level: report.summary.trust_level,
            production_verified: report.summary.production_verified,
            warnings: report.summary.warnings,
            ..Default::default()
        })
        .into(),
        ..Default::default()
    }
}

fn invalid_stored_value<T>(field: &'static str, value: &str) -> AppResult<T> {
    tracing::error!(field, value, "stored environment value is invalid");
    Err(AppError::InternalMsg(
        format!("failed to map {field}").into(),
    ))
}

fn environment_rpc_error(error: &AppError, ctx: &RequestContext) -> connectrpc::ConnectError {
    environment_connect_error(error, request_id(ctx))
}

fn request_id(ctx: &RequestContext) -> Option<&str> {
    ctx.headers()
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
}

fn environment_connect_error(
    error: &AppError,
    request_id: Option<&str>,
) -> connectrpc::ConnectError {
    let rendered = RenderedConnectError::from_app_error(error, request_id);
    let rendered = if matches!(
        error,
        AppError::Coded {
            code: "rate_limited",
            ..
        }
    ) {
        rendered.with_retry_delay(StdDuration::from_secs(60))
    } else {
        rendered
    };
    wire_error(&rendered)
}

#[cfg(test)]
mod tests {
    use super::*;
    use codewire_server_core::connect_error::{ConnectCode, ConnectError, ConnectErrorDetail};

    #[test]
    fn schema_states_round_trip_without_collapsing_unknown() {
        let states = [
            ("pending", proto::EnvironmentState::Pending),
            ("pending_build", proto::EnvironmentState::PendingBuild),
            ("building", proto::EnvironmentState::Building),
            ("build_failed", proto::EnvironmentState::BuildFailed),
            ("pulling_snapshot", proto::EnvironmentState::PullingSnapshot),
            ("creating", proto::EnvironmentState::Creating),
            ("starting", proto::EnvironmentState::Starting),
            ("running", proto::EnvironmentState::Running),
            ("stopping", proto::EnvironmentState::Stopping),
            ("stopped", proto::EnvironmentState::Stopped),
            ("archiving", proto::EnvironmentState::Archiving),
            ("archived", proto::EnvironmentState::Archived),
            ("restoring", proto::EnvironmentState::Restoring),
            ("resizing", proto::EnvironmentState::Resizing),
            ("destroying", proto::EnvironmentState::Destroying),
            ("destroyed", proto::EnvironmentState::Destroyed),
            ("error", proto::EnvironmentState::Error),
            ("unknown", proto::EnvironmentState::Unknown),
        ];

        for (stored, wire) in states {
            assert_eq!(proto_environment_state(stored).unwrap(), wire);
            assert_eq!(api_environment_state(wire.into()).unwrap(), stored);
        }
        assert_eq!(
            api_environment_state(proto::EnvironmentState::Unspecified.into()).unwrap(),
            ""
        );
    }

    #[test]
    fn schema_desired_states_map_one_to_one() {
        for (stored, wire) in [
            ("started", proto::DesiredState::Started),
            ("stopped", proto::DesiredState::Stopped),
            ("destroyed", proto::DesiredState::Destroyed),
            ("archived", proto::DesiredState::Archived),
            ("resized", proto::DesiredState::Resized),
        ] {
            assert_eq!(proto_desired_state(stored).unwrap(), wire);
        }
    }

    #[test]
    fn poll_interval_table_is_bounded_and_terminal_states_are_absent() {
        let mut environment = test_environment("pending", false);
        assert_eq!(poll_interval_seconds(&environment), Some(5));
        environment.state = "creating".into();
        assert_eq!(poll_interval_seconds(&environment), Some(3));
        environment.state = "running".into();
        assert_eq!(poll_interval_seconds(&environment), Some(2));
        environment.setup_complete = true;
        assert_eq!(poll_interval_seconds(&environment), None);

        for state in [
            "pending_build",
            "building",
            "build_failed",
            "pulling_snapshot",
            "starting",
            "stopping",
            "stopped",
            "archiving",
            "archived",
            "restoring",
            "resizing",
            "destroying",
            "destroyed",
            "error",
            "unknown",
        ] {
            environment.state = state.into();
            assert_eq!(poll_interval_seconds(&environment), None, "{state}");
        }
    }

    #[test]
    fn pagination_and_ttl_validation_render_invalid_argument_details() {
        assert!(validate_pagination("").is_ok());
        let pagination = validate_pagination("future").unwrap_err();
        assert_eq!(
            ConnectError::from_app_error(&pagination, None).code,
            ConnectCode::InvalidArgument
        );

        let ttl = validate_additional_seconds(59).unwrap_err();
        let rendered = ConnectError::from_app_error(&ttl, None);
        assert_eq!(rendered.code, ConnectCode::InvalidArgument);
        let ConnectErrorDetail::BadRequest(detail) = &rendered.details[0] else {
            panic!("expected BadRequest detail");
        };
        assert_eq!(detail.field_violations[0].field, "additional_seconds");
        assert!(validate_additional_seconds(60).is_ok());
        assert!(validate_additional_seconds(86_400).is_ok());
        assert!(validate_additional_seconds(86_401).is_err());
    }

    #[test]
    fn start_outcomes_are_explicit() {
        assert_eq!(
            proto_start_outcome(StartOutcomeCore::Started),
            proto::StartOutcome::Started
        );
        assert_eq!(
            proto_start_outcome(StartOutcomeCore::Retried),
            proto::StartOutcome::Retried
        );
    }

    #[test]
    fn daemon_state_mapping_preserves_every_contract_state() {
        use codewire_gateway_proto::daemon::v1::DaemonState as Internal;

        for (internal, public) in [
            (
                Internal::Unspecified,
                proto::EnvironmentDaemonState::Unspecified,
            ),
            (
                Internal::Unsupported,
                proto::EnvironmentDaemonState::Unsupported,
            ),
            (Internal::Starting, proto::EnvironmentDaemonState::Starting),
            (Internal::Ready, proto::EnvironmentDaemonState::Ready),
            (
                Internal::Unhealthy,
                proto::EnvironmentDaemonState::Unhealthy,
            ),
            (
                Internal::UpgradeRequired,
                proto::EnvironmentDaemonState::UpgradeRequired,
            ),
        ] {
            assert_eq!(proto_environment_daemon_state(internal), public);
        }
    }

    #[test]
    fn access_timestamp_normalizes_postgres_text() {
        let timestamp = proto_postgres_timestamp("2026-07-18 12:34:56.123456").unwrap();
        assert_eq!(timestamp.nanos, 123_456_000);
    }

    #[test]
    fn prepare_connect_stream_preserves_one_recorded_sequence() {
        let repo = "https://example.test/acme/repo";
        let events = [
            PrepareStreamEvent::Progress {
                phase: "repo_config".into(),
                message: "Checking saved configuration...".into(),
                total: None,
                repo: None,
            },
            PrepareStreamEvent::Progress {
                phase: "resolving".into(),
                message: "Resolving preset...".into(),
                total: None,
                repo: None,
            },
            PrepareStreamEvent::Progress {
                phase: "repo_fetch".into(),
                message: "Fetching repository context...".into(),
                total: Some(1),
                repo: None,
            },
            PrepareStreamEvent::RepoFetched {
                index: 0,
                repo: repo.into(),
                ok: true,
            },
            PrepareStreamEvent::Complete(Box::new(PrepareResponse {
                draft: CreateEnvironmentBody {
                    repo_url: repo.into(),
                    repos: vec![RepoEntry {
                        url: repo.into(),
                        branch: String::new(),
                    }],
                    ..Default::default()
                },
                detection: None,
                resolved_preset: None,
                repo_config: None,
            })),
        ];
        let connect = events
            .iter()
            .cloned()
            .map(|event| proto_prepare_event(event, "org_contract").unwrap())
            .collect::<Vec<_>>();
        assert_eq!(connect.len(), events.len());

        use proto::watch_environment_create_response::Event;
        assert!(
            matches!(connect[0].event, Some(Event::Progress(ref event)) if
            event.phase == "repo_config" && event.message == "Checking saved configuration...")
        );
        assert!(
            matches!(connect[1].event, Some(Event::Progress(ref event)) if
            event.phase == "resolving" && event.message == "Resolving preset...")
        );
        assert!(
            matches!(connect[2].event, Some(Event::Progress(ref event)) if
            event.phase == "repo_fetch" && event.total == 1)
        );
        assert!(
            matches!(connect[3].event, Some(Event::RepoFetched(ref event)) if
            event.index == 0 && event.repo == repo && event.ok)
        );
        assert!(
            matches!(connect[4].event, Some(Event::Complete(ref event)) if
            event.draft.org_id == "org_contract" && event.draft.repo_url == repo)
        );
    }

    #[test]
    fn prepare_complete_maps_full_typed_payload() {
        let complete = proto_prepare_complete(
            PrepareResponse {
                draft: CreateEnvironmentBody {
                    name: Some("typed-draft".into()),
                    app_ports: vec![AppPort {
                        port: 3000,
                        label: "web".into(),
                        access: "public".into(),
                    }],
                    ..Default::default()
                },
                detection: Some(crate::api::detect::DetectionResult {
                    project_type: "rust".into(),
                    agents: vec![SetupAgent {
                        agent_type: "codex".into(),
                    }],
                    install_agents: Some(true),
                    include_org_secrets: Some(false),
                    setup_notes: "deterministic".into(),
                    ..Default::default()
                }),
                resolved_preset: Some(crate::api::prepare::PresetWire {
                    id: "preset_typed".into(),
                    org_id: Some("org_contract".into()),
                    name: "Typed".into(),
                    slug: Some("typed".into()),
                    language: Some("rust".into()),
                    official: false,
                    description: None,
                    build_status: "ready".into(),
                    build_error: None,
                    default_cpu_millicores: 2_000,
                    default_memory_mb: 4_096,
                    default_disk_gb: 10,
                    default_ttl_seconds: Some(3_600),
                    image: Some("example.test/typed:latest".into()),
                    default_setup_config: None,
                    secret_project_id: None,
                    created_at: "2026-07-18T12:34:56Z".into(),
                }),
                repo_config: Some(RepoConfig {
                    id: "repo_config_typed".into(),
                    org_id: "org_contract".into(),
                    repo_url: "https://example.test/acme/typed".into(),
                    preset_id: Some("preset_typed".into()),
                    setup_config: serde_json::json!({
                        "install_command": "cargo build",
                        "env_vars": {"RUST_LOG": "info"}
                    }),
                    created_by: "usr_contract".into(),
                    updated_at: "2026-07-18T12:34:56Z".into(),
                }),
            },
            "org_contract",
        )
        .unwrap();

        let json = serde_json::to_value(complete).unwrap();
        assert_eq!(json["draft"]["orgId"], "org_contract");
        assert_eq!(json["draft"]["appPorts"][0]["port"], 3000);
        assert_eq!(json["detection"]["projectType"], "rust");
        assert_eq!(json["detection"]["agents"][0]["type"], "codex");
        assert_eq!(json["detection"]["installAgents"], true);
        assert_eq!(json["resolvedPreset"]["id"], "preset_typed");
        assert_eq!(
            json["repoConfig"]["setupConfig"]["env_vars"]["RUST_LOG"],
            "info"
        );
    }

    #[test]
    fn log_events_map_metadata_timestamp_and_typed_heartbeat() {
        let log = proto_log_event(LogStreamEvent::Log(ApiEnvironmentLog {
            id: "log_1".into(),
            environment_id: "env_1".into(),
            phase: "setup".into(),
            status: "running".into(),
            message: "installing".into(),
            metadata: serde_json::value::RawValue::from_string(
                r#"{"step":2,"nested":{"ok":true}}"#.into(),
            )
            .ok(),
            created_at: "2026-07-18T21:00:00Z".into(),
        }))
        .unwrap();
        let json = serde_json::to_value(log).unwrap();
        assert_eq!(json["log"]["id"], "log_1");
        assert_eq!(json["log"]["metadata"]["step"], 2.0);
        assert_eq!(json["log"]["metadata"]["nested"]["ok"], true);
        assert_eq!(json["log"]["createdAt"], "2026-07-18T21:00:00Z");

        let sent_at = DateTime::parse_from_rfc3339("2026-07-18T21:00:15.123456Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let heartbeat = proto_log_event(LogStreamEvent::Heartbeat(sent_at)).unwrap();
        let json = serde_json::to_value(heartbeat).unwrap();
        assert_eq!(json["heartbeat"]["sentAt"], "2026-07-18T21:00:15.123456Z");

        let null_metadata = proto_environment_log(ApiEnvironmentLog {
            id: "log_null".into(),
            environment_id: "env_1".into(),
            phase: "setup".into(),
            status: "running".into(),
            message: String::new(),
            metadata: serde_json::value::RawValue::from_string("null".into()).ok(),
            created_at: "2026-07-18T21:00:00Z".into(),
        })
        .unwrap();
        assert!(null_metadata.metadata.is_unset());
    }

    fn test_environment(state: &str, setup_complete: bool) -> Environment {
        Environment {
            id: "env_1".into(),
            org_id: "org_1".into(),
            created_by: "usr_1".into(),
            preset_id: None,
            env_type: "sandbox".into(),
            name: None,
            state: state.into(),
            desired_state: "started".into(),
            isolation_tier: "standard".into(),
            error_reason: None,
            recoverable: false,
            state_changed_at: "2026-07-18T12:34:56Z".into(),
            retry_count: 0,
            setup_phase: 0,
            setup_complete,
            setup_error: None,
            ttl_seconds: None,
            shutdown_at: None,
            cpu_millicores: 2_000,
            memory_mb: 4_096,
            disk_gb: 10,
            total_running_seconds: 0,
            created_at: "2026-07-18T12:34:56Z".into(),
            started_at: None,
            stopped_at: None,
            destroyed_at: None,
            protected: false,
            deletion_requested_at: None,
            deletion_grace_until: None,
            preset_name: None,
            network: None,
            ports: Vec::new(),
        }
    }
}
