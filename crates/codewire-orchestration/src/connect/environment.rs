//! Connect-RPC adapter for environment resources and lifecycle operations.
//!
//! This module maps shared environment service logic to protobuf, validates
//! pagination, supplies polling hints and typed outcomes, and renders Connect
//! errors.

use std::borrow::Cow;
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
use crate::api::create::{CreateEnvironmentBody, create_environment_core};
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
use crate::api::environment_project_spec::get_environment_project_spec_core;
use crate::api::environment_resize::{
    EnvironmentResizeDisruptionPolicy, EnvironmentResizeExecutionMode, EnvironmentResizeOperation,
    EnvironmentResizePlan, EnvironmentResources, PlanEnvironmentResizeParams,
    ResizeEnvironmentParams, get_resize_operation_core, plan_environment_resize_core,
    resize_environment_core,
};
use crate::api::environment_sources::{
    EnvironmentSourceSelection, EnvironmentSourcesUpdate, EnvironmentSourcesUpdateOutcome,
    UpdateEnvironmentSourcesBody, update_environment_sources_core,
};
use crate::api::environments::{
    Environment, EnvironmentPort, ListEnvironmentsQuery, StartOutcomeCore,
    cancel_environment_deletion_core, delete_environment_core, extend_environment_ttl_core,
    get_environment_core, list_environments_core, protect_environment_core, require_org_member,
    start_environment_core, stop_environment_core, unprotect_environment_core,
};
use crate::api::host_key::{RecordedHostKeys, get_environment_host_key_core};
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
        let body = create_body(request).map_err(|error| environment_rpc_error(&error, &ctx))?;
        let environment = create_environment_core(&self.state, &user, &org_id, body)
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

    async fn get_environment_project_spec(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, proto::GetEnvironmentProjectSpecRequest>,
    ) -> ServiceResult<proto::GetEnvironmentProjectSpecResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();
        let saved = get_environment_project_spec_core(
            &self.state,
            &user,
            request.org_id,
            request.environment_id,
        )
        .await
        .map_err(|error| environment_rpc_error(&error, &ctx))?;
        connectrpc::Response::ok(proto::GetEnvironmentProjectSpecResponse {
            project_spec: Some(codewire_project_proto::to_proto(saved.spec)).into(),
            withheld_environment_keys: saved.withheld_environment_keys,
            ..Default::default()
        })
    }

    async fn get_environment_host_key(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, proto::GetEnvironmentHostKeyRequest>,
    ) -> ServiceResult<proto::GetEnvironmentHostKeyResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();
        let key = get_environment_host_key_core(
            &self.state,
            &user,
            request.org_id,
            request.environment_id,
            &RecordedHostKeys(&self.state.pool),
        )
        .await
        .map_err(|error| environment_rpc_error(&error, &ctx))?;
        connectrpc::Response::ok(proto::GetEnvironmentHostKeyResponse {
            generation: key.generation,
            public_key_openssh: key.public_key_openssh,
            ..Default::default()
        })
    }

    async fn resize_environment(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, proto::ResizeEnvironmentRequest>,
    ) -> ServiceResult<proto::ResizeEnvironmentResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();
        let result = resize_environment_core(
            &self.state,
            &user,
            ResizeEnvironmentParams {
                org_id: request.org_id.to_owned(),
                environment_id: request.environment_id.to_owned(),
                desired_resources: EnvironmentResources {
                    cpu_millicores: request.cpu_millicores,
                    memory_mb: request.memory_mb,
                    disk_gb: request.disk_gb,
                },
                request_id: request.request_id.to_owned(),
                force: request.force,
                disruption_policy: api_resize_disruption_policy(request.disruption_policy)
                    .map_err(|error| environment_rpc_error(&error, &ctx))?,
            },
        )
        .await
        .map_err(|error| environment_rpc_error(&error, &ctx))?;
        let poll_interval = result.operation.is_active().then(|| Duration::from_secs(1));

        connectrpc::Response::ok(proto::ResizeEnvironmentResponse {
            operation: Some(
                proto_environment_resize_operation(result.operation)
                    .map_err(|error| environment_rpc_error(&error, &ctx))?,
            )
            .into(),
            environment: Some(
                proto_environment(result.environment)
                    .map_err(|error| environment_rpc_error(&error, &ctx))?,
            )
            .into(),
            poll_interval: poll_interval.into(),
            ..Default::default()
        })
    }

    async fn update_environment_sources(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, proto::UpdateEnvironmentSourcesRequest>,
    ) -> ServiceResult<proto::UpdateEnvironmentSourcesResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.to_owned_message();
        let organization = request.org_id.clone();
        let environment = request.environment_id.clone();
        let body =
            source_update_body(request).map_err(|error| environment_rpc_error(&error, &ctx))?;
        let result =
            update_environment_sources_core(&self.state, &user, &organization, &environment, body)
                .await
                .map_err(|error| environment_rpc_error(&error, &ctx))?;
        connectrpc::Response::ok(proto_source_update(result))
    }

    async fn plan_environment_resize(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, proto::PlanEnvironmentResizeRequest>,
    ) -> ServiceResult<proto::PlanEnvironmentResizeResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();
        let result = plan_environment_resize_core(
            &self.state,
            &user,
            PlanEnvironmentResizeParams {
                org_id: request.org_id.to_owned(),
                environment_id: request.environment_id.to_owned(),
                desired_resources: EnvironmentResources {
                    cpu_millicores: request.cpu_millicores,
                    memory_mb: request.memory_mb,
                    disk_gb: request.disk_gb,
                },
            },
        )
        .await
        .map_err(|error| environment_rpc_error(&error, &ctx))?;

        connectrpc::Response::ok(proto::PlanEnvironmentResizeResponse {
            plan: Some(proto_environment_resize_plan(result.plan)).into(),
            environment: Some(
                proto_environment(result.environment)
                    .map_err(|error| environment_rpc_error(&error, &ctx))?,
            )
            .into(),
            ..Default::default()
        })
    }

    async fn get_environment_resize_operation(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, proto::GetEnvironmentResizeOperationRequest>,
    ) -> ServiceResult<proto::GetEnvironmentResizeOperationResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();
        let result = get_resize_operation_core(
            &self.state,
            &user,
            request.org_id,
            request.environment_id,
            request.operation_id,
        )
        .await
        .map_err(|error| environment_rpc_error(&error, &ctx))?;
        let poll_interval = result.operation.is_active().then(|| Duration::from_secs(1));

        connectrpc::Response::ok(proto::GetEnvironmentResizeOperationResponse {
            operation: Some(
                proto_environment_resize_operation(result.operation)
                    .map_err(|error| environment_rpc_error(&error, &ctx))?,
            )
            .into(),
            environment: Some(
                proto_environment(result.environment)
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
        let draft = create_body(draft).map_err(|error| environment_rpc_error(&error, &ctx))?;
        let events = start_prepare_stream(self.state.clone(), org_id.clone(), draft);
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

fn create_body(request: proto::CreateEnvironmentRequest) -> AppResult<CreateEnvironmentBody> {
    let project_spec = request
        .project_spec
        .into_option()
        .ok_or_else(|| {
            crate::api::environments::coded(
                axum::http::StatusCode::BAD_REQUEST,
                "project_spec_required",
                "project_spec is required",
            )
        })
        .and_then(|value| {
            codewire_project_proto::from_proto(value).map_err(|error| {
                crate::api::environments::coded_owned(
                    axum::http::StatusCode::BAD_REQUEST,
                    "invalid_project_spec",
                    error.to_string(),
                )
            })
        })?;
    Ok(CreateEnvironmentBody {
        preset_id: request.preset_id,
        name: request.name,
        ttl_seconds: request.ttl_seconds,
        isolation_tier: match request.isolation_tier.as_known() {
            Some(proto::IsolationTier::Unspecified) | Some(proto::IsolationTier::Standard) => {
                String::new()
            }
            Some(proto::IsolationTier::Confidential) => "confidential".to_string(),
            None => format!("unknown-enum-value-{}", request.isolation_tier.to_i32()),
        },
        project_spec,
        expected_profile_revision: request.expected_profile_revision,
        confirm_personal_credentials: request.confirm_personal_credentials,
        confirm_personal_secrets: request.confirm_personal_secrets,
        omit_application_previews: request.omit_application_previews,
        network: (!request.network.is_empty()).then_some(request.network),
        source_snapshot_id: (!request.source_snapshot_id.is_empty())
            .then_some(request.source_snapshot_id),
    })
}

fn source_update_body(
    request: proto::UpdateEnvironmentSourcesRequest,
) -> AppResult<UpdateEnvironmentSourcesBody> {
    Ok(UpdateEnvironmentSourcesBody {
        expected_operation_generation: request.expected_operation_generation,
        expected: source_selection(request.expected.into_option())?,
        replacement: source_selection(request.replacement.into_option())?,
        allow_restart: request.allow_restart,
        confirm_personal_credentials: request.confirm_personal_credentials,
        confirm_personal_secrets: request.confirm_personal_secrets,
    })
}

fn source_selection(
    selection: Option<proto::EnvironmentSourceSelection>,
) -> AppResult<EnvironmentSourceSelection> {
    let selection = selection.ok_or_else(|| {
        AppError::BadRequest("expected and replacement source selections are required".into())
    })?;
    let spec = codewire_project_proto::from_proto(proto::ProjectSpec {
        secrets: selection.secrets,
        credentials: selection.credentials,
        ..codewire_project_proto::to_proto(codewire_project::ProjectSpec::default())
    })
    .map_err(|_| AppError::BadRequest("invalid environment source selection".into()))?;
    Ok(EnvironmentSourceSelection {
        secrets: spec.secrets,
        credentials: spec.credentials,
        profile_revision: selection.profile_revision,
    })
}

fn proto_source_selection(
    selection: EnvironmentSourceSelection,
) -> proto::EnvironmentSourceSelection {
    let spec = codewire_project_proto::to_proto(codewire_project::ProjectSpec {
        secrets: selection.secrets,
        credentials: selection.credentials,
        ..Default::default()
    });
    proto::EnvironmentSourceSelection {
        secrets: spec.secrets,
        credentials: spec.credentials,
        profile_revision: selection.profile_revision,
        ..Default::default()
    }
}

fn proto_source_update(
    update: EnvironmentSourcesUpdate,
) -> proto::UpdateEnvironmentSourcesResponse {
    proto::UpdateEnvironmentSourcesResponse {
        environment_id: update.environment_id,
        operation_generation: update.operation_generation,
        selection: Some(proto_source_selection(update.selection)).into(),
        outcome: match update.outcome {
            EnvironmentSourcesUpdateOutcome::Unchanged => {
                proto::EnvironmentSourcesUpdateOutcome::Unchanged
            }
            EnvironmentSourcesUpdateOutcome::Stored => {
                proto::EnvironmentSourcesUpdateOutcome::Stored
            }
            EnvironmentSourcesUpdateOutcome::RestartRequired => {
                proto::EnvironmentSourcesUpdateOutcome::RestartRequired
            }
        }
        .into(),
        ..Default::default()
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
    state: codewire_daemon_proto::daemon::v1::DaemonState,
) -> proto::EnvironmentDaemonState {
    use codewire_daemon_proto::daemon::v1::DaemonState as Internal;
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
        ttl_seconds: body.ttl_seconds,
        isolation_tier: match body.isolation_tier.as_str() {
            "confidential" => proto::IsolationTier::Confidential,
            "" | "standard" => proto::IsolationTier::Standard,
            _ => proto::IsolationTier::Unspecified,
        }
        .into(),
        project_spec: Some(codewire_project_proto::to_proto(body.project_spec)).into(),
        expected_profile_revision: body.expected_profile_revision,
        confirm_personal_credentials: body.confirm_personal_credentials,
        confirm_personal_secrets: body.confirm_personal_secrets,
        omit_application_previews: body.omit_application_previews,
        network: body.network.unwrap_or_default(),
        ..Default::default()
    }
}

fn proto_repo_config(value: RepoConfig) -> AppResult<proto::RepoConfig> {
    Ok(proto::RepoConfig {
        id: value.id,
        org_id: value.org_id,
        repo_url: value.repo_url,
        project_spec: Some(codewire_project_proto::to_proto(value.project_spec)).into(),
        created_by: value.created_by,
        updated_at: value.updated_at,
        ..Default::default()
    })
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
        error_code: environment.error_code.unwrap_or_default(),
        recoverable: environment.recoverable,
        state_changed_at: Some(proto_timestamp(&environment.state_changed_at)?).into(),
        retry_count: environment.retry_count,
        setup_phase: environment.setup_phase,
        setup_complete: environment.setup_complete,
        operation_generation: environment.operation_generation,
        source_selection: environment
            .source_selection
            .map(proto_source_selection)
            .into(),
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
        network_state: proto_network_state(environment.network_state.as_deref())?.into(),
        network_failure: proto_network_failure(environment.network_failure.as_deref())?.into(),
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

fn proto_network_state(state: Option<&str>) -> AppResult<proto::NetworkAttachmentState> {
    Ok(match state {
        None => proto::NetworkAttachmentState::Unspecified,
        Some("pending") => proto::NetworkAttachmentState::Pending,
        Some("attached") => proto::NetworkAttachmentState::Attached,
        Some("failed") => proto::NetworkAttachmentState::Failed,
        Some("revoked") => proto::NetworkAttachmentState::Revoked,
        Some(unexpected) => return invalid_stored_value("network attachment state", unexpected),
    })
}

fn proto_network_failure(failure: Option<&str>) -> AppResult<proto::NetworkAttachmentFailure> {
    Ok(match failure {
        None => proto::NetworkAttachmentFailure::Unspecified,
        Some("mesh_unreachable") => proto::NetworkAttachmentFailure::MeshUnreachable,
        Some("network_not_found") => proto::NetworkAttachmentFailure::NetworkNotFound,
        Some("not_a_member") => proto::NetworkAttachmentFailure::NotAMember,
        Some("node_name_taken") => proto::NetworkAttachmentFailure::NodeNameTaken,
        Some("refused") => proto::NetworkAttachmentFailure::Refused,
        Some(unexpected) => return invalid_stored_value("network attachment failure", unexpected),
    })
}

fn proto_environment_resources(resources: EnvironmentResources) -> proto::EnvironmentResources {
    proto::EnvironmentResources {
        cpu_millicores: resources.cpu_millicores,
        memory_mb: resources.memory_mb,
        disk_gb: resources.disk_gb,
        ..Default::default()
    }
}

fn api_resize_disruption_policy(
    policy: EnumValue<proto::EnvironmentResizeDisruptionPolicy>,
) -> AppResult<EnvironmentResizeDisruptionPolicy> {
    match policy.as_known() {
        None
        | Some(proto::EnvironmentResizeDisruptionPolicy::Unspecified)
        | Some(proto::EnvironmentResizeDisruptionPolicy::LiveOnly) => {
            Ok(EnvironmentResizeDisruptionPolicy::LiveOnly)
        }
        Some(proto::EnvironmentResizeDisruptionPolicy::AllowRestart) => {
            Ok(EnvironmentResizeDisruptionPolicy::AllowRestart)
        }
    }
}

fn proto_resize_disruption_policy(
    policy: EnvironmentResizeDisruptionPolicy,
) -> proto::EnvironmentResizeDisruptionPolicy {
    match policy {
        EnvironmentResizeDisruptionPolicy::LiveOnly => {
            proto::EnvironmentResizeDisruptionPolicy::LiveOnly
        }
        EnvironmentResizeDisruptionPolicy::AllowRestart => {
            proto::EnvironmentResizeDisruptionPolicy::AllowRestart
        }
    }
}

fn proto_resize_execution_mode(
    mode: EnvironmentResizeExecutionMode,
) -> proto::EnvironmentResizeExecutionMode {
    match mode {
        EnvironmentResizeExecutionMode::Noop => proto::EnvironmentResizeExecutionMode::Noop,
        EnvironmentResizeExecutionMode::ApplyOnStart => {
            proto::EnvironmentResizeExecutionMode::ApplyOnStart
        }
        EnvironmentResizeExecutionMode::InPlace => proto::EnvironmentResizeExecutionMode::InPlace,
        EnvironmentResizeExecutionMode::Restart => proto::EnvironmentResizeExecutionMode::Restart,
    }
}

fn proto_environment_resize_plan(plan: EnvironmentResizePlan) -> proto::EnvironmentResizePlan {
    proto::EnvironmentResizePlan {
        previous_resources: Some(proto_environment_resources(plan.previous_resources)).into(),
        desired_resources: Some(proto_environment_resources(plan.desired_resources)).into(),
        execution_mode: proto_resize_execution_mode(plan.execution_mode).into(),
        active_session_count: plan.active_session_count,
        active_sessions_will_be_terminated: plan.active_sessions_will_be_terminated,
        reason: plan.reason,
        warnings: plan.warnings,
        ..Default::default()
    }
}

fn proto_environment_resize_operation(
    operation: EnvironmentResizeOperation,
) -> AppResult<proto::EnvironmentResizeOperation> {
    let state = match operation.state.as_str() {
        "pending" => proto::EnvironmentResizeOperationState::Pending,
        "applying" => proto::EnvironmentResizeOperationState::Applying,
        "restarting" => proto::EnvironmentResizeOperationState::Restarting,
        "completed" => proto::EnvironmentResizeOperationState::Completed,
        "failed" => proto::EnvironmentResizeOperationState::Failed,
        unexpected => {
            return invalid_stored_value("environment resize operation state", unexpected);
        }
    };
    Ok(proto::EnvironmentResizeOperation {
        id: operation.id,
        environment_id: operation.environment_id,
        request_id: operation.request_id,
        previous_resources: Some(proto_environment_resources(operation.previous_resources)).into(),
        desired_resources: Some(proto_environment_resources(operation.desired_resources)).into(),
        last_applied_resources: Some(proto_environment_resources(
            operation.last_applied_resources,
        ))
        .into(),
        state: state.into(),
        failure: operation
            .failure
            .map(|failure| proto::EnvironmentResizeFailure {
                code: failure.code,
                message: failure.message,
                ..Default::default()
            })
            .into(),
        created_at: Some(proto_naive_timestamp(operation.created_at)).into(),
        updated_at: Some(proto_naive_timestamp(operation.updated_at)).into(),
        completed_at: operation.completed_at.map(proto_naive_timestamp).into(),
        disruption_policy: proto_resize_disruption_policy(operation.disruption_policy).into(),
        planned_mode: proto_resize_execution_mode(operation.planned_mode).into(),
        applied_mode: operation
            .applied_mode
            .map(proto_resize_execution_mode)
            .unwrap_or(proto::EnvironmentResizeExecutionMode::Unspecified)
            .into(),
        pod_replaced: operation.pod_replaced,
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

fn proto_naive_timestamp(value: NaiveDateTime) -> Timestamp {
    let value = value.and_utc();
    Timestamp::from_unix(value.timestamp(), value.timestamp_subsec_nanos() as i32)
}

fn optional_timestamp(
    value: Option<String>,
) -> AppResult<buffa::MessageField<Timestamp, buffa::Inline<Timestamp>>> {
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
    fn source_update_requires_both_complete_selections_and_preserves_fences() {
        assert!(source_update_body(proto::UpdateEnvironmentSourcesRequest::default()).is_err());
        let selection = EnvironmentSourceSelection {
            credentials: Some(codewire_project::CredentialBinding {
                profile: "platform:id:6bf8d155-e84c-4fc5-b479-b17022fe41dd".into(),
            }),
            profile_revision: Some(3),
            ..Default::default()
        };
        let body = source_update_body(proto::UpdateEnvironmentSourcesRequest {
            expected_operation_generation: 7,
            expected: Some(proto_source_selection(selection.clone())).into(),
            replacement: Some(proto::EnvironmentSourceSelection::default()).into(),
            confirm_personal_secrets: true,
            ..Default::default()
        })
        .unwrap();
        assert_eq!(body.expected_operation_generation, 7);
        assert_eq!(body.expected, selection);
        assert_eq!(body.replacement, EnvironmentSourceSelection::default());
        assert!(
            body.confirm_personal_secrets
                && !body.confirm_personal_credentials
                && !body.allow_restart
        );
        let unknown = proto::EnvironmentSourceSelection {
            secrets: Some(proto::ProjectSecretBindings {
                user: Some(99.into()),
                ..Default::default()
            })
            .into(),
            ..Default::default()
        };
        assert!(source_selection(Some(unknown)).is_err());
    }

    #[test]
    fn source_metadata_and_restart_outcomes_never_collapse_into_successful_start() {
        let mut environment = test_environment("stopped", true);
        environment
            .source_selection
            .as_mut()
            .unwrap()
            .secrets
            .organization = true;
        let wire = proto_environment(environment).unwrap();
        assert_eq!(wire.operation_generation, 7);
        assert!(
            wire.source_selection
                .as_option()
                .unwrap()
                .secrets
                .as_option()
                .unwrap()
                .organization
        );
        let mut unavailable = test_environment("destroyed", true);
        unavailable.source_selection = None;
        assert!(
            proto_environment(unavailable)
                .unwrap()
                .source_selection
                .is_unset()
        );
        for (outcome, expected) in [
            (
                EnvironmentSourcesUpdateOutcome::Unchanged,
                proto::EnvironmentSourcesUpdateOutcome::Unchanged,
            ),
            (
                EnvironmentSourcesUpdateOutcome::Stored,
                proto::EnvironmentSourcesUpdateOutcome::Stored,
            ),
            (
                EnvironmentSourcesUpdateOutcome::RestartRequired,
                proto::EnvironmentSourcesUpdateOutcome::RestartRequired,
            ),
        ] {
            let wire = proto_source_update(EnvironmentSourcesUpdate {
                environment_id: "environment".into(),
                operation_generation: 7,
                selection: Default::default(),
                outcome,
            });
            assert_eq!(wire.outcome.as_known(), Some(expected));
            assert_eq!(wire.operation_generation, 7);
            assert!(wire.selection.as_option().is_some());
        }
    }

    #[test]
    fn create_round_trip_keeps_profile_revision_and_personal_confirmations_distinct() {
        let request = proto::CreateEnvironmentRequest {
            project_spec: Some(codewire_project_proto::to_proto(
                codewire_project::ProjectSpec::default(),
            ))
            .into(),
            expected_profile_revision: Some(3),
            confirm_personal_credentials: true,
            confirm_personal_secrets: false,
            omit_application_previews: true,
            ..Default::default()
        };
        let body = create_body(request).unwrap();
        assert_eq!(body.expected_profile_revision, Some(3));
        assert!(body.confirm_personal_credentials && !body.confirm_personal_secrets);
        assert!(body.omit_application_previews);
        let wire = proto_create_request(body, "organization");
        assert_eq!(wire.expected_profile_revision, Some(3));
        assert!(wire.confirm_personal_credentials && !wire.confirm_personal_secrets);
        assert!(wire.omit_application_previews);
    }

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
        use codewire_daemon_proto::daemon::v1::DaemonState as Internal;

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
    fn create_requires_and_round_trips_one_canonical_project_spec() {
        let error = create_body(proto::CreateEnvironmentRequest::default()).unwrap_err();
        assert!(matches!(
            error,
            AppError::Coded {
                status: axum::http::StatusCode::BAD_REQUEST,
                code: "project_spec_required",
                ..
            }
        ));

        let project_spec = codewire_project::parse_project_yaml(
            r#"
image: ghcr.io/example/workspace:1
repositories:
  - source: https://example.test/acme/repo.git
    destination: /workspace/repo
working_directory: /workspace/repo
environment: {RUST_LOG: info}
agents: {install: false, tools: [codex]}
ports: [{port: 8080, label: api, access: private}]
cpu: "2"
memory: "8Gi"
"#,
        )
        .unwrap()
        .spec;
        let body = create_body(proto::CreateEnvironmentRequest {
            org_id: "org_contract".into(),
            name: Some("canonical".into()),
            isolation_tier: proto::IsolationTier::Confidential.into(),
            project_spec: Some(codewire_project_proto::to_proto(project_spec.clone())).into(),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(body.project_spec, project_spec);
        assert_eq!(body.isolation_tier, "confidential");

        let request = proto_create_request(body, "org_contract");
        let mapped = codewire_project_proto::from_proto(
            request
                .project_spec
                .into_option()
                .expect("project spec remains present"),
        )
        .unwrap();
        assert_eq!(mapped, project_spec);
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
            PrepareStreamEvent::Complete(Box::new(PrepareResponse {
                draft: CreateEnvironmentBody {
                    project_spec: codewire_project::parse_project_yaml(&format!(
                        "repositories: [{{source: {repo}}}]\n"
                    ))
                    .unwrap()
                    .spec,
                    ..Default::default()
                },
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
            matches!(connect[2].event, Some(Event::Complete(ref event)) if
            event.draft.org_id == "org_contract"
                && event.draft.project_spec.repositories[0].source == repo)
        );
    }

    #[test]
    fn prepare_complete_maps_canonical_project_specs_at_every_boundary() {
        let draft_spec = codewire_project::parse_project_yaml(
            r#"
image: example.test/draft:latest
environment: {RUST_LOG: info}
agents: {install: true, tools: [codex]}
ports: [{port: 3000, label: web, access: public}]
"#,
        )
        .unwrap()
        .spec;
        let preset_spec = codewire_project::parse_project_yaml(
            "image: example.test/preset:latest\nmemory: \"4Gi\"\n",
        )
        .unwrap()
        .spec;
        let repo_spec = codewire_project::parse_project_yaml(
            "install_command: cargo build\nenvironment: {RUST_BACKTRACE: '1'}\n",
        )
        .unwrap()
        .spec;
        let complete = proto_prepare_complete(
            PrepareResponse {
                draft: CreateEnvironmentBody {
                    name: Some("typed-draft".into()),
                    isolation_tier: "confidential".into(),
                    project_spec: draft_spec,
                    ..Default::default()
                },
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
                    default_ttl_seconds: Some(3_600),
                    project_spec: preset_spec,
                    created_at: "2026-07-18T12:34:56Z".into(),
                }),
                repo_config: Some(RepoConfig {
                    id: "repo_config_typed".into(),
                    org_id: "org_contract".into(),
                    repo_url: "https://example.test/acme/typed".into(),
                    project_spec: repo_spec,
                    created_by: "usr_contract".into(),
                    updated_at: "2026-07-18T12:34:56Z".into(),
                }),
            },
            "org_contract",
        )
        .unwrap();

        let json = serde_json::to_value(complete).unwrap();
        assert_eq!(json["draft"]["orgId"], "org_contract");
        assert_eq!(
            json["draft"]["isolationTier"],
            "ISOLATION_TIER_CONFIDENTIAL"
        );
        assert_eq!(
            json["draft"]["projectSpec"]["applicationPorts"][0]["port"],
            3000
        );
        assert_eq!(
            json["draft"]["projectSpec"]["environment"]["RUST_LOG"],
            "info"
        );
        assert!(json.get("detection").is_none());
        assert_eq!(json["resolvedPreset"]["id"], "preset_typed");
        assert_eq!(
            json["resolvedPreset"]["projectSpec"]["image"],
            "example.test/preset:latest"
        );
        assert_eq!(
            json["repoConfig"]["projectSpec"]["installCommand"],
            "cargo build"
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

    #[test]
    fn shutdown_deadline_round_trips_source_precision_through_environment_mapping() {
        for (value, expected_nanos) in [
            ("2026-09-17T00:43:17Z", 0),
            ("2026-09-17T00:43:17.753549Z", 753_549_000),
        ] {
            let source = chrono::DateTime::parse_from_rfc3339(value)
                .unwrap()
                .naive_utc();
            let mut environment = test_environment("running", true);
            environment.shutdown_at =
                crate::api::environments::shutdown_deadline_string(Some(source));
            let mapped = proto_environment(environment).unwrap();
            let timestamp = mapped.shutdown_at.as_option().unwrap();
            assert_eq!(timestamp.seconds, source.and_utc().timestamp());
            assert_eq!(timestamp.nanos, expected_nanos);
            let json = serde_json::to_value(&mapped).unwrap();
            assert_eq!(json["shutdownAt"], value);
        }
        let absent = proto_environment(test_environment("running", true)).unwrap();
        assert!(absent.shutdown_at.as_option().is_none());
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
            error_code: None,
            recoverable: false,
            state_changed_at: "2026-07-18T12:34:56Z".into(),
            retry_count: 0,
            setup_phase: 0,
            setup_complete,
            operation_generation: 7,
            source_selection: Some(Default::default()),
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
            network_state: None,
            network_failure: None,
            ports: Vec::new(),
        }
    }
}
