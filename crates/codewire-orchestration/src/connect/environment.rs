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
use codewire_daemon_bridge::drain::{Restart, end_at, end_on, restart_end};
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
use crate::api::environment_setup_retry::retry_environment_setup_core;
use crate::api::environment_sources::{
    EnvironmentSourceSelection, EnvironmentSourcesUpdate, EnvironmentSourcesUpdateOutcome,
    UpdateEnvironmentSourcesBody, update_environment_sources_core,
};
use crate::api::environment_startup_script::set_environment_startup_script_core;
use crate::api::environments::{
    Environment, EnvironmentPort, ListEnvironmentsQuery, StartOutcomeCore,
    cancel_environment_deletion_core, delete_environment_core, extend_environment_ttl_core,
    get_environment_core, list_environments_core, protect_environment_core, require_org_member,
    set_environment_idle_stop_core, start_environment_core, stop_environment_core,
    unprotect_environment_core,
};
use crate::api::host_key::{RecordedHostKeys, get_environment_host_key_core};
use crate::api::logs::{
    EnvironmentLog as ApiEnvironmentLog, LogStreamEvent, open_environment_log_stream,
};
use crate::api::network_policies::NetworkPolicyFlags;
use crate::api::prepare::{PrepareResponse, PrepareStreamEvent, RepoConfig, start_prepare_stream};
use crate::api::trust_report::{EnvironmentTrustReport, get_environment_trust_report_core};
use crate::connect::presets::proto_preset;

mod create_body;
use create_body::create_body;

/// A watch or a log follow ended as this replica restarts (#4426): nothing is
/// lost, and the next replica serves the same stream.
const WATCH_RESTARTED: &str = "Codewire is restarting this server; watch again to continue";

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
                include_failed_creates: request.include_failed_creates,
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
            .map(|environment| {
                proto_environment(
                    environment,
                    self.state.network_policy_flags,
                    self.state.idle_stop,
                )
            })
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
        let org_id = create_organization(&self.state.pool, &user, &request)
            .await
            .map_err(|error| environment_rpc_error(&error, &ctx))?;
        let body = create_body(request).map_err(|error| environment_rpc_error(&error, &ctx))?;
        let environment = create_environment_core(&self.state, &user, &org_id, body)
            .await
            .map_err(|error| environment_rpc_error(&error, &ctx))?;

        connectrpc::Response::ok(proto::CreateEnvironmentResponse {
            environment: Some(
                proto_environment(
                    environment,
                    self.state.network_policy_flags,
                    self.state.idle_stop,
                )
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
                proto_environment(
                    environment,
                    self.state.network_policy_flags,
                    self.state.idle_stop,
                )
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
                proto_environment(
                    result.environment,
                    self.state.network_policy_flags,
                    self.state.idle_stop,
                )
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
                proto_environment(
                    result.environment,
                    self.state.network_policy_flags,
                    self.state.idle_stop,
                )
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
                proto_environment(
                    result.environment,
                    self.state.network_policy_flags,
                    self.state.idle_stop,
                )
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
            completes_with_log: true,
            ..Default::default()
        })
    }

    async fn retry_environment_setup(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, proto::RetryEnvironmentSetupRequest>,
    ) -> ServiceResult<proto::RetryEnvironmentSetupResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();
        retry_environment_setup_core(
            &self.state,
            &user,
            request.org_id,
            request.environment_id,
            request.confirm_reclone,
        )
        .await
        .map_err(|error| environment_rpc_error(&error, &ctx))?;
        connectrpc::Response::ok(proto::RetryEnvironmentSetupResponse::default())
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

    async fn set_environment_idle_stop(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, proto::SetEnvironmentIdleStopRequest>,
    ) -> ServiceResult<proto::SetEnvironmentIdleStopResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();
        let result = set_environment_idle_stop_core(
            &self.state,
            &user,
            request.org_id,
            request.environment_id,
            request.idle_stop_seconds,
        )
        .await
        .map_err(|error| environment_rpc_error(&error, &ctx))?;
        connectrpc::Response::ok(proto::SetEnvironmentIdleStopResponse {
            status: result.status.into(),
            ..Default::default()
        })
    }

    async fn set_environment_startup_script(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, proto::SetEnvironmentStartupScriptRequest>,
    ) -> ServiceResult<proto::SetEnvironmentStartupScriptResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();
        let result = set_environment_startup_script_core(
            &self.state,
            &user,
            request.org_id,
            request.environment_id,
            request.startup_script,
        )
        .await
        .map_err(|error| environment_rpc_error(&error, &ctx))?;
        connectrpc::Response::ok(proto::SetEnvironmentStartupScriptResponse {
            changed: result.changed,
            state: state::proto_scriptable_state(result.state).into(),
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
        connectrpc::Response::stream_ok(end_at(
            stream,
            Some(self.state.drain.signal(Restart::Deadline)),
            WATCH_RESTARTED,
        ))
    }

    async fn stream_logs(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, proto::StreamLogsRequest>,
    ) -> ServiceResult<ServiceStream<proto::StreamLogsResponse>> {
        let user = auth_user(&ctx)?.clone();
        let request = request.to_owned_message();
        // A follow lasts; a read of what is there ends by itself.
        let revoked = if request.follow {
            Some(
                crate::connect::fenced_stream(&self.state, &ctx, "logs", &request.environment_id)
                    .await?,
            )
        } else {
            None
        };
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
        connectrpc::Response::stream_ok(end_on(
            stream,
            restart_end(
                Some(self.state.drain.signal(Restart::Deadline)),
                WATCH_RESTARTED,
            )
            .into_iter()
            .chain(revoked),
        ))
    }
}

/// The organization a create goes to: `org_id`, or what the server resolves
/// from `organization`. Both is refused: a mismatch must not pick one.
async fn create_organization(
    pool: &sqlx::PgPool,
    user: &codewire_server_core::auth::AuthUser,
    request: &proto::CreateEnvironmentRequest,
) -> AppResult<String> {
    let Some(selector) = request.organization.as_deref() else {
        return Ok(request.org_id.clone());
    };
    if !request.org_id.is_empty() {
        return Err(crate::api::environments::coded(
            axum::http::StatusCode::BAD_REQUEST,
            "organization_ambiguous",
            "send org_id or organization, not both",
        ));
    }
    crate::api::organizations::resolve_create_organization(pool, user, selector).await
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
        idle_stop_seconds: body.idle_stop_seconds,
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
        network_policy: body.network_policy.unwrap_or_default(),
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

mod state;
use state::{api_environment_state, proto_environment_state};
mod wire;
use wire::proto_environment;
#[cfg(test)]
mod tests;
