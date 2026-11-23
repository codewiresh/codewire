//! Connect-RPC adapter for sandbox identity's records (#4663):
//! `SandboxIdentityService` over [`crate::api::identity`].

use std::sync::Arc;

use buffa_types::{Duration, Timestamp};
use chrono::{DateTime, Utc};
use codewire_proto::codewire::v1::{
    EnvironmentIdentityGroups, GetEnvironmentIdentityGroupsRequest,
    GetEnvironmentIdentityGroupsResponse, IdentityAudience, IdentityAudienceGroups,
    IdentityGroupUser, IdentityGroupUserReason, ListIdentityAudiencesRequest,
    ListIdentityAudiencesResponse, RegisterIdentityAudienceRequest,
    RegisterIdentityAudienceResponse, RemoveIdentityAudienceRequest,
    RemoveIdentityAudienceResponse, ResumeIdentityMintingRequest, ResumeIdentityMintingResponse,
    SandboxIdentityService, SetEnvironmentIdentityGroupsRequest,
    SetEnvironmentIdentityGroupsResponse, StopIdentityMintingRequest, StopIdentityMintingResponse,
};
use codewire_server_core::connect::{auth_user, rpc_app_error};
use codewire_server_core::{AppError, AppResult};
use connectrpc::{RequestContext, ServiceRequest, ServiceResult};
use sqlx::PgPool;

use crate::api::identity::audiences::{
    AudienceRequest, AudienceView, list_audiences, register_audience, remove_audience,
};
use crate::api::identity::groups::{
    CodeRunner, CodeRunnerReason, GroupsView, get_groups, set_groups,
};
use crate::api::identity::stops::{StopTarget, resume_minting, stop_minting};
use crate::identity::audience::AudienceDenylist;

pub fn router(pool: PgPool, denylist: AudienceDenylist) -> connectrpc::Router {
    connectrpc::Router::new()
        .add_service(Arc::new(SandboxIdentityConnectService { pool, denylist }))
}

struct SandboxIdentityConnectService {
    pool: PgPool,
    denylist: AudienceDenylist,
}

#[allow(refining_impl_trait)]
impl SandboxIdentityService for SandboxIdentityConnectService {
    async fn get_environment_identity_groups(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, GetEnvironmentIdentityGroupsRequest>,
    ) -> ServiceResult<GetEnvironmentIdentityGroupsResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();
        let groups = get_groups(&self.pool, &user, request.org_id, request.environment_id)
            .await
            .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(GetEnvironmentIdentityGroupsResponse {
            groups: Some(proto_groups(groups)).into(),
            ..Default::default()
        })
    }

    async fn set_environment_identity_groups(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, SetEnvironmentIdentityGroupsRequest>,
    ) -> ServiceResult<SetEnvironmentIdentityGroupsResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.to_owned_message();
        let outcome = set_groups(
            &self.pool,
            &user,
            &request.org_id,
            &request.environment_id,
            &request.groups,
        )
        .await
        .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(SetEnvironmentIdentityGroupsResponse {
            groups: Some(proto_groups(outcome.groups)).into(),
            previous_groups: outcome.previous,
            changed: outcome.changed,
            can_run_code: outcome.can_run_code.into_iter().map(proto_runner).collect(),
            ..Default::default()
        })
    }

    async fn register_identity_audience(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, RegisterIdentityAudienceRequest>,
    ) -> ServiceResult<RegisterIdentityAudienceResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.to_owned_message();
        let visible_groups = request
            .visible_groups
            .as_option()
            .map(|groups| groups.names.clone());
        let lifetime = request
            .lifetime
            .as_option()
            .map(lifetime)
            .transpose()
            .map_err(|error| rpc_app_error(&error, &ctx))?;
        let registered = register_audience(
            &self.pool,
            &self.denylist,
            &user,
            &request.org_id,
            AudienceRequest {
                audience: &request.audience,
                visible_groups: visible_groups.as_deref(),
                lifetime,
                claim_created_by: request.claim_created_by,
                claim_environment_name: request.claim_environment_name,
                file_name: request.file_name.as_deref(),
            },
        )
        .await
        .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(RegisterIdentityAudienceResponse {
            audience: Some(proto_audience(registered)).into(),
            ..Default::default()
        })
    }

    async fn list_identity_audiences(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ListIdentityAudiencesRequest>,
    ) -> ServiceResult<ListIdentityAudiencesResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();
        if !request.page_token.is_empty() {
            return Err(rpc_app_error(
                &AppError::BadRequest("unrecognized page_token".into()),
                &ctx,
            ));
        }
        let audiences = list_audiences(&self.pool, &user, request.org_id)
            .await
            .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(ListIdentityAudiencesResponse {
            audiences: audiences.into_iter().map(proto_audience).collect(),
            next_page_token: String::new(),
            ..Default::default()
        })
    }

    async fn remove_identity_audience(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, RemoveIdentityAudienceRequest>,
    ) -> ServiceResult<RemoveIdentityAudienceResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();
        let audience = remove_audience(&self.pool, &user, request.org_id, request.audience)
            .await
            .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(RemoveIdentityAudienceResponse {
            audience,
            ..Default::default()
        })
    }

    async fn stop_identity_minting(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, StopIdentityMintingRequest>,
    ) -> ServiceResult<StopIdentityMintingResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();
        let changed = stop_minting(
            &self.pool,
            &user,
            request.org_id,
            target(request.environment_id),
        )
        .await
        .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(StopIdentityMintingResponse {
            changed,
            ..Default::default()
        })
    }

    async fn resume_identity_minting(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ResumeIdentityMintingRequest>,
    ) -> ServiceResult<ResumeIdentityMintingResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();
        let changed = resume_minting(
            &self.pool,
            &user,
            request.org_id,
            target(request.environment_id),
        )
        .await
        .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(ResumeIdentityMintingResponse {
            changed,
            ..Default::default()
        })
    }
}

fn target(environment_id: &str) -> StopTarget<'_> {
    if environment_id.is_empty() {
        StopTarget::Organization
    } else {
        StopTarget::Environment(environment_id)
    }
}

/// A requested lifetime, in whole seconds; its range is checked with the
/// rest of the registration.
fn lifetime(value: &Duration) -> AppResult<std::time::Duration> {
    let invalid = || AppError::Coded {
        status: axum::http::StatusCode::BAD_REQUEST,
        code: "invalid_audience_lifetime",
        detail: "a lifetime is whole seconds from 1 to 10 minutes".into(),
    };
    if value.nanos != 0 {
        return Err(invalid());
    }
    u64::try_from(value.seconds)
        .map(std::time::Duration::from_secs)
        .map_err(|_| invalid())
}

fn proto_timestamp(value: DateTime<Utc>) -> Timestamp {
    Timestamp::from_unix(
        value.timestamp(),
        i32::try_from(value.timestamp_subsec_nanos()).unwrap_or_default(),
    )
}

fn proto_groups(view: GroupsView) -> EnvironmentIdentityGroups {
    EnvironmentIdentityGroups {
        environment_id: view.environment_id,
        groups: view.groups,
        version: view.version,
        updated_at: view.updated_at.map(proto_timestamp).into(),
        ..Default::default()
    }
}

fn proto_runner(runner: CodeRunner) -> IdentityGroupUser {
    let reason = match runner.reason {
        CodeRunnerReason::Creator => IdentityGroupUserReason::IDENTITY_GROUP_USER_REASON_CREATOR,
        CodeRunnerReason::OwnerGrant => {
            IdentityGroupUserReason::IDENTITY_GROUP_USER_REASON_OWNER_GRANT
        }
        CodeRunnerReason::OperatorGrant => {
            IdentityGroupUserReason::IDENTITY_GROUP_USER_REASON_OPERATOR_GRANT
        }
        CodeRunnerReason::OrganizationAdmin => {
            IdentityGroupUserReason::IDENTITY_GROUP_USER_REASON_ORGANIZATION_ADMIN
        }
    };
    IdentityGroupUser {
        user_id: runner.user_id,
        email: runner.email,
        reason: reason.into(),
        ..Default::default()
    }
}

fn proto_audience(view: AudienceView) -> IdentityAudience {
    IdentityAudience {
        org_id: view.org_id,
        audience: view.audience,
        visible_groups: view
            .visible_groups
            .map(|names| IdentityAudienceGroups {
                names,
                ..Default::default()
            })
            .into(),
        lifetime: Some(Duration::from_secs(i64::from(view.lifetime_seconds))).into(),
        claim_created_by: view.claim_created_by,
        claim_environment_name: view.claim_environment_name,
        file_name: view.file_name,
        version: view.version,
        created_by: view.created_by,
        created_at: Some(proto_timestamp(view.created_at)).into(),
        ..Default::default()
    }
}
