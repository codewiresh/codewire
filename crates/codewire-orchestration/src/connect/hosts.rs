//! Connect-RPC adapter for hosts (#3609, slice 1).

use std::sync::Arc;

use buffa_types::Timestamp;
use chrono::{DateTime, Utc};
use codewire_proto::codewire::v1::__buffa::view::oneof::{
    grant_host_request, revoke_host_grant_request,
};
use codewire_proto::codewire::v1::{
    EnrollHostRequest, EnrollHostResponse, GetHostRequest, GetHostResponse, GrantHostRequest,
    GrantHostResponse, Host, HostLimits as ProtoHostLimits, HostLimitsView,
    HostPlatform as ProtoHostPlatform, HostService, HostState as ProtoHostState, LeaveHostRequest,
    LeaveHostResponse, ListHostsRequest, ListHostsResponse, RevokeHostGrantRequest,
    RevokeHostGrantResponse, RevokeHostRequest, RevokeHostResponse, UpdateHostProvideRequest,
    UpdateHostProvideResponse,
};
use codewire_server_core::AppError;
use codewire_server_core::connect::{auth_user, rpc_app_error};
use connectrpc::{RequestContext, ServiceRequest, ServiceResult};
use sqlx::PgPool;

use crate::api::hosts::{
    Grantee, HostLimits, HostPlatform, HostRow, HostState, HostView, NewHost, enroll_host,
    get_host, grant_host, leave_host, list_hosts, revoke_grant, revoke_host, update_provide,
};

pub fn router(pool: PgPool) -> connectrpc::Router {
    connectrpc::Router::new().add_service(Arc::new(HostConnectService { pool }))
}

struct HostConnectService {
    pool: PgPool,
}

#[allow(refining_impl_trait)]
impl HostService for HostConnectService {
    async fn enroll_host(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, EnrollHostRequest>,
    ) -> ServiceResult<EnrollHostResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();
        let host = NewHost {
            name: request.name,
            platform: platform(request.platform.as_known()),
            capability_version: request.capability_version,
            public_key: request.public_key,
            enrollment_signature: request.enrollment_signature,
        };
        let view = enroll_host(&self.pool, &user, request.org_id, &host)
            .await
            .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(EnrollHostResponse {
            host: Some(proto_host(view)).into(),
            ..Default::default()
        })
    }

    async fn list_hosts(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ListHostsRequest>,
    ) -> ServiceResult<ListHostsResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();
        let rows = list_hosts(&self.pool, &user, request.org_id, request.page_token)
            .await
            .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(ListHostsResponse {
            hosts: rows
                .into_iter()
                .map(|host| {
                    proto_host(HostView {
                        host,
                        granted_user_ids: Vec::new(),
                    })
                })
                .collect(),
            ..Default::default()
        })
    }

    async fn get_host(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, GetHostRequest>,
    ) -> ServiceResult<GetHostResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();
        let view = get_host(&self.pool, &user, request.org_id, request.host_id)
            .await
            .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(GetHostResponse {
            host: Some(proto_host(view)).into(),
            ..Default::default()
        })
    }

    async fn update_host_provide(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, UpdateHostProvideRequest>,
    ) -> ServiceResult<UpdateHostProvideResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();
        let limits = request.limits.as_option().map(limits);
        let view = update_provide(
            &self.pool,
            &user,
            request.org_id,
            request.host_id,
            request.provide,
            limits,
        )
        .await
        .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(UpdateHostProvideResponse {
            host: Some(proto_host(view)).into(),
            ..Default::default()
        })
    }

    async fn grant_host(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, GrantHostRequest>,
    ) -> ServiceResult<GrantHostResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();
        let grantee = match &request.grantee {
            Some(grant_host_request::Grantee::UserId(user_id)) => Some(Grantee::User(user_id)),
            Some(grant_host_request::Grantee::Organization(true)) => Some(Grantee::Organization),
            _ => None,
        }
        .ok_or_else(|| rpc_app_error(&no_grantee(), &ctx))?;
        let view = grant_host(&self.pool, &user, request.org_id, request.host_id, grantee)
            .await
            .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(GrantHostResponse {
            host: Some(proto_host(view)).into(),
            ..Default::default()
        })
    }

    async fn revoke_host_grant(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, RevokeHostGrantRequest>,
    ) -> ServiceResult<RevokeHostGrantResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();
        let grantee = match &request.grantee {
            Some(revoke_host_grant_request::Grantee::UserId(user_id)) => {
                Some(Grantee::User(user_id))
            }
            Some(revoke_host_grant_request::Grantee::Organization(true)) => {
                Some(Grantee::Organization)
            }
            _ => None,
        }
        .ok_or_else(|| rpc_app_error(&no_grantee(), &ctx))?;
        let view = revoke_grant(&self.pool, &user, request.org_id, request.host_id, grantee)
            .await
            .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(RevokeHostGrantResponse {
            host: Some(proto_host(view)).into(),
            ..Default::default()
        })
    }

    async fn revoke_host(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, RevokeHostRequest>,
    ) -> ServiceResult<RevokeHostResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();
        let view = revoke_host(&self.pool, &user, request.org_id, request.host_id)
            .await
            .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(RevokeHostResponse {
            host: Some(proto_host(view)).into(),
            ..Default::default()
        })
    }

    async fn leave_host(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, LeaveHostRequest>,
    ) -> ServiceResult<LeaveHostResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();
        leave_host(&self.pool, &user, request.org_id, request.host_id)
            .await
            .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(LeaveHostResponse::default())
    }
}

fn no_grantee() -> AppError {
    AppError::Validation {
        errors: vec![codewire_server_core::ValidationIssue {
            path: "/grantee".into(),
            message: "must name a user_id, or set organization to true".into(),
        }],
    }
}

fn platform(platform: Option<ProtoHostPlatform>) -> Option<HostPlatform> {
    match platform? {
        ProtoHostPlatform::HOST_PLATFORM_LINUX_X86_64_KVM => Some(HostPlatform::LinuxX86_64Kvm),
        ProtoHostPlatform::HOST_PLATFORM_DARWIN_ARM64_VZ => Some(HostPlatform::DarwinArm64Vz),
        ProtoHostPlatform::HOST_PLATFORM_UNSPECIFIED => None,
    }
}

fn proto_platform(stored: &str) -> ProtoHostPlatform {
    match HostPlatform::parse(stored) {
        Some(HostPlatform::LinuxX86_64Kvm) => ProtoHostPlatform::HOST_PLATFORM_LINUX_X86_64_KVM,
        Some(HostPlatform::DarwinArm64Vz) => ProtoHostPlatform::HOST_PLATFORM_DARWIN_ARM64_VZ,
        None => ProtoHostPlatform::HOST_PLATFORM_UNSPECIFIED,
    }
}

fn limits(view: &HostLimitsView<'_>) -> HostLimits {
    HostLimits {
        max_vms: view.max_vms,
        max_vcpus: view.max_vcpus,
        max_memory_mib: view.max_memory_mib,
        max_disk_gib: view.max_disk_gib,
    }
}

fn proto_timestamp(value: DateTime<Utc>) -> Timestamp {
    Timestamp::from_unix(value.timestamp(), value.timestamp_subsec_nanos() as i32)
}

fn proto_host(view: HostView) -> Host {
    let HostView {
        host,
        granted_user_ids,
    } = view;
    let state = match host.state() {
        HostState::Online => ProtoHostState::HOST_STATE_ONLINE,
        HostState::Offline => ProtoHostState::HOST_STATE_OFFLINE,
        HostState::Revoked => ProtoHostState::HOST_STATE_REVOKED,
    };
    let limits = host.limits().map(|limits| ProtoHostLimits {
        max_vms: limits.max_vms,
        max_vcpus: limits.max_vcpus,
        max_memory_mib: limits.max_memory_mib,
        max_disk_gib: limits.max_disk_gib,
        ..Default::default()
    });
    let HostRow {
        id,
        org_id,
        owner_user_id,
        name,
        platform,
        capability_version,
        public_key,
        provide,
        organization_grant,
        created_at,
        last_seen_at,
        revoked_at,
        ..
    } = host;
    Host {
        id,
        org_id,
        owner_user_id,
        name,
        platform: proto_platform(&platform).into(),
        capability_version: u32::try_from(capability_version).unwrap_or_default(),
        public_key,
        state: state.into(),
        provide,
        limits: limits.into(),
        organization_grant,
        granted_user_ids,
        created_at: Some(proto_timestamp(created_at)).into(),
        last_seen_at: last_seen_at.map(proto_timestamp).into(),
        revoked_at: revoked_at.map(proto_timestamp).into(),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_wire_platform_maps_to_its_stored_name() {
        for wire in [
            ProtoHostPlatform::HOST_PLATFORM_LINUX_X86_64_KVM,
            ProtoHostPlatform::HOST_PLATFORM_DARWIN_ARM64_VZ,
        ] {
            let stored = platform(Some(wire)).unwrap().as_str();
            assert_eq!(proto_platform(stored), wire);
        }
        assert_eq!(
            platform(Some(ProtoHostPlatform::HOST_PLATFORM_UNSPECIFIED)),
            None
        );
    }
}
