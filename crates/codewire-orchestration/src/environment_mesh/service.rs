//! `EnvironmentMeshService` on orchestration's internal listener. Its only
//! caller is hosted Mesh, authenticated by [`internal_service_layer`].

use std::sync::Arc;

use codewire_proto::codewire::internal::v1::{
    CheckEnvironmentMembersRequest, CheckEnvironmentMembersResponse, EnvironmentMeshMember,
    EnvironmentMeshMemberStatus, EnvironmentMeshService, RedeemEnvironmentEnrollmentRequest,
    RedeemEnvironmentEnrollmentResponse,
};
use codewire_server_core::connect::InternalServiceLayer;
use codewire_server_core::internal_hmac::derive_internal_hmac_secret;
use connectrpc::{ConnectError, RequestContext, ServiceRequest, ServiceResult};
use sqlx::PgPool;

use super::store::{self, MemberRef, MemberStatus};
use super::{
    MAX_CHECKED_MEMBERS, enrollment_code_sha256, valid_network_id, well_formed_enrollment_code,
};

/// The one service allowed to call [`EnvironmentMeshService`].
pub const ENVIRONMENT_MESH_CALLER: &str = "codewire-mesh";

/// The derivation label of this hop's signing key. Mesh signs with the same
/// derivation of the shared internal secret; a credential for any other hop
/// never verifies here.
pub const ENVIRONMENT_MESH_HMAC_LABEL: &str = "codewire/environment-mesh/v1";

/// Every method of the service, each scoped separately.
pub const ENVIRONMENT_MESH_METHODS: [&str; 2] = [
    "codewire.internal.v1.EnvironmentMeshService/RedeemEnvironmentEnrollment",
    "codewire.internal.v1.EnvironmentMeshService/CheckEnvironmentMembers",
];

/// The authentication boundary of the service's internal mount.
pub fn internal_service_layer(internal_secret: &str) -> anyhow::Result<InternalServiceLayer> {
    let key = derive_internal_hmac_secret(internal_secret, ENVIRONMENT_MESH_HMAC_LABEL)
        .map_err(|_| anyhow::anyhow!("the internal secret for environment Mesh is not set"))?;
    Ok(InternalServiceLayer::new(
        key,
        ENVIRONMENT_MESH_CALLER,
        ENVIRONMENT_MESH_METHODS,
    ))
}

/// The generated service. Mount it only on the internal listener, behind
/// [`internal_service_layer`].
pub fn environment_mesh_router(pool: PgPool) -> connectrpc::Router {
    connectrpc::Router::new().add_service(Arc::new(EnvironmentMeshConnectService { pool }))
}

struct EnvironmentMeshConnectService {
    pool: PgPool,
}

fn unavailable(error: sqlx::Error) -> ConnectError {
    tracing::warn!(%error, "environment Mesh store failed");
    ConnectError::unavailable("environment Mesh membership is unavailable")
}

#[allow(refining_impl_trait)]
impl EnvironmentMeshService for EnvironmentMeshConnectService {
    async fn redeem_environment_enrollment(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, RedeemEnvironmentEnrollmentRequest>,
    ) -> ServiceResult<RedeemEnvironmentEnrollmentResponse> {
        let request = request.view();
        if !well_formed_enrollment_code(request.enrollment_code)
            || request.org_id.is_empty()
            || !valid_network_id(request.network_id)
        {
            return Err(ConnectError::permission_denied(
                "environment Mesh enrollment is not admitted",
            ));
        }
        let member = store::redeem_enrollment(
            &self.pool,
            &enrollment_code_sha256(request.enrollment_code),
            request.org_id,
            request.network_id,
        )
        .await
        .map_err(unavailable)?
        .ok_or_else(|| {
            ConnectError::permission_denied("environment Mesh enrollment is not admitted")
        })?;
        connectrpc::Response::ok(RedeemEnvironmentEnrollmentResponse {
            member: Some(EnvironmentMeshMember {
                environment_id: member.environment_id,
                org_id: member.org_id,
                network_id: member.network_id,
                node_name: member.node_name,
                pod_uid: member.pod_uid,
                operation_generation: member.operation_generation,
                attached_by_user_id: member.attached_by_user_id,
                ..Default::default()
            })
            .into(),
            ..Default::default()
        })
    }

    async fn check_environment_members(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, CheckEnvironmentMembersRequest>,
    ) -> ServiceResult<CheckEnvironmentMembersResponse> {
        let request = request.to_owned_message();
        if request.members.len() > MAX_CHECKED_MEMBERS {
            return Err(ConnectError::invalid_argument(
                "at most 256 members may be checked at once",
            ));
        }
        let members = request
            .members
            .into_iter()
            .map(|member| {
                if member.environment_id.is_empty()
                    || member.org_id.is_empty()
                    || !valid_network_id(&member.network_id)
                {
                    return Err(ConnectError::invalid_argument(
                        "a checked member needs its environment, organization and network",
                    ));
                }
                Ok(MemberRef {
                    environment_id: member.environment_id,
                    org_id: member.org_id,
                    network_id: member.network_id,
                    pod_uid: member.pod_uid,
                    operation_generation: member.operation_generation,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let statuses = store::check_members(&self.pool, &members)
            .await
            .map_err(unavailable)?
            .into_iter()
            .map(|status| {
                match status {
                    MemberStatus::Live => EnvironmentMeshMemberStatus::Live,
                    MemberStatus::Stale => EnvironmentMeshMemberStatus::Stale,
                    MemberStatus::Gone => EnvironmentMeshMemberStatus::Gone,
                }
                .into()
            })
            .collect();
        connectrpc::Response::ok(CheckEnvironmentMembersResponse {
            statuses,
            ..Default::default()
        })
    }
}
