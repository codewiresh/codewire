//! Connect-only, authenticated public platform CW runtime operations.
use crate::api::{ApiState, cw_runtime::service};
use crate::connect::workspace_rpc_error;
use codewire_proto::codewire::v1 as proto;
use codewire_server_core::connect::auth_user;
use connectrpc::{InboundStream, RequestContext, ServiceRequest, ServiceResult};
use futures_util::StreamExt as _;
use std::sync::Arc;

pub fn router(state: ApiState) -> connectrpc::Router {
    with_limits(connectrpc::Router::new().add_service(Arc::new(RuntimeService { state })))
}

fn with_limits(mut router: connectrpc::Router) -> connectrpc::Router {
    let prefix = "/codewire.v1.EnvironmentCwRuntimeService/";
    for method in [
        "GetEnvironmentCwRuntime",
        "RollbackEnvironmentCwRuntime",
        "ObserveEnvironmentCwRuntime",
    ] {
        router = router.with_route_limits(
            &format!("{prefix}{method}"),
            connectrpc::Limits::default().with_max_message_size(32 * 1024),
        );
    }
    router.with_route_limits(
        &format!("{prefix}UpdateEnvironmentCwRuntime"),
        connectrpc::Limits::default().with_max_message_size(64 * 1024 + 1024),
    )
}

#[cfg(test)]
#[path = "environment_cw_runtime_tests.rs"]
mod tests;

struct RuntimeService {
    state: ApiState,
}

#[allow(refining_impl_trait)]
impl proto::EnvironmentCwRuntimeService for RuntimeService {
    async fn get_environment_cw_runtime(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, proto::GetEnvironmentCwRuntimeRequest>,
    ) -> ServiceResult<proto::GetEnvironmentCwRuntimeResponse> {
        let user = auth_user(&ctx)?.clone();
        let result = service::info(&self.state, &user, &request.to_owned_message())
            .await
            .map_err(|e| workspace_rpc_error(&e, &ctx))?;
        connectrpc::Response::ok(result)
    }
    async fn update_environment_cw_runtime(
        &self,
        ctx: RequestContext,
        requests: InboundStream<proto::UpdateEnvironmentCwRuntimeRequest>,
    ) -> ServiceResult<proto::UpdateEnvironmentCwRuntimeResponse> {
        let user = auth_user(&ctx)?.clone();
        let requests = requests.map(|value| {
            value.map(|v| v.to_owned_message()).map_err(|_| {
                codewire_server_core::AppError::BadRequest(
                    "cw runtime request metadata is invalid".into(),
                )
            })
        });
        let result = service::update(self.state.clone(), user, requests)
            .await
            .map_err(|e| workspace_rpc_error(&e, &ctx))?;
        connectrpc::Response::ok(result)
    }
    async fn rollback_environment_cw_runtime(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, proto::RollbackEnvironmentCwRuntimeRequest>,
    ) -> ServiceResult<proto::RollbackEnvironmentCwRuntimeResponse> {
        let user = auth_user(&ctx)?.clone();
        let result = service::rollback(self.state.clone(), user, request.to_owned_message())
            .await
            .map_err(|e| workspace_rpc_error(&e, &ctx))?;
        connectrpc::Response::ok(result)
    }
    async fn observe_environment_cw_runtime(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, proto::ObserveEnvironmentCwRuntimeRequest>,
    ) -> ServiceResult<proto::ObserveEnvironmentCwRuntimeResponse> {
        let user = auth_user(&ctx)?.clone();
        let result = service::observe(&self.state, &user, &request.to_owned_message())
            .await
            .map_err(|e| workspace_rpc_error(&e, &ctx))?;
        connectrpc::Response::ok(result)
    }
}
