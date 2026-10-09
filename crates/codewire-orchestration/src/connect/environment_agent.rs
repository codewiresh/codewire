//! Authenticated Connect surface for captured platform managed conversations.
use crate::api::{ApiState, platform_agents as service};
use crate::connect::workspace_rpc_error;
use codewire_proto::codewire::v1 as proto;
use codewire_server_core::connect::auth_user;
use connectrpc::{RequestContext, ServiceRequest, ServiceResult};
use std::sync::Arc;

pub fn router(state: ApiState) -> connectrpc::Router {
    let mut router = connectrpc::Router::new().add_service(Arc::new(AgentService { state }));
    for method in [
        "GetEnvironmentAgentInfo",
        "MutateEnvironmentAgent",
        "ObserveEnvironmentAgent",
        "ListEnvironmentAgents",
        "ReadEnvironmentAgent",
    ] {
        let bound = match method {
            "MutateEnvironmentAgent" => 256 * 1024,
            "ReadEnvironmentAgent" => 5 * 1024 * 1024 + 32 * 1024,
            _ => 32 * 1024,
        };
        router = router.with_route_limits(
            &format!("/codewire.v1.EnvironmentAgentService/{method}"),
            connectrpc::Limits::default().with_max_message_size(bound),
        );
    }
    router
}
struct AgentService {
    state: ApiState,
}
#[allow(refining_impl_trait)]
impl proto::EnvironmentAgentService for AgentService {
    async fn get_environment_agent_info(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, proto::GetEnvironmentAgentInfoRequest>,
    ) -> ServiceResult<proto::GetEnvironmentAgentInfoResponse> {
        let user = auth_user(&ctx)?;
        let value = service::info(&self.state, user, &request.to_owned_message())
            .await
            .map_err(|e| workspace_rpc_error(&e, &ctx))?;
        connectrpc::Response::ok(value)
    }
    async fn mutate_environment_agent(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, proto::MutateEnvironmentAgentRequest>,
    ) -> ServiceResult<proto::MutateEnvironmentAgentResponse> {
        let user = auth_user(&ctx)?.clone();
        let value = service::mutate(self.state.clone(), user, request.to_owned_message())
            .await
            .map_err(|e| workspace_rpc_error(&e, &ctx))?;
        connectrpc::Response::ok(value)
    }
    async fn observe_environment_agent(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, proto::ObserveEnvironmentAgentRequest>,
    ) -> ServiceResult<proto::ObserveEnvironmentAgentResponse> {
        let user = auth_user(&ctx)?;
        let value = service::observe(&self.state, user, &request.to_owned_message())
            .await
            .map_err(|e| workspace_rpc_error(&e, &ctx))?;
        connectrpc::Response::ok(value)
    }
    async fn list_environment_agents(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, proto::ListEnvironmentAgentsRequest>,
    ) -> ServiceResult<proto::ListEnvironmentAgentsResponse> {
        let user = auth_user(&ctx)?;
        let value = service::list(&self.state, user, &request.to_owned_message())
            .await
            .map_err(|e| workspace_rpc_error(&e, &ctx))?;
        connectrpc::Response::ok(value)
    }
    async fn read_environment_agent(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, proto::ReadEnvironmentAgentRequest>,
    ) -> ServiceResult<proto::ReadEnvironmentAgentResponse> {
        let user = auth_user(&ctx)?;
        let value = service::read(&self.state, user, &request.to_owned_message())
            .await
            .map_err(|e| workspace_rpc_error(&e, &ctx))?;
        connectrpc::Response::ok(value)
    }
}
