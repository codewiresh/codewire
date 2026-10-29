//! Connect-RPC adapter for the first-party environment-creation setup UX.
//!
//! This module maps shared creation options and terminal-ticket service logic
//! to Connect. The terminal WebSocket remains raw HTTP.

use std::sync::Arc;

use codewire_proto::codewire::console::v1::{
    EnvironmentSetupService, GetEnvironmentCreateOptionsRequest,
    GetEnvironmentCreateOptionsResponse, IssueTerminalTicketRequest, IssueTerminalTicketResponse,
};
use codewire_server_core::AppResult;
use codewire_server_core::connect::{auth_user, rpc_app_error};
use connectrpc::{RequestContext, ServiceRequest, ServiceResult};

use crate::api::ApiState;
use crate::api::prepare::get_environment_create_options_core;
use crate::api::terminal::issue_terminal_ticket_core;
use crate::connect::presets::proto_preset;

/// Registers the EnvironmentSetupService RPCs on their generated routes.
pub fn router(state: ApiState) -> connectrpc::Router {
    connectrpc::Router::new().add_service(Arc::new(EnvironmentSetupConnectService { state }))
}

struct EnvironmentSetupConnectService {
    state: ApiState,
}

#[allow(refining_impl_trait)]
impl EnvironmentSetupService for EnvironmentSetupConnectService {
    async fn get_environment_create_options(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, GetEnvironmentCreateOptionsRequest>,
    ) -> ServiceResult<GetEnvironmentCreateOptionsResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();
        let options = get_environment_create_options_core(&self.state, &user, request.org_id)
            .await
            .map_err(|error| rpc_app_error(&error, &ctx))?;
        let presets = options
            .presets
            .into_iter()
            .map(proto_preset)
            .collect::<AppResult<Vec<_>>>()
            .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(GetEnvironmentCreateOptionsResponse {
            presets,
            preview_base_domain: options.preview_base_domain,
            confidential_available: options.confidential_available,
            ..Default::default()
        })
    }

    async fn issue_terminal_ticket(
        &self,
        ctx: RequestContext,
        _request: ServiceRequest<'_, IssueTerminalTicketRequest>,
    ) -> ServiceResult<IssueTerminalTicketResponse> {
        let user = auth_user(&ctx)?.clone();
        let ticket = issue_terminal_ticket_core(&self.state, &user)
            .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(IssueTerminalTicketResponse {
            ticket,
            ..Default::default()
        })
    }
}
