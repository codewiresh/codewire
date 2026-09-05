//! Connect-RPC adapter for account-global user settings.
//!
//! This module maps `crate::api::account::service` to protobuf and renders
//! Connect errors.

use std::sync::Arc;

use codewire_proto::codewire::console::v1::{
    AccountService, GetGitIdentityRequest, GetGitIdentityResponse, GitIdentity,
    UpdateGitIdentityRequest, UpdateGitIdentityResponse,
};
use codewire_server_core::connect::{auth_user, rpc_app_error};
use connectrpc::{RequestContext, ServiceRequest, ServiceResult};

use crate::api::ApiState;
use crate::api::account::service::{self, GitIdentityRecord, UpdateGitIdentityParams};

/// Registers the two AccountService RPCs on their generated Connect routes.
pub fn router(state: ApiState) -> connectrpc::Router {
    connectrpc::Router::new().add_service(Arc::new(AccountConnectService { state }))
}

struct AccountConnectService {
    state: ApiState,
}

#[allow(refining_impl_trait)]
impl AccountService for AccountConnectService {
    async fn get_git_identity(
        &self,
        ctx: RequestContext,
        _request: ServiceRequest<'_, GetGitIdentityRequest>,
    ) -> ServiceResult<GetGitIdentityResponse> {
        let user = auth_user(&ctx)?.clone();
        let identity = service::get_git_identity(&self.state, &user)
            .await
            .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(GetGitIdentityResponse {
            git_identity: Some(proto_git_identity(identity)).into(),
            ..Default::default()
        })
    }

    async fn update_git_identity(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, UpdateGitIdentityRequest>,
    ) -> ServiceResult<UpdateGitIdentityResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();
        let identity = service::update_git_identity(
            &self.state,
            &user,
            update_git_identity_params(request.git_name, request.git_email),
        )
        .await
        .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(UpdateGitIdentityResponse {
            git_identity: Some(proto_git_identity(identity)).into(),
            ..Default::default()
        })
    }
}

fn update_git_identity_params(
    git_name: Option<&str>,
    git_email: Option<&str>,
) -> UpdateGitIdentityParams {
    UpdateGitIdentityParams {
        git_name: git_name.map(str::to_owned),
        git_email: git_email.map(str::to_owned),
    }
}

fn proto_git_identity(record: GitIdentityRecord) -> GitIdentity {
    GitIdentity {
        git_name: record.git_name,
        git_email: record.git_email,
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use codewire_server_core::connect_error::ConnectErrorDetail;
    use codewire_server_core::{ConnectCode, ConnectError};

    use super::*;

    #[test]
    fn update_identity_presence_is_preserved_for_clear_semantics() {
        let clear_identity = update_git_identity_params(None, None);
        assert_eq!(clear_identity.git_name, None);
        assert_eq!(clear_identity.git_email, None);
    }

    #[test]
    fn account_scope_violation_renders_permission_denied_error_info() {
        let user = codewire_server_core::auth::AuthUser {
            user_id: "user_1".into(),
            org_id: Some("org_1".into()),
            is_admin: false,
            via_api_key: true,
        };
        let error = user
            .require_account_credential()
            .expect_err("organization API keys cannot call AccountService");
        let rendered = ConnectError::from_app_error(&error, Some("req_account"));
        assert_eq!(rendered.code, ConnectCode::PermissionDenied);
        let ConnectErrorDetail::ErrorInfo(info) = &rendered.details[0] else {
            panic!("expected ErrorInfo detail");
        };
        assert_eq!(info.reason, "API_KEY_SCOPE_VIOLATION");
        assert_eq!(
            info.metadata.get("request_id").map(String::as_str),
            Some("req_account")
        );
    }
}
