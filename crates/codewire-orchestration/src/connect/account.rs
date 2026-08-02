//! Connect-RPC adapter for account-global user settings.
//!
//! This module maps [`crate::api::account::service`] to protobuf and renders
//! Connect errors.

use std::sync::Arc;

use buffa_types::Timestamp;
use codewire_proto::codewire::console::v1::{
    AccountService, CreateGitCredentialRequest, CreateGitCredentialResponse, CreateLoginKeyRequest,
    CreateLoginKeyResponse, DeleteGitCredentialRequest, DeleteGitCredentialResponse,
    DeleteLoginKeyRequest, DeleteLoginKeyResponse, EnsureSshKeyRequest, EnsureSshKeyResponse,
    GetGitIdentityRequest, GetGitIdentityResponse, GetSshKeyRequest, GetSshKeyResponse,
    GitCredential, GitIdentity, ListGitCredentialsRequest, ListGitCredentialsResponse,
    ListLoginKeysRequest, ListLoginKeysResponse, LoginKey, RegenerateSshKeyRequest,
    RegenerateSshKeyResponse, SshKey, UpdateGitCredentialRequest, UpdateGitCredentialResponse,
    UpdateGitIdentityRequest, UpdateGitIdentityResponse,
};
use codewire_server_core::connect::{auth_user, rpc_app_error};
use connectrpc::{RequestContext, ServiceRequest, ServiceResult};

use crate::api::ApiState;
use crate::api::account::service::{
    self, CreateGitCredentialParams, CreateLoginKeyParams, GitCredentialRecord, GitIdentityRecord,
    LoginKeyRecord, SshKeyRecord, UpdateGitCredentialParams, UpdateGitIdentityParams,
};

/// Registers the 12 AccountService RPCs on their generated Connect routes.
pub fn router(state: ApiState) -> connectrpc::Router {
    connectrpc::Router::new().add_service(Arc::new(AccountConnectService { state }))
}

struct AccountConnectService {
    state: ApiState,
}

#[allow(refining_impl_trait)]
impl AccountService for AccountConnectService {
    async fn list_login_keys(
        &self,
        ctx: RequestContext,
        _request: ServiceRequest<'_, ListLoginKeysRequest>,
    ) -> ServiceResult<ListLoginKeysResponse> {
        let user = auth_user(&ctx)?.clone();
        let login_keys = service::list_login_keys(&self.state, &user)
            .await
            .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(ListLoginKeysResponse {
            login_keys: login_keys.into_iter().map(proto_login_key).collect(),
            ..Default::default()
        })
    }

    async fn create_login_key(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, CreateLoginKeyRequest>,
    ) -> ServiceResult<CreateLoginKeyResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();
        let login_key = service::create_login_key(
            &self.state,
            &user,
            CreateLoginKeyParams {
                name: request.name.to_owned(),
                public_key: request.public_key.to_owned(),
            },
        )
        .await
        .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(CreateLoginKeyResponse {
            login_key: Some(proto_login_key(login_key)).into(),
            ..Default::default()
        })
    }

    async fn delete_login_key(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, DeleteLoginKeyRequest>,
    ) -> ServiceResult<DeleteLoginKeyResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();
        service::delete_login_key(&self.state, &user, request.id)
            .await
            .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(DeleteLoginKeyResponse::default())
    }

    async fn ensure_ssh_key(
        &self,
        ctx: RequestContext,
        _request: ServiceRequest<'_, EnsureSshKeyRequest>,
    ) -> ServiceResult<EnsureSshKeyResponse> {
        let user = auth_user(&ctx)?.clone();
        let ssh_key = service::ensure_ssh_key(&self.state, &user)
            .await
            .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(EnsureSshKeyResponse {
            ssh_key: Some(proto_ssh_key(ssh_key)).into(),
            ..Default::default()
        })
    }

    async fn get_ssh_key(
        &self,
        ctx: RequestContext,
        _request: ServiceRequest<'_, GetSshKeyRequest>,
    ) -> ServiceResult<GetSshKeyResponse> {
        let user = auth_user(&ctx)?.clone();
        let ssh_key = service::get_ssh_key(&self.state, &user)
            .await
            .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(GetSshKeyResponse {
            ssh_key: Some(proto_ssh_key(ssh_key)).into(),
            ..Default::default()
        })
    }

    async fn regenerate_ssh_key(
        &self,
        ctx: RequestContext,
        _request: ServiceRequest<'_, RegenerateSshKeyRequest>,
    ) -> ServiceResult<RegenerateSshKeyResponse> {
        let user = auth_user(&ctx)?.clone();
        let ssh_key = service::regenerate_ssh_key(&self.state, &user)
            .await
            .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(RegenerateSshKeyResponse {
            ssh_key: Some(proto_ssh_key(ssh_key)).into(),
            ..Default::default()
        })
    }

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

    async fn list_git_credentials(
        &self,
        ctx: RequestContext,
        _request: ServiceRequest<'_, ListGitCredentialsRequest>,
    ) -> ServiceResult<ListGitCredentialsResponse> {
        let user = auth_user(&ctx)?.clone();
        let git_credentials = service::list_git_credentials(&self.state, &user)
            .await
            .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(ListGitCredentialsResponse {
            git_credentials: git_credentials
                .into_iter()
                .map(proto_git_credential)
                .collect(),
            ..Default::default()
        })
    }

    async fn create_git_credential(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, CreateGitCredentialRequest>,
    ) -> ServiceResult<CreateGitCredentialResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();
        let credential = service::create_git_credential(
            &self.state,
            &user,
            CreateGitCredentialParams {
                name: request.name.to_owned(),
                host: request.host.to_owned(),
                auth_type: request.auth_type.to_owned(),
                username: request.username.to_owned(),
                password: request.password.to_owned(),
            },
        )
        .await
        .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(CreateGitCredentialResponse {
            git_credential: Some(proto_git_credential(credential)).into(),
            ..Default::default()
        })
    }

    async fn update_git_credential(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, UpdateGitCredentialRequest>,
    ) -> ServiceResult<UpdateGitCredentialResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();
        let credential = service::update_git_credential(
            &self.state,
            &user,
            request.credential_id,
            update_git_credential_params(request.name, request.username, request.password),
        )
        .await
        .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(UpdateGitCredentialResponse {
            git_credential: Some(proto_git_credential(credential)).into(),
            ..Default::default()
        })
    }

    async fn delete_git_credential(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, DeleteGitCredentialRequest>,
    ) -> ServiceResult<DeleteGitCredentialResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();
        service::delete_git_credential(&self.state, &user, request.credential_id)
            .await
            .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(DeleteGitCredentialResponse::default())
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

fn update_git_credential_params(
    name: Option<&str>,
    username: Option<&str>,
    password: Option<&str>,
) -> UpdateGitCredentialParams {
    UpdateGitCredentialParams {
        name: name.map(str::to_owned),
        username: username.map(str::to_owned),
        password: password.map(str::to_owned),
    }
}

fn utc_timestamp(value: chrono::DateTime<chrono::Utc>) -> Timestamp {
    Timestamp::from_unix(value.timestamp(), value.timestamp_subsec_nanos() as i32)
}

fn naive_timestamp(value: chrono::NaiveDateTime) -> Timestamp {
    utc_timestamp(value.and_utc())
}

fn proto_login_key(record: LoginKeyRecord) -> LoginKey {
    LoginKey {
        id: record.id,
        name: record.name,
        public_key: record.public_key,
        fingerprint: record.fingerprint,
        created_at: Some(utc_timestamp(record.created_at)).into(),
        ..Default::default()
    }
}

fn proto_ssh_key(record: SshKeyRecord) -> SshKey {
    SshKey {
        public_key: record.public_key,
        fingerprint: record.fingerprint,
        created_at: Some(naive_timestamp(record.created_at)).into(),
        regenerated_at: record.regenerated_at.map(naive_timestamp).into(),
        ..Default::default()
    }
}

fn proto_git_identity(record: GitIdentityRecord) -> GitIdentity {
    GitIdentity {
        git_name: record.git_name,
        git_email: record.git_email,
        ..Default::default()
    }
}

fn proto_git_credential(record: GitCredentialRecord) -> GitCredential {
    GitCredential {
        id: record.id,
        user_id: record.user_id,
        name: record.name,
        host: record.host,
        auth_type: record.auth_type,
        username: record.username,
        created_at: Some(utc_timestamp(record.created_at)).into(),
        updated_at: Some(utc_timestamp(record.updated_at)).into(),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use chrono::{NaiveDate, TimeZone, Timelike, Utc};
    use codewire_server_core::connect_error::ConnectErrorDetail;
    use codewire_server_core::{AppError, ConnectCode, ConnectError};

    use super::*;

    #[test]
    fn account_error_classes_use_canonical_connect_codes() {
        for (error, expected) in [
            (
                AppError::Conflict("key with this fingerprint already exists".into()),
                ConnectCode::AlreadyExists,
            ),
            (
                AppError::BadRequest("auth_type must be 'basic'".into()),
                ConnectCode::InvalidArgument,
            ),
            (
                AppError::NotFound("ssh key not found".into()),
                ConnectCode::NotFound,
            ),
        ] {
            assert_eq!(ConnectError::from_app_error(&error, None).code, expected);
        }
    }

    #[test]
    fn update_presence_is_preserved_for_clear_and_partial_semantics() {
        let clear_identity = update_git_identity_params(None, None);
        assert_eq!(clear_identity.git_name, None);
        assert_eq!(clear_identity.git_email, None);

        let partial_credential = update_git_credential_params(Some("forge"), None, Some(""));
        assert_eq!(partial_credential.name.as_deref(), Some("forge"));
        assert_eq!(partial_credential.username, None);
        assert_eq!(partial_credential.password.as_deref(), Some(""));
    }

    #[test]
    fn timestamp_and_optional_fields_preserve_database_precision_and_presence() {
        let created_at = Utc
            .with_ymd_and_hms(2026, 7, 17, 12, 34, 56)
            .unwrap()
            .with_nanosecond(123_456_000)
            .unwrap();
        let credential = proto_git_credential(GitCredentialRecord {
            id: "credential_1".into(),
            user_id: "user_1".into(),
            name: "forge".into(),
            host: "git.example.com".into(),
            auth_type: "basic".into(),
            username: None,
            created_at,
            updated_at: created_at,
        });
        assert_eq!(credential.username, None);
        assert_eq!(
            credential.created_at.as_option().unwrap().nanos,
            123_456_000
        );

        let created_at = NaiveDate::from_ymd_opt(2026, 7, 17)
            .unwrap()
            .and_hms_micro_opt(12, 34, 56, 654_321)
            .unwrap();
        let ssh_key = proto_ssh_key(SshKeyRecord {
            public_key: "ssh-ed25519 AAAA\n".into(),
            fingerprint: "SHA256:test".into(),
            created_at,
            regenerated_at: None,
        });
        assert!(ssh_key.regenerated_at.is_unset());
        assert_eq!(ssh_key.created_at.as_option().unwrap().nanos, 654_321_000);
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
