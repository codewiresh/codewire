//! Generated material-free credential metadata service. No mutation routes.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use codewire_proto::codewire::v1::{
    Credential, CredentialAuthenticationKind, CredentialService, CredentialStatus,
    GetCredentialRequest, GetCredentialResponse, ListCredentialsRequest, ListCredentialsResponse,
    get_credential_request,
};
use codewire_server_core::auth::AuthUser;
use codewire_server_core::connect::{auth_user, rpc_app_error};
use codewire_server_core::{AppError, AppResult};
use connectrpc::{RequestContext, ServiceRequest, ServiceResult};
use sqlx::PgPool;

use crate::credentials::{CredentialSelector, Credentials};

/// Mount only CredentialService with ordinary account authentication. Cookies
/// and scoped OAuth are accepted; organization API keys never confer ownership.
pub fn router(pool: PgPool) -> connectrpc::Router {
    connectrpc::Router::new().add_service(Arc::new(MetadataService {
        credentials: Credentials::new(pool),
    }))
}

struct MetadataService {
    credentials: Credentials,
}

#[allow(refining_impl_trait)]
impl CredentialService for MetadataService {
    async fn list_credentials(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ListCredentialsRequest>,
    ) -> ServiceResult<ListCredentialsResponse> {
        let user = account_user(&ctx)?;
        let request = request.view();
        let (credentials, next_page_token) = bounded(
            &ctx,
            self.credentials
                .list(&user, request.page_size, request.page_token),
        )
        .await?;
        connectrpc::Response::ok(ListCredentialsResponse {
            credentials: credentials.into_iter().map(proto_credential).collect(),
            next_page_token,
            ..Default::default()
        })
    }

    async fn get_credential(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, GetCredentialRequest>,
    ) -> ServiceResult<GetCredentialResponse> {
        let user = account_user(&ctx)?;
        let request = request.to_owned_message();
        let selector = match &request.selector {
            Some(get_credential_request::Selector::CredentialId(id)) => CredentialSelector::Id(id),
            Some(get_credential_request::Selector::Name(name)) => CredentialSelector::Name(name),
            None => {
                return Err(rpc_app_error(
                    &AppError::BadRequest("one credential selector is required".into()),
                    &ctx,
                ));
            }
        };
        let credential = bounded(&ctx, self.credentials.get(&user, selector)).await?;
        connectrpc::Response::ok(GetCredentialResponse {
            credential: Some(proto_credential(credential)).into(),
            ..Default::default()
        })
    }
}

fn account_user(ctx: &RequestContext) -> Result<AuthUser, connectrpc::ConnectError> {
    let user = auth_user(ctx)?.clone();
    user.require_account_credential()
        .map_err(|error| rpc_app_error(&error, ctx))?;
    Ok(user)
}

async fn bounded<T>(
    ctx: &RequestContext,
    operation: impl Future<Output = AppResult<T>>,
) -> Result<T, connectrpc::ConnectError> {
    // Response-admission bound only. These indexed metadata SELECTs acquire no
    // explicit owner/profile row locks and start no publication transaction.
    // Dropping SQLx's future is not a server cancellation or network-drain ACK.
    tokio::time::timeout(Duration::from_secs(5), operation)
        .await
        .map_err(|_| {
            rpc_app_error(
                &AppError::ServiceUnavailable("credential metadata unavailable".into()),
                ctx,
            )
        })?
        .map_err(|error| rpc_app_error(&error, ctx))
}

fn proto_credential(value: codewire_access::CredentialMetadata) -> Credential {
    use codewire_access::{CredentialAuthKind as Kind, CredentialStatus as Status};
    Credential {
        id: value.id.as_str().to_owned(),
        name: value.display_name,
        provider: value.provider.as_str().to_owned(),
        authentication_kind: match value.authentication_kind {
            Kind::OAuth => CredentialAuthenticationKind::Oauth,
            Kind::ApiKey => CredentialAuthenticationKind::ApiKey,
            Kind::AccessToken => CredentialAuthenticationKind::AccessToken,
            Kind::GitHubApp => CredentialAuthenticationKind::GithubApp,
            Kind::SshKey => CredentialAuthenticationKind::SshKey,
        }
        .into(),
        account_hint: value.account_hint,
        ssh_public_key: value
            .ssh_public_key
            .map(|key| codewire_proto::codewire::v1::SshPublicKey {
                openssh: key.openssh,
                fingerprint: key.fingerprint,
                ..Default::default()
            })
            .into(),
        status: match value.status {
            Status::Active => CredentialStatus::Active,
            Status::Revoked => CredentialStatus::Revoked,
            Status::Expired => CredentialStatus::Expired,
            Status::RefreshFailed => CredentialStatus::RefreshFailed,
        }
        .into(),
        expires_at_unix: value.expires_at_unix,
        revocation_generation: value.revocation_generation,
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use codewire_access::{
        CredentialAuthKind as Kind, CredentialId, CredentialMetadata, CredentialStatus as Status,
        Owner, OwnerId, Placement, ProviderId,
    };

    #[test]
    fn ssh_metadata_mapping_returns_only_public_registration_data() {
        let public = codewire_access::SshPublicKeyMetadata {
            openssh: format!("ssh-ed25519 {}", "A".repeat(68)),
            fingerprint: format!("SHA256:{}", "A".repeat(43)),
        };
        let metadata = CredentialMetadata {
            id: CredentialId::parse("synthetic-ssh").unwrap(),
            owner: Owner::User(OwnerId::parse("synthetic-owner").unwrap()),
            placement: Placement::Platform,
            provider: ProviderId::parse("ssh").unwrap(),
            authentication_kind: Kind::SshKey,
            display_name: "work-ssh".into(),
            account_hint: None,
            ssh_public_key: Some(public.clone()),
            status: Status::Active,
            expires_at_unix: None,
            revocation_generation: 1,
        };
        metadata.validate().unwrap();
        let mapped = proto_credential(metadata);
        assert_eq!(
            mapped.authentication_kind,
            CredentialAuthenticationKind::SshKey
        );
        let key = mapped.ssh_public_key.as_option().unwrap();
        assert_eq!(key.openssh, public.openssh);
        assert_eq!(key.fingerprint, public.fingerprint);
        assert!(mapped.account_hint.is_none());
    }

    #[test]
    fn metadata_mapping_preserves_every_kind_status_optional_field_and_u64() {
        for (kind, expected_kind) in [
            (Kind::OAuth, CredentialAuthenticationKind::Oauth),
            (Kind::ApiKey, CredentialAuthenticationKind::ApiKey),
            (Kind::AccessToken, CredentialAuthenticationKind::AccessToken),
            (Kind::GitHubApp, CredentialAuthenticationKind::GithubApp),
        ] {
            for (status, expected_status) in [
                (Status::Active, CredentialStatus::Active),
                (Status::Revoked, CredentialStatus::Revoked),
                (Status::Expired, CredentialStatus::Expired),
                (Status::RefreshFailed, CredentialStatus::RefreshFailed),
            ] {
                for present in [false, true] {
                    let mapped = proto_credential(CredentialMetadata {
                        id: CredentialId::parse("synthetic-id").unwrap(),
                        owner: Owner::User(OwnerId::parse("synthetic-owner").unwrap()),
                        placement: Placement::Platform,
                        provider: ProviderId::parse("openai").unwrap(),
                        authentication_kind: kind,
                        display_name: "Synthetic metadata".into(),
                        account_hint: present.then(|| "Synthetic account".into()),
                        ssh_public_key: None,
                        status,
                        expires_at_unix: present.then_some(u64::MAX),
                        revocation_generation: u64::MAX,
                    });
                    assert_eq!(mapped.authentication_kind, expected_kind);
                    assert_eq!(mapped.status, expected_status);
                    assert_eq!(
                        mapped.account_hint.as_deref(),
                        present.then_some("Synthetic account")
                    );
                    assert_eq!(mapped.expires_at_unix, present.then_some(u64::MAX));
                    assert_eq!(mapped.revocation_generation, u64::MAX);
                }
            }
        }
    }
}
