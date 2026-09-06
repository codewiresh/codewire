use std::sync::Arc;

use codewire_access::{CredentialAuthKind, CredentialMetadata, CredentialStatus};
use codewire_proto::codewire::v1::{self as proto, CredentialMutationService};
use codewire_server_core::auth::OAuthBearerAuthority;
use codewire_server_core::connect::{oauth_bearer_authority, wire_error};
use codewire_server_core::connect_error::{ConnectCode, ConnectError};
use connectrpc::{RequestContext, ServiceRequest, ServiceResult, ServiceStream};

use super::{CredentialMutationOwner, Error};

pub(super) fn router(owner: Arc<CredentialMutationOwner>) -> connectrpc::Router {
    connectrpc::Router::new().add_service(Arc::new(Service { owner }))
}

struct Service {
    owner: Arc<CredentialMutationOwner>,
}

fn authority(ctx: &RequestContext) -> Result<OAuthBearerAuthority, connectrpc::ConnectError> {
    Ok(oauth_bearer_authority(ctx)?.clone())
}

#[allow(refining_impl_trait)]
impl CredentialMutationService for Service {
    async fn enroll_codex(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, proto::EnrollCodexRequest>,
    ) -> ServiceResult<ServiceStream<proto::EnrollCodexResponse>> {
        let events = self
            .owner
            .enroll(authority(&ctx)?, request.view().name.to_owned())
            .map_err(error)?;
        let stream = futures::stream::unfold(events, |mut events| async {
            let message = events.receiver.recv().await?;
            Some((message.map_err(error), events))
        });
        connectrpc::Response::stream_ok(stream)
    }

    async fn revoke_credential(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, proto::RevokeCredentialRequest>,
    ) -> ServiceResult<proto::RevokeCredentialResponse> {
        let request = request.to_owned_message();
        let metadata = self
            .owner
            .lifecycle(
                authority(&ctx)?,
                request.credential_id,
                request.expected_revocation_generation,
                false,
            )
            .await
            .map_err(error)?
            .ok_or_else(|| error(Error::PublicationUnknown))?;
        connectrpc::Response::ok(proto::RevokeCredentialResponse {
            credential: Some(credential(metadata)).into(),
            ..Default::default()
        })
    }

    async fn delete_credential(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, proto::DeleteCredentialRequest>,
    ) -> ServiceResult<proto::DeleteCredentialResponse> {
        let request = request.to_owned_message();
        self.owner
            .lifecycle(
                authority(&ctx)?,
                request.credential_id,
                request.expected_revocation_generation,
                true,
            )
            .await
            .map_err(error)?;
        connectrpc::Response::ok(proto::DeleteCredentialResponse::default())
    }
}

pub(super) fn credential(metadata: CredentialMetadata) -> proto::Credential {
    proto::Credential {
        id: metadata.id.as_str().to_owned(),
        name: metadata.display_name,
        provider: metadata.provider.as_str().to_owned(),
        authentication_kind: match metadata.authentication_kind {
            CredentialAuthKind::OAuth => proto::CredentialAuthenticationKind::Oauth,
            CredentialAuthKind::ApiKey => proto::CredentialAuthenticationKind::ApiKey,
            CredentialAuthKind::AccessToken => proto::CredentialAuthenticationKind::AccessToken,
            CredentialAuthKind::GitHubApp => proto::CredentialAuthenticationKind::GithubApp,
        }
        .into(),
        account_hint: metadata.account_hint,
        status: match metadata.status {
            CredentialStatus::Active => proto::CredentialStatus::Active,
            CredentialStatus::Expired => proto::CredentialStatus::Expired,
            CredentialStatus::RefreshFailed => proto::CredentialStatus::RefreshFailed,
            CredentialStatus::Revoked => proto::CredentialStatus::Revoked,
        }
        .into(),
        expires_at_unix: metadata.expires_at_unix,
        revocation_generation: metadata.revocation_generation,
        ..Default::default()
    }
}

fn error(error: Error) -> connectrpc::ConnectError {
    let (code, message) = match error {
        Error::InvalidInput => (
            ConnectCode::InvalidArgument,
            "invalid credential name, identity or revision",
        ),
        Error::Denied => (
            ConnectCode::Unauthenticated,
            "original OAuth authority is no longer valid",
        ),
        Error::Unavailable => (ConnectCode::Unavailable, "credential authority unavailable"),
        Error::Cancelled => (
            ConnectCode::Canceled,
            "credential operation cancelled; reconcile by name before retrying",
        ),
        Error::Expired => (
            ConnectCode::DeadlineExceeded,
            "original credential operation deadline elapsed; reconcile by name before retrying",
        ),
        Error::AlreadyExists => (ConnectCode::AlreadyExists, "credential name already exists"),
        Error::NotFound => (
            ConnectCode::NotFound,
            "credential or active owner not found",
        ),
        Error::StaleRevision => (
            ConnectCode::FailedPrecondition,
            "credential revision changed; inspect current metadata",
        ),
        Error::InUse => (
            ConnectCode::FailedPrecondition,
            "credential is referenced by a profile or binding",
        ),
        Error::MustBeRevoked => (
            ConnectCode::FailedPrecondition,
            "credential must be revoked before deletion",
        ),
        Error::EnrollmentFailed => (
            ConnectCode::FailedPrecondition,
            "isolated Codex enrollment did not complete",
        ),
        Error::CleanupFailed => (
            ConnectCode::Unavailable,
            "enrollment cleanup failed; reconcile stored metadata before retrying; no stored credential was revoked",
        ),
        Error::PublicationUnknown => (
            ConnectCode::Unknown,
            "credential mutation may have completed; inspect current metadata before retrying",
        ),
    };
    wire_error(&ConnectError {
        code,
        message: message.to_owned(),
        details: Vec::new(),
    })
}
