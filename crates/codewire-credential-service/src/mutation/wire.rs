use std::sync::Arc;

use codewire_access::{CredentialAuthKind, CredentialMetadata, CredentialStatus};
use codewire_protected_store::ProtectedValue;
use codewire_proto::codewire::v1::{self as proto, CredentialMutationService};
use codewire_server_core::auth::CredentialMutationAuthority;
use codewire_server_core::connect::{credential_mutation_authority, wire_error};
use codewire_server_core::connect_error::{
    ConnectCode, ConnectError, ConnectErrorDetail, ERROR_INFO_DOMAIN, ErrorInfo,
};
use connectrpc::{RequestContext, ServiceRequest, ServiceResult, ServiceStream};

use super::{CredentialMutationOwner, Error};

pub(super) fn router(owner: Arc<CredentialMutationOwner>) -> connectrpc::Router {
    connectrpc::Router::new().add_service(Arc::new(Service { owner }))
}

struct Service {
    owner: Arc<CredentialMutationOwner>,
}

fn authority(
    ctx: &RequestContext,
) -> Result<CredentialMutationAuthority, connectrpc::ConnectError> {
    Ok(credential_mutation_authority(ctx)?.clone())
}

#[allow(refining_impl_trait)]
impl CredentialMutationService for Service {
    async fn rename_credential(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, proto::RenameCredentialRequest>,
    ) -> ServiceResult<proto::RenameCredentialResponse> {
        let authority = authority(&ctx)?;
        let request = request.to_owned_message();
        let metadata = self
            .owner
            .update(
                authority,
                request.credential_id,
                request.expected_revocation_generation,
                super::keys::Update::Rename {
                    expected_name: request.expected_name,
                    name: request.name,
                },
            )
            .await
            .map_err(error)?;
        connectrpc::Response::ok(proto::RenameCredentialResponse {
            credential: Some(credential(metadata)).into(),
            ..Default::default()
        })
    }

    async fn rotate_api_key_credential(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, proto::RotateApiKeyCredentialRequest>,
    ) -> ServiceResult<proto::RotateApiKeyCredentialResponse> {
        let authority = authority(&ctx)?;
        let mut request = request.to_owned_message();
        let bytes = zeroize::Zeroizing::new(std::mem::take(&mut request.value));
        let material =
            ProtectedValue::from_slice(&bytes).map_err(|_| error(Error::InvalidInput))?;
        drop(bytes);
        let metadata = self
            .owner
            .update(
                authority,
                request.credential_id,
                request.expected_revocation_generation,
                super::keys::Update::Rotate {
                    material,
                    expires_at_unix: request.expires_at_unix,
                },
            )
            .await
            .map_err(error)?;
        connectrpc::Response::ok(proto::RotateApiKeyCredentialResponse {
            credential: Some(credential(metadata)).into(),
            ..Default::default()
        })
    }

    async fn enroll_github(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, proto::EnrollGithubRequest>,
    ) -> ServiceResult<ServiceStream<proto::EnrollGithubResponse>> {
        let request = request.to_owned_message();
        let events = self
            .owner
            .enroll_github(
                authority(&ctx)?,
                request.name,
                request.credential_id,
                request.expected_revocation_generation,
            )
            .map_err(error)?;
        let stream = futures::stream::unfold(events, |mut events| async {
            let message = events.receiver.recv().await?;
            Some((message.map_err(error), events))
        });
        connectrpc::Response::stream_ok(stream)
    }

    async fn complete_github_app_authorization(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, proto::CompleteGithubAppAuthorizationRequest>,
    ) -> ServiceResult<proto::CompleteGithubAppAuthorizationResponse> {
        let authority = authority(&ctx)?;
        let mut request = request.to_owned_message();
        let code = zeroize::Zeroizing::new(std::mem::take(&mut request.code));
        let metadata = self
            .owner
            .complete_github_app_authorization(
                authority,
                code,
                request.credential_id,
                request.expected_revocation_generation,
            )
            .await
            .map_err(error)?;
        connectrpc::Response::ok(proto::CompleteGithubAppAuthorizationResponse {
            credential: Some(credential(metadata)).into(),
            ..Default::default()
        })
    }

    async fn generate_ssh_credential(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, proto::GenerateSshCredentialRequest>,
    ) -> ServiceResult<proto::GenerateSshCredentialResponse> {
        let authority = authority(&ctx)?;
        let request = request.to_owned_message();
        let metadata = self
            .owner
            .add_ssh(
                authority,
                request.name,
                request.expires_at_unix,
                super::ssh::Input::Generate,
            )
            .await
            .map_err(error)?;
        connectrpc::Response::ok(proto::GenerateSshCredentialResponse {
            credential: Some(credential(metadata)).into(),
            ..Default::default()
        })
    }

    async fn add_ssh_credential(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, proto::AddSshCredentialRequest>,
    ) -> ServiceResult<proto::AddSshCredentialResponse> {
        let authority = authority(&ctx)?;
        let mut request = request.to_owned_message();
        let input = super::ssh::Input::Import {
            private_key: zeroize::Zeroizing::new(std::mem::take(&mut request.private_key)),
            passphrase: request.passphrase.take().map(zeroize::Zeroizing::new),
        };
        let metadata = self
            .owner
            .add_ssh(authority, request.name, request.expires_at_unix, input)
            .await
            .map_err(error)?;
        connectrpc::Response::ok(proto::AddSshCredentialResponse {
            credential: Some(credential(metadata)).into(),
            ..Default::default()
        })
    }

    async fn enroll_codex(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, proto::EnrollCodexRequest>,
    ) -> ServiceResult<ServiceStream<proto::EnrollCodexResponse>> {
        let request = request.to_owned_message();
        let events = self
            .owner
            .enroll(
                authority(&ctx)?,
                request.name,
                request.credential_id,
                request.expected_revocation_generation,
            )
            .map_err(error)?;
        let stream = futures::stream::unfold(events, |mut events| async {
            let message = events.receiver.recv().await?;
            Some((message.map_err(error), events))
        });
        connectrpc::Response::stream_ok(stream)
    }

    async fn add_api_key_credential(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, proto::AddApiKeyCredentialRequest>,
    ) -> ServiceResult<proto::AddApiKeyCredentialResponse> {
        let authority = authority(&ctx)?;
        let request = request.to_owned_message();
        // This typed material-bearing DTO is write-only at the isolated
        // authority. Never Debug/serialize it into an error or log.
        let material =
            ProtectedValue::new(request.value).map_err(|_| error(Error::InvalidInput))?;
        let metadata = self
            .owner
            .add_api_key(
                authority,
                request.provider,
                request.name,
                material,
                request.expires_at_unix,
            )
            .await
            .map_err(error)?;
        connectrpc::Response::ok(proto::AddApiKeyCredentialResponse {
            credential: Some(credential(metadata)).into(),
            ..Default::default()
        })
    }

    async fn add_claude_subscription_token_credential(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, proto::AddClaudeSubscriptionTokenCredentialRequest>,
    ) -> ServiceResult<proto::AddClaudeSubscriptionTokenCredentialResponse> {
        let authority = authority(&ctx)?;
        let mut request = request.to_owned_message();
        // Write-only token at the isolated authority. Never Debug/serialize
        // the request into an error or log.
        let bytes = zeroize::Zeroizing::new(std::mem::take(&mut request.token));
        let material =
            ProtectedValue::from_slice(&bytes).map_err(|_| error(Error::InvalidInput))?;
        drop(bytes);
        let metadata = self
            .owner
            .add_claude_subscription_token(
                authority,
                request.name,
                material,
                request.credential_id,
                request.expected_revocation_generation,
            )
            .await
            .map_err(error)?;
        connectrpc::Response::ok(proto::AddClaudeSubscriptionTokenCredentialResponse {
            credential: Some(credential(metadata)).into(),
            ..Default::default()
        })
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
            CredentialAuthKind::SshKey => proto::CredentialAuthenticationKind::SshKey,
        }
        .into(),
        account_hint: metadata.account_hint,
        ssh_public_key: metadata
            .ssh_public_key
            .map(|key| proto::SshPublicKey {
                openssh: key.openssh,
                fingerprint: key.fingerprint,
                ..Default::default()
            })
            .into(),
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
            "original credential-mutation authority is no longer valid",
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
            "isolated provider enrollment did not complete",
        ),
        Error::EnrollmentUnsupported => (
            ConnectCode::FailedPrecondition,
            "isolated provider enrollment version or response is unsupported",
        ),
        Error::EnrollmentNotPublished => (
            ConnectCode::FailedPrecondition,
            "credential enrollment did not reach publication; no platform credential was stored",
        ),
        Error::GitHubInstallationRequired => (
            ConnectCode::FailedPrecondition,
            "install the GitHub App for this account before connecting",
        ),
        Error::GitHubAlreadyConnected => (
            ConnectCode::AlreadyExists,
            "GitHub is already connected for this account; reconnect or delete it",
        ),
        Error::GitHubAppNotConfigured => (
            ConnectCode::FailedPrecondition,
            "GitHub App authorization is not configured; no credential was changed",
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
    // Closed classifications only: provider stderr, material, SQL and source
    // errors are never retained in the service error or its public detail.
    let reason = match error {
        Error::StaleRevision => "CREDENTIAL_REVISION_CHANGED",
        Error::EnrollmentFailed => "CREDENTIAL_ENROLLMENT_FAILED",
        Error::EnrollmentUnsupported => "CREDENTIAL_ENROLLMENT_UNSUPPORTED",
        Error::EnrollmentNotPublished => "CREDENTIAL_ENROLLMENT_NOT_PUBLISHED",
        Error::GitHubInstallationRequired => "CREDENTIAL_GITHUB_INSTALLATION_REQUIRED",
        Error::GitHubAlreadyConnected => "CREDENTIAL_GITHUB_ALREADY_CONNECTED",
        Error::GitHubAppNotConfigured => "CREDENTIAL_GITHUB_APP_NOT_CONFIGURED",
        Error::CleanupFailed => "CREDENTIAL_ENROLLMENT_CLEANUP_FAILED",
        Error::PublicationUnknown => "CREDENTIAL_MUTATION_UNCERTAIN",
        _ => "",
    };
    wire_error(&ConnectError {
        code,
        message: message.to_owned(),
        details: if reason.is_empty() {
            Vec::new()
        } else {
            vec![ConnectErrorDetail::ErrorInfo(ErrorInfo {
                reason: reason.into(),
                domain: ERROR_INFO_DOMAIN.into(),
                metadata: Default::default(),
            })]
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD};
    use buffa::Message as _;

    #[test]
    fn enrollment_wire_reasons_are_closed_domain_bound_and_material_free() {
        for (failure, reason, code) in [
            (
                Error::StaleRevision,
                "CREDENTIAL_REVISION_CHANGED",
                connectrpc::ErrorCode::FailedPrecondition,
            ),
            (
                Error::EnrollmentFailed,
                "CREDENTIAL_ENROLLMENT_FAILED",
                connectrpc::ErrorCode::FailedPrecondition,
            ),
            (
                Error::EnrollmentUnsupported,
                "CREDENTIAL_ENROLLMENT_UNSUPPORTED",
                connectrpc::ErrorCode::FailedPrecondition,
            ),
            (
                Error::EnrollmentNotPublished,
                "CREDENTIAL_ENROLLMENT_NOT_PUBLISHED",
                connectrpc::ErrorCode::FailedPrecondition,
            ),
            (
                Error::GitHubInstallationRequired,
                "CREDENTIAL_GITHUB_INSTALLATION_REQUIRED",
                connectrpc::ErrorCode::FailedPrecondition,
            ),
            (
                Error::GitHubAlreadyConnected,
                "CREDENTIAL_GITHUB_ALREADY_CONNECTED",
                connectrpc::ErrorCode::AlreadyExists,
            ),
            (
                Error::GitHubAppNotConfigured,
                "CREDENTIAL_GITHUB_APP_NOT_CONFIGURED",
                connectrpc::ErrorCode::FailedPrecondition,
            ),
            (
                Error::CleanupFailed,
                "CREDENTIAL_ENROLLMENT_CLEANUP_FAILED",
                connectrpc::ErrorCode::Unavailable,
            ),
            (
                Error::PublicationUnknown,
                "CREDENTIAL_MUTATION_UNCERTAIN",
                connectrpc::ErrorCode::Unknown,
            ),
        ] {
            let wire = error(failure);
            assert_eq!(wire.code, code);
            assert_eq!(wire.details.len(), 1);
            let detail = &wire.details[0];
            assert!(detail.debug.is_none());
            let bytes = STANDARD_NO_PAD
                .decode(detail.value.as_deref().unwrap())
                .unwrap();
            let info = codewire_proto::google::rpc::ErrorInfo::decode_from_slice(&bytes).unwrap();
            assert_eq!(info.domain, ERROR_INFO_DOMAIN);
            assert_eq!(info.reason, reason);
            assert!(info.metadata.is_empty());
        }
    }
}
