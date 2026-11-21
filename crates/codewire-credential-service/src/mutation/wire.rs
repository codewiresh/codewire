use std::sync::Arc;

use codewire_access::{CredentialAuthKind, CredentialMetadata, CredentialStatus};
use codewire_credential_broker::provider_oauth::claude::{
    CLAUDE_SIGN_IN_CODE_INVALID, CLAUDE_SIGN_IN_EXPIRED,
};
use codewire_protected_store::ProtectedValue;
use codewire_proto::codewire::v1::{self as proto, CredentialMutationService};
use codewire_server_core::auth::CredentialMutationAuthority;
use codewire_server_core::connect::{credential_mutation_authority, wire_error};
use codewire_server_core::connect_error::{
    ConnectCode, ConnectError, ConnectErrorDetail, ERROR_INFO_DOMAIN, ErrorInfo,
};
use connectrpc::{RequestContext, ServiceRequest, ServiceResult, ServiceStream};

use super::{CredentialMutationOwner, Error};

/// The ErrorInfo metadata key of the configured GitHub App's install page on
/// `CREDENTIAL_GITHUB_INSTALLATION_REQUIRED` (`docs/dev/SECRETS-AND-CREDENTIALS.md`).
const INSTALL_URL: &str = "install_url";

pub(super) fn router(owner: Arc<CredentialMutationOwner>) -> connectrpc::Router {
    connectrpc::Router::new().add_service(Arc::new(Service::new(owner)))
}

struct Service {
    owner: Arc<CredentialMutationOwner>,
    github_install_url: Option<Arc<str>>,
}

impl Service {
    fn new(owner: Arc<CredentialMutationOwner>) -> Self {
        Self {
            github_install_url: owner.github_app_install_url().map(Arc::from),
            owner,
        }
    }

    /// [`error`] for the GitHub calls, which name the configured App's
    /// install page when it isn't installed.
    fn github_error(&self) -> impl Fn(Error) -> connectrpc::ConnectError + Send + 'static {
        let install_url = self.github_install_url.clone();
        move |failure| error_with_install_url(failure, install_url.as_deref())
    }
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
        let github_error = self.github_error();
        let events = self
            .owner
            .enroll_github(
                authority(&ctx)?,
                request.name,
                request.credential_id,
                request.expected_revocation_generation,
            )
            .map_err(&github_error)?;
        let stream = futures::stream::unfold(
            (events, github_error),
            |(mut events, github_error)| async move {
                let message = events.receiver.recv().await?;
                Some((message.map_err(&github_error), (events, github_error)))
            },
        );
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
        let (metadata, pending_permissions) = self
            .owner
            .complete_github_app_authorization(
                authority,
                code,
                request.credential_id,
                request.expected_revocation_generation,
            )
            .await
            .map_err(self.github_error())?;
        connectrpc::Response::ok(proto::CompleteGithubAppAuthorizationResponse {
            credential: Some(credential(metadata)).into(),
            pending_permissions,
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

    async fn start_claude_sign_in(
        &self,
        ctx: RequestContext,
        _request: ServiceRequest<'_, proto::StartClaudeSignInRequest>,
    ) -> ServiceResult<proto::StartClaudeSignInResponse> {
        let mut started = self
            .owner
            .start_claude_sign_in(authority(&ctx)?)
            .await
            .map_err(error)?;
        connectrpc::Response::ok(proto::StartClaudeSignInResponse {
            authorize_url: started.authorize_url,
            sign_in: std::mem::take(&mut *started.handle),
            expires_at_unix: started.expires_at_unix,
            ..Default::default()
        })
    }

    async fn complete_claude_sign_in(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, proto::CompleteClaudeSignInRequest>,
    ) -> ServiceResult<proto::CompleteClaudeSignInResponse> {
        let authority = authority(&ctx)?;
        let mut request = request.to_owned_message();
        // The handle and the pasted code are write-only here. Never
        // Debug/serialize the request into an error or log.
        let handle = zeroize::Zeroizing::new(std::mem::take(&mut request.sign_in));
        let code = zeroize::Zeroizing::new(std::mem::take(&mut request.authorization_code));
        let metadata = self
            .owner
            .complete_claude_sign_in(
                authority,
                request.name,
                handle,
                code,
                request.credential_id,
                request.expected_revocation_generation,
            )
            .await
            .map_err(error)?;
        connectrpc::Response::ok(proto::CompleteClaudeSignInResponse {
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
        let (metadata, provider) = self
            .owner
            .revoke(
                authority(&ctx)?,
                request.credential_id,
                request.expected_revocation_generation,
            )
            .await
            .map_err(error)?;
        let metadata = metadata.ok_or_else(|| error(Error::PublicationUnknown))?;
        connectrpc::Response::ok(proto::RevokeCredentialResponse {
            credential: Some(credential(metadata)).into(),
            provider_revocation: provider.to_proto().into(),
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
            CredentialAuthKind::ClaudeSignIn => proto::CredentialAuthenticationKind::ClaudeSignIn,
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
    error_with_install_url(error, None)
}

/// `install_url`, built by the service from its validated App slug, rides
/// only on `CREDENTIAL_GITHUB_INSTALLATION_REQUIRED`.
fn error_with_install_url(error: Error, install_url: Option<&str>) -> connectrpc::ConnectError {
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
        Error::ClaudeSignInCodeInvalid => {
            (ConnectCode::InvalidArgument, CLAUDE_SIGN_IN_CODE_INVALID)
        }
        Error::ClaudeSignInExpired => (ConnectCode::FailedPrecondition, CLAUDE_SIGN_IN_EXPIRED),
        Error::NameReservesProvider => (
            ConnectCode::InvalidArgument,
            "a new credential name may not start with anthropic/, openai/, github/ or ssh/",
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
        Error::ClaudeSignInCodeInvalid => "CREDENTIAL_CLAUDE_SIGN_IN_CODE_INVALID",
        Error::ClaudeSignInExpired => "CREDENTIAL_CLAUDE_SIGN_IN_EXPIRED",
        Error::NameReservesProvider => "CREDENTIAL_NAME_RESERVES_PROVIDER",
        _ => "",
    };
    let metadata = match (error, install_url) {
        (Error::GitHubInstallationRequired, Some(install_url)) => {
            [(INSTALL_URL.to_owned(), install_url.to_owned())].into()
        }
        _ => Default::default(),
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
                metadata,
            })]
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD};
    use buffa::Message as _;

    /// The refusal writes the prefixes out; it names exactly the providers a
    /// name is unique within.
    #[test]
    fn a_name_reserving_a_provider_is_refused_naming_every_provider() {
        let refused = error(Error::NameReservesProvider);
        assert_eq!(
            refused.message.as_deref(),
            Some(
                format!(
                    "a new credential name may not start with {}",
                    codewire_access::credential_name_provider_prefixes()
                )
                .as_str()
            )
        );
    }

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
            (
                Error::ClaudeSignInCodeInvalid,
                "CREDENTIAL_CLAUDE_SIGN_IN_CODE_INVALID",
                connectrpc::ErrorCode::InvalidArgument,
            ),
            (
                Error::ClaudeSignInExpired,
                "CREDENTIAL_CLAUDE_SIGN_IN_EXPIRED",
                connectrpc::ErrorCode::FailedPrecondition,
            ),
            (
                Error::NameReservesProvider,
                "CREDENTIAL_NAME_RESERVES_PROVIDER",
                connectrpc::ErrorCode::InvalidArgument,
            ),
        ] {
            for install_url in [None, Some(SYNTHETIC_INSTALL_URL)] {
                let wire = error_with_install_url(failure, install_url);
                assert_eq!(wire.code, code);
                let info = error_info(&wire);
                assert_eq!(info.domain, ERROR_INFO_DOMAIN);
                assert_eq!(info.reason, reason);
                let expected = match (failure, install_url) {
                    (Error::GitHubInstallationRequired, Some(url)) => vec![(INSTALL_URL, url)],
                    _ => Vec::new(),
                };
                assert_eq!(metadata(&info), expected, "{reason}");
            }
            assert!(error_info(&error(failure)).metadata.is_empty());
        }
    }

    const SYNTHETIC_INSTALL_URL: &str =
        "https://github.com/apps/codewire-synthetic/installations/new";

    fn error_info(wire: &connectrpc::ConnectError) -> codewire_proto::google::rpc::ErrorInfo {
        assert_eq!(wire.details.len(), 1);
        let detail = &wire.details[0];
        assert!(detail.debug.is_none());
        let bytes = STANDARD_NO_PAD
            .decode(detail.value.as_deref().unwrap())
            .unwrap();
        codewire_proto::google::rpc::ErrorInfo::decode_from_slice(&bytes).unwrap()
    }

    fn metadata(info: &codewire_proto::google::rpc::ErrorInfo) -> Vec<(&str, &str)> {
        info.metadata
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
            .collect()
    }

    /// The service as `router` builds it, over an owner whose GitHub App is
    /// `codewire-synthetic`, or that has none. No database is reached.
    async fn service(github_slug: Option<&str>) -> Service {
        use codewire_credential_broker::provider_oauth::claude::ClaudeSignIn;
        use codewire_credential_broker::provider_oauth::codex::CodexDeviceLogin;
        use codewire_credential_broker::provider_oauth::github::{
            GitHubDeviceLogin, GitHubDeviceLoginConfig,
        };
        use codewire_platform_credentials::PlatformCredentialStore;
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgresql://synthetic:synthetic@127.0.0.1:1/synthetic")
            .unwrap();
        pool.close().await;
        let device = Arc::new(crate::mutation::tests::support::DeviceProvider::default());
        let github_login = github_slug.map(|slug| {
            GitHubDeviceLogin::new(
                GitHubDeviceLoginConfig::new("Iv1.synthetic".into(), slug.into()).unwrap(),
                device.clone(),
            )
        });
        let store = Arc::new(PlatformCredentialStore::new(
            pool.clone(),
            Arc::new(codewire_protected_store::secret_envelope::TestKekProvider),
            codewire_access::builtin_provider_catalog(),
        ));
        Service::new(Arc::new(CredentialMutationOwner::new(
            pool,
            store,
            CodexDeviceLogin::new(device.clone()),
            ClaudeSignIn::new(device),
            github_login,
            None,
        )))
    }

    #[tokio::test]
    async fn the_installation_refusal_names_the_configured_app() {
        let wire = (service(Some("codewire-synthetic")).await.github_error())(
            Error::GitHubInstallationRequired,
        );
        let info = error_info(&wire);
        assert_eq!(info.reason, "CREDENTIAL_GITHUB_INSTALLATION_REQUIRED");
        assert_eq!(metadata(&info), [(INSTALL_URL, SYNTHETIC_INSTALL_URL)]);
        // Without an App there is no page to name.
        let wire = (service(None).await.github_error())(Error::GitHubInstallationRequired);
        assert!(error_info(&wire).metadata.is_empty());
    }
}
