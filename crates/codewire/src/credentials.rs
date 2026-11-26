//! Personal metadata, write-only key enrollment and one-connection OAuth login.

use crate::*;

impl CodewireClient {
    /// One account-scoped repository page for an exact GitHub credential.
    /// No provider material or runtime grant is returned.
    pub async fn list_github_repositories(
        &self,
        request: ListGithubRepositoriesRequest,
    ) -> Result<ListGithubRepositoriesResponse, ClientError> {
        self.github_repositories
            .list_github_repositories_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    /// The installations of the authenticated owner's GitHub App connection
    /// that have not yet granted what Codewire needs, checked live (#2712).
    /// Login, installation ID and account kind only.
    pub async fn list_github_pending_permissions(
        &self,
    ) -> Result<ListGithubPendingPermissionsResponse, ClientError> {
        self.github_repositories
            .list_github_pending_permissions_with_options(
                ListGithubPendingPermissionsRequest::default(),
                self.auth_options().await?,
            )
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    /// Rename the exact observed identity without changing its material or bindings.
    pub async fn rename_credential(
        &self,
        request: RenameCredentialRequest,
    ) -> Result<RenameCredentialResponse, ClientError> {
        self.credential_mutations
            .rename_credential_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    /// Explicitly replace an API key and activate it; omitted expiry clears the
    /// deadline. An uncertain acknowledgement must not be automatically retried.
    pub async fn rotate_api_key_credential(
        &self,
        request: RotateApiKeyCredentialRequest,
    ) -> Result<RotateApiKeyCredentialResponse, ClientError> {
        self.credential_mutations
            .rotate_api_key_credential_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    /// Generate an identity inside the authority; only its public metadata is returned.
    pub async fn generate_ssh_credential(
        &self,
        request: GenerateSshCredentialRequest,
    ) -> Result<GenerateSshCredentialResponse, ClientError> {
        self.credential_mutations
            .generate_ssh_credential_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    /// Explicit write-only private-key import, never a key-file or ambient-agent lookup.
    pub async fn add_ssh_credential(
        &self,
        request: AddSshCredentialRequest,
    ) -> Result<AddSshCredentialResponse, ClientError> {
        self.credential_mutations
            .add_ssh_credential_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    /// Submit a key for protected storage. There is deliberately no read-back
    /// method; the reply contains only the committed credential metadata.
    pub async fn add_api_key_credential(
        &self,
        request: AddApiKeyCredentialRequest,
    ) -> Result<AddApiKeyCredentialResponse, ClientError> {
        self.credential_mutations
            .add_api_key_credential_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    /// Submit a pasted Claude subscription token (`claude setup-token`) for
    /// protected storage, or replace an exact existing one. There is no
    /// read-back method; the reply contains only committed metadata.
    pub async fn add_claude_subscription_token_credential(
        &self,
        request: AddClaudeSubscriptionTokenCredentialRequest,
    ) -> Result<AddClaudeSubscriptionTokenCredentialResponse, ClientError> {
        self.credential_mutations
            .add_claude_subscription_token_credential_with_options(
                request,
                self.auth_options().await?,
            )
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    /// Begin a Claude sign-in: Claude's authorize URL and the opaque handle
    /// the caller keeps private and returns to
    /// [`Self::complete_claude_sign_in`].
    pub async fn start_claude_sign_in(
        &self,
        request: StartClaudeSignInRequest,
    ) -> Result<StartClaudeSignInResponse, ClientError> {
        self.credential_mutations
            .start_claude_sign_in_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    /// Submit the pasted `code#state` of a started Claude sign-in. The reply
    /// contains only committed metadata; no token is returned.
    pub async fn complete_claude_sign_in(
        &self,
        request: CompleteClaudeSignInRequest,
    ) -> Result<CompleteClaudeSignInResponse, ClientError> {
        self.credential_mutations
            .complete_claude_sign_in_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    /// Begin an Antigravity sign-in: Google's authorize URL and the opaque
    /// handle the caller keeps private and returns to
    /// [`Self::complete_antigravity_sign_in`].
    pub async fn start_antigravity_sign_in(
        &self,
        request: StartAntigravitySignInRequest,
    ) -> Result<StartAntigravitySignInResponse, ClientError> {
        self.credential_mutations
            .start_antigravity_sign_in_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    /// Submit the pasted callback URL or `code#state` of a started Antigravity
    /// sign-in. The reply contains only committed metadata; no token is returned.
    pub async fn complete_antigravity_sign_in(
        &self,
        request: CompleteAntigravitySignInRequest,
    ) -> Result<CompleteAntigravitySignInResponse, ClientError> {
        self.credential_mutations
            .complete_antigravity_sign_in_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn list_credentials(
        &self,
        request: ListCredentialsRequest,
    ) -> Result<ListCredentialsResponse, ClientError> {
        self.credentials
            .list_credentials_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn get_credential(
        &self,
        request: GetCredentialRequest,
    ) -> Result<GetCredentialResponse, ClientError> {
        self.credentials
            .get_credential_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn revoke_credential(
        &self,
        request: RevokeCredentialRequest,
    ) -> Result<RevokeCredentialResponse, ClientError> {
        self.credential_mutations
            .revoke_credential_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn delete_credential(
        &self,
        request: DeleteCredentialRequest,
    ) -> Result<DeleteCredentialResponse, ClientError> {
        self.credential_mutations
            .delete_credential_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    /// Deliver the device prompt immediately and return only committed metadata.
    /// Returning false from the callback or dropping this future cancels the
    /// original stream. Missing acknowledgement is uncertain: reconcile by name
    /// rather than automatically reenrolling or revoking the provider login.
    /// The callback must return promptly; the one-time code is not a log field.
    pub async fn enroll_codex(
        &self,
        mut request: EnrollCodexRequest,
        mut on_challenge: impl FnMut(CodexDeviceChallenge) -> bool,
    ) -> Result<Credential, ClientError> {
        // The edge ends a response silent for about two minutes (#6384).
        request.accepts_heartbeats = true;
        // Resolve once. Refreshing this provider for a future call never
        // replaces the original OAuth authority of this enrollment stream.
        let options = self
            .auth_options()
            .await?
            .with_timeout(Duration::from_secs(16 * 60));
        let mut stream = self
            .credential_mutations
            .enroll_codex_with_options(request, options)
            .await
            .map_err(|_| enrollment_unknown())?;
        let mut challenged = false;
        while let Some(message) = stream
            .message::<EnrollCodexResponse>()
            .await
            .map_err(|error| codex_enrollment_terminal_error(error, challenged))?
        {
            match message.to_owned_message().event {
                Some(enroll_codex_response::Event::Challenge(challenge)) if !challenged => {
                    if !valid_challenge(&challenge) || !on_challenge(*challenge) {
                        return Err(enrollment_unknown());
                    }
                    challenged = true;
                }
                Some(enroll_codex_response::Event::Credential(credential)) if challenged => {
                    if credential.id.is_empty() || credential.revocation_generation == 0 {
                        return Err(enrollment_unknown());
                    }
                    return Ok(*credential);
                }
                Some(enroll_codex_response::Event::Heartbeat(_)) => {}
                _ => return Err(enrollment_unknown()),
            }
        }
        Err(enrollment_unknown())
    }

    /// One GitHub device challenge followed by the exact committed identity.
    /// Cancellation or missing acknowledgement never automatically retries.
    pub async fn enroll_github(
        &self,
        mut request: EnrollGithubRequest,
        mut on_challenge: impl FnMut(GithubDeviceChallenge) -> bool,
    ) -> Result<GithubEnrollment, ClientError> {
        // The edge ends a response silent for about two minutes (#6384).
        request.accepts_heartbeats = true;
        let options = self
            .auth_options()
            .await?
            .with_timeout(Duration::from_secs(16 * 60));
        let mut stream = self
            .credential_mutations
            .enroll_github_with_options(request, options)
            .await
            .map_err(github_enrollment_refusal)?;
        let mut challenged = false;
        loop {
            let message = match stream.message::<EnrollGithubResponse>().await {
                Ok(Some(message)) => message,
                Ok(None) => return Err(github_enrollment_unknown()),
                Err(error) if challenged => return Err(github_enrollment_terminal_error(error)),
                Err(error) => return Err(github_enrollment_refusal(error)),
            };
            let message = message.to_owned_message();
            match message.event {
                Some(enroll_github_response::Event::Challenge(challenge)) if !challenged => {
                    if !valid_github_challenge(&challenge) || !on_challenge(*challenge) {
                        return Err(github_enrollment_unknown());
                    }
                    challenged = true;
                }
                Some(enroll_github_response::Event::Credential(credential)) if challenged => {
                    if credential.id.is_empty()
                        || credential.revocation_generation == 0
                        || credential.provider != "github"
                        || credential.authentication_kind != CredentialAuthenticationKind::Oauth
                    {
                        return Err(github_enrollment_unknown());
                    }
                    return Ok(GithubEnrollment {
                        credential: *credential,
                        pending_permissions: message.pending_permissions,
                    });
                }
                Some(enroll_github_response::Event::Heartbeat(_)) => {}
                _ => return Err(github_enrollment_unknown()),
            }
        }
    }
}

/// What a GitHub connect says when the GitHub App is installed on no account
/// the approving GitHub login can use: the service's
/// `CREDENTIAL_GITHUB_INSTALLATION_REQUIRED`, and the local CLI's own check.
/// One sentence for both placements (`docs/journeys/credentials.md`,
/// `cred-github`), ending with the install page of the App the connection
/// uses when there is one to name.
pub fn github_app_not_installed(install_url: Option<&GithubAppInstallUrl>) -> String {
    const SENTENCE: &str = "the Codewire GitHub App is not installed on any account this GitHub login can use; \
         install it, choose the accounts and repositories, then connect again";
    match install_url {
        Some(install_url) => format!("{SENTENCE}: {}", install_url.as_str()),
        None => SENTENCE.to_owned(),
    }
}

/// GitHub's page for installing one GitHub App, accepted only as exactly
/// `https://github.com/apps/SLUG/installations/new`. A server names its own
/// App with it, so nothing else it sends may reach a terminal as a link
/// (`docs/dev/SECRETS-AND-CREDENTIALS.md`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GithubAppInstallUrl(String);

impl GithubAppInstallUrl {
    pub fn parse(value: &str) -> Option<Self> {
        let slug = value
            .strip_prefix("https://github.com/apps/")?
            .strip_suffix("/installations/new")?;
        valid_github_app_slug(slug).then(|| Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The credential broker's App slug rule, which the service enforces on its
/// configured slug; a `codewire-cli` test pins the two together.
fn valid_github_app_slug(slug: &str) -> bool {
    !slug.is_empty()
        && slug.len() <= 100
        && !slug.starts_with('-')
        && !slug.ends_with('-')
        && slug
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

/// A committed GitHub connection, and the GitHub App installations that have
/// not yet granted the permissions Codewire needs. Those are reported once,
/// at connect time, and never stored.
#[derive(Debug)]
pub struct GithubEnrollment {
    pub credential: Credential,
    pub pending_permissions: Vec<GithubAppPendingPermissions>,
}

fn valid_github_challenge(challenge: &GithubDeviceChallenge) -> bool {
    challenge.verification_url == "https://github.com/login/device"
        && challenge.user_code.len() == 9
        && challenge
            .user_code
            .bytes()
            .enumerate()
            .all(|(index, byte)| {
                if index == 4 {
                    byte == b'-'
                } else {
                    byte.is_ascii_uppercase() || byte.is_ascii_digit()
                }
            })
        && challenge.expires_at_unix > 0
}

fn github_enrollment_unknown() -> ClientError {
    ClientError::new(
        ErrorCode::Unknown,
        "GitHub enrollment acknowledgement is unknown; reconcile the credential by name before retrying",
    )
}

/// Before any challenge the service refuses a second GitHub connection, a
/// server without its GitHub App settings, or a new name that starts with a
/// provider id and `/` (#4928), definitely, having asked GitHub nothing. Every
/// other early close stays uncertain.
fn github_enrollment_refusal(error: connectrpc::ConnectError) -> ClientError {
    let error = ClientError::from(error);
    match (error.code(), codewire_reason(&error)) {
        (ErrorCode::AlreadyExists, Some("CREDENTIAL_GITHUB_ALREADY_CONNECTED")) => {
            ClientError::new(
                ErrorCode::AlreadyExists,
                "GitHub is already connected for this account; no platform credential was changed",
            )
        }
        (ErrorCode::FailedPrecondition, Some("CREDENTIAL_GITHUB_APP_NOT_CONFIGURED")) => {
            ClientError::new(
                ErrorCode::FailedPrecondition,
                "GitHub App authorization is not configured on this Codewire server; no platform credential was changed; ask an administrator to finish the GitHub App setup",
            )
        }
        (ErrorCode::InvalidArgument, Some("CREDENTIAL_NAME_RESERVES_PROVIDER")) => {
            ClientError::new(ErrorCode::InvalidArgument, GITHUB_NAME_RESERVES_PROVIDER)
        }
        _ => github_enrollment_unknown(),
    }
}

/// A new name that `PROVIDER/NAME` would read as another credential.
const GITHUB_NAME_RESERVES_PROVIDER: &str = "a credential's name can't start with anthropic/, openai/, github/, ssh/ or google/, which reads as a provider; choose another name; no platform credential was changed";

fn codewire_reason(error: &ClientError) -> Option<&str> {
    error
        .error_info()
        .filter(|info| info.domain() == "codewire.sh")
        .map(ErrorInfo::reason)
}

/// A known terminal reason after a verified challenge is safe to render using
/// our own fixed text. Every other close remains an uncertain publication: no
/// peer-supplied message or provider diagnostic crosses this boundary. The one
/// peer-supplied value that does is the installation refusal's `install_url`,
/// and only in the exact form `GithubAppInstallUrl::parse` accepts.
fn github_enrollment_terminal_error(error: connectrpc::ConnectError) -> ClientError {
    let error = ClientError::from(error);
    match (error.code(), codewire_reason(&error)) {
        (ErrorCode::FailedPrecondition, Some("CREDENTIAL_ENROLLMENT_FAILED")) => ClientError::new(
            ErrorCode::FailedPrecondition,
            "isolated GitHub enrollment did not complete; no platform credential was stored",
        ),
        (ErrorCode::FailedPrecondition, Some("CREDENTIAL_ENROLLMENT_UNSUPPORTED")) => {
            ClientError::new(
                ErrorCode::FailedPrecondition,
                "isolated GitHub enrollment output is unsupported; no platform credential was stored",
            )
        }
        (ErrorCode::FailedPrecondition, Some("CREDENTIAL_ENROLLMENT_NOT_PUBLISHED")) => {
            ClientError::new(
                ErrorCode::FailedPrecondition,
                "GitHub enrollment did not reach platform publication; no platform credential was stored",
            )
        }
        (ErrorCode::DeadlineExceeded, Some("CREDENTIAL_ENROLLMENT_EXPIRED")) => ClientError::new(
            ErrorCode::FailedPrecondition,
            "GitHub was not approved in time; no platform credential was stored; connect again for a new code",
        ),
        (ErrorCode::FailedPrecondition, Some("CREDENTIAL_GITHUB_INSTALLATION_REQUIRED")) => {
            let install_url = error
                .error_info()
                .and_then(|info| info.metadata().get("install_url"))
                .and_then(|value| GithubAppInstallUrl::parse(value));
            ClientError::new(
                ErrorCode::FailedPrecondition,
                github_app_not_installed(install_url.as_ref()),
            )
        }
        _ => github_enrollment_unknown(),
    }
}

fn valid_challenge(challenge: &CodexDeviceChallenge) -> bool {
    challenge.verification_url == "https://auth.openai.com/codex/device"
        && !challenge.user_code.is_empty()
        && challenge.user_code.len() <= 64
        && challenge
            .user_code
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        && challenge.expires_at_unix > 0
}

/// After a verified challenge, the two reasons that prove nothing was stored
/// render with our own fixed text (#6535). Every other close stays uncertain.
fn codex_enrollment_terminal_error(
    error: connectrpc::ConnectError,
    challenged: bool,
) -> ClientError {
    let error = ClientError::from(error);
    match (challenged, error.code(), codewire_reason(&error)) {
        (true, ErrorCode::FailedPrecondition, Some("CREDENTIAL_ENROLLMENT_NOT_PUBLISHED")) => {
            ClientError::new(
                ErrorCode::FailedPrecondition,
                "Codex enrollment did not reach platform publication; no platform credential was stored",
            )
        }
        (true, ErrorCode::DeadlineExceeded, Some("CREDENTIAL_ENROLLMENT_EXPIRED")) => {
            ClientError::new(
                ErrorCode::FailedPrecondition,
                "Codex was not approved in time; no platform credential was stored; connect again for a new code",
            )
        }
        _ => enrollment_unknown(),
    }
}

fn enrollment_unknown() -> ClientError {
    ClientError::new(
        ErrorCode::Unknown,
        "Codex enrollment acknowledgement is unknown; reconcile the credential by name before retrying",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use buffa::Message;
    use codewire_proto::google::rpc::ErrorInfo as GoogleErrorInfo;
    use wiremock::matchers::{body_bytes, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn client(server: &MockServer) -> CodewireClient {
        CodewireClient::with_http(
            ClientConfig::new(server.uri()).unwrap(),
            StaticTokenProvider::new("synthetic-credential-client-oauth").unwrap(),
            reqwest::Client::new(),
        )
        .unwrap()
    }

    async fn unary(server: &MockServer, route: &str, request: Vec<u8>, response: Vec<u8>) {
        Mock::given(method("POST"))
            .and(path(route))
            .and(header(
                "authorization",
                "Bearer synthetic-credential-client-oauth",
            ))
            .and(body_bytes(request))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/proto")
                    .set_body_bytes(response),
            )
            .expect(1)
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn ssh_enrollment_facade_uses_typed_write_only_routes_and_shared_auth() {
        let server = MockServer::start().await;
        let client = client(&server);
        let generation = GenerateSshCredentialRequest {
            name: "synthetic-ssh".into(),
            expires_at_unix: Some(4_102_444_800),
            ..Default::default()
        };
        unary(
            &server,
            "/codewire.v1.CredentialMutationService/GenerateSshCredential",
            generation.encode_to_vec(),
            GenerateSshCredentialResponse::default().encode_to_vec(),
        )
        .await;
        client.generate_ssh_credential(generation).await.unwrap();
        let import = AddSshCredentialRequest {
            name: "synthetic-import".into(),
            private_key: b"synthetic-key-not-real".to_vec(),
            passphrase: Some(b"synthetic-passphrase-not-real".to_vec()),
            ..Default::default()
        };
        let debug = format!("{import:?}");
        assert!(!debug.contains("synthetic-key-not-real"));
        assert!(!debug.contains("synthetic-passphrase-not-real"));
        assert_eq!(debug.matches("[REDACTED]").count(), 2);
        let alternate_material = AddSshCredentialRequest {
            private_key: vec![1, 2, 3, 4],
            passphrase: Some(vec![5, 6, 7, 8]),
            ..import.clone()
        };
        assert_eq!(debug, format!("{alternate_material:?}"));
        unary(
            &server,
            "/codewire.v1.CredentialMutationService/AddSshCredential",
            import.encode_to_vec(),
            AddSshCredentialResponse::default().encode_to_vec(),
        )
        .await;
        client.add_ssh_credential(import).await.unwrap();
        server.verify().await;
    }

    #[tokio::test]
    async fn credential_facade_preserves_selectors_exact_revisions_and_shared_auth() {
        let server = MockServer::start().await;
        let client = client(&server);
        let request = ListCredentialsRequest {
            page_size: 1,
            page_token: "opaque".into(),
            ..Default::default()
        };
        unary(
            &server,
            "/codewire.v1.CredentialService/ListCredentials",
            request.encode_to_vec(),
            ListCredentialsResponse::default().encode_to_vec(),
        )
        .await;
        client.list_credentials(request).await.unwrap();
        for selector in [
            get_credential_request::Selector::CredentialId("exact-id".into()),
            get_credential_request::Selector::Name("Exact Name".into()),
        ] {
            let request = GetCredentialRequest {
                selector: Some(selector),
                ..Default::default()
            };
            unary(
                &server,
                "/codewire.v1.CredentialService/GetCredential",
                request.encode_to_vec(),
                GetCredentialResponse::default().encode_to_vec(),
            )
            .await;
            client.get_credential(request).await.unwrap();
        }
        let request = RevokeCredentialRequest {
            credential_id: "exact-id".into(),
            expected_revocation_generation: 9_007_199_254_740_993,
            ..Default::default()
        };
        unary(
            &server,
            "/codewire.v1.CredentialMutationService/RevokeCredential",
            request.encode_to_vec(),
            RevokeCredentialResponse::default().encode_to_vec(),
        )
        .await;
        client.revoke_credential(request).await.unwrap();
        let request = DeleteCredentialRequest {
            credential_id: "exact-id".into(),
            expected_revocation_generation: 9_007_199_254_740_994,
            ..Default::default()
        };
        unary(
            &server,
            "/codewire.v1.CredentialMutationService/DeleteCredential",
            request.encode_to_vec(),
            DeleteCredentialResponse::default().encode_to_vec(),
        )
        .await;
        client.delete_credential(request).await.unwrap();
    }

    #[tokio::test]
    async fn key_enrollment_uses_write_only_authenticated_mutation() {
        let server = MockServer::start().await;
        let client = client(&server);
        let request = AddApiKeyCredentialRequest {
            provider: "anthropic".into(),
            name: "work".into(),
            value: b"synthetic-api-key".to_vec(),
            expires_at_unix: Some(4_102_444_800),
            ..Default::default()
        };
        unary(
            &server,
            "/codewire.v1.CredentialMutationService/AddApiKeyCredential",
            request.encode_to_vec(),
            AddApiKeyCredentialResponse::default().encode_to_vec(),
        )
        .await;
        client.add_api_key_credential(request).await.unwrap();
        server.verify().await;
    }

    #[tokio::test]
    async fn subscription_token_enrollment_uses_write_only_authenticated_mutation() {
        let server = MockServer::start().await;
        let client = client(&server);
        let request = AddClaudeSubscriptionTokenCredentialRequest {
            name: "claude".into(),
            token: b"sk-ant-oat01-synthetic-token".to_vec(),
            ..Default::default()
        };
        assert!(!format!("{request:?}").contains("synthetic-token"));
        unary(
            &server,
            "/codewire.v1.CredentialMutationService/AddClaudeSubscriptionTokenCredential",
            request.encode_to_vec(),
            AddClaudeSubscriptionTokenCredentialResponse::default().encode_to_vec(),
        )
        .await;
        client
            .add_claude_subscription_token_credential(request)
            .await
            .unwrap();
        server.verify().await;
    }

    fn frame(message: impl Message) -> Vec<u8> {
        let payload = message.encode_to_vec();
        let mut bytes = vec![0];
        bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        bytes.extend(payload);
        bytes
    }

    /// The one request of an enrollment stream, out of its Connect envelope.
    async fn enrollment_request<M: Message>(server: &MockServer) -> M {
        let requests = server.received_requests().await.unwrap();
        let [request] = requests.as_slice() else {
            panic!("expected one request, got {}", requests.len());
        };
        M::decode_from_slice(&request.body[5..]).unwrap()
    }

    fn challenge() -> EnrollCodexResponse {
        EnrollCodexResponse {
            event: Some(enroll_codex_response::Event::Challenge(Box::new(
                CodexDeviceChallenge {
                    verification_url: "https://auth.openai.com/codex/device".into(),
                    user_code: "ABCD-EFGH".into(),
                    expires_at_unix: 9_007_199_254_740_993,
                    ..Default::default()
                },
            ))),
            ..Default::default()
        }
    }

    async fn stream(server: &MockServer, mut body: Vec<u8>) {
        stream_at(
            server,
            "/codewire.v1.CredentialMutationService/EnrollCodex",
            &mut body,
        )
        .await;
    }

    async fn stream_at(server: &MockServer, route: &str, body: &mut Vec<u8>) {
        stream_at_terminal(server, route, body, b"{}").await;
    }

    async fn stream_at_terminal(
        server: &MockServer,
        route: &str,
        body: &mut Vec<u8>,
        terminal: &[u8],
    ) {
        // Real Connect envelopes, including the terminal JSON envelope.
        body.push(2);
        body.extend_from_slice(&(terminal.len() as u32).to_be_bytes());
        body.extend_from_slice(terminal);
        Mock::given(method("POST"))
            .and(path(route))
            .and(header(
                "authorization",
                "Bearer synthetic-credential-client-oauth",
            ))
            .and(header("connect-timeout-ms", "960000"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/connect+proto")
                    .set_body_bytes(std::mem::take(body)),
            )
            .expect(1)
            .mount(server)
            .await;
    }

    fn github_terminal_error(code: &str, reason: &str, domain: &str) -> Vec<u8> {
        github_terminal_error_with(code, reason, domain, &[])
    }

    fn github_terminal_error_with(
        code: &str,
        reason: &str,
        domain: &str,
        metadata: &[(&str, &str)],
    ) -> Vec<u8> {
        let mut info = GoogleErrorInfo {
            reason: reason.into(),
            domain: domain.into(),
            ..Default::default()
        };
        for (key, value) in metadata {
            info.metadata.insert((*key).into(), (*value).into());
        }
        let detail = connectrpc::ErrorDetail::from_message("google.rpc.ErrorInfo", &info);
        serde_json::to_vec(&serde_json::json!({
            "error": {
                "code": code,
                "message": "private provider diagnostic must not cross the client boundary",
                "details": [detail],
            }
        }))
        .unwrap()
    }

    #[tokio::test]
    async fn enrollment_reports_challenge_before_returning_exact_committed_metadata() {
        let server = MockServer::start().await;
        let heartbeat = || {
            frame(EnrollCodexResponse {
                event: Some(enroll_codex_response::Event::Heartbeat(Default::default())),
                ..Default::default()
            })
        };
        // Heartbeats on either side of the challenge are skipped (#6384).
        let mut body = heartbeat();
        body.extend(frame(challenge()));
        body.extend(heartbeat());
        body.extend(heartbeat());
        body.extend(frame(EnrollCodexResponse {
            event: Some(enroll_codex_response::Event::Credential(Box::new(
                Credential {
                    id: "stored-id".into(),
                    name: "work".into(),
                    revocation_generation: 9_007_199_254_740_993,
                    ..Default::default()
                },
            ))),
            ..Default::default()
        }));
        stream(&server, body).await;
        let mut received = false;
        let result = client(&server)
            .enroll_codex(
                EnrollCodexRequest {
                    name: "work".into(),
                    ..Default::default()
                },
                |challenge| {
                    assert_eq!(challenge.user_code, "ABCD-EFGH");
                    assert!(!received);
                    received = true;
                    true
                },
            )
            .await
            .unwrap();
        assert!(received);
        assert_eq!(result.id, "stored-id");
        assert_eq!(result.revocation_generation, 9_007_199_254_740_993);
        let request: EnrollCodexRequest = enrollment_request(&server).await;
        assert!(request.accepts_heartbeats);
    }

    #[tokio::test]
    async fn codex_enrollment_heartbeats_alone_show_nothing_and_save_nothing() {
        let server = MockServer::start().await;
        let mut body = Vec::new();
        for _ in 0..3 {
            body.extend(frame(EnrollCodexResponse {
                event: Some(enroll_codex_response::Event::Heartbeat(Default::default())),
                ..Default::default()
            }));
        }
        stream(&server, body).await;
        let mut shown = 0;
        let error = client(&server)
            .enroll_codex(
                EnrollCodexRequest {
                    name: "work".into(),
                    ..Default::default()
                },
                |_| {
                    shown += 1;
                    true
                },
            )
            .await
            .unwrap_err();
        // A heartbeat is neither a challenge to show nor a result.
        assert_eq!(shown, 0);
        assert_eq!(error.code(), ErrorCode::Unknown);
        assert!(error.message().contains("reconcile"));
    }

    /// After the challenge, a stopped or timed-out enrollment that stored
    /// nothing says so; before it, the same reasons stay uncertain (#6535).
    #[tokio::test]
    async fn codex_enrollment_names_a_definite_unpublished_or_expired_end() {
        for (code, reason, expected) in [
            (
                "failed_precondition",
                "CREDENTIAL_ENROLLMENT_NOT_PUBLISHED",
                "Codex enrollment did not reach platform publication; no platform credential was stored",
            ),
            (
                "deadline_exceeded",
                "CREDENTIAL_ENROLLMENT_EXPIRED",
                "Codex was not approved in time; no platform credential was stored; connect again for a new code",
            ),
        ] {
            for challenged in [false, true] {
                let server = MockServer::start().await;
                let mut body = if challenged {
                    frame(challenge())
                } else {
                    Vec::new()
                };
                let terminal = github_terminal_error(code, reason, "codewire.sh");
                stream_at_terminal(
                    &server,
                    "/codewire.v1.CredentialMutationService/EnrollCodex",
                    &mut body,
                    &terminal,
                )
                .await;
                let error = client(&server)
                    .enroll_codex(
                        EnrollCodexRequest {
                            name: "work".into(),
                            ..Default::default()
                        },
                        |_| true,
                    )
                    .await
                    .unwrap_err();
                if challenged {
                    assert_eq!(
                        (error.code(), error.message()),
                        (ErrorCode::FailedPrecondition, expected)
                    );
                } else {
                    assert_eq!(error.code(), ErrorCode::Unknown, "{reason}");
                }
                assert!(error.reason().is_none());
            }
        }
    }

    #[tokio::test]
    async fn enrollment_missing_ack_or_callback_cancellation_never_retries() {
        for cancel in [false, true] {
            let server = MockServer::start().await;
            stream(&server, frame(challenge())).await;
            let error = client(&server)
                .enroll_codex(
                    EnrollCodexRequest {
                        name: "work".into(),
                        ..Default::default()
                    },
                    |_| !cancel,
                )
                .await
                .unwrap_err();
            assert_eq!(error.code(), ErrorCode::Unknown);
            assert!(error.message().contains("reconcile"));
            assert!(!error.message().contains("ABCD"));
        }
    }

    fn github_challenge(url: &str) -> EnrollGithubResponse {
        EnrollGithubResponse {
            event: Some(enroll_github_response::Event::Challenge(Box::new(
                GithubDeviceChallenge {
                    verification_url: url.into(),
                    user_code: "ABCD-1234".into(),
                    expires_at_unix: 4_102_444_800,
                    ..Default::default()
                },
            ))),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn github_enrollment_heartbeats_alone_show_nothing_and_save_nothing() {
        let server = MockServer::start().await;
        let mut body = Vec::new();
        for _ in 0..3 {
            body.extend(frame(EnrollGithubResponse {
                event: Some(enroll_github_response::Event::Heartbeat(Default::default())),
                ..Default::default()
            }));
        }
        stream_at(
            &server,
            "/codewire.v1.CredentialMutationService/EnrollGithub",
            &mut body,
        )
        .await;
        let mut shown = 0;
        let error = client(&server)
            .enroll_github(
                EnrollGithubRequest {
                    name: "work".into(),
                    ..Default::default()
                },
                |_| {
                    shown += 1;
                    true
                },
            )
            .await
            .unwrap_err();
        // A heartbeat is neither a challenge to show nor a result.
        assert_eq!(shown, 0);
        assert_eq!(error.code(), ErrorCode::Unknown);
        assert!(error.message().contains("reconcile"));
    }

    #[tokio::test]
    async fn github_enrollment_delivers_one_safe_challenge_and_committed_oauth_identity() {
        let server = MockServer::start().await;
        let heartbeat = || {
            frame(EnrollGithubResponse {
                event: Some(enroll_github_response::Event::Heartbeat(Default::default())),
                ..Default::default()
            })
        };
        // Heartbeats on either side of the challenge are skipped (#6384).
        let mut body = heartbeat();
        body.extend(frame(github_challenge("https://github.com/login/device")));
        body.extend(heartbeat());
        body.extend(heartbeat());
        body.extend(frame(EnrollGithubResponse {
            event: Some(enroll_github_response::Event::Credential(Box::new(
                Credential {
                    id: "stored-github-id".into(),
                    name: "work".into(),
                    provider: "github".into(),
                    authentication_kind: CredentialAuthenticationKind::Oauth.into(),
                    revocation_generation: 9_007_199_254_740_993,
                    ..Default::default()
                },
            ))),
            pending_permissions: vec![GithubAppPendingPermissions {
                account: "octo-org".into(),
                installation_id: 43,
                account_kind: GithubAppAccountKind::Organization.into(),
                ..Default::default()
            }],
            ..Default::default()
        }));
        stream_at(
            &server,
            "/codewire.v1.CredentialMutationService/EnrollGithub",
            &mut body,
        )
        .await;
        let mut challenges = 0;
        let result = client(&server)
            .enroll_github(
                EnrollGithubRequest {
                    name: "work".into(),
                    ..Default::default()
                },
                |challenge| {
                    challenges += 1;
                    assert_eq!(challenge.user_code, "ABCD-1234");
                    assert!(!format!("{challenge:?}").contains("ABCD-1234"));
                    true
                },
            )
            .await
            .unwrap();
        assert_eq!(challenges, 1);
        assert_eq!(result.credential.id, "stored-github-id");
        assert_eq!(
            result.credential.revocation_generation,
            9_007_199_254_740_993
        );
        assert_eq!(
            result.pending_permissions,
            [GithubAppPendingPermissions {
                account: "octo-org".into(),
                installation_id: 43,
                account_kind: GithubAppAccountKind::Organization.into(),
                ..Default::default()
            }]
        );
        server.verify().await;
        let request: EnrollGithubRequest = enrollment_request(&server).await;
        assert!(request.accepts_heartbeats);
    }

    #[tokio::test]
    async fn github_enrollment_renders_only_closed_post_challenge_failure_classes() {
        for (code, reason, domain, expected_code, expected_message) in [
            (
                "failed_precondition",
                "CREDENTIAL_ENROLLMENT_FAILED",
                "codewire.sh",
                ErrorCode::FailedPrecondition,
                "isolated GitHub enrollment did not complete; no platform credential was stored",
            ),
            (
                "failed_precondition",
                "CREDENTIAL_ENROLLMENT_UNSUPPORTED",
                "codewire.sh",
                ErrorCode::FailedPrecondition,
                "isolated GitHub enrollment output is unsupported; no platform credential was stored",
            ),
            (
                "failed_precondition",
                "CREDENTIAL_ENROLLMENT_NOT_PUBLISHED",
                "codewire.sh",
                ErrorCode::FailedPrecondition,
                "GitHub enrollment did not reach platform publication; no platform credential was stored",
            ),
            (
                "failed_precondition",
                "CREDENTIAL_GITHUB_INSTALLATION_REQUIRED",
                "codewire.sh",
                ErrorCode::FailedPrecondition,
                NOT_INSTALLED_WITHOUT_LINK,
            ),
            (
                "failed_precondition",
                "CREDENTIAL_ENROLLMENT_FAILED",
                "untrusted.invalid",
                ErrorCode::Unknown,
                "GitHub enrollment acknowledgement is unknown; reconcile the credential by name before retrying",
            ),
            (
                "failed_precondition",
                "CREDENTIAL_GITHUB_INSTALLATION_REQUIRED",
                "untrusted.invalid",
                ErrorCode::Unknown,
                "GitHub enrollment acknowledgement is unknown; reconcile the credential by name before retrying",
            ),
            (
                "unknown",
                "CREDENTIAL_MUTATION_UNCERTAIN",
                "codewire.sh",
                ErrorCode::Unknown,
                "GitHub enrollment acknowledgement is unknown; reconcile the credential by name before retrying",
            ),
        ] {
            let server = MockServer::start().await;
            let mut body = frame(github_challenge("https://github.com/login/device"));
            let terminal = github_terminal_error(code, reason, domain);
            stream_at_terminal(
                &server,
                "/codewire.v1.CredentialMutationService/EnrollGithub",
                &mut body,
                &terminal,
            )
            .await;
            let error = client(&server)
                .enroll_github(
                    EnrollGithubRequest {
                        name: "work".into(),
                        ..Default::default()
                    },
                    |_| true,
                )
                .await
                .unwrap_err();
            assert_eq!(error.code(), expected_code);
            assert_eq!(error.message(), expected_message);
            assert!(!error.message().contains("private provider"));
            assert!(error.reason().is_none());
            server.verify().await;
        }
    }

    const NOT_INSTALLED_WITHOUT_LINK: &str = "the Codewire GitHub App is not installed on any account this GitHub login can use; install it, choose the accounts and repositories, then connect again";

    /// The installation refusal after the challenge, carrying `metadata`.
    async fn github_installation_refusal(metadata: &[(&str, &str)]) -> ClientError {
        let server = MockServer::start().await;
        let mut body = frame(github_challenge("https://github.com/login/device"));
        let terminal = github_terminal_error_with(
            "failed_precondition",
            "CREDENTIAL_GITHUB_INSTALLATION_REQUIRED",
            "codewire.sh",
            metadata,
        );
        stream_at_terminal(
            &server,
            "/codewire.v1.CredentialMutationService/EnrollGithub",
            &mut body,
            &terminal,
        )
        .await;
        let error = client(&server)
            .enroll_github(
                EnrollGithubRequest {
                    name: "work".into(),
                    ..Default::default()
                },
                |_| true,
            )
            .await
            .unwrap_err();
        server.verify().await;
        assert_eq!(error.code(), ErrorCode::FailedPrecondition);
        assert!(error.reason().is_none());
        error
    }

    #[tokio::test]
    async fn github_installation_refusal_links_the_servers_own_app() {
        let link = "https://github.com/apps/codewire-synthetic/installations/new";
        let error = github_installation_refusal(&[("install_url", link)]).await;
        assert_eq!(
            error.message(),
            format!("{NOT_INSTALLED_WITHOUT_LINK}: {link}")
        );
        // The server names no App: the sentence, and never Codewire's link.
        let error = github_installation_refusal(&[]).await;
        assert_eq!(error.message(), NOT_INSTALLED_WITHOUT_LINK);
    }

    #[tokio::test]
    async fn github_installation_refusal_never_shows_a_malformed_link() {
        let overlong = format!(
            "https://github.com/apps/{}/installations/new",
            "a".repeat(101)
        );
        for (key, value) in [
            (
                "install_url",
                "http://github.com/apps/codewire-sh/installations/new",
            ),
            (
                "install_url",
                "https://evil.example/apps/codewire-sh/installations/new",
            ),
            (
                "install_url",
                "https://github.com.evil.example/apps/codewire-sh/installations/new",
            ),
            (
                "install_url",
                "https://github.com:443/apps/codewire-sh/installations/new",
            ),
            (
                "install_url",
                "https://user@github.com/apps/codewire-sh/installations/new",
            ),
            (
                "install_url",
                "https://github.com/apps/codewire-sh/installations/new?next=x",
            ),
            (
                "install_url",
                "https://github.com/apps/codewire-sh/installations/new#x",
            ),
            (
                "install_url",
                "https://github.com/apps/codewire-sh/installations/new/",
            ),
            (
                "install_url",
                "https://github.com/apps/codewire-sh/extra/installations/new",
            ),
            (
                "install_url",
                "https://github.com/apps/codewire-sh/installations/select_target",
            ),
            (
                "install_url",
                "HTTPS://GITHUB.COM/apps/codewire-sh/installations/new",
            ),
            (
                "install_url",
                "https://github.com/apps/Codewire/installations/new",
            ),
            (
                "install_url",
                "https://github.com/apps/code_wire/installations/new",
            ),
            (
                "install_url",
                "https://github.com/apps/-codewire/installations/new",
            ),
            ("install_url", "https://github.com/apps//installations/new"),
            (
                "install_url",
                "https://github.com/apps/code%2Fwire/installations/new",
            ),
            (
                "install_url",
                "https://github.com/apps/codewire-sh/installations/new\n",
            ),
            (
                "install_url",
                " https://github.com/apps/codewire-sh/installations/new",
            ),
            (
                "install_url",
                "https://github.com/apps/code\u{1b}[31mwire/installations/new",
            ),
            (
                "install_url",
                "\u{1b}]8;;https://evil.example\u{7}https://github.com/apps/codewire-sh/installations/new",
            ),
            ("install_url", overlong.as_str()),
            ("install_url", ""),
            (
                "url",
                "https://github.com/apps/codewire-sh/installations/new",
            ),
        ] {
            let error = github_installation_refusal(&[(key, value)]).await;
            assert_eq!(
                error.message(),
                NOT_INSTALLED_WITHOUT_LINK,
                "{key}={value:?}"
            );
        }
    }

    #[tokio::test]
    async fn github_already_connected_before_any_challenge_is_a_definite_refusal() {
        for (code, reason, domain, expected_code) in [
            (
                "already_exists",
                "CREDENTIAL_GITHUB_ALREADY_CONNECTED",
                "codewire.sh",
                ErrorCode::AlreadyExists,
            ),
            (
                "already_exists",
                "CREDENTIAL_GITHUB_ALREADY_CONNECTED",
                "untrusted.invalid",
                ErrorCode::Unknown,
            ),
            (
                "already_exists",
                "CREDENTIAL_MUTATION_UNCERTAIN",
                "codewire.sh",
                ErrorCode::Unknown,
            ),
            (
                "failed_precondition",
                "CREDENTIAL_GITHUB_ALREADY_CONNECTED",
                "codewire.sh",
                ErrorCode::Unknown,
            ),
        ] {
            let server = MockServer::start().await;
            let terminal = github_terminal_error(code, reason, domain);
            stream_at_terminal(
                &server,
                "/codewire.v1.CredentialMutationService/EnrollGithub",
                &mut Vec::new(),
                &terminal,
            )
            .await;
            let mut prompts = 0;
            let error = client(&server)
                .enroll_github(
                    EnrollGithubRequest {
                        name: "other".into(),
                        ..Default::default()
                    },
                    |_| {
                        prompts += 1;
                        true
                    },
                )
                .await
                .unwrap_err();
            assert_eq!(error.code(), expected_code, "{reason} from {domain}");
            assert_eq!(prompts, 0);
            assert!(!error.message().contains("private provider"));
            if expected_code == ErrorCode::AlreadyExists {
                assert_eq!(
                    error.message(),
                    "GitHub is already connected for this account; no platform credential was changed"
                );
            }
            server.verify().await;
        }
    }

    /// The refusal of a name that starts with a provider names exactly the
    /// providers a name is unique within, read from `codewire-access`'s own
    /// list, which this crate doesn't depend on.
    #[test]
    fn a_name_reserving_a_provider_names_every_provider() {
        const NAMES: &str = include_str!("../../codewire-access/src/credential_name.rs");
        let (_, list) = NAMES
            .split_once("pub const CREDENTIAL_NAME_PROVIDERS: [&str; ")
            .and_then(|(_, rest)| rest.split_once("= ["))
            .expect("the provider list moved");
        let (list, _) = list.split_once(']').expect("the provider list moved");
        let prefixes: Vec<String> = list
            .split(',')
            .map(|provider| format!("{}/", provider.trim().trim_matches('"')))
            .collect();
        let (last, rest) = prefixes.split_last().expect("a provider");
        let listed = format!("{} or {last}", rest.join(", "));
        assert!(
            GITHUB_NAME_RESERVES_PROVIDER
                .starts_with(&format!("a credential's name can't start with {listed}, ")),
            "{listed}"
        );
    }

    /// The closed reasons the credential service's mutation wire sends, each
    /// with its Connect code, read from the service's own `error` function so
    /// that a reason added there can't reach this client unclassified.
    fn service_mutation_reasons() -> Vec<(&'static str, String)> {
        const WIRE: &str = include_str!("../../codewire-credential-service/src/mutation/wire.rs");
        let between = |start: &str, end: &str| -> &'static str {
            let (_, rest) = WIRE.split_once(start).expect("the service's match moved");
            rest.split_once(end).expect("the service's match moved").0
        };
        let codes = between("let (code, message) = match error {", "\n    };");
        let reasons = between("let reason = match error {", "_ => \"\",");
        let pairs: Vec<_> = reasons
            .lines()
            .filter_map(|line| line.trim().strip_prefix("Error::"))
            .map(|arm| {
                let (variant, reason) = arm.split_once(" => ").expect("one arm per line");
                let (_, after) = codes
                    .split_once(&format!("Error::{variant} =>"))
                    .unwrap_or_else(|| panic!("{variant} has no code"));
                let (_, code) = after.split_once("ConnectCode::").expect("a Connect code");
                let code: String = code
                    .chars()
                    .take_while(char::is_ascii_alphanumeric)
                    .collect();
                (reason.trim_end_matches(',').trim_matches('"'), code)
            })
            .collect();
        assert!(pairs.len() >= 10, "read {pairs:?}");
        pairs
    }

    /// `FailedPrecondition` as the Connect wire spells it.
    fn wire_code(code: &str) -> String {
        code.chars()
            .enumerate()
            .fold(String::new(), |mut wire, (index, c)| {
                if c.is_ascii_uppercase() && index > 0 {
                    wire.push('_');
                }
                wire.push(c.to_ascii_lowercase());
                wire
            })
    }

    #[tokio::test]
    async fn github_enrollment_classifies_every_reason_the_service_sends() {
        const UNKNOWN: Option<(ErrorCode, &str)> = None;
        // What the person reads for each reason, before the device challenge
        // and after it. UNKNOWN is a decision, never a default: the service
        // can't tell (uncertain, cleanup), the person reconciles first
        // (revision), or EnrollGithub never sends it (Claude; in use, which
        // only a delete sends).
        let expected = [
            ("CREDENTIAL_REVISION_CHANGED", UNKNOWN, UNKNOWN),
            ("CREDENTIAL_IN_USE", UNKNOWN, UNKNOWN),
            (
                "CREDENTIAL_ENROLLMENT_FAILED",
                UNKNOWN,
                Some((
                    ErrorCode::FailedPrecondition,
                    "isolated GitHub enrollment did not complete; no platform credential was stored",
                )),
            ),
            (
                "CREDENTIAL_ENROLLMENT_UNSUPPORTED",
                UNKNOWN,
                Some((
                    ErrorCode::FailedPrecondition,
                    "isolated GitHub enrollment output is unsupported; no platform credential was stored",
                )),
            ),
            (
                "CREDENTIAL_ENROLLMENT_NOT_PUBLISHED",
                UNKNOWN,
                Some((
                    ErrorCode::FailedPrecondition,
                    "GitHub enrollment did not reach platform publication; no platform credential was stored",
                )),
            ),
            (
                "CREDENTIAL_ENROLLMENT_EXPIRED",
                UNKNOWN,
                Some((
                    ErrorCode::FailedPrecondition,
                    "GitHub was not approved in time; no platform credential was stored; connect again for a new code",
                )),
            ),
            (
                "CREDENTIAL_GITHUB_INSTALLATION_REQUIRED",
                UNKNOWN,
                Some((ErrorCode::FailedPrecondition, NOT_INSTALLED_WITHOUT_LINK)),
            ),
            (
                "CREDENTIAL_GITHUB_ALREADY_CONNECTED",
                Some((
                    ErrorCode::AlreadyExists,
                    "GitHub is already connected for this account; no platform credential was changed",
                )),
                UNKNOWN,
            ),
            (
                "CREDENTIAL_GITHUB_APP_NOT_CONFIGURED",
                Some((
                    ErrorCode::FailedPrecondition,
                    "GitHub App authorization is not configured on this Codewire server; no platform credential was changed; ask an administrator to finish the GitHub App setup",
                )),
                UNKNOWN,
            ),
            ("CREDENTIAL_ENROLLMENT_CLEANUP_FAILED", UNKNOWN, UNKNOWN),
            ("CREDENTIAL_MUTATION_UNCERTAIN", UNKNOWN, UNKNOWN),
            ("CREDENTIAL_CLAUDE_SIGN_IN_CODE_INVALID", UNKNOWN, UNKNOWN),
            ("CREDENTIAL_CLAUDE_SIGN_IN_EXPIRED", UNKNOWN, UNKNOWN),
            (
                "CREDENTIAL_ANTIGRAVITY_SIGN_IN_CODE_INVALID",
                UNKNOWN,
                UNKNOWN,
            ),
            ("CREDENTIAL_ANTIGRAVITY_SIGN_IN_EXPIRED", UNKNOWN, UNKNOWN),
            // After the challenge the service names a new credential after the
            // GitHub login, which has no `/`, so only the requested name can
            // reserve a provider.
            (
                "CREDENTIAL_NAME_RESERVES_PROVIDER",
                Some((ErrorCode::InvalidArgument, GITHUB_NAME_RESERVES_PROVIDER)),
                UNKNOWN,
            ),
        ];
        let sent = service_mutation_reasons();
        assert_eq!(
            sent.iter()
                .map(|(reason, _)| *reason)
                .collect::<std::collections::BTreeSet<_>>(),
            expected
                .iter()
                .map(|(reason, ..)| *reason)
                .collect::<std::collections::BTreeSet<_>>(),
            "classify every reason the credential service sends, before and after the challenge"
        );
        for (reason, code) in sent {
            let (_, before, after) = expected
                .iter()
                .find(|(expected, ..)| *expected == reason)
                .unwrap();
            for (challenged, rendered) in [(false, before), (true, after)] {
                let server = MockServer::start().await;
                let mut body = if challenged {
                    frame(github_challenge("https://github.com/login/device"))
                } else {
                    Vec::new()
                };
                let terminal = github_terminal_error(&wire_code(&code), reason, "codewire.sh");
                stream_at_terminal(
                    &server,
                    "/codewire.v1.CredentialMutationService/EnrollGithub",
                    &mut body,
                    &terminal,
                )
                .await;
                let error = client(&server)
                    .enroll_github(
                        EnrollGithubRequest {
                            name: "work".into(),
                            ..Default::default()
                        },
                        |_| true,
                    )
                    .await
                    .unwrap_err();
                let (expected_code, expected_message) = rendered.unwrap_or((
                    ErrorCode::Unknown,
                    "GitHub enrollment acknowledgement is unknown; reconcile the credential by name before retrying",
                ));
                assert_eq!(
                    (error.code(), error.message()),
                    (expected_code, expected_message),
                    "{reason} ({code}), challenged: {challenged}"
                );
                assert!(error.reason().is_none());
                server.verify().await;
            }
        }
    }

    #[tokio::test]
    async fn github_missing_ack_cancel_duplicate_or_foreign_prompt_never_retries() {
        for case in ["missing", "cancel", "duplicate", "foreign", "empty"] {
            let server = MockServer::start().await;
            let mut body = if case == "empty" {
                Vec::new()
            } else {
                frame(github_challenge(if case == "foreign" {
                    "https://untrusted.invalid/device"
                } else {
                    "https://github.com/login/device"
                }))
            };
            if case == "duplicate" {
                body.extend(frame(github_challenge("https://github.com/login/device")));
            }
            stream_at(
                &server,
                "/codewire.v1.CredentialMutationService/EnrollGithub",
                &mut body,
            )
            .await;
            let mut prompts = 0;
            let error = client(&server)
                .enroll_github(
                    EnrollGithubRequest {
                        name: "work".into(),
                        ..Default::default()
                    },
                    |_| {
                        prompts += 1;
                        case != "cancel"
                    },
                )
                .await
                .unwrap_err();
            assert_eq!(error.code(), ErrorCode::Unknown);
            assert!(!error.message().contains("ABCD-1234"));
            assert_eq!(prompts, usize::from(!matches!(case, "foreign" | "empty")));
            server.verify().await;
        }
    }
}
