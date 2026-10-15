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
        request: EnrollCodexRequest,
        mut on_challenge: impl FnMut(CodexDeviceChallenge) -> bool,
    ) -> Result<Credential, ClientError> {
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
            .map_err(|_| enrollment_unknown())?
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
                _ => return Err(enrollment_unknown()),
            }
        }
        Err(enrollment_unknown())
    }

    /// One GitHub device challenge followed by the exact committed identity.
    /// Cancellation or missing acknowledgement never automatically retries.
    pub async fn enroll_github(
        &self,
        request: EnrollGithubRequest,
        mut on_challenge: impl FnMut(GithubDeviceChallenge) -> bool,
    ) -> Result<GithubEnrollment, ClientError> {
        let options = self
            .auth_options()
            .await?
            .with_timeout(Duration::from_secs(16 * 60));
        let mut stream = self
            .credential_mutations
            .enroll_github_with_options(request, options)
            .await
            .map_err(|_| github_enrollment_unknown())?;
        let mut challenged = false;
        loop {
            let message = match stream.message::<EnrollGithubResponse>().await {
                Ok(Some(message)) => message,
                Ok(None) => return Err(github_enrollment_unknown()),
                Err(error) if challenged => return Err(github_enrollment_terminal_error(error)),
                Err(_) => return Err(github_enrollment_unknown()),
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
                _ => return Err(github_enrollment_unknown()),
            }
        }
    }
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

/// A known terminal reason after a verified challenge is safe to render using
/// our own fixed text. Every other close remains an uncertain publication: no
/// peer-supplied message or provider diagnostic crosses this boundary.
fn github_enrollment_terminal_error(error: connectrpc::ConnectError) -> ClientError {
    let error = ClientError::from(error);
    let reason = error
        .error_info()
        .filter(|info| info.domain() == "codewire.sh")
        .map(ErrorInfo::reason);
    match (error.code(), reason) {
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
        let detail = connectrpc::ErrorDetail::from_message(
            "google.rpc.ErrorInfo",
            &GoogleErrorInfo {
                reason: reason.into(),
                domain: domain.into(),
                ..Default::default()
            },
        );
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
        let mut body = frame(challenge());
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
    async fn github_enrollment_delivers_one_safe_challenge_and_committed_oauth_identity() {
        let server = MockServer::start().await;
        let mut body = frame(github_challenge("https://github.com/login/device"));
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
                "CREDENTIAL_ENROLLMENT_FAILED",
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
