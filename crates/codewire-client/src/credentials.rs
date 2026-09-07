//! Personal metadata and one-connection provider enrollment, never raw tokens.

use crate::*;

impl CodewireClient {
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

    fn frame(message: EnrollCodexResponse) -> Vec<u8> {
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
        // Real Connect envelopes, including the terminal JSON envelope.
        body.extend_from_slice(&[2, 0, 0, 0, 2, b'{', b'}']);
        Mock::given(method("POST"))
            .and(path("/codewire.v1.CredentialMutationService/EnrollCodex"))
            .and(header(
                "authorization",
                "Bearer synthetic-credential-client-oauth",
            ))
            .and(header("connect-timeout-ms", "960000"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/connect+proto")
                    .set_body_bytes(body),
            )
            .expect(1)
            .mount(server)
            .await;
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
}
