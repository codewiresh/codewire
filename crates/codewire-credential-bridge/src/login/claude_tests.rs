//! The Claude login shares the Codex login's path (tests.rs covers its
//! epochs, cancellation and limits); these tests cover what is its own: its
//! capability, frames and sealed format, and that the two never cross.

use codewire_workload_secrets::{ClaudeLogin, CodexLoginBinding, seal_claude_login};
use zeroize::Zeroizing;

use super::*;

type HostPayload = v1::credential_bridge_host_message::Payload;
type ClaudeResult = v1::claude_login_response::Result;
type CodexResult = v1::codex_login_response::Result;

const ACCESS: &str = "sk-ant-oat01-synthetic-claude-login-canary";

fn claude() -> String {
    codewire_daemon_proto::CREDENTIAL_BRIDGE_CAPABILITY_CLAUDE_LOGIN.to_owned()
}

fn codex() -> String {
    codewire_daemon_proto::CREDENTIAL_BRIDGE_CAPABILITY_CODEX_LOGIN.to_owned()
}

struct Harness {
    bridge: CredentialBridge,
    input: mpsc::Sender<Result<v1::CredentialBridgeHostMessage, Status>>,
    output: CredentialBridgeOutput,
    task: tokio::task::JoinHandle<()>,
}

impl Harness {
    async fn new(capabilities: &[String]) -> Self {
        let bridge = CredentialBridge::new(Uuid::new_v4(), 7).unwrap();
        let (prepared, mut output) = bridge.prepare_connection().unwrap();
        assert!(matches!(
            output.next().await.unwrap().unwrap().payload,
            Some(GuestPayload::Ready(_))
        ));
        let (input, receiver) = mpsc::channel(32);
        let connection = prepared
            .activate_with_capabilities(ReceiverStream::new(receiver), capabilities)
            .await
            .unwrap();
        let task = tokio::spawn(connection.run());
        Self {
            bridge,
            input,
            output,
            task,
        }
    }

    async fn submit(
        &mut self,
    ) -> (
        tokio::task::JoinHandle<Result<OpenedClaudeLogin, LoginFailure>>,
        v1::ClaudeLoginRequest,
    ) {
        let bridge = self.bridge.clone();
        let task = tokio::spawn(async move { bridge.claude_login().await });
        let message = bounded(self.output.next()).await.unwrap().unwrap();
        let Some(GuestPayload::ClaudeLogin(request)) = message.payload else {
            panic!("expected a typed Claude login request");
        };
        (task, request)
    }

    fn seal(&self, request: &v1::ClaudeLoginRequest) -> Vec<u8> {
        let login = ClaudeLogin::new(
            Zeroizing::new(ACCESS.into()),
            1_700_000_000_000,
            vec!["user:inference".into(), "user:profile".into()],
            Some("max".into()),
            Some("default_claude_max_20x".into()),
            1_699_999_000,
        )
        .unwrap();
        let context = CodexLoginContext {
            environment_id: *self.bridge.identity().environment_id.as_bytes(),
            environment_generation: self.bridge.identity().environment_generation,
            request_id: *Uuid::parse_str(&request.request_id).unwrap().as_bytes(),
            deadline_unix_ms: request.deadline_unix_ms,
        };
        seal_claude_login(
            &login,
            &CodexLoginBinding {
                credential_id: "credential-claude".into(),
                revocation_generation: 2,
                material_generation: 3,
            },
            &context,
            request.recipient_public_key.as_slice().try_into().unwrap(),
            login_now_unix_ms().unwrap(),
        )
        .unwrap()
    }

    async fn send(&self, payload: HostPayload) {
        self.input
            .send(Ok(v1::CredentialBridgeHostMessage {
                payload: Some(payload),
            }))
            .await
            .unwrap();
    }

    async fn reply(&self, request_id: &str, result: ClaudeResult) {
        self.send(HostPayload::ClaudeLogin(v1::ClaudeLoginResponse {
            request_id: request_id.to_owned(),
            result: Some(result),
        }))
        .await;
    }

    async fn stop(self) {
        drop(self.input);
        bounded(self.task).await.unwrap();
    }
}

async fn bounded<F: Future>(future: F) -> F::Output {
    tokio::time::timeout(Duration::from_secs(2), future)
        .await
        .expect("bounded Claude login fixture")
}

#[tokio::test]
async fn each_login_needs_its_own_capability() {
    // A host listing only codex-login is never sent a Claude login request.
    let mut codex_only = Harness::new(&[codex()]).await;
    assert!(codex_only.bridge.supports_codex_login().await);
    assert!(!codex_only.bridge.supports_claude_login().await);
    assert_eq!(
        codex_only.bridge.claude_login().await.unwrap_err(),
        LoginFailure::Unsupported
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(20), codex_only.output.next())
            .await
            .is_err()
    );
    codex_only.stop().await;

    let mut claude_only = Harness::new(&[claude()]).await;
    assert!(claude_only.bridge.supports_claude_login().await);
    assert!(!claude_only.bridge.supports_codex_login().await);
    assert_eq!(
        claude_only.bridge.codex_login().await.unwrap_err(),
        LoginFailure::Unsupported
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(20), claude_only.output.next())
            .await
            .is_err()
    );
    claude_only.stop().await;

    let both = Harness::new(&[codex(), claude()]).await;
    assert!(both.bridge.supports_codex_login().await);
    assert!(both.bridge.supports_claude_login().await);
    both.stop().await;
}

#[tokio::test]
async fn a_sealed_claude_login_round_trips_and_failures_stay_distinct() {
    let mut harness = Harness::new(&[claude()]).await;
    let (task, request) = harness.submit().await;
    assert!(Uuid::parse_str(&request.request_id).is_ok_and(|id| !id.is_nil()));
    assert_eq!(request.recipient_public_key.len(), 32);
    let remaining = request
        .deadline_unix_ms
        .saturating_sub(login_now_unix_ms().unwrap());
    assert!(remaining > 0 && remaining <= LOGIN_REQUEST_LIFETIME.as_millis() as u64);
    let sealed = harness.seal(&request);
    assert!(
        !sealed
            .windows(ACCESS.len())
            .any(|part| part == ACCESS.as_bytes())
    );
    harness
        .reply(&request.request_id, ClaudeResult::SealedLogin(sealed))
        .await;
    let opened = bounded(task).await.unwrap().unwrap();
    assert_eq!(opened.login.access_token(), ACCESS);
    assert_eq!(opened.login.subscription_type(), Some("max"));
    assert_eq!(opened.binding.credential_id, "credential-claude");
    assert!(harness.bridge.inner.lock().await.logins.is_empty());

    for (reason, expected) in [
        (
            v1::CredentialBridgeFailureReason::Denied,
            LoginFailure::Denied,
        ),
        (
            v1::CredentialBridgeFailureReason::Unavailable,
            LoginFailure::Unavailable,
        ),
    ] {
        let (task, request) = harness.submit().await;
        harness
            .reply(&request.request_id, ClaudeResult::Failure(reason as i32))
            .await;
        assert_eq!(bounded(task).await.unwrap().unwrap_err(), expected);
    }
    assert!(harness.bridge.supports_claude_login().await);
    harness.stop().await;
}

#[tokio::test]
async fn a_codex_frame_never_answers_a_claude_request_nor_the_reverse() {
    // A Codex answer to a Claude request ends the epoch; the request fails.
    let mut harness = Harness::new(&[codex(), claude()]).await;
    let (task, request) = harness.submit().await;
    harness
        .send(HostPayload::CodexLogin(v1::CodexLoginResponse {
            request_id: request.request_id.clone(),
            result: Some(CodexResult::Failure(
                v1::CredentialBridgeFailureReason::Denied as i32,
            )),
        }))
        .await;
    let status = bounded(harness.output.next()).await.unwrap().unwrap_err();
    assert_eq!(status.code(), tonic::Code::InvalidArgument);
    assert_eq!(
        bounded(task).await.unwrap().unwrap_err(),
        LoginFailure::Unavailable
    );
    harness.stop().await;

    // A Claude answer to a Codex request ends the epoch too.
    let mut harness = Harness::new(&[codex(), claude()]).await;
    let bridge = harness.bridge.clone();
    let task = tokio::spawn(async move { bridge.codex_login().await });
    let message = bounded(harness.output.next()).await.unwrap().unwrap();
    let Some(GuestPayload::CodexLogin(request)) = message.payload else {
        panic!("expected a typed Codex login request");
    };
    harness
        .reply(
            &request.request_id,
            ClaudeResult::Failure(v1::CredentialBridgeFailureReason::Denied as i32),
        )
        .await;
    let status = bounded(harness.output.next()).await.unwrap().unwrap_err();
    assert_eq!(status.code(), tonic::Code::InvalidArgument);
    assert_eq!(
        bounded(task).await.unwrap().unwrap_err(),
        LoginFailure::Unavailable
    );
    harness.stop().await;
}

#[tokio::test]
async fn malformed_claude_answers_end_the_epoch() {
    for case in 0..4 {
        let mut harness = Harness::new(&[claude()]).await;
        let (task, request) = harness.submit().await;
        let result = match case {
            0 => Some(ClaudeResult::SealedLogin(Vec::new())),
            1 => Some(ClaudeResult::SealedLogin(vec![
                1;
                MAX_SEALED_CLAUDE_LOGIN_BYTES
                    + 1
            ])),
            2 => Some(ClaudeResult::Failure(
                v1::CredentialBridgeFailureReason::ResponseTooLarge as i32,
            )),
            _ => None,
        };
        harness
            .send(HostPayload::ClaudeLogin(v1::ClaudeLoginResponse {
                request_id: request.request_id.clone(),
                result,
            }))
            .await;
        let status = bounded(harness.output.next()).await.unwrap().unwrap_err();
        assert_eq!(status.code(), tonic::Code::InvalidArgument, "case {case}");
        assert_eq!(
            bounded(task).await.unwrap().unwrap_err(),
            LoginFailure::Unavailable
        );
        harness.stop().await;
    }
}

#[tokio::test]
async fn application_http_ingress_cannot_request_a_claude_login() {
    let harness = Harness::new(&[claude()]).await;
    for path in ["/claude-login", "/_codewire/claude-login"] {
        let response = harness
            .bridge
            .respond(
                Request::builder()
                    .method(Method::POST)
                    .uri(path)
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
    assert!(harness.bridge.inner.lock().await.logins.is_empty());
    harness.stop().await;
}
