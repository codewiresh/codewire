use codewire_workload_secrets::{CodexLogin, CodexLoginBinding, seal_codex_login};
use zeroize::Zeroizing;

use super::*;

type GuestPayload = v1::credential_bridge_guest_message::Payload;
type HostPayload = v1::credential_bridge_host_message::Payload;
type LoginResult = v1::codex_login_response::Result;

const ACCESS: &str = "synthetic.access-token.canary";

fn capabilities() -> Vec<String> {
    vec![codewire_gateway_proto::CREDENTIAL_BRIDGE_CAPABILITY_CODEX_LOGIN.to_owned()]
}

struct Harness {
    bridge: CredentialBridge,
    input: mpsc::Sender<Result<v1::CredentialBridgeHostMessage, Status>>,
    output: CredentialBridgeOutput,
    task: tokio::task::JoinHandle<()>,
}

impl Harness {
    async fn new(bridge: CredentialBridge, capabilities: &[String]) -> Self {
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
        tokio::task::JoinHandle<Result<OpenedCodexLogin, CodexLoginFailure>>,
        v1::CodexLoginRequest,
    ) {
        let bridge = self.bridge.clone();
        let task = tokio::spawn(async move { bridge.codex_login().await });
        let message = bounded(self.output.next()).await.unwrap().unwrap();
        let Some(GuestPayload::CodexLogin(request)) = message.payload else {
            panic!("expected a typed Codex login request");
        };
        (task, request)
    }

    fn seal(&self, request: &v1::CodexLoginRequest, request_id: &str) -> Vec<u8> {
        let login = CodexLogin::new(
            Zeroizing::new(ACCESS.into()),
            Zeroizing::new("synthetic.id-token".into()),
            "account-synthetic".into(),
            1_700_000_000,
        )
        .unwrap();
        let context = CodexLoginContext {
            environment_id: *self.bridge.environment_id.as_bytes(),
            environment_generation: self.bridge.environment_generation,
            request_id: *Uuid::parse_str(request_id).unwrap().as_bytes(),
            deadline_unix_ms: request.deadline_unix_ms,
        };
        seal_codex_login(
            &login,
            &CodexLoginBinding {
                credential_id: "credential-codex".into(),
                revocation_generation: 2,
                material_generation: 3,
            },
            &context,
            request.recipient_public_key.as_slice().try_into().unwrap(),
            login_now_unix_ms().unwrap(),
        )
        .unwrap()
    }

    async fn reply(&self, request_id: &str, result: LoginResult) {
        self.input
            .send(Ok(v1::CredentialBridgeHostMessage {
                payload: Some(HostPayload::CodexLogin(v1::CodexLoginResponse {
                    request_id: request_id.to_owned(),
                    result: Some(result),
                })),
            }))
            .await
            .unwrap();
    }

    async fn stop(self) {
        drop(self.input);
        bounded(self.task).await.unwrap();
    }
}

fn bridge() -> CredentialBridge {
    CredentialBridge::new(Uuid::new_v4(), 7).unwrap()
}

async fn bounded<F: Future>(future: F) -> F::Output {
    tokio::time::timeout(Duration::from_secs(2), future)
        .await
        .expect("bounded Codex login fixture")
}

#[tokio::test]
async fn an_epoch_without_the_capability_is_never_sent_the_operation() {
    let bridge = bridge();
    // No admitted epoch at all: transient, nothing to send to.
    assert!(!bridge.supports_codex_login().await);
    assert_eq!(
        bridge.codex_login().await.unwrap_err(),
        CodexLoginFailure::Unavailable
    );
    // An older broker or gateway lists nothing: refuse without sending.
    let mut old = Harness::new(bridge.clone(), &[]).await;
    assert!(!bridge.supports_codex_login().await);
    assert_eq!(
        bridge.codex_login().await.unwrap_err(),
        CodexLoginFailure::Unsupported
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(20), old.output.next())
            .await
            .is_err()
    );
    assert!(bridge.inner.lock().await.codex_logins.is_empty());
    // An unknown capability enables nothing either.
    let unknown = Harness::new(bridge.clone(), &["future-op".to_owned()]).await;
    assert!(!bridge.supports_codex_login().await);
    old.stop().await;
    unknown.stop().await;
    // The capability is per epoch: a current host lists it.
    let current = Harness::new(bridge.clone(), &capabilities()).await;
    assert!(bridge.supports_codex_login().await);
    current.stop().await;
    assert!(!bridge.supports_codex_login().await);
}

#[tokio::test]
async fn malformed_capability_lists_refuse_activation() {
    for capabilities in [
        vec!["Codex-Login".to_owned()],
        vec![String::new()],
        vec!["x".repeat(codewire_gateway_proto::CREDENTIAL_BRIDGE_MAX_CAPABILITY_BYTES + 1)],
        vec!["a".to_owned(); codewire_gateway_proto::CREDENTIAL_BRIDGE_MAX_CAPABILITIES + 1],
    ] {
        let bridge = bridge();
        let (prepared, _output) = bridge.prepare_connection().unwrap();
        let (_input, receiver) = mpsc::channel(1);
        assert!(
            prepared
                .activate_with_capabilities(ReceiverStream::new(receiver), &capabilities)
                .await
                .is_err()
        );
        assert!(bridge.inner.lock().await.active.is_none());
    }
}

#[tokio::test]
async fn sealed_login_round_trips_to_the_requesting_recipient_only() {
    let mut harness = Harness::new(bridge(), &capabilities()).await;
    let (task, request) = harness.submit().await;
    let request_id = request.request_id.clone();
    assert!(Uuid::parse_str(&request_id).is_ok_and(|id| !id.is_nil()));
    assert_eq!(request.recipient_public_key.len(), 32);
    let remaining = request
        .deadline_unix_ms
        .saturating_sub(login_now_unix_ms().unwrap());
    assert!(remaining > 0 && remaining <= CODEX_LOGIN_REQUEST_LIFETIME.as_millis() as u64);
    let sealed = harness.seal(&request, &request_id);
    assert!(
        !sealed
            .windows(ACCESS.len())
            .any(|part| part == ACCESS.as_bytes())
    );
    harness
        .reply(&request_id, LoginResult::SealedLogin(sealed))
        .await;
    let opened = bounded(task).await.unwrap().unwrap();
    assert_eq!(opened.login.access_token(), ACCESS);
    assert_eq!(opened.binding.material_generation, 3);
    assert!(harness.bridge.inner.lock().await.codex_logins.is_empty());

    // A login sealed for a different request does not open for this one.
    let (task, request) = harness.submit().await;
    let sealed = harness.seal(&request, &Uuid::new_v4().to_string());
    harness
        .reply(&request.request_id, LoginResult::SealedLogin(sealed))
        .await;
    assert_eq!(
        bounded(task).await.unwrap().unwrap_err(),
        CodexLoginFailure::Unavailable
    );
    harness.stop().await;
}

#[tokio::test]
async fn denied_and_unavailable_answers_stay_distinct_and_keep_the_epoch() {
    let mut harness = Harness::new(bridge(), &capabilities()).await;
    for (reason, expected) in [
        (
            v1::CredentialBridgeFailureReason::Denied,
            CodexLoginFailure::Denied,
        ),
        (
            v1::CredentialBridgeFailureReason::Unavailable,
            CodexLoginFailure::Unavailable,
        ),
    ] {
        let (task, request) = harness.submit().await;
        harness
            .reply(&request.request_id, LoginResult::Failure(reason as i32))
            .await;
        assert_eq!(bounded(task).await.unwrap().unwrap_err(), expected);
    }
    assert!(harness.bridge.supports_codex_login().await);
    harness.stop().await;
}

#[tokio::test]
async fn pending_logins_fail_when_their_epoch_is_lost_or_replaced() {
    // Transport loss.
    let mut harness = Harness::new(bridge(), &capabilities()).await;
    let (task, _request) = harness.submit().await;
    let bridge = harness.bridge.clone();
    harness.stop().await;
    assert_eq!(
        bounded(task).await.unwrap().unwrap_err(),
        CodexLoginFailure::Unavailable
    );
    assert!(bridge.inner.lock().await.codex_logins.is_empty());

    // Replacement by a newer epoch; its late answer is never released.
    let mut first = Harness::new(bridge.clone(), &capabilities()).await;
    let (task, request) = first.submit().await;
    let second = Harness::new(bridge.clone(), &capabilities()).await;
    assert_eq!(
        bounded(task).await.unwrap().unwrap_err(),
        CodexLoginFailure::Unavailable
    );
    assert!(bridge.inner.lock().await.codex_logins.is_empty());
    let sealed = first.seal(&request, &request.request_id);
    let _ = first
        .input
        .send(Ok(v1::CredentialBridgeHostMessage {
            payload: Some(HostPayload::CodexLogin(v1::CodexLoginResponse {
                request_id: request.request_id.clone(),
                result: Some(LoginResult::SealedLogin(sealed)),
            })),
        }))
        .await;
    first.stop().await;
    second.stop().await;
}

#[tokio::test]
async fn cancellation_keeps_the_slot_until_the_late_answer_drains() {
    let mut harness = Harness::new(bridge(), &capabilities()).await;
    let (task, request) = harness.submit().await;
    task.abort();
    assert!(bounded(task).await.unwrap_err().is_cancelled());
    let cancel = bounded(harness.output.next()).await.unwrap().unwrap();
    assert!(matches!(
        cancel.payload,
        Some(GuestPayload::Cancel(ref cancel)) if cancel.request_id == request.request_id
    ));
    assert_eq!(harness.bridge.inner.lock().await.codex_logins.len(), 1);
    let sealed = harness.seal(&request, &request.request_id);
    harness
        .reply(&request.request_id, LoginResult::SealedLogin(sealed))
        .await;
    // A second round trip proves the late answer was drained, not fatal.
    let (task, request) = harness.submit().await;
    harness
        .reply(
            &request.request_id,
            LoginResult::Failure(v1::CredentialBridgeFailureReason::Denied as i32),
        )
        .await;
    assert_eq!(
        bounded(task).await.unwrap().unwrap_err(),
        CodexLoginFailure::Denied
    );
    assert!(harness.bridge.inner.lock().await.codex_logins.is_empty());
    harness.stop().await;
}

#[tokio::test]
async fn malformed_or_unsolicited_login_answers_end_the_epoch() {
    for case in 0..5 {
        let mut harness = Harness::new(bridge(), &capabilities()).await;
        let (task, request) = harness.submit().await;
        let (id, result) = match case {
            0 => (
                Uuid::new_v4().to_string(),
                Some(LoginResult::SealedLogin(vec![1])),
            ),
            1 => (
                request.request_id.clone(),
                Some(LoginResult::SealedLogin(Vec::new())),
            ),
            2 => (
                request.request_id.clone(),
                Some(LoginResult::SealedLogin(vec![
                    1;
                    MAX_SEALED_CODEX_LOGIN_BYTES
                        + 1
                ])),
            ),
            3 => (
                request.request_id.clone(),
                Some(LoginResult::Failure(
                    v1::CredentialBridgeFailureReason::ResponseTooLarge as i32,
                )),
            ),
            _ => (request.request_id.clone(), None),
        };
        harness
            .input
            .send(Ok(v1::CredentialBridgeHostMessage {
                payload: Some(HostPayload::CodexLogin(v1::CodexLoginResponse {
                    request_id: id,
                    result,
                })),
            }))
            .await
            .unwrap();
        let status = bounded(harness.output.next()).await.unwrap().unwrap_err();
        assert_eq!(status.code(), tonic::Code::InvalidArgument, "case {case}");
        assert_eq!(
            bounded(task).await.unwrap().unwrap_err(),
            CodexLoginFailure::Unavailable
        );
        harness.stop().await;
    }
}

#[tokio::test]
async fn application_http_ingress_cannot_request_a_login() {
    let harness = Harness::new(bridge(), &capabilities()).await;
    for path in ["/codex-login", "/v1/codex-login", "/_codewire/codex-login"] {
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
    assert!(harness.bridge.inner.lock().await.codex_logins.is_empty());
    harness.stop().await;
}
