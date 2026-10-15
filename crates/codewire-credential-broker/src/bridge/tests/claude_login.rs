//! The Claude login shares the Codex login's dispatch (codex_login.rs covers
//! IDs, capacity and the epoch); these tests cover its own frames and that
//! one login of each kind may run at once.

use super::*;

use std::time::Duration;

use tokio::sync::Semaphore;

type Payload = v1::credential_bridge_host_message::Payload;
type ClaudeResult = v1::claude_login_response::Result;

fn claude_login(id: Uuid) -> v1::CredentialBridgeGuestMessage {
    v1::CredentialBridgeGuestMessage {
        payload: Some(v1::credential_bridge_guest_message::Payload::ClaudeLogin(
            v1::ClaudeLoginRequest {
                request_id: id.to_string(),
                recipient_public_key: vec![3; 32],
                deadline_unix_ms: 42,
            },
        )),
    }
}

fn codex_login(id: Uuid) -> v1::CredentialBridgeGuestMessage {
    v1::CredentialBridgeGuestMessage {
        payload: Some(v1::credential_bridge_guest_message::Payload::CodexLogin(
            v1::CodexLoginRequest {
                request_id: id.to_string(),
                recipient_public_key: vec![3; 32],
                deadline_unix_ms: 42,
            },
        )),
    }
}

async fn receive(output: &mut mpsc::Receiver<Payload>) -> Payload {
    tokio::time::timeout(Duration::from_secs(2), output.recv())
        .await
        .expect("bounded bridge response")
        .expect("bridge remains attached")
}

/// Holds each login until released, reporting which kind started.
struct LoginExecutor {
    started: mpsc::UnboundedSender<&'static str>,
    release: Semaphore,
    drains: AtomicUsize,
}

#[async_trait]
impl BrokerRequestExecutor for LoginExecutor {
    async fn execute_request(
        &self,
        _: v1::CredentialBridgeRequest,
    ) -> Result<BrokerHttpResponse, BrokerRequestError> {
        panic!("a login must not use HTTP execution");
    }

    async fn codex_login(
        &self,
        _request: v1::CodexLoginRequest,
    ) -> Result<Vec<u8>, BrokerRequestError> {
        self.started.send("codex").unwrap();
        self.release.acquire().await.unwrap().forget();
        Ok(vec![0xc0; 64])
    }

    async fn claude_login(
        &self,
        _request: v1::ClaudeLoginRequest,
    ) -> Result<Vec<u8>, BrokerRequestError> {
        self.started.send("claude").unwrap();
        self.release.acquire().await.unwrap().forget();
        Ok(vec![0xc1; 64])
    }

    async fn wait_for_active_operations(&self) -> Result<(), BrokerRequestError> {
        self.drains.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

async fn started(receiver: &mut mpsc::UnboundedReceiver<&'static str>) -> &'static str {
    tokio::time::timeout(Duration::from_secs(2), receiver.recv())
        .await
        .unwrap()
        .unwrap()
}

#[tokio::test]
async fn one_login_of_each_kind_runs_at_once_and_each_gets_its_own_frame() {
    let environment_id = Uuid::new_v4();
    let (input, input_rx) = mpsc::channel(8);
    let (output, mut output_rx) = mpsc::channel(4);
    let (started_tx, mut started_rx) = mpsc::unbounded_channel();
    let executor = Arc::new(LoginExecutor {
        started: started_tx,
        release: Semaphore::new(0),
        drains: AtomicUsize::new(0),
    });
    let task = tokio::spawn(run_channel_test_bridge(
        Arc::clone(&executor),
        input_rx,
        output,
        environment_id,
        3,
    ));
    input.send(ready(environment_id, 3)).await.unwrap();

    // A Codex login in flight does not hold back a Claude login.
    let codex = Uuid::new_v4();
    input.send(codex_login(codex)).await.unwrap();
    assert_eq!(started(&mut started_rx).await, "codex");
    let claude = Uuid::new_v4();
    input.send(claude_login(claude)).await.unwrap();
    assert_eq!(started(&mut started_rx).await, "claude");

    // A second Claude login is refused before it leases anything.
    let second = Uuid::new_v4();
    input.send(claude_login(second)).await.unwrap();
    assert!(matches!(
        receive(&mut output_rx).await,
        Payload::ClaudeLogin(response)
            if response.request_id == second.to_string()
            && response.result == Some(ClaudeResult::Failure(
                v1::CredentialBridgeFailureReason::Unavailable as i32
            ))
    ));
    assert!(started_rx.try_recv().is_err(), "a refused login was leased");

    executor.release.add_permits(2);
    let mut answers = Vec::new();
    for _ in 0..2 {
        answers.push(receive(&mut output_rx).await);
    }
    assert!(answers.iter().any(|answer| matches!(
        answer,
        Payload::CodexLogin(response)
            if response.request_id == codex.to_string()
            && response.result
                == Some(v1::codex_login_response::Result::SealedLogin(vec![0xc0; 64]))
    )));
    assert!(answers.iter().any(|answer| matches!(
        answer,
        Payload::ClaudeLogin(response)
            if response.request_id == claude.to_string()
            && response.result == Some(ClaudeResult::SealedLogin(vec![0xc1; 64]))
    )));
    drop(input);
    assert_eq!(task.await.unwrap(), Err(BrokerBridgeError::Unavailable));
    assert_eq!(executor.drains.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn claude_login_answers_are_a_bounded_login_denied_or_unavailable() {
    let maximum = MAX_SEALED_CLAUDE_LOGIN_BYTES;
    let denied = || ClaudeResult::Failure(v1::CredentialBridgeFailureReason::Denied as i32);
    let unavailable =
        || ClaudeResult::Failure(v1::CredentialBridgeFailureReason::Unavailable as i32);
    let cases = [
        (
            Ok(vec![5; maximum]),
            ClaudeResult::SealedLogin(vec![5; maximum]),
        ),
        (Ok(Vec::new()), denied()),
        (Ok(vec![5; maximum + 1]), denied()),
        (Err(BrokerRequestError::Denied), denied()),
        (Err(BrokerRequestError::InvalidRequest), denied()),
        (Err(BrokerRequestError::ReconnectRequired), denied()),
        (Err(BrokerRequestError::AuthorityUnavailable), unavailable()),
        (Err(BrokerRequestError::UpstreamFailed), unavailable()),
        (Err(BrokerRequestError::ResponseTooLarge), unavailable()),
    ];
    for (result, expected) in cases {
        let (output, mut receiver) = mpsc::channel(1);
        let request_id = Uuid::new_v4().to_string();
        send_login_response(
            &FakeSender { output },
            LoginKind::Claude,
            request_id.clone(),
            result,
        )
        .await
        .unwrap();
        let Payload::ClaudeLogin(response) = receive(&mut receiver).await else {
            panic!("typed Claude login response");
        };
        assert_eq!(response.request_id, request_id);
        assert_eq!(response.result, Some(expected));
    }
}

#[tokio::test]
async fn the_default_executor_denies_a_claude_login_without_ending_the_epoch() {
    let environment_id = Uuid::new_v4();
    let (input, input_rx) = mpsc::channel(2);
    let (output, mut output_rx) = mpsc::channel(1);
    let executor = Arc::new(FakeExecutor {
        slow_started: Arc::new(AtomicBool::new(false)),
    });
    let task = tokio::spawn(run_channel_test_bridge(
        executor,
        input_rx,
        output,
        environment_id,
        3,
    ));
    input.send(ready(environment_id, 3)).await.unwrap();
    for _ in 0..2 {
        input.send(claude_login(Uuid::new_v4())).await.unwrap();
        assert!(matches!(
            receive(&mut output_rx).await,
            Payload::ClaudeLogin(v1::ClaudeLoginResponse {
                result: Some(ClaudeResult::Failure(reason)),
                ..
            }) if reason == v1::CredentialBridgeFailureReason::Denied as i32
        ));
    }
    assert!(!task.is_finished());
    drop(input);
    assert_eq!(task.await.unwrap(), Err(BrokerBridgeError::Unavailable));
}
