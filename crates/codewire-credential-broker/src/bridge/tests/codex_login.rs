use super::*;

use std::time::Duration;

use tokio::sync::Semaphore;

type Payload = v1::credential_bridge_host_message::Payload;
type LoginResult = v1::codex_login_response::Result;

fn login(id: Uuid) -> v1::CredentialBridgeGuestMessage {
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

struct LoginExecutor {
    started: mpsc::UnboundedSender<v1::CodexLoginRequest>,
    release: Semaphore,
    result: Result<Vec<u8>, BrokerRequestError>,
    drains: AtomicUsize,
}

#[async_trait]
impl BrokerRequestExecutor for LoginExecutor {
    async fn execute_request(
        &self,
        _: v1::CredentialBridgeRequest,
    ) -> Result<BrokerHttpResponse, BrokerRequestError> {
        panic!("a Codex login or a capacity-denied request must not use HTTP execution");
    }

    async fn codex_login(
        &self,
        request: v1::CodexLoginRequest,
    ) -> Result<Vec<u8>, BrokerRequestError> {
        self.started.send(request).unwrap();
        self.release.acquire().await.unwrap().forget();
        self.result.clone()
    }

    /// Holds a shared in-flight slot until released.
    async fn project_environment(
        &self,
        _request: v1::EnvironmentProjectionRequest,
    ) -> Result<Vec<u8>, BrokerRequestError> {
        self.release.acquire().await.unwrap().forget();
        Ok(vec![1])
    }

    async fn wait_for_active_operations(&self) -> Result<(), BrokerRequestError> {
        self.drains.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

fn executor(
    result: Result<Vec<u8>, BrokerRequestError>,
) -> (
    Arc<LoginExecutor>,
    mpsc::UnboundedReceiver<v1::CodexLoginRequest>,
) {
    let (started, started_rx) = mpsc::unbounded_channel();
    (
        Arc::new(LoginExecutor {
            started,
            release: Semaphore::new(0),
            result,
            drains: AtomicUsize::new(0),
        }),
        started_rx,
    )
}

#[tokio::test]
async fn typed_login_dispatch_returns_only_the_sealed_bytes_to_the_same_request() {
    let environment_id = Uuid::new_v4();
    let request_id = Uuid::new_v4();
    let (input, input_rx) = mpsc::channel(2);
    let (output, mut output_rx) = mpsc::channel(1);
    let (executor, mut started_rx) = executor(Ok(vec![0x5a; 4 * 1024]));
    let task = tokio::spawn(run_channel_test_bridge(
        Arc::clone(&executor),
        input_rx,
        output,
        environment_id,
        3,
    ));
    input.send(ready(environment_id, 3)).await.unwrap();
    let message = login(request_id);
    input.send(message.clone()).await.unwrap();
    let admitted = tokio::time::timeout(Duration::from_secs(2), started_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        message.payload,
        Some(v1::credential_bridge_guest_message::Payload::CodexLogin(
            admitted
        ))
    );
    executor.release.add_permits(1);
    let Payload::CodexLogin(response) = receive(&mut output_rx).await else {
        panic!("a Codex login has its own typed response");
    };
    assert_eq!(response.request_id, request_id.to_string());
    assert_eq!(
        response.result,
        Some(LoginResult::SealedLogin(vec![0x5a; 4 * 1024]))
    );
    drop(input);
    assert_eq!(task.await.unwrap(), Err(BrokerBridgeError::Unavailable));
    assert_eq!(executor.drains.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn login_answers_are_a_bounded_login_denied_or_unavailable() {
    let maximum = MAX_SEALED_CODEX_LOGIN_BYTES;
    let denied = || LoginResult::Failure(v1::CredentialBridgeFailureReason::Denied as i32);
    let unavailable =
        || LoginResult::Failure(v1::CredentialBridgeFailureReason::Unavailable as i32);
    let cases = [
        (
            Ok(vec![5; maximum]),
            LoginResult::SealedLogin(vec![5; maximum]),
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
            LoginKind::Codex,
            request_id.clone(),
            result,
        )
        .await
        .unwrap();
        let Payload::CodexLogin(response) = receive(&mut receiver).await else {
            panic!("typed Codex login response");
        };
        assert_eq!(response.request_id, request_id);
        assert_eq!(response.result, Some(expected));
    }
}

#[tokio::test]
async fn failures_and_the_default_executor_deny_without_ending_the_epoch() {
    for result in [
        Err(BrokerRequestError::Denied),
        Err(BrokerRequestError::AuthorityUnavailable),
        Err(BrokerRequestError::UpstreamFailed),
    ] {
        let environment_id = Uuid::new_v4();
        let (input, input_rx) = mpsc::channel(4);
        let (output, mut output_rx) = mpsc::channel(4);
        let (executor, _started) = executor(result);
        executor.release.add_permits(2);
        let task = tokio::spawn(run_channel_test_bridge(
            Arc::clone(&executor),
            input_rx,
            output,
            environment_id,
            3,
        ));
        input.send(ready(environment_id, 3)).await.unwrap();
        for _ in 0..2 {
            input.send(login(Uuid::new_v4())).await.unwrap();
            assert!(matches!(
                receive(&mut output_rx).await,
                Payload::CodexLogin(v1::CodexLoginResponse {
                    result: Some(LoginResult::Failure(_)),
                    ..
                })
            ));
        }
        assert!(!task.is_finished());
        drop(input);
        assert_eq!(task.await.unwrap(), Err(BrokerBridgeError::Unavailable));
    }

    // An executor without a delivery predicate (any non-platform placement)
    // denies through the trait default.
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
    input.send(login(Uuid::new_v4())).await.unwrap();
    assert!(matches!(
        receive(&mut output_rx).await,
        Payload::CodexLogin(v1::CodexLoginResponse {
            result: Some(LoginResult::Failure(reason)),
            ..
        }) if reason == v1::CredentialBridgeFailureReason::Denied as i32
    ));
    drop(input);
    assert_eq!(task.await.unwrap(), Err(BrokerBridgeError::Unavailable));
}

fn projection(id: Uuid) -> v1::CredentialBridgeGuestMessage {
    v1::CredentialBridgeGuestMessage {
        payload: Some(
            v1::credential_bridge_guest_message::Payload::EnvironmentProjection(
                v1::EnvironmentProjectionRequest {
                    request_id: id.to_string(),
                    recipient_public_key: vec![3; 32],
                    selection_sha256: vec![7; 32],
                    deadline_unix_ms: 42,
                    local_inventories: Vec::new(),
                },
            ),
        ),
    }
}

fn unavailable(response: &Payload, request_id: Uuid) -> bool {
    matches!(response, Payload::CodexLogin(response)
    if response.request_id == request_id.to_string()
    && response.result == Some(LoginResult::Failure(
        v1::CredentialBridgeFailureReason::Unavailable as i32
    )))
}

#[tokio::test]
async fn login_ids_are_canonical_and_unique_while_in_flight() {
    for invalid in [
        "not-a-uuid",
        "00000000-0000-0000-0000-000000000000",
        "duplicate",
    ] {
        let environment_id = Uuid::new_v4();
        let (input, input_rx) = mpsc::channel(4);
        let (output, _output_rx) = mpsc::channel(1);
        let (executor, mut started) = executor(Ok(vec![1]));
        let task = tokio::spawn(run_channel_test_bridge(
            Arc::clone(&executor),
            input_rx,
            output,
            environment_id,
            3,
        ));
        input.send(ready(environment_id, 3)).await.unwrap();
        let message = if invalid == "duplicate" {
            // The same ID cannot be reused while its login is in flight.
            let id = Uuid::new_v4();
            input.send(login(id)).await.unwrap();
            tokio::time::timeout(Duration::from_secs(2), started.recv())
                .await
                .unwrap()
                .unwrap();
            login(id)
        } else {
            let mut message = login(Uuid::new_v4());
            if let Some(v1::credential_bridge_guest_message::Payload::CodexLogin(request)) =
                &mut message.payload
            {
                request.request_id = invalid.into();
            }
            message
        };
        input.send(message).await.unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), task)
                .await
                .unwrap()
                .unwrap(),
            Err(BrokerBridgeError::InvalidProtocol),
            "{invalid}"
        );
        assert_eq!(executor.drains.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn an_epoch_runs_one_login_at_a_time_within_the_shared_in_flight_limit() {
    let environment_id = Uuid::new_v4();
    let (input, input_rx) = mpsc::channel(CREDENTIAL_BRIDGE_MAX_IN_FLIGHT + 4);
    let (output, mut output_rx) = mpsc::channel(1);
    let (executor, mut started_rx) = executor(Ok(vec![9; 64]));
    let task = tokio::spawn(run_channel_test_bridge(
        Arc::clone(&executor),
        input_rx,
        output,
        environment_id,
        3,
    ));
    input.send(ready(environment_id, 3)).await.unwrap();

    // A second concurrent login is refused before it leases anything.
    let first = Uuid::new_v4();
    input.send(login(first)).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), started_rx.recv())
        .await
        .unwrap()
        .unwrap();
    let second = Uuid::new_v4();
    input.send(login(second)).await.unwrap();
    assert!(unavailable(&receive(&mut output_rx).await, second));
    assert!(started_rx.try_recv().is_err(), "a refused login was leased");
    executor.release.add_permits(1);
    assert!(matches!(
        receive(&mut output_rx).await,
        Payload::CodexLogin(response)
            if response.request_id == first.to_string()
            && matches!(response.result, Some(LoginResult::SealedLogin(_)))
    ));

    // Once it finishes, the next login runs. Let the runner observe the
    // finished task before sending more frames.
    tokio::time::sleep(Duration::from_millis(50)).await;
    let third = Uuid::new_v4();
    input.send(login(third)).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), started_rx.recv())
        .await
        .unwrap()
        .unwrap();
    executor.release.add_permits(1);
    assert!(matches!(
        receive(&mut output_rx).await,
        Payload::CodexLogin(response) if response.request_id == third.to_string()
    ));

    // Logins share the epoch's in-flight limit with every other operation.
    tokio::time::sleep(Duration::from_millis(50)).await;
    for _ in 0..CREDENTIAL_BRIDGE_MAX_IN_FLIGHT {
        input.send(projection(Uuid::new_v4())).await.unwrap();
    }
    let overflow = Uuid::new_v4();
    input.send(login(overflow)).await.unwrap();
    assert!(unavailable(&receive(&mut output_rx).await, overflow));
    assert!(
        started_rx.try_recv().is_err(),
        "an over-limit login was leased"
    );
    executor
        .release
        .add_permits(CREDENTIAL_BRIDGE_MAX_IN_FLIGHT);
    for _ in 0..CREDENTIAL_BRIDGE_MAX_IN_FLIGHT {
        assert!(matches!(
            receive(&mut output_rx).await,
            Payload::EnvironmentProjection(_)
        ));
    }
    drop(input);
    assert_eq!(task.await.unwrap(), Err(BrokerBridgeError::Unavailable));
    assert_eq!(executor.drains.load(Ordering::SeqCst), 1);
}
