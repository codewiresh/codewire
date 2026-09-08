use super::*;

use std::time::Duration;

use tokio::sync::Semaphore;

type Payload = v1::credential_bridge_host_message::Payload;
type ProjectionResult = v1::environment_projection_response::Result;

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

async fn receive(output: &mut mpsc::Receiver<Payload>) -> Payload {
    tokio::time::timeout(Duration::from_secs(2), output.recv())
        .await
        .expect("bounded bridge response")
        .expect("bridge remains attached")
}

struct ProjectionExecutor {
    started: mpsc::UnboundedSender<v1::EnvironmentProjectionRequest>,
    release: Semaphore,
    drains: AtomicUsize,
}

#[async_trait]
impl BrokerRequestExecutor for ProjectionExecutor {
    async fn execute_request(
        &self,
        _: v1::CredentialBridgeRequest,
    ) -> Result<BrokerHttpResponse, BrokerRequestError> {
        panic!("a projection or capacity-denied HTTP request must not use HTTP execution");
    }

    async fn project_environment(
        &self,
        request: v1::EnvironmentProjectionRequest,
    ) -> Result<Vec<u8>, BrokerRequestError> {
        self.started.send(request).unwrap();
        self.release.acquire().await.unwrap().forget();
        Ok(vec![0x81; 70 * 1024])
    }

    async fn wait_for_active_operations(&self) -> Result<(), BrokerRequestError> {
        self.drains.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

#[tokio::test]
async fn typed_projection_dispatch_preserves_only_bound_request_and_sealed_response() {
    let environment_id = Uuid::new_v4();
    let request_id = Uuid::new_v4();
    let (input, input_rx) = mpsc::channel(2);
    let (output, mut output_rx) = mpsc::channel(1);
    let (started, mut started_rx) = mpsc::unbounded_channel();
    let executor = Arc::new(ProjectionExecutor {
        started,
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
    let message = projection(request_id);
    input.send(message.clone()).await.unwrap();
    let admitted = tokio::time::timeout(Duration::from_secs(2), started_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        message.payload,
        Some(v1::credential_bridge_guest_message::Payload::EnvironmentProjection(admitted))
    );
    executor.release.add_permits(1);
    let Payload::EnvironmentProjection(response) = receive(&mut output_rx).await else {
        panic!("projection is a typed response, not HTTP headers/body");
    };
    assert_eq!(response.request_id, request_id.to_string());
    assert_eq!(
        response.result,
        Some(ProjectionResult::SealedProjection(vec![0x81; 70 * 1024]))
    );
    drop(input);
    assert_eq!(task.await.unwrap(), Err(BrokerBridgeError::Unavailable));
    assert_eq!(executor.drains.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn projection_response_bounds_and_failures_are_finite() {
    let maximum = MAX_SEALED_ENVIRONMENT_PROJECTION_BYTES;
    let cases = [
        (
            Ok(vec![5; maximum]),
            ProjectionResult::SealedProjection(vec![5; maximum]),
        ),
        (
            Ok(Vec::new()),
            ProjectionResult::Failure(v1::CredentialBridgeFailureReason::ResponseTooLarge as i32),
        ),
        (
            Ok(vec![5; maximum + 1]),
            ProjectionResult::Failure(v1::CredentialBridgeFailureReason::ResponseTooLarge as i32),
        ),
        (
            Err(BrokerRequestError::Denied),
            ProjectionResult::Failure(v1::CredentialBridgeFailureReason::Denied as i32),
        ),
        (
            Err(BrokerRequestError::InvalidRequest),
            ProjectionResult::Failure(v1::CredentialBridgeFailureReason::Denied as i32),
        ),
        (
            Err(BrokerRequestError::AuthorityUnavailable),
            ProjectionResult::Failure(v1::CredentialBridgeFailureReason::Unavailable as i32),
        ),
    ];
    for (result, expected) in cases {
        let (output, mut receiver) = mpsc::channel(1);
        let request_id = Uuid::new_v4().to_string();
        send_projection_response(&FakeSender { output }, request_id.clone(), result)
            .await
            .unwrap();
        let Payload::EnvironmentProjection(response) = receive(&mut receiver).await else {
            panic!("typed projection response");
        };
        assert_eq!(response.request_id, request_id);
        assert_eq!(response.result, Some(expected));
    }
}

#[tokio::test]
async fn active_projection_and_http_request_ids_share_one_collision_domain() {
    for collide_with_projection in [false, true] {
        let environment_id = Uuid::new_v4();
        let request_id = Uuid::new_v4();
        let (input, input_rx) = mpsc::channel(3);
        let (output, _output_rx) = mpsc::channel(1);
        let (started, mut started_rx) = mpsc::unbounded_channel();
        let executor = Arc::new(ProjectionExecutor {
            started,
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
        input.send(projection(request_id)).await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), started_rx.recv())
            .await
            .unwrap()
            .unwrap();
        input
            .send(if collide_with_projection {
                projection(request_id)
            } else {
                request(request_id, "/responses")
            })
            .await
            .unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), task)
                .await
                .unwrap()
                .unwrap(),
            Err(BrokerBridgeError::InvalidProtocol)
        );
        assert_eq!(executor.drains.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn cancelled_projection_keeps_shared_capacity_and_drains_late_typed_response() {
    let environment_id = Uuid::new_v4();
    let (input, input_rx) = mpsc::channel(CREDENTIAL_BRIDGE_MAX_IN_FLIGHT + 4);
    let (output, mut output_rx) = mpsc::channel(1);
    let (started, mut started_rx) = mpsc::unbounded_channel();
    let executor = Arc::new(ProjectionExecutor {
        started,
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
    let mut pending = std::collections::BTreeSet::new();
    for _ in 0..CREDENTIAL_BRIDGE_MAX_IN_FLIGHT {
        let id = Uuid::new_v4();
        pending.insert(id.to_string());
        input.send(projection(id)).await.unwrap();
    }
    for _ in 0..CREDENTIAL_BRIDGE_MAX_IN_FLIGHT {
        tokio::time::timeout(Duration::from_secs(2), started_rx.recv())
            .await
            .unwrap()
            .unwrap();
    }
    input
        .send(v1::CredentialBridgeGuestMessage {
            payload: Some(v1::credential_bridge_guest_message::Payload::Cancel(
                v1::CredentialBridgeCancel {
                    request_id: pending.first().unwrap().clone(),
                },
            )),
        })
        .await
        .unwrap();
    let overflow = Uuid::new_v4();
    input.send(projection(overflow)).await.unwrap();
    assert!(
        matches!(receive(&mut output_rx).await, Payload::EnvironmentProjection(response)
        if response.request_id == overflow.to_string()
        && response.result == Some(ProjectionResult::Failure(v1::CredentialBridgeFailureReason::Unavailable as i32)))
    );
    let overflow_http = Uuid::new_v4();
    input
        .send(request(overflow_http, "/responses"))
        .await
        .unwrap();
    assert!(
        matches!(receive(&mut output_rx).await, Payload::ResponseFailure(response)
        if response.request_id == overflow_http.to_string()
        && response.reason == v1::CredentialBridgeFailureReason::Unavailable as i32)
    );
    executor
        .release
        .add_permits(CREDENTIAL_BRIDGE_MAX_IN_FLIGHT);
    for _ in 0..CREDENTIAL_BRIDGE_MAX_IN_FLIGHT {
        let Payload::EnvironmentProjection(response) = receive(&mut output_rx).await else {
            panic!("late typed response must drain, including cancelled request");
        };
        assert!(pending.remove(&response.request_id));
        assert!(matches!(
            response.result,
            Some(ProjectionResult::SealedProjection(_))
        ));
    }
    assert!(pending.is_empty());
    drop(input);
    assert_eq!(task.await.unwrap(), Err(BrokerBridgeError::Unavailable));
    assert_eq!(executor.drains.load(Ordering::SeqCst), 1);
}
