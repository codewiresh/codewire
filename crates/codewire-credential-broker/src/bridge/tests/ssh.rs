use super::*;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::Semaphore;

type Payload = v1::credential_bridge_host_message::Payload;
type SshResult = v1::credential_ssh_response::Result;

fn ssh_request(id: Uuid) -> v1::CredentialSshRequest {
    v1::CredentialSshRequest {
        request_id: id.to_string(),
        deadline_unix_ms: u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        )
        .unwrap()
            + 29_000,
        operation: Some(v1::credential_ssh_request::Operation::Sign(
            v1::CredentialSshSignRequest {
                public_key_blob: vec![1; 32],
                data: vec![2; 64],
                flags: 0,
            },
        )),
    }
}

fn message(request: v1::CredentialSshRequest) -> v1::CredentialBridgeGuestMessage {
    v1::CredentialBridgeGuestMessage {
        payload: Some(v1::credential_bridge_guest_message::Payload::Ssh(request)),
    }
}

fn signature() -> SshResult {
    SshResult::Signature(v1::CredentialSshSignature {
        signature_blob: vec![3; 64],
    })
}

struct SshExecutor {
    started: mpsc::UnboundedSender<(v1::CredentialSshRequest, CancellationToken)>,
    release: Semaphore,
    result: Result<SshResult, BrokerRequestError>,
    drains: AtomicUsize,
}

#[async_trait]
impl BrokerRequestExecutor for SshExecutor {
    async fn execute_request(
        &self,
        _: v1::CredentialBridgeRequest,
    ) -> Result<BrokerHttpResponse, BrokerRequestError> {
        panic!("SSH must not enter HTTP execution");
    }

    async fn execute_ssh(
        &self,
        request: v1::CredentialSshRequest,
        cancellation: CancellationToken,
    ) -> Result<SshResult, BrokerRequestError> {
        self.started.send((request, cancellation)).unwrap();
        self.release.acquire().await.unwrap().forget();
        self.result.clone()
    }

    async fn wait_for_active_operations(&self) -> Result<(), BrokerRequestError> {
        self.drains.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

fn executor(
    result: SshResult,
) -> (
    Arc<SshExecutor>,
    mpsc::UnboundedReceiver<(v1::CredentialSshRequest, CancellationToken)>,
) {
    let (started, receiver) = mpsc::unbounded_channel();
    (
        Arc::new(SshExecutor {
            started,
            release: Semaphore::new(0),
            result: Ok(result),
            drains: AtomicUsize::new(0),
        }),
        receiver,
    )
}

async fn bounded<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(3), future)
        .await
        .expect("bounded SSH operation")
}

fn assert_failure(payload: Payload, expected: v1::CredentialBridgeFailureReason) {
    let Payload::Ssh(response) = payload else {
        panic!("closed SSH terminal")
    };
    assert_eq!(response.result, Some(SshResult::Failure(expected as i32)));
}

#[tokio::test]
async fn typed_sign_preserves_original_request_and_never_uses_http() {
    let environment_id = Uuid::new_v4();
    let request = ssh_request(Uuid::new_v4());
    let (input, input_rx) = mpsc::channel(2);
    let (output, mut output_rx) = mpsc::channel(1);
    let (executor, mut started) = executor(signature());
    let task = tokio::spawn(run_channel_test_bridge(
        Arc::clone(&executor),
        input_rx,
        output,
        environment_id,
        3,
    ));
    input.send(ready(environment_id, 3)).await.unwrap();
    input.send(message(request.clone())).await.unwrap();
    let (admitted, _) = bounded(started.recv()).await.unwrap();
    assert_eq!(admitted, request);
    executor.release.add_permits(1);
    let Payload::Ssh(response) = bounded(output_rx.recv()).await.unwrap() else {
        panic!("typed response")
    };
    assert_eq!(response.request_id, request.request_id);
    assert_eq!(response.result, Some(signature()));
    drop(input);
    assert_eq!(
        bounded(task).await.unwrap(),
        Err(BrokerBridgeError::Unavailable)
    );
    assert_eq!(executor.drains.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn authority_failure_after_cancellation_still_ends_epoch_and_observes_drain() {
    for cancel in [false, true] {
        let environment_id = Uuid::new_v4();
        let request = ssh_request(Uuid::new_v4());
        let (input, input_rx) = mpsc::channel(3);
        let (output, mut output_rx) = mpsc::channel(1);
        let (mut executor, mut started) = executor(signature());
        Arc::get_mut(&mut executor).unwrap().result = Err(BrokerRequestError::AuthorityUnavailable);
        let task = tokio::spawn(run_channel_test_bridge(
            Arc::clone(&executor),
            input_rx,
            output,
            environment_id,
            3,
        ));
        input.send(ready(environment_id, 3)).await.unwrap();
        input.send(message(request.clone())).await.unwrap();
        let (_, cancellation) = bounded(started.recv()).await.unwrap();
        if cancel {
            input
                .send(v1::CredentialBridgeGuestMessage {
                    payload: Some(v1::credential_bridge_guest_message::Payload::Cancel(
                        v1::CredentialBridgeCancel {
                            request_id: request.request_id,
                        },
                    )),
                })
                .await
                .unwrap();
            bounded(cancellation.cancelled()).await;
        }
        executor.release.add_permits(1);
        assert_failure(
            bounded(output_rx.recv()).await.unwrap(),
            v1::CredentialBridgeFailureReason::Unavailable,
        );
        // Keep input open: failure, not EOF, must retire this epoch and call
        // the authority's drain hook even if cancellation arrived first.
        assert_eq!(
            bounded(task).await.unwrap(),
            Err(BrokerBridgeError::Unavailable)
        );
        assert_eq!(executor.drains.load(Ordering::SeqCst), 1);
        drop(input);
    }
}

#[tokio::test]
async fn invalid_sign_shapes_and_expired_deadlines_do_not_reach_executor() {
    for change in 0..5 {
        let (executor, mut started) = executor(signature());
        let mut request = ssh_request(Uuid::new_v4());
        match change {
            0 => request.deadline_unix_ms = 1,
            1 => request.deadline_unix_ms = u64::MAX,
            // A guest clock ahead of the host's past the 30 s window (#2763):
            // refused here alone; the bridge receives it and serves on.
            2 => request.deadline_unix_ms += 2_000,
            3 => request.operation = None,
            _ => {
                let Some(v1::credential_ssh_request::Operation::Sign(sign)) =
                    request.operation.as_mut()
                else {
                    unreachable!()
                };
                sign.flags = 1;
            }
        }
        let (output, mut receiver) = mpsc::channel(1);
        super::super::ssh::serve(
            &*executor,
            &FakeSender { output },
            request,
            CancellationToken::new(),
        )
        .await
        .unwrap();
        assert_failure(
            bounded(receiver.recv()).await.unwrap(),
            v1::CredentialBridgeFailureReason::Denied,
        );
        assert!(started.try_recv().is_err());
    }
}

#[tokio::test]
async fn response_kind_mismatch_is_denied_without_releasing_identity() {
    let (executor, _) = executor(SshResult::Identity(v1::CredentialSshIdentity {
        public_key_blob: vec![9],
    }));
    // Keep the observer alive while the fake worker publishes its admission.
    let (started, _receiver) = mpsc::unbounded_channel();
    let executor = SshExecutor {
        started,
        release: Semaphore::new(1),
        result: executor.result.clone(),
        drains: AtomicUsize::new(0),
    };
    let (output, mut receiver) = mpsc::channel(1);
    super::super::ssh::serve(
        &executor,
        &FakeSender { output },
        ssh_request(Uuid::new_v4()),
        CancellationToken::new(),
    )
    .await
    .unwrap();
    assert_failure(
        bounded(receiver.recv()).await.unwrap(),
        v1::CredentialBridgeFailureReason::Denied,
    );
}

#[tokio::test]
async fn cancelled_sign_retains_slot_and_discards_late_signature() {
    let environment_id = Uuid::new_v4();
    let (input, input_rx) = mpsc::channel(CREDENTIAL_BRIDGE_MAX_IN_FLIGHT + 4);
    let (output, mut output_rx) = mpsc::channel(CREDENTIAL_BRIDGE_MAX_IN_FLIGHT + 2);
    let (executor, mut started) = executor(signature());
    let task = tokio::spawn(run_channel_test_bridge(
        Arc::clone(&executor),
        input_rx,
        output,
        environment_id,
        3,
    ));
    input.send(ready(environment_id, 3)).await.unwrap();
    for _ in 0..CREDENTIAL_BRIDGE_MAX_IN_FLIGHT {
        let request = ssh_request(Uuid::new_v4());
        input.send(message(request.clone())).await.unwrap();
        let (_, cancellation) = bounded(started.recv()).await.unwrap();
        input
            .send(v1::CredentialBridgeGuestMessage {
                payload: Some(v1::credential_bridge_guest_message::Payload::Cancel(
                    v1::CredentialBridgeCancel {
                        request_id: request.request_id,
                    },
                )),
            })
            .await
            .unwrap();
        bounded(cancellation.cancelled()).await;
    }
    input
        .send(message(ssh_request(Uuid::new_v4())))
        .await
        .unwrap();
    assert_failure(
        bounded(output_rx.recv()).await.unwrap(),
        v1::CredentialBridgeFailureReason::Unavailable,
    );
    input
        .send(request(Uuid::new_v4(), "/responses"))
        .await
        .unwrap();
    let Payload::ResponseFailure(failure) = bounded(output_rx.recv()).await.unwrap() else {
        panic!("shared HTTP capacity")
    };
    assert_eq!(
        failure.reason,
        v1::CredentialBridgeFailureReason::Unavailable as i32
    );
    executor
        .release
        .add_permits(CREDENTIAL_BRIDGE_MAX_IN_FLIGHT);
    for _ in 0..CREDENTIAL_BRIDGE_MAX_IN_FLIGHT {
        assert_failure(
            bounded(output_rx.recv()).await.unwrap(),
            v1::CredentialBridgeFailureReason::Unavailable,
        );
    }
    assert!(started.try_recv().is_err());
    drop(input);
    assert_eq!(
        bounded(task).await.unwrap(),
        Err(BrokerBridgeError::Unavailable)
    );
}

#[tokio::test]
async fn ssh_http_and_projection_ids_collide_and_epoch_loss_cancels_signer() {
    for kind in 0..3 {
        let environment_id = Uuid::new_v4();
        let id = Uuid::new_v4();
        let (input, input_rx) = mpsc::channel(3);
        let (output, _output_rx) = mpsc::channel(1);
        let (executor, mut started) = executor(signature());
        let task = tokio::spawn(run_channel_test_bridge(
            Arc::clone(&executor),
            input_rx,
            output,
            environment_id,
            3,
        ));
        input.send(ready(environment_id, 3)).await.unwrap();
        input.send(message(ssh_request(id))).await.unwrap();
        let (_, cancellation) = bounded(started.recv()).await.unwrap();
        let collision = match kind {
            0 => message(ssh_request(id)),
            1 => request(id, "/responses"),
            _ => v1::CredentialBridgeGuestMessage {
                payload: Some(
                    v1::credential_bridge_guest_message::Payload::EnvironmentProjection(
                        v1::EnvironmentProjectionRequest {
                            request_id: id.to_string(),
                            recipient_public_key: vec![1; 32],
                            selection_sha256: vec![2; 32],
                            deadline_unix_ms: 1,
                            local_inventories: Vec::new(),
                        },
                    ),
                ),
            },
        };
        input.send(collision).await.unwrap();
        assert_eq!(
            bounded(task).await.unwrap(),
            Err(BrokerBridgeError::InvalidProtocol)
        );
        assert!(cancellation.is_cancelled());
        assert_eq!(executor.drains.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test(start_paused = true)]
async fn original_monotonic_deadline_suppresses_ready_late_signature() {
    let (executor, mut started) = executor(signature());
    let (output, mut receiver) = mpsc::channel(1);
    let cancellation = CancellationToken::new();
    let task = tokio::spawn({
        let executor = Arc::clone(&executor);
        let cancellation = cancellation.clone();
        async move {
            super::super::ssh::serve(
                &*executor,
                &FakeSender { output },
                ssh_request(Uuid::new_v4()),
                cancellation,
            )
            .await
        }
    });
    started.recv().await.unwrap();
    tokio::time::advance(Duration::from_secs(31)).await;
    executor.release.add_permits(1);
    assert_eq!(task.await.unwrap(), Ok(()));
    assert!(cancellation.is_cancelled());
    assert_failure(
        receiver.recv().await.unwrap(),
        v1::CredentialBridgeFailureReason::Unavailable,
    );
}

#[tokio::test(start_paused = true)]
async fn cancelled_backpressured_signature_cannot_escape_and_failure_send_is_bounded() {
    let (executor, mut started) = executor(signature());
    let (output, mut receiver) = mpsc::channel(1);
    output
        .send(Payload::ResponseEnd(v1::CredentialBridgeResponseEnd {
            request_id: Uuid::new_v4().to_string(),
        }))
        .await
        .unwrap();
    let cancellation = CancellationToken::new();
    let task = tokio::spawn({
        let executor = Arc::clone(&executor);
        let cancellation = cancellation.clone();
        async move {
            super::super::ssh::serve(
                &*executor,
                &FakeSender { output },
                ssh_request(Uuid::new_v4()),
                cancellation,
            )
            .await
        }
    });
    started.recv().await.unwrap();
    executor.release.add_permits(1);
    tokio::task::yield_now().await;
    cancellation.cancel();
    assert_eq!(task.await.unwrap(), Err(()));
    assert!(matches!(
        receiver.recv().await,
        Some(Payload::ResponseEnd(_))
    ));
    assert!(receiver.recv().await.is_none());
}
