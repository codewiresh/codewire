use codewire_workload_secrets::{ProjectionContext, ProjectionRecipient};

use super::*;

fn ssh_request() -> v1::CredentialSshRequest {
    v1::CredentialSshRequest {
        request_id: Uuid::new_v4().to_string(),
        deadline_unix_ms: now_ms() + 5_000,
        operation: Some(v1::credential_ssh_request::Operation::Identities(
            v1::CredentialSshIdentitiesRequest {},
        )),
    }
}

fn identity(request_id: &str) -> v1::CredentialSshResponse {
    v1::CredentialSshResponse {
        request_id: request_id.to_owned(),
        result: Some(v1::credential_ssh_response::Result::Identity(
            v1::CredentialSshIdentity {
                public_key_blob: b"synthetic-public-key".to_vec(),
            },
        )),
    }
}

fn signature(request_id: &str) -> v1::CredentialSshResponse {
    v1::CredentialSshResponse {
        request_id: request_id.to_owned(),
        result: Some(v1::credential_ssh_response::Result::Signature(
            v1::CredentialSshSignature {
                signature_blob: b"synthetic-signature".to_vec(),
            },
        )),
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .try_into()
        .unwrap()
}

async fn bounded<F: Future>(future: F) -> F::Output {
    tokio::time::timeout(Duration::from_secs(2), future)
        .await
        .expect("bounded SSH fixture")
}

struct Harness {
    bridge: CredentialBridge,
    epoch: u64,
    input: mpsc::Sender<Result<v1::CredentialBridgeHostMessage, Status>>,
    output: CredentialBridgeOutput,
    driver: tokio::task::JoinHandle<()>,
}

impl Harness {
    async fn new(bridge: CredentialBridge) -> Self {
        Self::with_replacement(bridge, EpochReplacement::FailPending).await
    }

    async fn with_replacement(bridge: CredentialBridge, replacement: EpochReplacement) -> Self {
        let (prepared, mut output) = bridge.prepare_connection().unwrap();
        assert!(matches!(
            output.next().await.unwrap().unwrap().payload,
            Some(v1::credential_bridge_guest_message::Payload::Ready(_))
        ));
        let (input, receiver) = mpsc::channel(8);
        let connection = prepared
            .activate_with_replacement(ReceiverStream::new(receiver), &[], replacement)
            .await
            .unwrap();
        Self {
            bridge,
            epoch: connection.epoch,
            input,
            output,
            driver: tokio::spawn(connection.run()),
        }
    }

    async fn submit(
        &mut self,
        request: v1::CredentialSshRequest,
    ) -> tokio::task::JoinHandle<Result<v1::CredentialSshResponse, Status>> {
        let expected = request.clone();
        let bridge = self.bridge.clone();
        let task = tokio::spawn(async move { bridge.relay_ssh(request).await });
        let frame = bounded(self.output.next()).await.unwrap().unwrap();
        assert_eq!(
            frame.payload,
            Some(v1::credential_bridge_guest_message::Payload::Ssh(expected))
        );
        task
    }

    async fn reply(&self, response: v1::CredentialSshResponse) {
        self.bridge
            .apply_host_message(
                self.epoch,
                v1::CredentialBridgeHostMessage {
                    payload: Some(v1::credential_bridge_host_message::Payload::Ssh(response)),
                },
            )
            .await
            .unwrap();
    }

    async fn fill_output(&self) -> GuestOutput {
        let output = self
            .bridge
            .inner
            .lock()
            .await
            .active
            .as_ref()
            .unwrap()
            .output
            .clone();
        for _ in 0..HOST_OUTPUT_BUFFER {
            output
                .try_send(Ok(guest_message(
                    v1::credential_bridge_guest_message::Payload::Cancel(
                        v1::CredentialBridgeCancel {
                            request_id: Uuid::new_v4().to_string(),
                        },
                    ),
                )))
                .unwrap();
        }
        output
    }

    async fn stop(self) {
        drop(self.input);
        bounded(self.driver).await.unwrap();
    }
}

fn bridge() -> CredentialBridge {
    CredentialBridge::new(Uuid::new_v4(), 7).unwrap()
}

fn context(bridge: &CredentialBridge) -> ProjectionContext {
    ProjectionContext {
        environment_id: *bridge.identity().environment_id.as_bytes(),
        operation_generation: bridge.identity().environment_generation,
        selection_sha256: [3; 32],
        deadline_unix_ms: now_ms() + 5_000,
    }
}

fn http_request(request_id: String) -> v1::CredentialBridgeRequest {
    v1::CredentialBridgeRequest {
        request_id,
        capability_slot: "codex".into(),
        route: "openai-api".into(),
        method: "POST".into(),
        path: "/v1/responses".into(),
        query: String::new(),
        headers: Vec::new(),
        body: b"{}".to_vec(),
        intercepted_host: String::new(),
        streamed_body: false,
    }
}

#[tokio::test]
async fn ssh_round_trip_preserves_request_deadline_id_and_closed_results() {
    let mut harness = Harness::new(bridge()).await;
    for operation in [SshOperation::Identities, SshOperation::Sign] {
        for failure in [None, Some(1), Some(2), Some(3), Some(4)] {
            let mut request = ssh_request();
            if operation == SshOperation::Sign {
                request.operation = Some(v1::credential_ssh_request::Operation::Sign(
                    v1::CredentialSshSignRequest {
                        public_key_blob: b"synthetic-public-key".to_vec(),
                        data: b"synthetic-signing-data".to_vec(),
                        flags: 4,
                    },
                ));
            }
            let response = if let Some(reason) = failure {
                v1::CredentialSshResponse {
                    request_id: request.request_id.clone(),
                    result: Some(v1::credential_ssh_response::Result::Failure(reason)),
                }
            } else if operation == SshOperation::Identities {
                identity(&request.request_id)
            } else {
                signature(&request.request_id)
            };
            let task = harness.submit(request).await;
            harness.reply(response.clone()).await;
            assert_eq!(bounded(task).await.unwrap().unwrap(), response);
        }
    }
    assert_eq!(harness.bridge.inner.lock().await.in_flight(), 0);
    harness.stop().await;
}

#[tokio::test]
async fn ssh_invalid_or_unadmitted_requests_register_and_dispatch_nothing() {
    let bridge = bridge();
    let (prepared, _output) = bridge.prepare_connection().unwrap();
    assert_eq!(
        bridge.relay_ssh(ssh_request()).await.unwrap_err().code(),
        tonic::Code::Unavailable
    );
    assert_eq!(bridge.inner.lock().await.next_epoch, 0);
    drop(prepared);
    let harness = Harness::new(bridge).await;
    for index in 0..6 {
        let mut request = ssh_request();
        match index {
            0 => request.request_id = Uuid::nil().to_string(),
            1 => request.request_id.push('x'),
            2 => request.operation = None,
            3 => request.deadline_unix_ms = 0,
            4 => request.deadline_unix_ms = now_ms() + 60_000,
            5 => {
                request.operation = Some(v1::credential_ssh_request::Operation::Sign(
                    v1::CredentialSshSignRequest {
                        public_key_blob: vec![1],
                        data: vec![1; codewire_daemon_proto::ssh::MAX_SIGNING_DATA_BYTES + 1],
                        flags: 0,
                    },
                ));
            }
            _ => unreachable!(),
        }
        assert_eq!(
            harness.bridge.relay_ssh(request).await.unwrap_err().code(),
            tonic::Code::InvalidArgument
        );
    }
    let state = harness.bridge.inner.lock().await;
    assert_eq!(state.in_flight(), 0);
    assert_eq!(
        state.active.as_ref().unwrap().output.capacity(),
        HOST_OUTPUT_BUFFER
    );
    drop(state);
    harness.stop().await;
}

#[tokio::test]
async fn ssh_http_and_projection_share_ids_and_one_in_flight_budget() {
    let mut harness = Harness::new(bridge()).await;
    let http_id = Uuid::new_v4().to_string();
    let request = http_request(http_id.clone());
    let shared = harness.bridge.clone();
    let http = tokio::spawn(async move { shared.submit(request, None).await });
    assert!(matches!(
        bounded(harness.output.next())
            .await
            .unwrap()
            .unwrap()
            .payload,
        Some(v1::credential_bridge_guest_message::Payload::Request(_))
    ));
    let shared = harness.bridge.clone();
    let projection_context = context(&shared);
    let key = ProjectionRecipient::new().public_key();
    let projection = tokio::spawn(async move {
        shared
            .project_environment_for_recipient(projection_context, key)
            .await
    });
    let frame = bounded(harness.output.next()).await.unwrap().unwrap();
    let Some(v1::credential_bridge_guest_message::Payload::EnvironmentProjection(project)) =
        frame.payload
    else {
        panic!("typed projection expected")
    };
    for id in [http_id, project.request_id] {
        // A typed SSH reply cannot consume HTTP or projection state even if
        // its ID and public result framing are otherwise valid.
        assert!(
            harness
                .bridge
                .apply_ssh_response(harness.epoch, identity(&id))
                .await
                .is_err()
        );
        assert_eq!(harness.bridge.inner.lock().await.in_flight(), 2);
        let mut duplicate = ssh_request();
        duplicate.request_id = id;
        assert_eq!(
            harness
                .bridge
                .relay_ssh(duplicate)
                .await
                .unwrap_err()
                .code(),
            tonic::Code::ResourceExhausted
        );
    }
    let mut tasks = Vec::new();
    let first = ssh_request();
    let first_id = first.request_id.clone();
    tasks.push(harness.submit(first).await);
    assert!(
        harness
            .bridge
            .submit(http_request(first_id.clone()), None)
            .await
            .is_err()
    );
    let mut duplicate = ssh_request();
    duplicate.request_id = first_id;
    assert_eq!(
        harness
            .bridge
            .relay_ssh(duplicate)
            .await
            .unwrap_err()
            .code(),
        tonic::Code::ResourceExhausted
    );
    for _ in 3..CREDENTIAL_BRIDGE_MAX_IN_FLIGHT {
        tasks.push(harness.submit(ssh_request()).await);
    }
    assert_eq!(
        harness.bridge.inner.lock().await.in_flight(),
        CREDENTIAL_BRIDGE_MAX_IN_FLIGHT
    );
    assert_eq!(
        harness
            .bridge
            .relay_ssh(ssh_request())
            .await
            .unwrap_err()
            .code(),
        tonic::Code::ResourceExhausted
    );
    assert!(
        harness
            .bridge
            .submit(http_request(Uuid::new_v4().to_string()), None)
            .await
            .is_err()
    );
    assert!(matches!(
        harness.bridge.project_environment_for_recipient(context(&harness.bridge), key).await,
        Err(status) if status.code() == tonic::Code::ResourceExhausted
    ));
    harness.stop().await;
    for task in tasks {
        assert_eq!(
            bounded(task).await.unwrap().unwrap_err().code(),
            tonic::Code::Unavailable
        );
    }
    assert!(bounded(http).await.unwrap().is_err());
    assert!(bounded(projection).await.unwrap().is_err());
}

#[tokio::test]
async fn ssh_cancellation_with_full_queue_keeps_tombstone_until_valid_terminal() {
    let mut harness = Harness::new(bridge()).await;
    let request = ssh_request();
    let task = harness.submit(request.clone()).await;
    let output = harness.fill_output().await;
    task.abort();
    assert!(bounded(task).await.unwrap_err().is_cancelled());
    // Synchronize cancellation without depending on the Drop task's scheduling.
    bounded(harness.bridge.cancel(&request.request_id, harness.epoch)).await;
    assert_eq!(output.capacity(), 0);
    assert!(
        harness.bridge.inner.lock().await.ssh[&request.request_id]
            .response
            .is_none()
    );
    assert_eq!(
        harness
            .bridge
            .relay_ssh(request.clone())
            .await
            .unwrap_err()
            .code(),
        tonic::Code::ResourceExhausted
    );
    assert!(
        harness
            .bridge
            .apply_ssh_response(harness.epoch, signature(&request.request_id))
            .await
            .is_err()
    );
    assert!(
        harness
            .bridge
            .inner
            .lock()
            .await
            .ssh
            .contains_key(&request.request_id)
    );
    harness.reply(identity(&request.request_id)).await;
    assert_eq!(harness.bridge.inner.lock().await.in_flight(), 0);
    for _ in 0..HOST_OUTPUT_BUFFER {
        bounded(harness.output.next()).await.unwrap().unwrap();
    }
    assert_eq!(output.capacity(), HOST_OUTPUT_BUFFER);
    let next = ssh_request();
    let task = harness.submit(next.clone()).await;
    harness.reply(identity(&next.request_id)).await;
    bounded(task).await.unwrap().unwrap();
    harness.stop().await;
}

#[tokio::test]
async fn ssh_cancellation_while_reserving_never_registers_an_unsent_request() {
    let mut harness = Harness::new(bridge()).await;
    let output = harness.fill_output().await;
    {
        let relay = harness.bridge.relay_ssh(ssh_request());
        tokio::pin!(relay);
        std::future::poll_fn(|cx| {
            assert!(relay.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        assert_eq!(harness.bridge.inner.lock().await.in_flight(), 0);
    }
    for _ in 0..HOST_OUTPUT_BUFFER {
        bounded(harness.output.next()).await.unwrap().unwrap();
    }
    assert_eq!(output.capacity(), HOST_OUTPUT_BUFFER);
    assert_eq!(harness.bridge.inner.lock().await.in_flight(), 0);
    harness.stop().await;
}

#[tokio::test]
async fn ssh_original_deadline_expires_and_late_terminal_only_drains() {
    let mut harness = Harness::new(bridge()).await;
    let mut request = ssh_request();
    request.deadline_unix_ms = now_ms() + 200;
    let task = harness.submit(request.clone()).await;
    assert_eq!(
        bounded(task).await.unwrap().unwrap_err().code(),
        tonic::Code::DeadlineExceeded
    );
    let frame = bounded(harness.output.next()).await.unwrap().unwrap();
    assert!(
        matches!(frame.payload, Some(v1::credential_bridge_guest_message::Payload::Cancel(ref cancel)) if cancel.request_id == request.request_id)
    );
    assert!(
        harness.bridge.inner.lock().await.ssh[&request.request_id]
            .response
            .is_none()
    );
    harness.reply(identity(&request.request_id)).await;
    assert_eq!(harness.bridge.inner.lock().await.in_flight(), 0);
    harness.stop().await;
}

#[tokio::test]
async fn ssh_output_reservation_expiry_never_dispatches_or_registers() {
    let mut harness = Harness::new(bridge()).await;
    let output = harness.fill_output().await;
    let mut request = ssh_request();
    request.deadline_unix_ms = now_ms() + 200;
    assert_eq!(
        bounded(harness.bridge.relay_ssh(request))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::DeadlineExceeded
    );
    assert_eq!(harness.bridge.inner.lock().await.in_flight(), 0);
    for _ in 0..HOST_OUTPUT_BUFFER {
        let frame = bounded(harness.output.next()).await.unwrap().unwrap();
        assert!(matches!(
            frame.payload,
            Some(v1::credential_bridge_guest_message::Payload::Cancel(_))
        ));
    }
    assert_eq!(output.capacity(), HOST_OUTPUT_BUFFER);
    harness.stop().await;
}

#[tokio::test]
async fn ssh_final_release_rejects_response_queued_before_original_deadline() {
    let mut harness = Harness::new(bridge()).await;
    {
        let mut request = ssh_request();
        request.deadline_unix_ms = now_ms() + 200;
        let relay = harness.bridge.relay_ssh(request.clone());
        tokio::pin!(relay);
        std::future::poll_fn(|cx| {
            assert!(relay.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        bounded(harness.output.next()).await.unwrap().unwrap();
        let deadline = harness.bridge.inner.lock().await.ssh[&request.request_id].deadline;
        harness.reply(identity(&request.request_id)).await;
        assert_eq!(harness.bridge.inner.lock().await.in_flight(), 0);
        // The result is already queued, but the caller has not resumed yet.
        // Synchronize on its actual original deadline, not a guessed delay.
        bounded(tokio::time::sleep_until(deadline)).await;
        assert_eq!(
            bounded(relay).await.unwrap_err().code(),
            tonic::Code::DeadlineExceeded
        );
    }
    harness.stop().await;
}

#[tokio::test]
async fn ssh_response_expiry_and_final_release_recheck_are_fail_closed() {
    let mut harness = Harness::new(bridge()).await;
    {
        let request = ssh_request();
        let relay = harness.bridge.relay_ssh(request.clone());
        tokio::pin!(relay);
        std::future::poll_fn(|cx| {
            assert!(relay.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        bounded(harness.output.next()).await.unwrap().unwrap();
        // Deterministically exercise late-response admission independently of the
        // caller's timer. The original deadline cannot be refreshed by a reply.
        harness
            .bridge
            .inner
            .lock()
            .await
            .ssh
            .get_mut(&request.request_id)
            .unwrap()
            .deadline = tokio::time::Instant::now();
        harness.reply(identity(&request.request_id)).await;
        assert_eq!(
            bounded(relay).await.unwrap_err().code(),
            tonic::Code::DeadlineExceeded
        );
        assert_eq!(harness.bridge.inner.lock().await.in_flight(), 0);
    }

    {
        let request = ssh_request();
        let relay = harness.bridge.relay_ssh(request.clone());
        tokio::pin!(relay);
        std::future::poll_fn(|cx| {
            assert!(relay.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        bounded(harness.output.next()).await.unwrap().unwrap();
        harness.reply(identity(&request.request_id)).await;
        let replacement = Harness::new(harness.bridge.clone()).await;
        assert_eq!(
            bounded(relay).await.unwrap_err().code(),
            tonic::Code::Aborted
        );
        replacement.stop().await;
    }
    harness.stop().await;
}

#[tokio::test]
async fn ssh_wrong_kind_or_wrong_family_response_detaches_instead_of_completing() {
    for wrong_family in [false, true] {
        let mut harness = Harness::new(bridge()).await;
        let request = ssh_request();
        let task = harness.submit(request.clone()).await;
        let payload = if wrong_family {
            v1::credential_bridge_host_message::Payload::ResponseFailure(
                v1::CredentialBridgeResponseFailure {
                    request_id: request.request_id.clone(),
                    reason: v1::CredentialBridgeFailureReason::Denied as i32,
                },
            )
        } else {
            v1::credential_bridge_host_message::Payload::Ssh(signature(&request.request_id))
        };
        harness
            .input
            .send(Ok(v1::CredentialBridgeHostMessage {
                payload: Some(payload),
            }))
            .await
            .unwrap();
        assert_eq!(
            bounded(task).await.unwrap().unwrap_err().code(),
            tonic::Code::Unavailable
        );
        assert_eq!(
            bounded(harness.output.next())
                .await
                .unwrap()
                .unwrap_err()
                .code(),
            tonic::Code::InvalidArgument
        );
        assert!(bounded(harness.output.next()).await.is_none());
        assert_eq!(harness.bridge.inner.lock().await.in_flight(), 0);
        assert!(harness.bridge.inner.lock().await.active.is_none());
        harness.stop().await;
    }
}

#[tokio::test]
async fn ssh_replacement_disconnect_and_old_epoch_never_replay_or_release() {
    let shared = bridge();
    let mut old = Harness::new(shared.clone()).await;
    let request = ssh_request();
    let task = old.submit(request.clone()).await;
    let mut replacement = Harness::new(shared.clone()).await;
    assert_eq!(
        bounded(task).await.unwrap().unwrap_err().code(),
        tonic::Code::Unavailable
    );
    assert_eq!(shared.inner.lock().await.in_flight(), 0);
    assert_eq!(
        shared
            .inner
            .lock()
            .await
            .active
            .as_ref()
            .unwrap()
            .output
            .capacity(),
        HOST_OUTPUT_BUFFER
    );
    // Even reuse in the new epoch cannot let an old terminal target it.
    let task = replacement.submit(request.clone()).await;
    assert_eq!(
        shared
            .apply_ssh_response(old.epoch, identity(&request.request_id))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::Aborted
    );
    shared.cancel(&request.request_id, old.epoch).await;
    shared.detach(old.epoch).await;
    assert!(
        shared.inner.lock().await.ssh[&request.request_id]
            .response
            .is_some()
    );
    replacement.stop().await;
    assert_eq!(
        bounded(task).await.unwrap().unwrap_err().code(),
        tonic::Code::Unavailable
    );
    let current = Harness::new(shared.clone()).await;
    assert_eq!(shared.inner.lock().await.in_flight(), 0);
    assert_eq!(
        shared
            .inner
            .lock()
            .await
            .active
            .as_ref()
            .unwrap()
            .output
            .capacity(),
        HOST_OUTPUT_BUFFER
    );
    current.stop().await;
    old.stop().await;
}

fn sign_request() -> v1::CredentialSshRequest {
    v1::CredentialSshRequest {
        operation: Some(v1::credential_ssh_request::Operation::Sign(
            v1::CredentialSshSignRequest {
                public_key_blob: b"synthetic-public-key".to_vec(),
                data: b"synthetic-signing-data".to_vec(),
                flags: 4,
            },
        )),
        ..ssh_request()
    }
}

#[tokio::test]
async fn ssh_signature_is_released_from_a_draining_epoch_within_its_deadline() {
    let shared = bridge();
    let mut old = Harness::new(shared.clone()).await;
    let released = sign_request();
    let released_task = old.submit(released.clone()).await;
    let expired = sign_request();
    let expired_relay = shared.relay_ssh(expired.clone());
    tokio::pin!(expired_relay);
    std::future::poll_fn(|cx| {
        assert!(expired_relay.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    bounded(old.output.next()).await.unwrap().unwrap();
    let mut successor = Harness::with_replacement(shared.clone(), EpochReplacement::Drain).await;
    // A signature answered on the draining epoch is still released.
    old.reply(signature(&released.request_id)).await;
    assert_eq!(
        bounded(released_task).await.unwrap().unwrap(),
        signature(&released.request_id)
    );
    // Its original deadline still applies there.
    shared
        .inner
        .lock()
        .await
        .ssh
        .get_mut(&expired.request_id)
        .unwrap()
        .deadline = tokio::time::Instant::now();
    old.reply(signature(&expired.request_id)).await;
    assert_eq!(
        bounded(expired_relay).await.unwrap_err().code(),
        tonic::Code::DeadlineExceeded
    );
    assert_eq!(shared.inner.lock().await.in_flight(), 0);
    // New work goes only to the successor.
    let next = ssh_request();
    let task = successor.submit(next.clone()).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(20), old.output.next())
            .await
            .is_err()
    );
    successor.reply(identity(&next.request_id)).await;
    bounded(task).await.unwrap().unwrap();
    assert_eq!(
        shared
            .inner
            .lock()
            .await
            .draining
            .as_ref()
            .map(|host| host.epoch),
        Some(old.epoch)
    );
    successor.stop().await;
    old.stop().await;
}
