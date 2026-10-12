use codewire_workload_secrets::seal_environment_projection;

use super::*;

fn initial_context(bridge: &CredentialBridge, lifetime_ms: u64) -> ProjectionContext {
    ProjectionContext {
        environment_id: *bridge.environment_id.as_bytes(),
        operation_generation: bridge.environment_generation,
        selection_sha256: [3; 32],
        deadline_unix_ms: now_unix_ms().unwrap() + lifetime_ms,
    }
}

#[tokio::test]
async fn startup_waits_for_authenticated_activation_not_prepared_socket_or_ready() {
    let bridge = bridge();
    let context = initial_context(&bridge, 5_000);
    let (prepared, mut output) = bridge.prepare_connection().unwrap();
    assert!(output.next().await.is_some()); // Ready is not authentication.
    let first = bridge.wait_for_initial_host(&context);
    let second = bridge.wait_for_initial_host(&context);
    tokio::pin!(first, second);
    for wait in [&mut first, &mut second] {
        assert!(
            tokio::time::timeout(Duration::from_millis(10), wait)
                .await
                .is_err()
        );
    }
    let (_sender, receiver) = mpsc::channel(1);
    let connection = prepared
        .activate(ReceiverStream::new(receiver))
        .await
        .unwrap();
    bounded(first).await.unwrap();
    bounded(second).await.unwrap();
    assert!(bridge.inner.lock().await.projections.is_empty());
    connection.run_until(std::future::ready(())).await;
}

#[tokio::test]
async fn startup_host_wait_respects_original_deadline_and_rejects_wrong_identity() {
    let bridge = bridge();
    let mut context = initial_context(&bridge, 20);
    assert_eq!(
        bounded(bridge.wait_for_initial_host(&context))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::Unavailable
    );
    assert!(bridge.inner.lock().await.projections.is_empty());
    context.deadline_unix_ms = now_unix_ms().unwrap() + 5_000;
    context.operation_generation += 1;
    assert_eq!(
        bridge
            .wait_for_initial_host(&context)
            .await
            .unwrap_err()
            .code(),
        tonic::Code::InvalidArgument
    );
}

#[tokio::test]
async fn startup_host_wait_never_waits_for_a_lost_epoch_to_reconnect() {
    let bridge = bridge();
    let context = initial_context(&bridge, 5_000);
    let harness = Harness::new(bridge.clone()).await;
    bridge.wait_for_initial_host(&context).await.unwrap();
    harness.stop().await;
    assert_eq!(
        bounded(bridge.wait_for_initial_host(&context))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::Unavailable
    );
}

#[tokio::test]
async fn ciphertext_relay_preserves_actual_launcher_recipient_and_epoch_fence() {
    let mut harness = Harness::new(bridge()).await;
    let context = harness.context();
    let recipient = ProjectionRecipient::new();
    let actual_key = recipient.public_key();
    let transport = harness.bridge.clone();
    let request_context = context.clone();
    let task = tokio::spawn(async move {
        transport
            .project_environment_for_recipient(request_context, actual_key)
            .await
    });
    let frame = bounded(harness.output.next()).await.unwrap().unwrap();
    let Some(v1::credential_bridge_guest_message::Payload::EnvironmentProjection(request)) =
        frame.payload
    else {
        panic!("typed projection expected")
    };
    assert_eq!(request.recipient_public_key, actual_key);
    harness.reply(&request).await;
    let sealed = bounded(task).await.unwrap().unwrap();
    sealed.validate().await.unwrap();
    let projection = recipient
        .open(sealed.ciphertext(), &context, now_unix_ms().unwrap())
        .unwrap();
    assert_eq!(
        projection.entries().collect::<Vec<_>>(),
        [("APP_TOKEN", "synthetic-application-value")]
    );
    let replacement = Harness::new(harness.bridge.clone()).await;
    assert!(sealed.validate().await.is_err());
    replacement.stop().await;
    harness.stop().await;
}

#[tokio::test]
async fn ciphertext_relay_rejects_invalid_recipient_before_registering_or_dispatching() {
    let mut harness = Harness::new(bridge()).await;
    let result = harness
        .bridge
        .project_environment_for_recipient(harness.context(), [0; 32])
        .await;
    assert!(matches!(result, Err(status) if status.code() == tonic::Code::InvalidArgument));
    assert!(harness.bridge.inner.lock().await.projections.is_empty());
    assert!(
        tokio::time::timeout(Duration::from_millis(20), harness.output.next())
            .await
            .is_err()
    );
    harness.stop().await;
}

struct Harness {
    bridge: CredentialBridge,
    input: mpsc::Sender<Result<v1::CredentialBridgeHostMessage, Status>>,
    output: CredentialBridgeOutput,
    task: tokio::task::JoinHandle<()>,
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
        let (input, receiver) = mpsc::channel(32);
        let connection = prepared
            .activate_with_replacement(ReceiverStream::new(receiver), &[], replacement)
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

    fn context(&self) -> ProjectionContext {
        ProjectionContext {
            environment_id: *self.bridge.environment_id.as_bytes(),
            operation_generation: self.bridge.environment_generation,
            selection_sha256: [3; 32],
            deadline_unix_ms: now_unix_ms().unwrap() + 5_000,
        }
    }

    async fn submit(
        &mut self,
    ) -> (
        tokio::task::JoinHandle<Result<EnvironmentProjection, Status>>,
        v1::EnvironmentProjectionRequest,
    ) {
        let bridge = self.bridge.clone();
        let context = self.context();
        let task = tokio::spawn(async move { bridge.project_environment(context).await });
        let message = bounded(self.output.next()).await.unwrap().unwrap();
        let Some(v1::credential_bridge_guest_message::Payload::EnvironmentProjection(request)) =
            message.payload
        else {
            panic!("expected typed projection");
        };
        (task, request)
    }

    async fn reply(&self, request: &v1::EnvironmentProjectionRequest) {
        let mut context = self.context();
        context.deadline_unix_ms = request.deadline_unix_ms;
        let projection = EnvironmentProjection::from_entries([(
            "APP_TOKEN".into(),
            b"synthetic-application-value".to_vec().into(),
        )])
        .unwrap();
        let encrypted = seal_environment_projection(
            projection,
            &context,
            request.recipient_public_key.as_slice().try_into().unwrap(),
            now_unix_ms().unwrap(),
        )
        .unwrap();
        self.input
            .send(Ok(v1::CredentialBridgeHostMessage {
                payload: Some(
                    v1::credential_bridge_host_message::Payload::EnvironmentProjection(
                        v1::EnvironmentProjectionResponse {
                            request_id: request.request_id.clone(),
                            result: Some(
                                v1::environment_projection_response::Result::SealedProjection(
                                    encrypted,
                                ),
                            ),
                        },
                    ),
                ),
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
        .expect("bounded projection fixture")
}

#[tokio::test]
async fn typed_projection_round_trip_uses_current_authenticated_epoch() {
    let mut harness = Harness::new(bridge()).await;
    let (task, request) = harness.submit().await;
    assert_eq!(request.selection_sha256, vec![3; 32]);
    harness.reply(&request).await;
    let opened = bounded(task).await.unwrap().unwrap();
    assert_eq!(
        opened.entries().collect::<Vec<_>>(),
        [("APP_TOKEN", "synthetic-application-value")]
    );
    assert!(harness.bridge.inner.lock().await.projections.is_empty());
    harness.stop().await;
}

#[tokio::test]
async fn invalid_coordinates_and_unadmitted_connection_enqueue_nothing() {
    let bridge = bridge();
    let context = ProjectionContext {
        environment_id: *bridge.environment_id.as_bytes(),
        operation_generation: 7,
        selection_sha256: [3; 32],
        deadline_unix_ms: now_unix_ms().unwrap() + 5_000,
    };
    assert_eq!(
        bridge
            .project_environment(context.clone())
            .await
            .unwrap_err()
            .code(),
        tonic::Code::Unavailable
    );
    let harness = Harness::new(bridge.clone()).await;
    for field in 0..3 {
        let mut wrong = context.clone();
        match field {
            0 => wrong.environment_id[0] ^= 1,
            1 => wrong.operation_generation += 1,
            _ => wrong.deadline_unix_ms = 1,
        }
        assert_eq!(
            bridge.project_environment(wrong).await.unwrap_err().code(),
            tonic::Code::InvalidArgument
        );
    }
    assert!(bridge.inner.lock().await.projections.is_empty());
    harness.stop().await;
}

#[tokio::test]
async fn application_http_ingress_cannot_request_a_projection() {
    let harness = Harness::new(bridge()).await;
    // `/v1/...` is the Codex client's transparent provider base, so a path
    // there is an ordinary proxied provider request, never a projection.
    for path in [
        "/environment-projection",
        "/internal/environment-projection",
    ] {
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
    assert!(harness.bridge.inner.lock().await.projections.is_empty());
    harness.stop().await;
}

#[tokio::test]
async fn cancellation_retains_its_slot_until_late_response_is_drained() {
    let mut harness = Harness::new(bridge()).await;
    let (task, request) = harness.submit().await;
    task.abort();
    assert!(bounded(task).await.unwrap_err().is_cancelled());
    let cancel = bounded(harness.output.next()).await.unwrap().unwrap();
    assert!(
        matches!(cancel.payload, Some(v1::credential_bridge_guest_message::Payload::Cancel(ref cancel)) if cancel.request_id == request.request_id)
    );
    assert_eq!(harness.bridge.inner.lock().await.projections.len(), 1);
    harness.reply(&request).await;
    // A second completed request proves the preceding late response was drained.
    let (task, request) = harness.submit().await;
    harness.reply(&request).await;
    bounded(task).await.unwrap().unwrap();
    assert!(harness.bridge.inner.lock().await.projections.is_empty());
    harness.stop().await;
}

#[tokio::test]
async fn replacing_the_epoch_fails_old_projection_and_old_reply_cannot_reach_new_launch() {
    let shared = bridge();
    let mut old = Harness::new(shared.clone()).await;
    let (task, _) = old.submit().await;
    let mut new = Harness::new(shared).await;
    assert_eq!(
        bounded(task).await.unwrap().unwrap_err().code(),
        tonic::Code::Unavailable
    );
    let (task, request) = new.submit().await;
    new.reply(&request).await;
    bounded(task).await.unwrap().unwrap();
    old.stop().await;
    new.stop().await;
}

#[tokio::test]
async fn a_projection_answered_on_a_draining_epoch_is_not_released() {
    let shared = bridge();
    let mut old = Harness::new(shared.clone()).await;
    let (task, request) = old.submit().await;
    let mut new = Harness::with_replacement(shared.clone(), EpochReplacement::Drain).await;
    // The draining epoch accepts the answer without ending, but the release
    // stays strict like `validate`: only the active epoch's fence is kept.
    old.reply(&request).await;
    assert_eq!(
        bounded(task).await.unwrap().unwrap_err().code(),
        tonic::Code::Aborted
    );
    assert!(!old.task.is_finished());
    assert!(shared.inner.lock().await.projections.is_empty());
    let (task, request) = new.submit().await;
    new.reply(&request).await;
    bounded(task).await.unwrap().unwrap();
    old.stop().await;
    new.stop().await;
}

#[tokio::test]
async fn a_projection_answer_on_the_wrong_epoch_leaves_the_other_request() {
    for draining_sends in [true, false] {
        let shared = bridge();
        let mut old = Harness::new(shared.clone()).await;
        let (old_task, old_request) = old.submit().await;
        let mut new = Harness::with_replacement(shared.clone(), EpochReplacement::Drain).await;
        let (new_task, new_request) = new.submit().await;
        let (wrong, kept, kept_request, kept_task, wrong_task) = if draining_sends {
            (old, new, new_request, new_task, old_task)
        } else {
            (new, old, old_request, old_task, new_task)
        };
        wrong.reply(&kept_request).await;
        bounded(wrong.task).await.unwrap();
        assert_eq!(
            bounded(wrong_task).await.unwrap().unwrap_err().code(),
            tonic::Code::Unavailable
        );
        assert!(
            shared
                .inner
                .lock()
                .await
                .projections
                .contains_key(&kept_request.request_id)
        );
        kept.reply(&kept_request).await;
        let result = bounded(kept_task).await.unwrap();
        if draining_sends {
            // The active epoch's own answer is released.
            result.unwrap();
        } else {
            // Answered on its own, now inactive epoch: accepted without
            // ending that epoch, and released strictly, as `validate` is.
            assert_eq!(result.unwrap_err().code(), tonic::Code::Aborted);
        }
        assert!(!kept.task.is_finished());
        assert!(shared.inner.lock().await.projections.is_empty());
        kept.stop().await;
    }
}

#[tokio::test]
async fn disconnected_authority_fails_pending_launch_without_partial_values() {
    let mut harness = Harness::new(bridge()).await;
    let (task, _) = harness.submit().await;
    harness.stop().await;
    assert_eq!(
        bounded(task).await.unwrap().unwrap_err().code(),
        tonic::Code::Unavailable
    );
}

#[tokio::test]
async fn projections_share_the_existing_http_in_flight_budget() {
    let mut harness = Harness::new(bridge()).await;
    let mut tasks = Vec::new();
    for _ in 0..CREDENTIAL_BRIDGE_MAX_IN_FLIGHT {
        tasks.push(harness.submit().await.0);
    }
    assert_eq!(
        harness
            .bridge
            .project_environment(harness.context())
            .await
            .unwrap_err()
            .code(),
        tonic::Code::ResourceExhausted
    );
    let response = harness
        .bridge
        .respond(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/responses")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    harness.stop().await;
    for task in tasks {
        assert!(bounded(task).await.unwrap().is_err());
    }
}

#[tokio::test]
async fn cancellation_before_output_reservation_leaves_no_unsent_tombstone() {
    let mut harness = Harness::new(bridge()).await;
    let output = harness
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
                v1::credential_bridge_guest_message::Payload::Cancel(v1::CredentialBridgeCancel {
                    request_id: Uuid::new_v4().to_string(),
                }),
            )))
            .unwrap();
    }
    let context = harness.context();
    {
        let projection = harness.bridge.project_environment(context);
        tokio::pin!(projection);
        // Poll to the full-queue suspension, then actually drop the future
        // (not just its Pin borrow) before any frame is dispatched.
        std::future::poll_fn(|cx| {
            assert!(projection.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        assert!(harness.bridge.inner.lock().await.projections.is_empty());
    }
    for _ in 0..HOST_OUTPUT_BUFFER {
        let _ = bounded(harness.output.next()).await.unwrap().unwrap();
    }
    assert_eq!(output.capacity(), HOST_OUTPUT_BUFFER);
    let (task, request) = harness.submit().await;
    harness.reply(&request).await;
    bounded(task).await.unwrap().unwrap();
    harness.stop().await;
}
