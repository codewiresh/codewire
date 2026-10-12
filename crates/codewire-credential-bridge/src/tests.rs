use super::*;
use v1::credential_bridge_guest_message::Payload as GuestPayload;
use v1::credential_bridge_host_message::Payload as HostPayload;

const TIMEOUT: Duration = Duration::from_secs(2);

async fn bounded<F: Future>(future: F) -> F::Output {
    tokio::time::timeout(TIMEOUT, future)
        .await
        .expect("bounded synthetic bridge operation")
}

fn bridge() -> CredentialBridge {
    CredentialBridge::new(Uuid::new_v4(), 7).unwrap()
}

fn request() -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri("/v1/responses")
        .header("content-type", "application/json")
        .header("content-length", "2")
        .body(Body::from("{}"))
        .unwrap()
}

fn start(id: &str) -> HostPayload {
    HostPayload::ResponseStart(v1::CredentialBridgeResponseStart {
        request_id: id.to_owned(),
        status_code: 200,
        headers: vec![v1::CredentialHttpHeader {
            name: "content-type".to_owned(),
            value: b"text/event-stream".to_vec(),
        }],
    })
}

fn body(id: &str, data: &[u8]) -> HostPayload {
    HostPayload::ResponseBody(v1::CredentialBridgeResponseBody {
        request_id: id.to_owned(),
        data: data.to_vec(),
    })
}

fn end(id: &str) -> HostPayload {
    HostPayload::ResponseEnd(v1::CredentialBridgeResponseEnd {
        request_id: id.to_owned(),
    })
}

struct Harness {
    bridge: CredentialBridge,
    epoch: u64,
    input: mpsc::Sender<Result<v1::CredentialBridgeHostMessage, Status>>,
    output: CredentialBridgeOutput,
    shutdown: oneshot::Sender<()>,
    task: tokio::task::JoinHandle<()>,
}

impl Harness {
    async fn new() -> Self {
        Self::for_bridge(bridge()).await
    }

    async fn for_bridge(bridge: CredentialBridge) -> Self {
        Self::with_replacement(bridge, EpochReplacement::FailPending).await
    }

    /// A successor that leaves the epoch it replaces draining.
    async fn draining(bridge: CredentialBridge) -> Self {
        Self::with_replacement(bridge, EpochReplacement::Drain).await
    }

    async fn with_replacement(bridge: CredentialBridge, replacement: EpochReplacement) -> Self {
        let (prepared, output) = Self::prepare(&bridge).await;
        Self::activate(bridge, prepared, output, replacement).await
    }

    /// A successor that has sent Ready but is not yet activated.
    async fn prepare(
        bridge: &CredentialBridge,
    ) -> (PreparedBridgeConnection, CredentialBridgeOutput) {
        let (prepared, mut output) = bridge.prepare_connection().unwrap();
        let ready = bounded(output.next()).await.unwrap().unwrap();
        let Some(GuestPayload::Ready(ready)) = ready.payload else {
            panic!("Ready must precede activation and all requests");
        };
        assert_eq!(ready.protocol_version, CREDENTIAL_BRIDGE_PROTOCOL_VERSION);
        assert_eq!(ready.environment_id, bridge.environment_id.to_string());
        assert_eq!(ready.environment_generation, bridge.environment_generation);
        (prepared, output)
    }

    async fn activate(
        bridge: CredentialBridge,
        prepared: PreparedBridgeConnection,
        output: CredentialBridgeOutput,
        replacement: EpochReplacement,
    ) -> Self {
        let (input, receiver) = mpsc::channel(32);
        let connection = prepared
            .activate_with_replacement(ReceiverStream::new(receiver), &[], replacement)
            .await
            .unwrap();
        let epoch = connection.epoch;
        let (shutdown, shutdown_rx) = oneshot::channel();
        let task = tokio::spawn(connection.run_until(async {
            let _ = shutdown_rx.await;
        }));
        Self {
            bridge,
            epoch,
            input,
            output,
            shutdown,
            task,
        }
    }

    async fn next(&mut self) -> v1::CredentialBridgeGuestMessage {
        bounded(self.output.next()).await.unwrap().unwrap()
    }

    async fn submit(
        &mut self,
    ) -> (
        tokio::task::JoinHandle<Response<Body>>,
        v1::CredentialBridgeRequest,
    ) {
        let bridge = self.bridge.clone();
        let task = tokio::spawn(async move { bridge.respond(request()).await });
        let Some(GuestPayload::Request(request)) = self.next().await.payload else {
            panic!("expected a request");
        };
        (task, request)
    }

    async fn send(&self, payload: HostPayload) {
        bounded(self.input.send(Ok(v1::CredentialBridgeHostMessage {
            payload: Some(payload),
        })))
        .await
        .unwrap();
    }

    async fn terminal(&mut self, code: tonic::Code) {
        let status = bounded(self.output.next()).await.unwrap().unwrap_err();
        assert_eq!(status.code(), code);
        assert!(bounded(self.output.next()).await.is_none());
    }

    async fn stop(self) {
        let _ = self.shutdown.send(());
        bounded(self.task).await.unwrap();
    }

    /// The host ends this epoch's stream, as a broker does at its expiry.
    async fn end_stream(self) -> CredentialBridgeOutput {
        drop(self.input);
        bounded(self.task).await.unwrap();
        drop(self.shutdown);
        self.output
    }

    /// Nothing more is sent on this epoch for now.
    async fn quiet(&mut self) {
        assert!(
            tokio::time::timeout(Duration::from_millis(20), self.output.next())
                .await
                .is_err(),
            "unexpected frame on this epoch"
        );
    }
}

#[test]
fn identity_requires_nonzero_fixed_coordinates() {
    assert!(CredentialBridge::new(Uuid::nil(), 1).is_err());
    assert!(CredentialBridge::new(Uuid::new_v4(), 0).is_err());
}

#[tokio::test]
async fn ready_is_available_before_activation_but_http_is_not_admitted() {
    let bridge = bridge();
    let (prepared, mut output) = bridge.prepare_connection().unwrap();
    assert!(matches!(
        bounded(output.next()).await.unwrap().unwrap().payload,
        Some(GuestPayload::Ready(_))
    ));
    assert_eq!(
        bounded(bridge.respond(request())).await.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    drop(prepared);
    assert!(bounded(output.next()).await.is_none());

    let (prepared, output) = bridge.prepare_connection().unwrap();
    drop(output);
    let result = prepared.activate(tokio_stream::empty()).await;
    assert!(matches!(result, Err(status) if status.code() == tonic::Code::Unavailable));
    assert!(bridge.inner.lock().await.active.is_none());
}

#[tokio::test]
async fn abandoned_preparation_does_not_replace_an_active_connection() {
    let mut harness = Harness::new().await;
    let (task, request) = harness.submit().await;
    let (prepared, mut output) = harness.bridge.prepare_connection().unwrap();
    assert!(matches!(
        bounded(output.next()).await.unwrap().unwrap().payload,
        Some(GuestPayload::Ready(_))
    ));
    drop(prepared);
    assert!(bounded(output.next()).await.is_none());
    harness.send(start(&request.request_id)).await;
    harness.send(end(&request.request_id)).await;
    let response = bounded(task).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        bounded(to_bytes(response.into_body(), 100))
            .await
            .unwrap()
            .is_empty()
    );
    harness.stop().await;
}

#[tokio::test]
async fn admitted_bridge_carries_bounded_request_and_streamed_response() {
    let mut harness = Harness::new().await;
    let (task, request) = harness.submit().await;
    assert_eq!(request.method, "POST");
    assert_eq!(request.path, "/responses");
    assert!(request.query.is_empty());
    assert_eq!(request.body, b"{}");
    assert_eq!(
        Uuid::parse_str(&request.request_id).unwrap().to_string(),
        request.request_id
    );
    assert!(
        request
            .headers
            .iter()
            .any(|header| header.name == "content-type")
    );
    assert!(
        request
            .headers
            .iter()
            .all(|header| header.name != "content-length")
    );
    harness.send(start(&request.request_id)).await;
    harness
        .send(body(&request.request_id, b"data: synthetic"))
        .await;
    harness
        .send(body(&request.request_id, b" response\n\n"))
        .await;
    harness.send(end(&request.request_id)).await;
    let response = bounded(task).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["content-type"], "text/event-stream");
    assert_eq!(
        bounded(to_bytes(response.into_body(), 100)).await.unwrap(),
        "data: synthetic response\n\n"
    );
    harness.stop().await;
}

#[tokio::test]
async fn replacement_closes_stale_stream_and_fails_its_pending_request() {
    let mut first = Harness::new().await;
    let (task, _) = first.submit().await;
    let mut second = Harness::for_bridge(first.bridge.clone()).await;
    assert_eq!(
        bounded(task).await.unwrap().status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert!(bounded(first.output.next()).await.is_none());
    first.stop().await;
    let (task, request) = second.submit().await;
    second.send(start(&request.request_id)).await;
    second.send(end(&request.request_id)).await;
    assert_eq!(bounded(task).await.unwrap().status(), StatusCode::OK);
    second.stop().await;
}

#[tokio::test]
async fn out_of_order_or_unknown_host_frames_fail_closed() {
    for case in 0..8 {
        let mut harness = Harness::new().await;
        let (task, request) = harness.submit().await;
        let id = request.request_id;
        if case == 2 {
            harness.send(start(&id)).await;
        }
        let payload = match case {
            0 => Some(body(&id, b"body-before-start")),
            1 => Some(end(&id)),
            2 => Some(start(&id)),
            3 => Some(start("unknown-id")),
            4 => Some(HostPayload::Open(v1::CredentialBridgeOpen {
                protocol_version: CREDENTIAL_BRIDGE_PROTOCOL_VERSION,
                environment_id: harness.bridge.environment_id.to_string(),
                environment_generation: 7,
                capabilities: Vec::new(),
            })),
            5 => None,
            6 => Some(HostPayload::ResponseFailure(
                v1::CredentialBridgeResponseFailure {
                    request_id: id.clone(),
                    reason: 0,
                },
            )),
            7 => Some(HostPayload::ResponseStart(
                v1::CredentialBridgeResponseStart {
                    request_id: id,
                    status_code: 100,
                    headers: Vec::new(),
                },
            )),
            _ => unreachable!(),
        };
        bounded(
            harness
                .input
                .send(Ok(v1::CredentialBridgeHostMessage { payload })),
        )
        .await
        .unwrap();
        harness.terminal(tonic::Code::InvalidArgument).await;
        let response = bounded(task).await.unwrap();
        if case == 2 {
            assert!(bounded(to_bytes(response.into_body(), 100)).await.is_err());
        } else {
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        }
        harness.stop().await;
    }
}

#[tokio::test]
async fn cancelled_guest_request_tolerates_late_host_frames_without_detaching_bridge() {
    for after_start in [false, true] {
        let mut harness = Harness::new().await;
        let (task, request) = harness.submit().await;
        let id = request.request_id;
        if after_start {
            harness.send(start(&id)).await;
            drop(bounded(task).await.unwrap());
        } else {
            task.abort();
            assert!(bounded(task).await.unwrap_err().is_cancelled());
        }
        let Some(GuestPayload::Cancel(cancel)) = harness.next().await.payload else {
            panic!("cancel frame required");
        };
        assert_eq!(cancel.request_id, id);
        if !after_start {
            harness.send(start(&id)).await;
        }
        harness.send(body(&id, b"late")).await;
        harness.send(end(&id)).await;
        let (task, request) = harness.submit().await;
        harness
            .send(HostPayload::ResponseFailure(
                v1::CredentialBridgeResponseFailure {
                    request_id: request.request_id,
                    reason: v1::CredentialBridgeFailureReason::Denied as i32,
                },
            ))
            .await;
        assert_eq!(bounded(task).await.unwrap().status(), StatusCode::FORBIDDEN);
        assert!(harness.bridge.inner.lock().await.pending.is_empty());
        harness.stop().await;
    }
}

#[tokio::test]
async fn response_stream_requires_an_explicit_end_for_clean_eof() {
    let mut harness = Harness::new().await;
    let (task, request) = harness.submit().await;
    harness.send(start(&request.request_id)).await;
    harness.send(body(&request.request_id, b"partial")).await;
    let response = bounded(task).await.unwrap();
    harness.stop().await;
    assert!(bounded(to_bytes(response.into_body(), 100)).await.is_err());

    let mut harness = Harness::new().await;
    let (task, request) = harness.submit().await;
    harness.send(start(&request.request_id)).await;
    harness.send(end(&request.request_id)).await;
    let response = bounded(task).await.unwrap();
    assert!(
        bounded(to_bytes(response.into_body(), 100))
            .await
            .unwrap()
            .is_empty()
    );
    harness.stop().await;
}

#[tokio::test]
async fn response_chunk_and_cumulative_limits_are_enforced() {
    for case in 0..3 {
        let mut harness = Harness::new().await;
        let (task, request) = harness.submit().await;
        harness.send(start(&request.request_id)).await;
        let response = bounded(task).await.unwrap();
        let data = match case {
            0 => Vec::new(),
            1 => vec![b'x'; CREDENTIAL_BRIDGE_MAX_BODY_CHUNK_BYTES + 1],
            2 => {
                harness
                    .bridge
                    .inner
                    .lock()
                    .await
                    .pending
                    .get_mut(&request.request_id)
                    .unwrap()
                    .received_bytes = CREDENTIAL_BRIDGE_MAX_RESPONSE_BYTES;
                vec![b'x']
            }
            _ => unreachable!(),
        };
        harness.send(body(&request.request_id, &data)).await;
        harness
            .terminal(if case == 2 {
                tonic::Code::ResourceExhausted
            } else {
                tonic::Code::InvalidArgument
            })
            .await;
        assert!(bounded(to_bytes(response.into_body(), 100)).await.is_err());
        harness.stop().await;
    }
}

/// Queue host frames from a separate task: a reader that has not caught up
/// holds the host stream back, so these sends wait rather than fail.
fn stream_body(harness: &Harness, request_id: &str, chunks: usize) -> tokio::task::JoinHandle<()> {
    let input = harness.input.clone();
    let request_id = request_id.to_owned();
    tokio::spawn(async move {
        for payload in (0..chunks)
            .map(|_| body(&request_id, b"x"))
            .chain([end(&request_id)])
        {
            let message = v1::CredentialBridgeHostMessage {
                payload: Some(payload),
            };
            if input.send(Ok(message)).await.is_err() {
                return;
            }
        }
    })
}

#[tokio::test]
async fn a_slow_reader_holds_the_host_back_and_receives_every_byte() {
    let mut harness = Harness::new().await;
    let (task, request) = harness.submit().await;
    harness.send(start(&request.request_id)).await;
    let response = bounded(task).await.unwrap();
    // More than the reader's bounded queue arrives before it reads anything.
    let chunks = 2 * RESPONSE_BODY_BUFFER;
    let sender = stream_body(&harness, &request.request_id, chunks);
    for _ in 0..64 {
        tokio::task::yield_now().await;
    }
    assert!(harness.bridge.inner.lock().await.active.is_some());
    let bytes = bounded(to_bytes(response.into_body(), chunks))
        .await
        .unwrap();
    assert_eq!(bytes.len(), chunks);
    bounded(sender).await.unwrap();
    harness.stop().await;
}

#[tokio::test]
async fn a_stalled_reader_loses_only_its_own_response() {
    let mut harness = Harness::new().await;
    let (task, request) = harness.submit().await;
    harness.send(start(&request.request_id)).await;
    let response = bounded(task).await.unwrap();
    let sender = stream_body(&harness, &request.request_id, RESPONSE_BODY_BUFFER + 2);
    // The reader never reads: after its timeout the host is asked to stop.
    let cancel = harness.next().await;
    assert!(matches!(
        cancel.payload,
        Some(GuestPayload::Cancel(ref cancel)) if cancel.request_id == request.request_id
    ));
    bounded(sender).await.unwrap();
    // Buffered bytes are delivered, then the body ends as incomplete.
    assert!(bounded(to_bytes(response.into_body(), 1024)).await.is_err());
    // The bridge still serves other requests.
    let (task, request) = harness.submit().await;
    harness.send(start(&request.request_id)).await;
    harness.send(end(&request.request_id)).await;
    assert_eq!(bounded(task).await.unwrap().status(), StatusCode::OK);
    harness.stop().await;
}

#[tokio::test]
async fn pending_request_limit_includes_cancelled_requests_until_terminal_frame() {
    let mut harness = Harness::new().await;
    let mut pending = Vec::new();
    for _ in 0..CREDENTIAL_BRIDGE_MAX_IN_FLIGHT {
        pending.push(harness.submit().await);
    }
    assert_eq!(
        bounded(harness.bridge.respond(request())).await.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    let (task, cancelled) = pending.pop().unwrap();
    task.abort();
    assert!(bounded(task).await.unwrap_err().is_cancelled());
    assert!(matches!(
        harness.next().await.payload,
        Some(GuestPayload::Cancel(_))
    ));
    assert_eq!(
        bounded(harness.bridge.respond(request())).await.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    harness
        .send(HostPayload::ResponseFailure(
            v1::CredentialBridgeResponseFailure {
                request_id: cancelled.request_id,
                reason: v1::CredentialBridgeFailureReason::Denied as i32,
            },
        ))
        .await;
    // Observe terminal-frame completion with bounded scheduler yields, without
    // wall-clock sleeps or an unbounded pending-state poll.
    bounded(async {
        loop {
            if harness.bridge.inner.lock().await.pending.len() < CREDENTIAL_BRIDGE_MAX_IN_FLIGHT {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await;
    let (task, request) = harness.submit().await;
    harness.send(start(&request.request_id)).await;
    harness.send(end(&request.request_id)).await;
    assert_eq!(bounded(task).await.unwrap().status(), StatusCode::OK);
    harness.stop().await;
    for (task, _) in pending {
        assert_eq!(
            bounded(task).await.unwrap().status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }
}

#[tokio::test]
async fn driver_drop_closes_both_halves_despite_queued_frames_and_writer_clones() {
    let bridge = bridge();
    let (prepared, mut output) = bridge.prepare_connection().unwrap();
    assert!(matches!(
        bounded(output.next()).await.unwrap().unwrap().payload,
        Some(GuestPayload::Ready(_))
    ));
    let (input, receiver) = mpsc::channel(4);
    let driver = prepared
        .activate(ReceiverStream::new(receiver))
        .await
        .unwrap();
    let writer = driver.output.clone();
    let submitted = {
        let bridge = bridge.clone();
        tokio::spawn(async move { bridge.respond(request()).await })
    };
    bounded(async {
        loop {
            if !bridge.inner.lock().await.pending.is_empty() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await;
    drop(driver);
    assert!(
        bounded(output.next()).await.is_none(),
        "queued requests must not survive driver ownership"
    );
    assert!(input.is_closed(), "response input must close too");
    assert!(writer.is_closed(), "outgoing writer clones must close too");
    assert_eq!(
        bounded(submitted).await.unwrap().status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    drop(writer);
}

#[tokio::test]
async fn upstream_transport_errors_are_value_blind_and_close_the_epoch() {
    let mut harness = Harness::new().await;
    bounded(
        harness
            .input
            .send(Err(Status::internal("synthetic-opaque-upstream-canary"))),
    )
    .await
    .unwrap();
    let error = bounded(harness.output.next()).await.unwrap().unwrap_err();
    assert_eq!(error.code(), tonic::Code::Unavailable);
    assert!(!error.message().contains("canary"));
    assert!(bounded(harness.output.next()).await.is_none());
    harness.stop().await;
}

#[tokio::test]
async fn request_route_body_and_header_validation_remain_bounded() {
    let bridge = bridge();
    for uri in ["/responses", "https://example.invalid/v1/responses"] {
        let request = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            bounded(bridge.respond(request)).await.status(),
            StatusCode::FORBIDDEN
        );
    }
    // Provider families admit any CRUD method; anything else is refused.
    let request = Request::builder()
        .method(Method::OPTIONS)
        .uri("/v1/responses")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        bounded(bridge.respond(request)).await.status(),
        StatusCode::FORBIDDEN
    );
    let request = Request::builder()
        .method(Method::POST)
        .uri("/v1/responses")
        .body(Body::from(vec![
            b'x';
            CREDENTIAL_BRIDGE_MAX_REQUEST_BYTES + 1
        ]))
        .unwrap();
    assert_eq!(
        bounded(bridge.respond(request)).await.status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
    let request = Request::builder()
        .method(Method::POST)
        .uri("/v1/responses")
        .header(
            "x-test",
            "x".repeat(CREDENTIAL_BRIDGE_MAX_HEADER_VALUE_BYTES + 1),
        )
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        bounded(bridge.respond(request)).await.status(),
        StatusCode::BAD_REQUEST
    );
}

#[test]
fn response_headers_require_canonical_names_no_framing_and_bounded_values() {
    for name in [
        "Content-Type",
        "connection",
        "content-length",
        "transfer-encoding",
        "upgrade",
        "proxy-connection",
        "keep-alive",
        "trailer",
        "bad name",
    ] {
        assert!(
            headers_from_proto(&[v1::CredentialHttpHeader {
                name: name.to_owned(),
                value: b"synthetic".to_vec()
            }])
            .is_err()
        );
    }
    assert!(
        headers_from_proto(&[v1::CredentialHttpHeader {
            name: "x-test".to_owned(),
            value: vec![b'x'; CREDENTIAL_BRIDGE_MAX_HEADER_VALUE_BYTES + 1],
        }])
        .is_err()
    );
    assert!(
        headers_from_proto(&vec![
            v1::CredentialHttpHeader {
                name: "x-test".to_owned(),
                value: b"synthetic".to_vec(),
            };
            CREDENTIAL_BRIDGE_MAX_HEADERS + 1
        ])
        .is_err()
    );
    assert!(
        headers_from_proto(&[v1::CredentialHttpHeader {
            name: "x-test".to_owned(),
            value: b"bad\r\nvalue".to_vec(),
        }])
        .is_err()
    );
}

async fn in_flight(bridge: &CredentialBridge) -> usize {
    bridge.inner.lock().await.in_flight()
}

/// Wait, with bounded scheduler yields, until the shared budget reaches `count`.
async fn in_flight_reaches(bridge: &CredentialBridge, count: usize) {
    bounded(async {
        while in_flight(bridge).await != count {
            tokio::task::yield_now().await;
        }
    })
    .await;
}

async fn complete(harness: &Harness, request: &v1::CredentialBridgeRequest, data: &[u8]) {
    harness.send(start(&request.request_id)).await;
    harness.send(body(&request.request_id, data)).await;
    harness.send(end(&request.request_id)).await;
}

async fn body_of(task: tokio::task::JoinHandle<Response<Body>>) -> WireBytes {
    let response = bounded(task).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    bounded(to_bytes(response.into_body(), 100)).await.unwrap()
}

#[tokio::test]
async fn a_draining_epoch_finishes_its_request_while_new_work_uses_the_successor() {
    let mut first = Harness::new().await;
    let (old_task, old_request) = first.submit().await;
    let mut second = Harness::draining(first.bridge.clone()).await;
    {
        let state = second.bridge.inner.lock().await;
        assert_eq!(state.active.as_ref().unwrap().epoch, second.epoch);
        assert_eq!(state.draining.as_ref().unwrap().epoch, first.epoch);
    }
    // New work reaches only the successor, never the draining epoch.
    let (new_task, new_request) = second.submit().await;
    first.quiet().await;
    // The draining epoch answers what was already sent on it, after the
    // successor activated, and the successor answers its own.
    complete(&first, &old_request, b"old epoch").await;
    complete(&second, &new_request, b"new epoch").await;
    assert_eq!(body_of(old_task).await, "old epoch");
    assert_eq!(body_of(new_task).await, "new epoch");
    second.quiet().await;
    assert_eq!(in_flight(&second.bridge).await, 0);
    // The host then ends the draining epoch; the successor stays active.
    assert!(bounded(first.end_stream().await.next()).await.is_none());
    {
        let state = second.bridge.inner.lock().await;
        assert!(state.draining.is_none());
        assert_eq!(state.active.as_ref().unwrap().epoch, second.epoch);
    }
    second.stop().await;
}

/// A request issued at any point of a drain handoff has an epoch: while the
/// successor is only prepared it goes to the current epoch, from activation
/// on to the successor, and the predecessor's end changes nothing for it.
/// Activation replaces the active epoch under the state lock, so there is
/// no instant with neither.
#[tokio::test]
async fn a_request_at_every_point_of_a_drain_handoff_has_an_epoch() {
    let mut first = Harness::new().await;
    let bridge = first.bridge.clone();
    let (prepared, output) = Harness::prepare(&bridge).await;
    // Prepared, Ready sent, not activated: the current epoch takes it.
    let (before_task, before_request) = first.submit().await;
    let mut second =
        Harness::activate(bridge.clone(), prepared, output, EpochReplacement::Drain).await;
    // Activated: the successor takes it; the predecessor is told nothing.
    let (during_task, during_request) = second.submit().await;
    first.quiet().await;
    complete(&first, &before_request, b"before").await;
    complete(&second, &during_request, b"during").await;
    assert_eq!(body_of(before_task).await, "before");
    assert_eq!(body_of(during_task).await, "during");
    // The predecessor's stream ends at its expiry: the successor still takes it.
    drop(first.end_stream().await);
    let (after_task, after_request) = second.submit().await;
    complete(&second, &after_request, b"after").await;
    assert_eq!(body_of(after_task).await, "after");
    assert_eq!(in_flight(&bridge).await, 0);
    second.stop().await;
}

#[tokio::test]
async fn losing_the_draining_epoch_fails_only_its_own_requests() {
    let mut first = Harness::new().await;
    let (old_task, _) = first.submit().await;
    let mut second = Harness::draining(first.bridge.clone()).await;
    let (new_task, new_request) = second.submit().await;
    let bridge = second.bridge.clone();
    // The broker ends the draining epoch before answering.
    drop(first.end_stream().await);
    assert_eq!(
        bounded(old_task).await.unwrap().status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(in_flight(&bridge).await, 1);
    complete(&second, &new_request, b"kept").await;
    assert_eq!(body_of(new_task).await, "kept");

    // Losing the active epoch likewise fails only its own requests.
    let (draining_task, draining_request) = second.submit().await;
    let mut third = Harness::draining(bridge.clone()).await;
    let (active_task, _) = third.submit().await;
    drop(third.end_stream().await);
    assert_eq!(
        bounded(active_task).await.unwrap().status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    // No epoch is active now: new work fails at once, as before.
    assert_eq!(
        bounded(bridge.respond(request())).await.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    // A later activation finds no active epoch and keeps the draining one.
    let mut fourth = Harness::draining(bridge.clone()).await;
    assert_eq!(
        bridge
            .inner
            .lock()
            .await
            .draining
            .as_ref()
            .map(|host| host.epoch),
        Some(second.epoch)
    );
    complete(&second, &draining_request, b"still draining").await;
    assert_eq!(body_of(draining_task).await, "still draining");
    let (task, request) = fourth.submit().await;
    second.quiet().await;
    complete(&fourth, &request, b"fourth").await;
    assert_eq!(body_of(task).await, "fourth");
    second.stop().await;
    fourth.stop().await;
    assert_eq!(in_flight(&bridge).await, 0);
}

#[tokio::test]
async fn cancelling_a_draining_request_reaches_its_own_epoch() {
    let mut first = Harness::new().await;
    let (waiting, waiting_request) = first.submit().await;
    let (streaming, streaming_request) = first.submit().await;
    first.send(start(&streaming_request.request_id)).await;
    let streaming = bounded(streaming).await.unwrap();
    let mut second = Harness::draining(first.bridge.clone()).await;
    // A caller leaving before the response starts, and a reader leaving
    // mid-body, each ask the draining epoch, not the successor, to stop.
    waiting.abort();
    assert!(bounded(waiting).await.unwrap_err().is_cancelled());
    let Some(GuestPayload::Cancel(cancel)) = first.next().await.payload else {
        panic!("cancel frame required on the draining epoch");
    };
    assert_eq!(cancel.request_id, waiting_request.request_id);
    drop(streaming);
    let Some(GuestPayload::Cancel(cancel)) = first.next().await.payload else {
        panic!("cancel frame required on the draining epoch");
    };
    assert_eq!(cancel.request_id, streaming_request.request_id);
    second.quiet().await;
    // Late frames for both are tolerated and drain their tombstones.
    first.send(start(&waiting_request.request_id)).await;
    first.send(end(&waiting_request.request_id)).await;
    first
        .send(body(&streaming_request.request_id, b"late"))
        .await;
    first.send(end(&streaming_request.request_id)).await;
    in_flight_reaches(&first.bridge, 0).await;
    assert_eq!(
        first
            .bridge
            .inner
            .lock()
            .await
            .draining
            .as_ref()
            .map(|host| host.epoch),
        Some(first.epoch)
    );
    first.stop().await;
    second.stop().await;
}

#[tokio::test]
async fn draining_tombstones_hold_the_shared_budget_until_answered_or_lost() {
    let mut first = Harness::new().await;
    let mut pending = Vec::new();
    for _ in 0..CREDENTIAL_BRIDGE_MAX_IN_FLIGHT {
        pending.push(first.submit().await);
    }
    let mut second = Harness::draining(first.bridge.clone()).await;
    let bridge = second.bridge.clone();
    let (answered_task, answered) = pending.pop().unwrap();
    let (lost_task, lost) = pending.pop().unwrap();
    for task in [answered_task, lost_task] {
        task.abort();
        assert!(bounded(task).await.unwrap_err().is_cancelled());
    }
    for _ in 0..2 {
        assert!(matches!(
            first.next().await.payload,
            Some(GuestPayload::Cancel(_))
        ));
    }
    // Both cancelled requests still count, so the successor is refused.
    assert_eq!(in_flight(&bridge).await, CREDENTIAL_BRIDGE_MAX_IN_FLIGHT);
    assert_eq!(
        bounded(bridge.respond(request())).await.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    second.quiet().await;
    // A response drains one tombstone and frees its slot for the successor.
    first
        .send(HostPayload::ResponseFailure(
            v1::CredentialBridgeResponseFailure {
                request_id: answered.request_id,
                reason: v1::CredentialBridgeFailureReason::Denied as i32,
            },
        ))
        .await;
    in_flight_reaches(&bridge, CREDENTIAL_BRIDGE_MAX_IN_FLIGHT - 1).await;
    assert!(
        bridge
            .inner
            .lock()
            .await
            .pending
            .contains_key(&lost.request_id)
    );
    let (task, request) = second.submit().await;
    // Losing the draining epoch removes the other tombstone with the rest.
    drop(first.end_stream().await);
    in_flight_reaches(&bridge, 1).await;
    assert!(
        !bridge
            .inner
            .lock()
            .await
            .pending
            .contains_key(&lost.request_id)
    );
    for (task, _) in pending {
        assert_eq!(
            bounded(task).await.unwrap().status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }
    complete(&second, &request, b"successor").await;
    assert_eq!(body_of(task).await, "successor");
    second.stop().await;
}

#[tokio::test]
async fn a_third_activation_loses_only_the_oldest_epoch() {
    let mut first = Harness::new().await;
    let bridge = first.bridge.clone();
    let (oldest_task, _) = first.submit().await;
    let mut second = Harness::draining(bridge.clone()).await;
    let (middle_task, middle_request) = second.submit().await;
    let (doomed_task, _) = second.submit().await;
    let mut third = Harness::draining(bridge.clone()).await;
    // The oldest epoch is closed and fails its request...
    assert_eq!(
        bounded(oldest_task).await.unwrap().status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert!(bounded(first.output.next()).await.is_none());
    {
        let state = bridge.inner.lock().await;
        assert_eq!(state.active.as_ref().unwrap().epoch, third.epoch);
        assert_eq!(state.draining.as_ref().unwrap().epoch, second.epoch);
    }
    // ...while the previous successor drains its own.
    let (newest_task, newest_request) = third.submit().await;
    second.quiet().await;
    complete(&second, &middle_request, b"middle").await;
    complete(&third, &newest_request, b"newest").await;
    assert_eq!(body_of(middle_task).await, "middle");
    assert_eq!(body_of(newest_task).await, "newest");

    // A fail-pending activation still closes both epochs and all requests.
    let (active_task, _) = third.submit().await;
    let fourth = Harness::for_bridge(bridge.clone()).await;
    for task in [doomed_task, active_task] {
        assert_eq!(
            bounded(task).await.unwrap().status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }
    assert!(bounded(second.output.next()).await.is_none());
    assert!(bounded(third.output.next()).await.is_none());
    {
        let state = bridge.inner.lock().await;
        assert_eq!(state.active.as_ref().unwrap().epoch, fourth.epoch);
        assert!(state.draining.is_none());
        assert_eq!(state.in_flight(), 0);
    }
    for harness in [first, second, third, fourth] {
        harness.stop().await;
    }
}

#[tokio::test]
async fn a_frame_for_the_other_epochs_request_ends_only_its_sender() {
    let failure = |id: &str| {
        HostPayload::ResponseFailure(v1::CredentialBridgeResponseFailure {
            request_id: id.to_owned(),
            reason: v1::CredentialBridgeFailureReason::Denied as i32,
        })
    };
    for frame in ["start", "end", "failure"] {
        for draining_sends in [true, false] {
            let mut first = Harness::new().await;
            let bridge = first.bridge.clone();
            let (old_task, old_request) = first.submit().await;
            let mut second = Harness::draining(bridge.clone()).await;
            let (new_task, new_request) = second.submit().await;
            let (wrong, kept, kept_request, kept_task, ended_task) = if draining_sends {
                (&mut first, &second, &new_request, new_task, old_task)
            } else {
                (&mut second, &first, &old_request, old_task, new_task)
            };
            let id = kept_request.request_id.as_str();
            kept.send(start(id)).await;
            let kept_response = bounded(kept_task).await.unwrap();
            assert_eq!(kept_response.status(), StatusCode::OK);
            wrong
                .send(match frame {
                    "start" => start(id),
                    "end" => end(id),
                    _ => failure(id),
                })
                .await;
            wrong.terminal(tonic::Code::InvalidArgument).await;
            assert_eq!(
                bounded(ended_task).await.unwrap().status(),
                StatusCode::SERVICE_UNAVAILABLE,
                "{frame}"
            );
            // The other epoch's request, and its slot, are untouched...
            assert!(
                bridge
                    .inner
                    .lock()
                    .await
                    .pending
                    .get(id)
                    .is_some_and(|pending| pending.epoch == kept.epoch),
                "{frame}"
            );
            // ...so its own epoch still completes it.
            kept.send(body(id, b"kept")).await;
            kept.send(end(id)).await;
            assert_eq!(
                bounded(to_bytes(kept_response.into_body(), 100))
                    .await
                    .unwrap(),
                "kept",
                "{frame}"
            );
            assert_eq!(in_flight(&bridge).await, 0);
            first.stop().await;
            second.stop().await;
        }
    }
}

#[tokio::test(start_paused = true)]
async fn a_draining_epoch_fails_what_it_still_holds_after_ninety_seconds() {
    let mut first = Harness::new().await;
    let bridge = first.bridge.clone();
    let (old_task, _) = first.submit().await;
    let (cancelled, _) = first.submit().await;
    cancelled.abort();
    assert!(bounded(cancelled).await.unwrap_err().is_cancelled());
    assert!(matches!(
        first.next().await.payload,
        Some(GuestPayload::Cancel(_))
    ));
    let mut second = Harness::draining(bridge.clone()).await;
    let (new_task, new_request) = second.submit().await;
    tokio::time::advance(DRAINING_LIFETIME - Duration::from_secs(1)).await;
    // Still draining: its request and its cancelled tombstone hold slots.
    assert_eq!(in_flight(&bridge).await, 3);
    assert!(bridge.inner.lock().await.draining.is_some());
    tokio::time::advance(Duration::from_secs(2)).await;
    // A half-open old transport then loses its requests, slots and epoch.
    assert_eq!(
        bounded(old_task).await.unwrap().status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert!(bounded(first.output.next()).await.is_none());
    assert!(bridge.inner.lock().await.draining.is_none());
    assert_eq!(in_flight(&bridge).await, 1);
    // The successor is untouched.
    complete(&second, &new_request, b"successor").await;
    assert_eq!(body_of(new_task).await, "successor");
    first.stop().await;
    second.stop().await;
}

#[tokio::test(start_paused = true)]
async fn the_draining_deadline_never_touches_a_later_draining_epoch() {
    let first = Harness::new().await;
    let bridge = first.bridge.clone();
    tokio::time::advance(Duration::from_secs(60)).await;
    let mut second = Harness::draining(bridge.clone()).await;
    let (task, request) = second.submit().await;
    tokio::time::advance(Duration::from_secs(60)).await;
    // The second epoch now drains: the first epoch's deadline passes without
    // affecting it, and its own runs from its own replacement.
    let third = Harness::draining(bridge.clone()).await;
    tokio::time::advance(Duration::from_secs(45)).await;
    assert_eq!(
        bridge
            .inner
            .lock()
            .await
            .draining
            .as_ref()
            .map(|host| host.epoch),
        Some(second.epoch)
    );
    complete(&second, &request, b"second").await;
    assert_eq!(body_of(task).await, "second");
    tokio::time::advance(Duration::from_secs(50)).await;
    assert!(bounded(second.output.next()).await.is_none());
    assert_eq!(
        bridge
            .inner
            .lock()
            .await
            .active
            .as_ref()
            .map(|host| host.epoch),
        Some(third.epoch)
    );
    for harness in [first, second, third] {
        harness.stop().await;
    }
}
