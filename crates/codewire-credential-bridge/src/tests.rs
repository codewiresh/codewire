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
        let (prepared, mut output) = bridge.prepare_connection().unwrap();
        let ready = bounded(output.next()).await.unwrap().unwrap();
        let Some(GuestPayload::Ready(ready)) = ready.payload else {
            panic!("Ready must precede activation and all requests");
        };
        assert_eq!(ready.protocol_version, CREDENTIAL_BRIDGE_PROTOCOL_VERSION);
        assert_eq!(ready.environment_id, bridge.environment_id.to_string());
        assert_eq!(ready.environment_generation, bridge.environment_generation);
        let (input, receiver) = mpsc::channel(32);
        let connection = prepared
            .activate(ReceiverStream::new(receiver))
            .await
            .unwrap();
        let (shutdown, shutdown_rx) = oneshot::channel();
        let task = tokio::spawn(connection.run_until(async {
            let _ = shutdown_rx.await;
        }));
        Self {
            bridge,
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

#[tokio::test]
async fn slow_consumer_cannot_grow_the_response_queue() {
    let mut harness = Harness::new().await;
    let (task, request) = harness.submit().await;
    harness.send(start(&request.request_id)).await;
    let response = bounded(task).await.unwrap();
    for _ in 0..=RESPONSE_BODY_BUFFER {
        harness.send(body(&request.request_id, b"x")).await;
    }
    harness.terminal(tonic::Code::ResourceExhausted).await;
    assert!(bounded(to_bytes(response.into_body(), 100)).await.is_err());
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
    for uri in [
        "/responses",
        "/v1/responses?query=x",
        "https://example.invalid/v1/responses",
    ] {
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
    let request = Request::builder()
        .method(Method::GET)
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
