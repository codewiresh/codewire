use std::io;

use axum::body::to_bytes;
use axum::http::Request;
use codewire_daemon_proto::CREDENTIAL_BRIDGE_MAX_REQUEST_BYTES;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::Status;
use uuid::Uuid;

use super::*;
use crate::{CredentialBridge, CredentialBridgeOutput};
use v1::credential_bridge_guest_message::Payload as GuestPayload;
use v1::credential_bridge_host_message::Payload as HostPayload;

const PUSH: &str = "/_codewire/github/owner/repo.git/git-receive-pack";
const WINDOW: u32 = CREDENTIAL_BRIDGE_REQUEST_BODY_WINDOW_FRAMES;

struct Harness {
    bridge: CredentialBridge,
    input: mpsc::Sender<Result<v1::CredentialBridgeHostMessage, Status>>,
    output: CredentialBridgeOutput,
}

impl Harness {
    /// An epoch whose host lists streamed request bodies, or an older one.
    async fn new(streams: bool) -> Self {
        let bridge = CredentialBridge::new(Uuid::new_v4(), 3).unwrap();
        let (prepared, mut output) = bridge.prepare_connection().unwrap();
        assert!(matches!(
            output.next().await.unwrap().unwrap().payload,
            Some(GuestPayload::Ready(_))
        ));
        let capabilities = if streams {
            vec![CREDENTIAL_BRIDGE_CAPABILITY_REQUEST_BODY_STREAM.to_owned()]
        } else {
            Vec::new()
        };
        let (input, receiver) = mpsc::channel(32);
        let connection = prepared
            .activate_with_capabilities(ReceiverStream::new(receiver), &capabilities)
            .await
            .unwrap();
        tokio::spawn(connection.run());
        Self {
            bridge,
            input,
            output,
        }
    }

    fn respond(&self, request: Request<Body>) -> tokio::task::JoinHandle<axum::response::Response> {
        let bridge = self.bridge.clone();
        tokio::spawn(async move { bridge.respond(request).await })
    }

    async fn next(&mut self) -> GuestPayload {
        self.output.next().await.unwrap().unwrap().payload.unwrap()
    }

    async fn request(&mut self) -> v1::CredentialBridgeRequest {
        match self.next().await {
            GuestPayload::Request(request) => request,
            _ => panic!("expected a request"),
        }
    }

    async fn send(&self, payload: HostPayload) {
        self.input
            .send(Ok(v1::CredentialBridgeHostMessage {
                payload: Some(payload),
            }))
            .await
            .unwrap();
    }

    async fn grant(&self, request_id: &str, frames: u32) {
        self.send(HostPayload::RequestCredit(
            v1::CredentialBridgeRequestCredit {
                request_id: request_id.to_owned(),
                frames,
            },
        ))
        .await;
    }

    async fn answer(&self, request_id: &str) {
        self.send(HostPayload::ResponseStart(
            v1::CredentialBridgeResponseStart {
                request_id: request_id.to_owned(),
                status_code: 200,
                headers: Vec::new(),
            },
        ))
        .await;
        self.send(HostPayload::ResponseEnd(v1::CredentialBridgeResponseEnd {
            request_id: request_id.to_owned(),
        }))
        .await;
    }

    /// Nothing more is sent for now.
    async fn quiet(&mut self) {
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), self.output.next())
                .await
                .is_err(),
            "unexpected frame"
        );
    }
}

fn git_request(path: &str, body: Body) -> Request<Body> {
    Request::builder()
        .method(if path.contains("/info/refs") {
            Method::GET
        } else {
            Method::POST
        })
        .uri(path)
        .header("content-type", "application/x-git-receive-pack-request")
        .body(body)
        .unwrap()
}

/// A client body that sends `bytes` and then nothing, never ending.
fn stalled_body(bytes: Vec<u8>) -> Body {
    let stream = tokio_stream::iter([Ok::<_, io::Error>(bytes::Bytes::from(bytes))])
        .chain(tokio_stream::pending());
    Body::from_stream(stream)
}

fn body_bytes(payload: GuestPayload) -> Vec<u8> {
    match payload {
        GuestPayload::RequestBody(body) => body.data,
        _ => panic!("expected a body frame"),
    }
}

#[tokio::test]
async fn an_older_host_gets_the_whole_body_and_a_clear_413_past_4_mib() {
    let mut harness = Harness::new(false).await;
    let task = harness.respond(git_request(PUSH, Body::from(vec![7; 1024])));
    let request = harness.request().await;
    assert!(!request.streamed_body);
    assert_eq!(request.body, vec![7; 1024]);
    harness.answer(&request.request_id).await;
    assert_eq!(task.await.unwrap().status(), StatusCode::OK);

    let body = vec![7; CREDENTIAL_BRIDGE_MAX_REQUEST_BYTES + 1];
    let response = harness
        .respond(git_request(PUSH, Body::from(body)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let text = to_bytes(response.into_body(), 1024).await.unwrap();
    assert!(
        std::str::from_utf8(&text)
            .unwrap()
            .contains("4 MiB limit: this host does not stream request bodies")
    );
    harness.quiet().await;
}

#[tokio::test]
async fn a_listing_host_gets_body_frames_only_under_its_credit() {
    let mut harness = Harness::new(true).await;
    // Only a Git POST streams; a GET carries its empty body as before.
    let refs = harness.respond(git_request(
        "/_codewire/github/owner/repo.git/info/refs?service=git-receive-pack",
        Body::empty(),
    ));
    let request = harness.request().await;
    assert!(!request.streamed_body);
    harness.answer(&request.request_id).await;
    assert_eq!(refs.await.unwrap().status(), StatusCode::OK);

    let chunk = CREDENTIAL_BRIDGE_MAX_BODY_CHUNK_BYTES;
    let body = (0..3 * chunk + 8)
        .map(|byte| byte as u8)
        .collect::<Vec<_>>();
    let task = harness.respond(git_request(PUSH, Body::from(body.clone())));
    let request = harness.request().await;
    assert!(request.streamed_body);
    assert!(request.body.is_empty());
    harness.quiet().await;

    harness.grant(&request.request_id, 2).await;
    let mut received = body_bytes(harness.next().await);
    received.extend(body_bytes(harness.next().await));
    harness.quiet().await;
    harness.grant(&request.request_id, 2).await;
    received.extend(body_bytes(harness.next().await));
    received.extend(body_bytes(harness.next().await));
    assert!(
        matches!(harness.next().await, GuestPayload::RequestEnd(end) if end.request_id == request.request_id)
    );
    assert_eq!(received, body);

    harness.answer(&request.request_id).await;
    assert_eq!(task.await.unwrap().status(), StatusCode::OK);
    // A credit that crosses the request's end is ignored.
    harness.grant(&request.request_id, 1).await;
    harness.quiet().await;
}

#[tokio::test]
async fn credit_past_one_window_ends_the_epoch() {
    let mut harness = Harness::new(true).await;
    let _task = harness.respond(git_request(PUSH, stalled_body(vec![1])));
    let request = harness.request().await;
    harness.grant(&request.request_id, WINDOW).await;
    assert_eq!(body_bytes(harness.next().await), vec![1]);
    // One frame is spent, so one more fits; two more do not.
    harness.grant(&request.request_id, 2).await;
    let status = harness.output.next().await.unwrap().unwrap_err();
    assert_eq!(status.code(), tonic::Code::InvalidArgument);
}

#[tokio::test(start_paused = true)]
async fn a_client_that_stops_sending_fails_after_the_idle_bound() {
    let mut harness = Harness::new(true).await;
    let started = tokio::time::Instant::now();
    let task = harness.respond(git_request(PUSH, stalled_body(vec![1; 10])));
    let request = harness.request().await;
    harness.grant(&request.request_id, WINDOW).await;
    assert_eq!(body_bytes(harness.next().await), vec![1; 10]);
    let response = task.await.unwrap();
    assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
    assert!(started.elapsed() >= CREDENTIAL_BRIDGE_BODY_IDLE_TIMEOUT);
    assert!(
        matches!(harness.next().await, GuestPayload::Cancel(cancel) if cancel.request_id == request.request_id)
    );
}

#[tokio::test(start_paused = true)]
async fn a_host_that_grants_no_credit_fails_after_the_idle_bound() {
    let mut harness = Harness::new(true).await;
    let task = harness.respond(git_request(PUSH, Body::from(vec![1; 10])));
    let request = harness.request().await;
    assert_eq!(task.await.unwrap().status(), StatusCode::GATEWAY_TIMEOUT);
    assert!(
        matches!(harness.next().await, GuestPayload::Cancel(cancel) if cancel.request_id == request.request_id)
    );
}

#[tokio::test(start_paused = true)]
async fn after_the_body_the_response_may_take_ten_minutes_but_no_longer() {
    let mut harness = Harness::new(true).await;
    let task = harness.respond(git_request(PUSH, Body::from(vec![1; 10])));
    let request = harness.request().await;
    harness.grant(&request.request_id, WINDOW).await;
    body_bytes(harness.next().await);
    assert!(matches!(harness.next().await, GuestPayload::RequestEnd(_)));
    tokio::time::sleep(CREDENTIAL_BRIDGE_STREAMED_FIRST_RESPONSE_TIMEOUT).await;
    harness.answer(&request.request_id).await;
    assert_eq!(task.await.unwrap().status(), StatusCode::OK);

    let started = tokio::time::Instant::now();
    let task = harness.respond(git_request(PUSH, Body::from(vec![1; 10])));
    let request = harness.request().await;
    harness.grant(&request.request_id, WINDOW).await;
    body_bytes(harness.next().await);
    assert!(matches!(harness.next().await, GuestPayload::RequestEnd(_)));
    assert_eq!(task.await.unwrap().status(), StatusCode::GATEWAY_TIMEOUT);
    assert!(started.elapsed() > CREDENTIAL_BRIDGE_STREAMED_FIRST_RESPONSE_TIMEOUT);
    assert!(matches!(harness.next().await, GuestPayload::Cancel(_)));
}

/// `git http-backend` sends its headers before it reads the push: a response
/// that starts before the body is complete leaves the rest of the body
/// flowing, and the response completes after it.
#[tokio::test]
async fn a_response_that_starts_before_the_body_ends_keeps_the_body_flowing() {
    let mut harness = Harness::new(true).await;
    let chunk = CREDENTIAL_BRIDGE_MAX_BODY_CHUNK_BYTES;
    let body = (0..(WINDOW as usize + 4) * chunk)
        .map(|byte| byte as u8)
        .collect::<Vec<_>>();
    let task = harness.respond(git_request(PUSH, Body::from(body.clone())));
    let request = harness.request().await;
    harness.grant(&request.request_id, WINDOW).await;
    let mut received = Vec::new();
    for _ in 0..WINDOW {
        received.extend(body_bytes(harness.next().await));
    }
    harness
        .send(HostPayload::ResponseStart(
            v1::CredentialBridgeResponseStart {
                request_id: request.request_id.clone(),
                status_code: 200,
                headers: Vec::new(),
            },
        ))
        .await;
    let response = task.await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    harness.grant(&request.request_id, 4).await;
    let rest = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        for _ in 0..4 {
            received.extend(body_bytes(harness.next().await));
        }
        harness.next().await
    })
    .await
    .expect("the body must keep flowing after the response starts");
    assert!(matches!(rest, GuestPayload::RequestEnd(end) if end.request_id == request.request_id));
    assert_eq!(received, body);
    harness
        .send(HostPayload::ResponseEnd(v1::CredentialBridgeResponseEnd {
            request_id: request.request_id,
        }))
        .await;
    assert!(
        to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .is_empty()
    );
}
