//! End to end (#4280): an HTTPS Git request through the guest credential
//! bridge, its frames, the broker's runner and the GitHub adapter, to a fake
//! provider. The link between the two bridges counts body frames against the
//! host's credit, so the in-flight bound is asserted on the window itself.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::body::Body;
use bytes::Bytes;
use codewire_credential_bridge::{CredentialBridge, CredentialBridgeOutput};
use codewire_daemon_proto::codewire::bridge::v1;
use codewire_daemon_proto::{
    CREDENTIAL_BRIDGE_CAPABILITY_REQUEST_BODY_STREAM, CREDENTIAL_BRIDGE_MAX_BODY_CHUNK_BYTES,
    CREDENTIAL_BRIDGE_MAX_REQUEST_BYTES, CREDENTIAL_BRIDGE_MAX_RESPONSE_BYTES,
    CREDENTIAL_BRIDGE_REQUEST_BODY_WINDOW_FRAMES,
};
use futures::StreamExt as _;
use http::{HeaderMap, HeaderValue, Method, Request, StatusCode};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use uuid::Uuid;

use super::http_tests::Authority;
use crate::bridge::{
    BrokerBridgeError, CredentialBridgeResponseSink, CredentialBridgeTransport,
    run_credential_bridge,
};
use crate::{
    BrokerUpstreamError, BrokerUpstreamRequest, BrokerUpstreamResponse, BrokerUpstreamTransport,
    OpenAiBroker,
};

const PUSH: &str = "/_codewire/github/owner/repo.git/git-receive-pack";
const FETCH: &str = "/_codewire/github/owner/repo.git/git-upload-pack";

/// Frames the guest sent and the host granted, counted on the link.
#[derive(Default)]
struct Window {
    sent: AtomicU64,
    granted: AtomicU64,
    /// The most frames the host held at once, sent but not yet granted back.
    peak: AtomicU64,
}

impl Window {
    fn held(&self) -> u64 {
        let granted = self.granted.load(Ordering::Acquire);
        let window = u64::from(CREDENTIAL_BRIDGE_REQUEST_BODY_WINDOW_FRAMES);
        (self.sent.load(Ordering::Acquire) + window).saturating_sub(granted)
    }
}

struct Link {
    guest: CredentialBridgeOutput,
    host: mpsc::Sender<Result<v1::CredentialBridgeHostMessage, tonic::Status>>,
    window: Arc<Window>,
}

#[derive(Clone)]
struct LinkSink {
    host: mpsc::Sender<Result<v1::CredentialBridgeHostMessage, tonic::Status>>,
    window: Arc<Window>,
}

#[async_trait]
impl CredentialBridgeTransport for Link {
    type ResponseSink = LinkSink;

    fn response_sink(&self) -> LinkSink {
        LinkSink {
            host: self.host.clone(),
            window: Arc::clone(&self.window),
        }
    }

    async fn receive(
        &mut self,
    ) -> Result<Option<v1::CredentialBridgeGuestMessage>, BrokerBridgeError> {
        let frame = match self.guest.next().await {
            Some(Ok(frame)) => frame,
            Some(Err(_)) => return Err(BrokerBridgeError::Unavailable),
            None => return Ok(None),
        };
        if let Some(v1::credential_bridge_guest_message::Payload::RequestBody(body)) =
            &frame.payload
        {
            assert!(body.data.len() <= CREDENTIAL_BRIDGE_MAX_BODY_CHUNK_BYTES);
            let sent = self.window.sent.fetch_add(1, Ordering::AcqRel) + 1;
            // Never a frame without credit.
            assert!(sent <= self.window.granted.load(Ordering::Acquire));
            self.window
                .peak
                .fetch_max(self.window.held(), Ordering::AcqRel);
        }
        Ok(Some(frame))
    }
}

#[async_trait]
impl CredentialBridgeResponseSink for LinkSink {
    async fn send(
        &self,
        payload: v1::credential_bridge_host_message::Payload,
    ) -> Result<(), BrokerBridgeError> {
        if let v1::credential_bridge_host_message::Payload::RequestCredit(credit) = &payload {
            self.window
                .granted
                .fetch_add(u64::from(credit.frames), Ordering::AcqRel);
        }
        self.host
            .send(Ok(v1::CredentialBridgeHostMessage {
                payload: Some(payload),
            }))
            .await
            .map_err(|_| BrokerBridgeError::Unavailable)
    }
}

/// Each request body the provider got, and whether it streamed.
type Bodies = Arc<Mutex<Vec<(bool, Vec<u8>)>>>;

/// A Git provider: reads the request body whole, then answers with
/// `response_bytes` of a fixed pattern, generated as it is read.
#[derive(Clone)]
struct GitProvider {
    response_bytes: usize,
    bodies: Bodies,
    polls: Arc<AtomicUsize>,
}

#[async_trait]
impl BrokerUpstreamTransport for GitProvider {
    async fn execute(
        &self,
        mut request: BrokerUpstreamRequest,
    ) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
        let stream = request.take_body_stream();
        let (_, target, _, whole) = request.into_parts();
        let (streamed, body) = match stream {
            None => (false, whole),
            Some(mut stream) => {
                let mut body = Vec::new();
                while let Some(chunk) = stream.next().await {
                    body.extend_from_slice(&chunk.map_err(|_| BrokerUpstreamError::Protocol)?);
                }
                (true, body)
            }
        };
        self.bodies.lock().unwrap().push((streamed, body));
        let media = if target.path().ends_with("/git-receive-pack") {
            "application/x-git-receive-pack-result"
        } else {
            "application/x-git-upload-pack-result"
        };
        let headers =
            HeaderMap::from_iter([(http::header::CONTENT_TYPE, HeaderValue::from_static(media))]);
        let chunk = Bytes::from(vec![b'p'; CREDENTIAL_BRIDGE_MAX_BODY_CHUNK_BYTES]);
        let mut remaining = self.response_bytes;
        let polls = Arc::clone(&self.polls);
        let body = futures::stream::poll_fn(move |_| {
            polls.fetch_add(1, Ordering::Relaxed);
            if remaining == 0 {
                return std::task::Poll::Ready(None);
            }
            let next = remaining.min(chunk.len());
            remaining -= next;
            std::task::Poll::Ready(Some(Ok(chunk.slice(..next))))
        });
        Ok(BrokerUpstreamResponse::new(
            StatusCode::OK,
            headers,
            Box::pin(body),
        ))
    }
}

struct Fixture {
    guest: CredentialBridge,
    window: Arc<Window>,
    provider: GitProvider,
}

impl Fixture {
    /// A guest bridge on an epoch whose host lists streamed bodies when
    /// `streams`, linked to a broker runner over the GitHub adapter.
    async fn new(streams: bool, response_bytes: usize) -> Self {
        let environment = Uuid::new_v4();
        let guest = CredentialBridge::new(environment, 1).unwrap();
        let (prepared, output) = guest.prepare_connection().unwrap();
        let (host, frames) = mpsc::channel(32);
        let capabilities = if streams {
            vec![CREDENTIAL_BRIDGE_CAPABILITY_REQUEST_BODY_STREAM.to_owned()]
        } else {
            Vec::new()
        };
        let connection = prepared
            .activate_with_capabilities(ReceiverStream::new(frames), &capabilities)
            .await
            .unwrap();
        tokio::spawn(connection.run());
        let window = Arc::new(Window::default());
        let provider = GitProvider {
            response_bytes,
            bodies: Arc::new(Mutex::new(Vec::new())),
            polls: Arc::new(AtomicUsize::new(0)),
        };
        let broker = OpenAiBroker::new(Authority::github(), provider.clone()).unwrap();
        let link = Link {
            guest: output,
            host,
            window: Arc::clone(&window),
        };
        tokio::spawn(run_credential_bridge(broker, link, environment, 1));
        Self {
            guest,
            window,
            provider,
        }
    }

    async fn post(&self, path: &str, body: Vec<u8>) -> (StatusCode, usize, Vec<u8>) {
        let media = if path == PUSH {
            "application/x-git-receive-pack-request"
        } else {
            "application/x-git-upload-pack-request"
        };
        let request = Request::builder()
            .method(Method::POST)
            .uri(path)
            .header("content-type", media)
            .body(Body::from(body))
            .unwrap();
        let response = self.guest.respond(request).await;
        let status = response.status();
        let mut stream = response.into_body().into_data_stream();
        let (mut length, mut head) = (0, Vec::new());
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.expect("the response body completes");
            if head.len() < 64 {
                head.extend_from_slice(&chunk[..chunk.len().min(64)]);
            }
            length += chunk.len();
        }
        (status, length, head)
    }
}

/// A push-shaped body: a deterministic pattern no redaction rule matches.
fn pack(length: usize) -> Vec<u8> {
    (0..length).map(|index| (index % 251) as u8).collect()
}

#[tokio::test]
async fn a_push_over_the_old_request_limit_streams_whole_with_one_window_in_flight() {
    let fixture = Fixture::new(true, 1024).await;
    let body = pack(20 * 1024 * 1024);
    let (status, length, _) = fixture.post(PUSH, body.clone()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(length, 1024);
    let bodies = fixture.provider.bodies.lock().unwrap();
    assert_eq!(bodies.len(), 1);
    assert!(bodies[0].0, "the provider must get a streamed body");
    assert!(bodies[0].1 == body, "the provider must get the exact bytes");
    let window = u64::from(CREDENTIAL_BRIDGE_REQUEST_BODY_WINDOW_FRAMES);
    let frames = (body.len() / CREDENTIAL_BRIDGE_MAX_BODY_CHUNK_BYTES) as u64;
    assert_eq!(fixture.window.sent.load(Ordering::Acquire), frames);
    // One window up front and one frame back for each consumed: never more
    // than one window (1 MiB) held by the host, and the bound was reached.
    assert_eq!(
        fixture.window.granted.load(Ordering::Acquire),
        window + frames
    );
    assert!(fixture.window.peak.load(Ordering::Acquire) <= window);
    assert!(fixture.window.peak.load(Ordering::Acquire) >= 1);
}

#[tokio::test]
async fn a_fetch_response_over_the_old_response_limit_streams_through() {
    let response_bytes =
        CREDENTIAL_BRIDGE_MAX_RESPONSE_BYTES + 3 * CREDENTIAL_BRIDGE_MAX_BODY_CHUNK_BYTES;
    let fixture = Fixture::new(true, response_bytes).await;
    let (status, length, head) = fixture.post(FETCH, b"0032want 0000".to_vec()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(length, response_bytes);
    assert_eq!(head, vec![b'p'; 64]);
}

#[tokio::test]
async fn an_older_host_gets_whole_bodies_with_the_old_limits() {
    let fixture = Fixture::new(false, 1024).await;
    let body = pack(1024 * 1024);
    let (status, length, _) = fixture.post(PUSH, body.clone()).await;
    assert_eq!((status, length), (StatusCode::OK, 1024));
    assert_eq!(*fixture.provider.bodies.lock().unwrap(), [(false, body)]);
    assert_eq!(fixture.window.granted.load(Ordering::Acquire), 0);

    let (status, _, text) = fixture
        .post(PUSH, pack(CREDENTIAL_BRIDGE_MAX_REQUEST_BYTES + 1))
        .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert!(text.starts_with(b"request body exceeds the credential bridge's 4 MiB limit"));
    assert_eq!(fixture.provider.bodies.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn an_older_host_keeps_the_response_limit() {
    let fixture = Fixture::new(false, CREDENTIAL_BRIDGE_MAX_RESPONSE_BYTES + 1).await;
    let request = Request::builder()
        .method(Method::POST)
        .uri(FETCH)
        .header("content-type", "application/x-git-upload-pack-request")
        .body(Body::from(b"0000".to_vec()))
        .unwrap();
    let response = fixture.guest.respond(request).await;
    assert_eq!(response.status(), StatusCode::OK);
    let mut stream = response.into_body().into_data_stream();
    let mut length = 0;
    let failed = loop {
        match stream.next().await {
            Some(Ok(chunk)) => length += chunk.len(),
            Some(Err(_)) => break true,
            None => break false,
        }
    };
    // The whole-body request's response stops at the old limit, as an error.
    assert!(failed);
    assert!(length <= CREDENTIAL_BRIDGE_MAX_RESPONSE_BYTES);
}
