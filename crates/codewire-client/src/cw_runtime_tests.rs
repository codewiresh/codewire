//! Synthetic in-memory generated transport, without a network or incoming
//! executable. Tests exercise the actual bounded facade and cancellation.
use super::*;
use connectrpc::{
    ConnectError,
    client::{BoxFuture, CallOptions, ClientBody, ClientConfig},
};
use futures_util::{StreamExt as _, stream};
use http::{Request, Response};
use http_body_util::BodyExt as _;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

fn header(size: u64) -> UpdateEnvironmentCwRuntimeHeader {
    let id = "550e8400-e29b-41d4-a716-446655440000";
    UpdateEnvironmentCwRuntimeHeader {
        org_id: "org".into(),
        environment_id: id.into(),
        request_id: Uuid::new_v4().to_string(),
        identity: Some(EnvironmentCwRuntimeIdentity {
            size,
            target: "x86_64-unknown-linux-musl".into(),
            ..Default::default()
        })
        .into(),
        expected_incarnation: Some(EnvironmentCwRuntimeIncarnation {
            org_id: "org".into(),
            environment_id: id.into(),
            ..Default::default()
        })
        .into(),
        expected_selection: Some(EnvironmentCwRuntimeExpectation {
            generation: u64::MAX,
            current_sha256: Some("a".repeat(64)),
            ..Default::default()
        })
        .into(),
        ..Default::default()
    }
}

#[tokio::test]
async fn lazy_chunks_and_generated_header_preserve_uint64() {
    let polls = Arc::new(AtomicUsize::new(0));
    let observed = polls.clone();
    let source = stream::iter([Ok(vec![1; CHUNK_BYTES]), Ok(vec![2; 64])]).inspect(move |_| {
        observed.fetch_add(1, Ordering::SeqCst);
    });
    let mut frames = Frames::new(header((CHUNK_BYTES + 64) as u64), source).unwrap();
    assert_eq!(polls.load(Ordering::SeqCst), 0);
    let first = frames.next().await.unwrap();
    assert_eq!(polls.load(Ordering::SeqCst), 0);
    let decoded =
        UpdateEnvironmentCwRuntimeRequest::decode_from_slice(&first.encode_to_vec()).unwrap();
    let Some(update_environment_cw_runtime_request::Payload::Header(header)) = decoded.payload
    else {
        panic!("header")
    };
    assert_eq!(header.expected_selection.generation, u64::MAX);
    let remaining = frames.collect::<Vec<_>>().await;
    assert_eq!(remaining.len(), 2);
    assert_eq!(polls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn local_errors_never_turn_into_successful_stream_eof() {
    for source in [
        vec![Ok(vec![1; 63])],
        vec![Ok(vec![1; 65])],
        vec![Ok(vec![])],
        vec![Ok(vec![1; CHUNK_BYTES + 1])],
        vec![
            Ok(vec![1; 64]),
            Err(ClientError::new(
                ErrorCode::Internal,
                "synthetic late file custody loss",
            )),
        ],
    ] {
        let frames = Frames::new(header(64), stream::iter(source)).unwrap();
        let error = frames.error.clone();
        let frames = frames.collect::<Vec<_>>().await;
        assert!(error.lock().unwrap().is_some());
        assert!(frames.last().unwrap().payload.is_none());
    }
}

#[test]
fn invalid_scope_and_candidate_bounds_refuse_without_stream_polling() {
    for size in [0, 63, MAX_BYTES + 1] {
        assert!(
            Frames::new(
                header(size),
                stream::pending::<Result<Vec<u8>, ClientError>>()
            )
            .is_err()
        );
    }
    let mut h = header(64);
    h.expected_incarnation
        .as_option_mut()
        .unwrap()
        .environment_id = Uuid::new_v4().to_string();
    assert!(Frames::new(h, stream::pending::<Result<Vec<u8>, ClientError>>()).is_err());
}

#[derive(Clone)]
struct LostAck(Arc<AtomicUsize>);
impl ClientTransport for LostAck {
    type ResponseBody = reqwest::Body;
    type Error = ConnectError;
    fn send(
        &self,
        request: Request<ClientBody>,
    ) -> BoxFuture<'static, Result<Response<Self::ResponseBody>, Self::Error>> {
        self.0.fetch_add(1, Ordering::SeqCst);
        assert!(
            request
                .uri()
                .path()
                .ends_with("/UpdateEnvironmentCwRuntime")
        );
        assert_eq!(request.headers()["connect-timeout-ms"], "960000");
        Box::pin(async move {
            let mut body = request.into_body();
            while let Some(frame) = body.frame().await {
                frame.map_err(|_| ConnectError::unavailable("synthetic send failure"))?;
            }
            Err(ConnectError::unavailable("synthetic lost ACK after EOF"))
        })
    }
}

#[tokio::test]
async fn generated_stream_lost_ack_never_retries_and_retains_original_uuid() {
    let calls = Arc::new(AtomicUsize::new(0));
    let client = EnvironmentCwRuntimeServiceClient::new(
        LostAck(calls.clone()),
        ClientConfig::new("http://runtime-test.invalid".parse().unwrap()),
    );
    let header = header(64);
    let original = header.request_id.clone();
    let error = update(
        &client,
        header,
        stream::iter([Ok(vec![1; 64])]),
        CallOptions::default(),
    )
    .await
    .unwrap_err();
    assert_eq!(error.request_id, original);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

struct OwnedSource(Arc<AtomicBool>);
impl Stream for OwnedSource {
    type Item = Result<Vec<u8>, ClientError>;
    fn poll_next(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Poll::Pending
    }
}
impl Drop for OwnedSource {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}
#[derive(Clone)]
struct PendingTransport(Arc<AtomicBool>);
impl ClientTransport for PendingTransport {
    type ResponseBody = reqwest::Body;
    type Error = ConnectError;
    fn send(
        &self,
        request: Request<ClientBody>,
    ) -> BoxFuture<'static, Result<Response<Self::ResponseBody>, Self::Error>> {
        self.0.store(true, Ordering::SeqCst);
        Box::pin(async move {
            let _request = request;
            futures_util::future::pending().await
        })
    }
}

#[tokio::test]
async fn dropping_generated_call_closes_owned_source_without_replay() {
    let started = Arc::new(AtomicBool::new(false));
    let dropped = Arc::new(AtomicBool::new(false));
    let client = EnvironmentCwRuntimeServiceClient::new(
        PendingTransport(started.clone()),
        ClientConfig::new("http://runtime-test.invalid".parse().unwrap()),
    );
    let mut call = Box::pin(update(
        &client,
        header(64),
        OwnedSource(dropped.clone()),
        CallOptions::default(),
    ));
    assert!(futures_util::poll!(&mut call).is_pending());
    assert!(started.load(Ordering::SeqCst));
    assert!(!dropped.load(Ordering::SeqCst));
    drop(call);
    assert!(dropped.load(Ordering::SeqCst));
}
