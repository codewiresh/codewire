//! The host side alone, driven by raw guest frames: credit, the idle bounds,
//! and an older guest's whole-body request.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use codewire_daemon_proto::{
    CREDENTIAL_BRIDGE_MAX_REQUEST_BYTES, CREDENTIAL_BRIDGE_PROTOCOL_VERSION,
};
use futures::StreamExt as _;
use http::{HeaderMap, StatusCode};
use uuid::Uuid;

use super::*;
use crate::bridge::{BrokerBridgeError, CredentialBridgeTransport, run_bridge};
use v1::credential_bridge_guest_message::Payload as GuestPayload;
use v1::credential_bridge_host_message::Payload as HostPayload;

struct Link {
    input: mpsc::Receiver<v1::CredentialBridgeGuestMessage>,
    output: mpsc::Sender<HostPayload>,
}

#[derive(Clone)]
struct Sink(mpsc::Sender<HostPayload>);

#[async_trait]
impl CredentialBridgeTransport for Link {
    type ResponseSink = Sink;

    fn response_sink(&self) -> Sink {
        Sink(self.output.clone())
    }

    async fn receive(
        &mut self,
    ) -> Result<Option<v1::CredentialBridgeGuestMessage>, BrokerBridgeError> {
        Ok(self.input.recv().await)
    }
}

#[async_trait]
impl CredentialBridgeResponseSink for Sink {
    async fn send(&self, payload: HostPayload) -> Result<(), BrokerBridgeError> {
        self.0
            .send(payload)
            .await
            .map_err(|_| BrokerBridgeError::Unavailable)
    }
}

/// What the fake provider saw of each request body.
#[derive(Debug, PartialEq, Eq)]
enum Seen {
    Whole(usize),
    Streamed(Result<Vec<u8>, io::ErrorKind>),
}

/// Reads the whole body, waits `answer_after`, then answers.
struct Provider {
    seen: Arc<Mutex<Vec<Seen>>>,
    answer_after: Duration,
    /// Never read the body.
    hold: Arc<std::sync::atomic::AtomicBool>,
}

#[async_trait]
impl BrokerRequestExecutor for Provider {
    async fn execute_request(
        &self,
        request: v1::CredentialBridgeRequest,
    ) -> Result<BrokerHttpResponse, BrokerRequestError> {
        if request.body.len() > CREDENTIAL_BRIDGE_MAX_REQUEST_BYTES {
            return Err(BrokerRequestError::InvalidRequest);
        }
        self.seen
            .lock()
            .unwrap()
            .push(Seen::Whole(request.body.len()));
        Ok(answer(Vec::new()))
    }

    async fn execute_streamed_request(
        &self,
        _request: v1::CredentialBridgeRequest,
        mut body: BrokerRequestBodyStream,
    ) -> Result<BrokerHttpResponse, BrokerRequestError> {
        if self.hold.load(std::sync::atomic::Ordering::Acquire) {
            std::future::pending::<()>().await;
        }
        let mut bytes = Vec::new();
        let result = loop {
            match body.next().await {
                None => break Ok(bytes),
                Some(Ok(chunk)) => bytes.extend_from_slice(&chunk),
                Some(Err(error)) => break Err(error.kind()),
            }
        };
        let failed = result.is_err();
        self.seen.lock().unwrap().push(Seen::Streamed(result));
        if failed {
            return Err(BrokerRequestError::UpstreamFailed);
        }
        tokio::time::sleep(self.answer_after).await;
        Ok(answer(vec![
            Ok(Bytes::from_static(b"first")),
            // A provider that goes quiet mid-response.
            Err(BrokerRequestError::UpstreamFailed),
        ]))
    }
}

/// A response whose body yields `chunks`, where an `Err` stands for silence.
fn answer(chunks: Vec<Result<Bytes, BrokerRequestError>>) -> BrokerHttpResponse {
    let body = stream::iter(chunks).then(|chunk| async move {
        match chunk {
            Ok(chunk) => Ok(chunk),
            Err(_) => std::future::pending().await,
        }
    });
    BrokerHttpResponse::new(StatusCode::OK, HeaderMap::new(), Box::pin(body))
}

struct Harness {
    guest: mpsc::Sender<v1::CredentialBridgeGuestMessage>,
    host: mpsc::Receiver<HostPayload>,
    seen: Arc<Mutex<Vec<Seen>>>,
    hold: Arc<std::sync::atomic::AtomicBool>,
    runner: tokio::task::JoinHandle<Result<(), BrokerBridgeError>>,
}

impl Harness {
    async fn new(answer_after: Duration) -> Self {
        let (guest, input) = mpsc::channel(64);
        let (output, host) = mpsc::channel(64);
        let seen = Arc::new(Mutex::new(Vec::new()));
        let hold = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let environment = Uuid::new_v4();
        let provider = Arc::new(Provider {
            seen: Arc::clone(&seen),
            answer_after,
            hold: Arc::clone(&hold),
        });
        let runner = tokio::spawn(run_bridge(provider, Link { input, output }, environment, 1));
        let harness = Self {
            guest,
            host,
            seen,
            hold,
            runner,
        };
        harness
            .send(GuestPayload::Ready(v1::CredentialBridgeReady {
                protocol_version: CREDENTIAL_BRIDGE_PROTOCOL_VERSION,
                environment_id: environment.to_string(),
                environment_generation: 1,
            }))
            .await;
        harness
    }

    async fn send(&self, payload: GuestPayload) {
        self.guest
            .send(v1::CredentialBridgeGuestMessage {
                payload: Some(payload),
            })
            .await
            .unwrap();
    }

    /// Start a push; with `streamed`, its body follows in frames.
    async fn push(&self, streamed: bool, body: Vec<u8>) -> String {
        let request_id = Uuid::new_v4().to_string();
        self.send(GuestPayload::Request(v1::CredentialBridgeRequest {
            request_id: request_id.clone(),
            capability_slot: "github".into(),
            route: "github-https".into(),
            method: "POST".into(),
            path: "/owner/repo.git/git-receive-pack".into(),
            query: String::new(),
            headers: Vec::new(),
            body,
            intercepted_host: String::new(),
            streamed_body: streamed,
        }))
        .await;
        request_id
    }

    async fn chunk(&self, request_id: &str, data: Vec<u8>) {
        self.send(GuestPayload::RequestBody(v1::CredentialBridgeRequestBody {
            request_id: request_id.to_owned(),
            data,
        }))
        .await;
    }

    async fn end(&self, request_id: &str) {
        self.send(GuestPayload::RequestEnd(v1::CredentialBridgeRequestEnd {
            request_id: request_id.to_owned(),
        }))
        .await;
    }

    async fn next(&mut self) -> HostPayload {
        self.host.recv().await.unwrap()
    }

    async fn credit(&mut self) -> u32 {
        match self.next().await {
            HostPayload::RequestCredit(credit) => credit.frames,
            _ => panic!("expected credit"),
        }
    }
}

#[tokio::test]
async fn credit_is_one_window_then_one_frame_per_frame_consumed() {
    let mut harness = Harness::new(Duration::ZERO).await;
    let request_id = harness.push(true, Vec::new()).await;
    assert_eq!(
        harness.credit().await,
        CREDENTIAL_BRIDGE_REQUEST_BODY_WINDOW_FRAMES
    );
    let mut sent = Vec::new();
    for index in 0..40_u8 {
        let data = vec![index; CREDENTIAL_BRIDGE_MAX_BODY_CHUNK_BYTES];
        sent.extend_from_slice(&data);
        harness.chunk(&request_id, data).await;
        assert_eq!(harness.credit().await, 1);
    }
    harness.end(&request_id).await;
    assert!(matches!(
        harness.next().await,
        HostPayload::ResponseStart(_)
    ));
    assert_eq!(*harness.seen.lock().unwrap(), [Seen::Streamed(Ok(sent))]);
}

#[tokio::test]
async fn a_frame_past_the_credit_or_out_of_bounds_ends_the_epoch() {
    for case in 0..3 {
        let mut harness = Harness::new(Duration::ZERO).await;
        // A provider that has not read yet holds every frame here.
        harness
            .hold
            .store(true, std::sync::atomic::Ordering::Release);
        let request_id = harness.push(true, Vec::new()).await;
        assert_eq!(
            harness.credit().await,
            CREDENTIAL_BRIDGE_REQUEST_BODY_WINDOW_FRAMES
        );
        match case {
            0 => {
                for _ in 0..=CREDENTIAL_BRIDGE_REQUEST_BODY_WINDOW_FRAMES {
                    harness.chunk(&request_id, vec![1]).await;
                }
            }
            1 => harness.chunk(&request_id, Vec::new()).await,
            _ => {
                harness
                    .chunk(
                        &request_id,
                        vec![1; CREDENTIAL_BRIDGE_MAX_BODY_CHUNK_BYTES + 1],
                    )
                    .await
            }
        }
        assert_eq!(
            harness.runner.await.unwrap(),
            Err(BrokerBridgeError::InvalidProtocol),
            "case {case}"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn a_body_that_stops_mid_stream_fails_after_the_idle_bound() {
    let mut harness = Harness::new(Duration::ZERO).await;
    let request_id = harness.push(true, Vec::new()).await;
    harness.credit().await;
    harness.chunk(&request_id, vec![1; 100]).await;
    assert_eq!(harness.credit().await, 1);
    let started = tokio::time::Instant::now();
    assert!(matches!(
        harness.next().await,
        HostPayload::ResponseFailure(failure)
            if failure.reason == v1::CredentialBridgeFailureReason::UpstreamFailed as i32
    ));
    assert!(started.elapsed() >= CREDENTIAL_BRIDGE_BODY_IDLE_TIMEOUT);
    assert_eq!(
        *harness.seen.lock().unwrap(),
        [Seen::Streamed(Err(io::ErrorKind::TimedOut))]
    );
}

#[tokio::test]
async fn a_cancelled_body_fails_rather_than_ending_short() {
    let mut harness = Harness::new(Duration::ZERO).await;
    let request_id = harness.push(true, Vec::new()).await;
    harness.credit().await;
    harness.chunk(&request_id, vec![1; 100]).await;
    harness.credit().await;
    harness
        .send(GuestPayload::Cancel(v1::CredentialBridgeCancel {
            request_id: request_id.clone(),
        }))
        .await;
    assert!(matches!(
        harness.next().await,
        HostPayload::ResponseFailure(_)
    ));
    assert_eq!(
        *harness.seen.lock().unwrap(),
        [Seen::Streamed(Err(io::ErrorKind::UnexpectedEof))]
    );
    // Frames still in flight for it are dropped, not an error.
    harness.chunk(&request_id, vec![1; 100]).await;
    harness.end(&request_id).await;
    assert!(!harness.runner.is_finished());
}

#[tokio::test(start_paused = true)]
async fn a_silent_provider_may_take_ten_minutes_after_the_body() {
    // Seventy seconds of silence after the body is fine.
    let mut harness = Harness::new(Duration::from_secs(70)).await;
    let request_id = harness.push(true, Vec::new()).await;
    harness.credit().await;
    harness.end(&request_id).await;
    assert!(matches!(
        harness.next().await,
        HostPayload::ResponseStart(_)
    ));
    assert!(matches!(harness.next().await, HostPayload::ResponseBody(_)));
    // Then the response itself goes quiet: the idle bound fails it.
    let quiet = tokio::time::Instant::now();
    assert!(matches!(
        harness.next().await,
        HostPayload::ResponseFailure(_)
    ));
    assert!(quiet.elapsed() >= CREDENTIAL_BRIDGE_BODY_IDLE_TIMEOUT);

    // Past ten minutes it fails.
    let mut harness = Harness::new(Duration::from_secs(11 * 60)).await;
    let request_id = harness.push(true, Vec::new()).await;
    harness.credit().await;
    harness.end(&request_id).await;
    let started = tokio::time::Instant::now();
    assert!(matches!(
        harness.next().await,
        HostPayload::ResponseFailure(failure)
            if failure.reason == v1::CredentialBridgeFailureReason::UpstreamFailed as i32
    ));
    assert!(started.elapsed() >= CREDENTIAL_BRIDGE_STREAMED_FIRST_RESPONSE_TIMEOUT);
    assert!(started.elapsed() < Duration::from_secs(11 * 60));
}

#[tokio::test]
async fn an_older_guest_sends_whole_bodies_and_never_sees_credit() {
    let mut harness = Harness::new(Duration::ZERO).await;
    harness.push(false, vec![1; 1024]).await;
    assert!(matches!(
        harness.next().await,
        HostPayload::ResponseStart(_)
    ));
    assert!(matches!(harness.next().await, HostPayload::ResponseEnd(_)));
    // Past 4 MiB a whole body is refused as before.
    harness
        .push(false, vec![1; CREDENTIAL_BRIDGE_MAX_REQUEST_BYTES + 1])
        .await;
    assert!(matches!(
        harness.next().await,
        HostPayload::ResponseFailure(failure)
            if failure.reason == v1::CredentialBridgeFailureReason::Denied as i32
    ));
    assert_eq!(*harness.seen.lock().unwrap(), [Seen::Whole(1024)]);
}

#[tokio::test(start_paused = true)]
async fn a_provider_that_stops_reading_fails_the_request_after_the_idle_bound() {
    // The provider accepts the request and never reads its body, as a server
    // whose connection stopped reading mid-push leaves the write blocked.
    let mut harness = Harness::new(Duration::ZERO).await;
    harness
        .hold
        .store(true, std::sync::atomic::Ordering::Release);
    let request_id = harness.push(true, Vec::new()).await;
    harness.credit().await;
    harness.chunk(&request_id, vec![1; 100]).await;
    let started = tokio::time::Instant::now();
    assert!(matches!(
        harness.next().await,
        HostPayload::ResponseFailure(failure)
            if failure.reason == v1::CredentialBridgeFailureReason::UpstreamFailed as i32
    ));
    assert!(started.elapsed() >= CREDENTIAL_BRIDGE_BODY_IDLE_TIMEOUT);
    assert!(started.elapsed() < 2 * CREDENTIAL_BRIDGE_BODY_IDLE_TIMEOUT);

    // A cancel of such a request takes effect within the same bound.
    let request_id = harness.push(true, Vec::new()).await;
    harness.credit().await;
    harness
        .send(GuestPayload::Cancel(v1::CredentialBridgeCancel {
            request_id: request_id.clone(),
        }))
        .await;
    let started = tokio::time::Instant::now();
    assert!(matches!(
        harness.next().await,
        HostPayload::ResponseFailure(_)
    ));
    assert!(started.elapsed() <= CREDENTIAL_BRIDGE_BODY_IDLE_TIMEOUT);
    assert!(harness.seen.lock().unwrap().is_empty());
    assert!(!harness.runner.is_finished());
}

#[tokio::test]
async fn a_stray_body_frame_or_end_ends_the_epoch() {
    for case in 0..5 {
        let harness = Harness::new(Duration::ZERO).await;
        harness
            .hold
            .store(true, std::sync::atomic::Ordering::Release);
        match case {
            // A frame on a request whose body came whole.
            0 => {
                let mut harness = harness;
                let request_id = harness.push(false, vec![1]).await;
                // Its answer arrives; the request may or may not be finished,
                // and the frame is an error either way.
                harness.next().await;
                harness.chunk(&request_id, vec![1]).await;
                assert_eq!(
                    harness.runner.await.unwrap(),
                    Err(BrokerBridgeError::InvalidProtocol),
                    "case {case}"
                );
                continue;
            }
            // A frame or an end for a request this epoch never had.
            1 => harness.chunk(&Uuid::new_v4().to_string(), vec![1]).await,
            2 => harness.end(&Uuid::new_v4().to_string()).await,
            // A second end, and a frame after the end, on a live request.
            3 | 4 => {
                let request_id = harness.push(true, Vec::new()).await;
                harness.end(&request_id).await;
                if case == 3 {
                    harness.end(&request_id).await;
                } else {
                    harness.chunk(&request_id, vec![1]).await;
                }
            }
            _ => unreachable!(),
        }
        assert_eq!(
            harness.runner.await.unwrap(),
            Err(BrokerBridgeError::InvalidProtocol),
            "case {case}"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn late_frames_for_a_finished_or_cancelled_streamed_request_are_dropped() {
    let mut harness = Harness::new(Duration::ZERO).await;
    // One whose response went quiet and failed after the idle bound.
    let finished = harness.push(true, Vec::new()).await;
    harness.credit().await;
    harness.end(&finished).await;
    assert!(matches!(
        harness.next().await,
        HostPayload::ResponseStart(_)
    ));
    assert!(matches!(harness.next().await, HostPayload::ResponseBody(_)));
    assert!(matches!(
        harness.next().await,
        HostPayload::ResponseFailure(_)
    ));
    // One cancelled while its provider still holds it.
    harness
        .hold
        .store(true, std::sync::atomic::Ordering::Release);
    let cancelled = harness.push(true, Vec::new()).await;
    harness.credit().await;
    harness
        .send(GuestPayload::Cancel(v1::CredentialBridgeCancel {
            request_id: cancelled.clone(),
        }))
        .await;
    // Frames racing that answer or that cancel are dropped.
    for request_id in [&finished, &cancelled] {
        harness.chunk(request_id, vec![1]).await;
        harness.end(request_id).await;
    }
    // The epoch keeps serving: the cancelled request fails within the bound.
    assert!(matches!(
        harness.next().await,
        HostPayload::ResponseFailure(_)
    ));
    tokio::task::yield_now().await;
    assert!(!harness.runner.is_finished());
}
