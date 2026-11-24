//! `FrontDoorSession` (#4001): the Pod is checked before any relay work, the
//! session joins only its live binding's current epoch, and the epoch's
//! refusals reach cw-egress by their code alone. Once attached, the session
//! checks the front door's Ready, routes requests by id across the epochs of
//! a renewal, and ends only with cw-egress, its token or a broken frame.

use base64::engine::general_purpose::STANDARD;
use futures::StreamExt as _;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tonic::Status;
use uuid::Uuid;

use super::*;
use crate::front_door::{
    self as registry, BindingKey, EpochRequest, FrontDoorEpochs, Join, Joined, Registration,
};
use crate::worker::environment_auth::WorkspaceCredentialScope;
use codewire_daemon_proto::codewire::bridge::v1;
use prost::Message as _;

const ENVIRONMENT: &str = "4b0f9a3e-2c41-4d7a-9a51-6f1f8d2b7c10";
const GENERATION: i64 = 5;

struct Bound;

#[async_trait]
impl BindingStore for Bound {
    async fn live_binding(
        &self,
        pod_uid: &str,
        namespace: &str,
        pod_name: &str,
    ) -> Result<Option<LiveBinding>, BindingStoreUnavailable> {
        Ok(
            (pod_uid == GUEST_UID && namespace == SANDBOXES && pod_name == GUEST).then(|| {
                LiveBinding {
                    environment_id: ENVIRONMENT.into(),
                    pod_uid: GUEST_UID.into(),
                    namespace: SANDBOXES.into(),
                    pod_name: GUEST.into(),
                    claim_uid: "claim".into(),
                    sandbox_uid: "sandbox".into(),
                    operation_generation: GENERATION,
                    projection_selection_sha256: Some("ab".repeat(32)),
                    managed_credential_clients: String::new(),
                    credential_scope: WorkspaceCredentialScope::Pod,
                    environment_generation: 1,
                    isolation_tier: "standard".into(),
                    working_directory: String::new(),
                    defaults: None,
                    interception: None,
                }
            }),
        )
    }

    /// No record yet: each first writer's answer is recorded.
    async fn record_trust(
        &self,
        _pod_uid: &str,
        ca_given: bool,
    ) -> Result<bool, BindingStoreUnavailable> {
        Ok(ca_given)
    }
}

fn key() -> BindingKey {
    BindingKey {
        environment_id: Uuid::parse_str(ENVIRONMENT).unwrap(),
        pod_uid: GUEST_UID.into(),
        generation: u64::try_from(GENERATION).unwrap(),
    }
}

fn open() -> Value {
    json!({"open": named_guest()})
}

fn bridge(frame: &[u8]) -> Value {
    json!({"bridge": STANDARD.encode(frame)})
}

/// Every message of a session that sends `frames`, ending with its
/// end-of-stream message.
async fn session(app: axum::Router, frames: &[Value]) -> Vec<Value> {
    let mut body = Vec::new();
    for frame in frames {
        let payload = serde_json::to_vec(frame).unwrap();
        body.push(0_u8);
        body.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_be_bytes());
        body.extend_from_slice(&payload);
    }
    let request = Request::post("/codewire.internal.v1.EgressService/FrontDoorSession")
        .header("content-type", "application/connect+json")
        .header(AUTHORIZATION, format!("Bearer {}", token()))
        .body(Body::from(body))
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    let bytes = tokio::time::timeout(Duration::from_secs(5), response.into_body().collect())
        .await
        .expect("the session ends")
        .unwrap()
        .to_bytes();
    let mut messages = Vec::new();
    let mut rest = &bytes[..];
    while rest.len() >= 5 {
        let length = frame_len(rest);
        messages.push(serde_json::from_slice(&rest[5..5 + length]).unwrap());
        rest = &rest[5 + length..];
    }
    messages
}

/// A registered epoch for `key`, and the joins it is asked.
fn epoch(
    front_doors: &Arc<FrontDoorEpochs>,
    key: BindingKey,
) -> (Registration, mpsc::Receiver<EpochRequest>) {
    let (joins, asked) = mpsc::channel(1);
    (front_doors.register(key, joins), asked)
}

fn refused(messages: &[Value]) -> &str {
    messages.last().unwrap()["error"]["code"]
        .as_str()
        .unwrap_or("none")
}

#[tokio::test]
async fn a_pod_on_another_node_is_refused_before_any_relay_work() {
    let cluster = Cluster::healthy().with(|cluster| {
        cluster.edit_guest(|pod| pod.spec.as_mut().unwrap().node_name = Some("runtime-b".into()));
    });
    let front_doors = Arc::new(FrontDoorEpochs::default());
    let (_epoch, mut asked) = epoch(&front_doors, key());
    let messages = session(
        app_with(&cluster, Arc::new(Bound), Some(front_doors)),
        &[open()],
    )
    .await;
    assert_eq!(refused(&messages), "permission_denied", "{messages:?}");
    assert!(asked.try_recv().is_err(), "the epoch was never asked");
}

#[tokio::test]
async fn a_pod_named_with_another_uid_is_refused_before_any_relay_work() {
    let front_doors = Arc::new(FrontDoorEpochs::default());
    let (_epoch, mut asked) = epoch(&front_doors, key());
    let messages = session(
        app_with(&Cluster::healthy(), Arc::new(Bound), Some(front_doors)),
        &[json!({"open": {"podUid": "1d0c2b9a-0000-4000-8000-000000000000", "podName": GUEST}})],
    )
    .await;
    assert_eq!(refused(&messages), "permission_denied", "{messages:?}");
    assert!(asked.try_recv().is_err(), "the epoch was never asked");
}

#[tokio::test]
async fn an_unbound_pod_is_refused_and_no_epoch_is_asked() {
    let front_doors = Arc::new(FrontDoorEpochs::default());
    let (_epoch, mut asked) = epoch(&front_doors, key());
    let messages = session(
        app_with(&Cluster::healthy(), Arc::new(Unbound), Some(front_doors)),
        &[open()],
    )
    .await;
    assert_eq!(refused(&messages), "permission_denied", "{messages:?}");
    assert!(asked.try_recv().is_err());
}

#[tokio::test]
async fn without_an_epoch_for_the_pods_current_binding_cw_egress_retries() {
    // None at all, or only one for the binding's previous generation, which
    // the relay is about to replace.
    for registered in [
        None,
        Some(BindingKey {
            generation: 4,
            ..key()
        }),
    ] {
        let front_doors = Arc::new(FrontDoorEpochs::default());
        let registered = registered.map(|key| epoch(&front_doors, key));
        let messages = session(
            app_with(&Cluster::healthy(), Arc::new(Bound), Some(front_doors)),
            &[open()],
        )
        .await;
        assert_eq!(refused(&messages), "unavailable", "{messages:?}");
        if let Some((_epoch, mut asked)) = registered {
            assert!(asked.try_recv().is_err());
        }
    }
}

#[tokio::test]
async fn an_epochs_refusal_reaches_cw_egress_by_its_code_alone() {
    for (status, code) in [
        (Status::already_exists("broker detail"), "already_exists"),
        (
            Status::permission_denied("broker detail"),
            "permission_denied",
        ),
        (Status::internal("broker detail"), "unavailable"),
    ] {
        let front_doors = Arc::new(FrontDoorEpochs::default());
        let (_epoch, mut asked) = epoch(&front_doors, key());
        let epoch = tokio::spawn(async move {
            let EpochRequest::Join(Join { reply, .. }) = asked.recv().await.unwrap() else {
                panic!("the epoch was asked to join");
            };
            assert!(reply.send(Err(status)).is_ok());
        });
        let messages = session(
            app_with(&Cluster::healthy(), Arc::new(Bound), Some(front_doors)),
            &[open()],
        )
        .await;
        epoch.await.unwrap();
        assert_eq!(refused(&messages), code, "{messages:?}");
        assert!(
            !serde_json::to_string(&messages)
                .unwrap()
                .contains("broker detail"),
            "{messages:?}"
        );
    }
}

#[tokio::test]
async fn an_unlabelled_or_ending_pod_is_refused_before_any_relay_work() {
    for edit in [
        (|pod: &mut Pod| {
            pod.metadata
                .labels
                .as_mut()
                .unwrap()
                .remove(EGRESS_MODE_LABEL);
        }) as fn(&mut Pod),
        |pod: &mut Pod| {
            pod.metadata.deletion_timestamp =
                Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
                    k8s_openapi::jiff::Timestamp::UNIX_EPOCH,
                ))
        },
    ] {
        let cluster = Cluster::healthy().with(|cluster| cluster.edit_guest(edit));
        let front_doors = Arc::new(FrontDoorEpochs::default());
        let (_epoch, mut asked) = epoch(&front_doors, key());
        let messages = session(
            app_with(&cluster, Arc::new(Bound), Some(front_doors)),
            &[open()],
        )
        .await;
        assert_eq!(refused(&messages), "permission_denied", "{messages:?}");
        assert!(asked.try_recv().is_err(), "the epoch was never asked");
    }
}

/// One upstream as the relay hands it over, and the test's ends of it.
struct Upstream {
    guests: mpsc::Receiver<Vec<u8>>,
    host: mpsc::Sender<Result<Vec<u8>, Status>>,
    ended: CancellationToken,
}

fn upstream() -> (Joined, Upstream) {
    let (guest, guests) = mpsc::channel(8);
    let (host, hosts) = mpsc::channel(8);
    let ended = CancellationToken::new();
    let joined = Joined {
        capabilities: vec![
            codewire_daemon_proto::CREDENTIAL_BRIDGE_CAPABILITY_FRONT_DOOR.into(),
            codewire_daemon_proto::CREDENTIAL_BRIDGE_CAPABILITY_REQUEST_BODY_STREAM.into(),
        ],
        guest,
        host: tokio_stream::wrappers::ReceiverStream::new(hosts).boxed(),
        session: ended.clone().drop_guard(),
    };
    (
        joined,
        Upstream {
            guests,
            host,
            ended,
        },
    )
}

/// An epoch that answers its first join with `joined`.
fn serving(mut asked: mpsc::Receiver<EpochRequest>, joined: Joined) {
    tokio::spawn(async move {
        let EpochRequest::Join(Join { reply }) = asked.recv().await.unwrap() else {
            panic!("the epoch was asked to join");
        };
        assert!(reply.send(Ok(joined)).is_ok());
    });
}

fn ready() -> Vec<u8> {
    registry::binding_ready(key().environment_id, key().generation)
}

fn request(id: &str) -> Vec<u8> {
    v1::CredentialBridgeGuestMessage {
        payload: Some(v1::credential_bridge_guest_message::Payload::Request(
            v1::CredentialBridgeRequest {
                request_id: id.into(),
                ..Default::default()
            },
        )),
    }
    .encode_to_vec()
}

fn request_body(id: &str) -> Vec<u8> {
    v1::CredentialBridgeGuestMessage {
        payload: Some(v1::credential_bridge_guest_message::Payload::RequestBody(
            v1::CredentialBridgeRequestBody {
                request_id: id.into(),
                ..Default::default()
            },
        )),
    }
    .encode_to_vec()
}

fn response_end(id: &str) -> Vec<u8> {
    v1::CredentialBridgeHostMessage {
        payload: Some(v1::credential_bridge_host_message::Payload::ResponseEnd(
            v1::CredentialBridgeResponseEnd {
                request_id: id.into(),
            },
        )),
    }
    .encode_to_vec()
}

fn framed_bridge(message: &[u8]) -> Value {
    bridge(&registry::framed(message).unwrap())
}

/// A session cw-egress drives frame by frame.
struct Live {
    input: mpsc::Sender<Result<Vec<u8>, std::io::Error>>,
    body: Body,
    buffer: Vec<u8>,
}

impl Live {
    async fn start(app: axum::Router) -> Self {
        let (input, frames) = mpsc::channel(8);
        let request = Request::post("/codewire.internal.v1.EgressService/FrontDoorSession")
            .header("content-type", "application/connect+json")
            .header(AUTHORIZATION, format!("Bearer {}", token()))
            .body(Body::from_stream(
                tokio_stream::wrappers::ReceiverStream::new(frames),
            ))
            .unwrap();
        let live = Self {
            input,
            body: Body::empty(),
            buffer: Vec::new(),
        };
        live.send(&open()).await;
        let response = app.oneshot(request).await.unwrap();
        Self {
            body: response.into_body(),
            ..live
        }
    }

    async fn send(&self, frame: &Value) {
        let payload = serde_json::to_vec(frame).unwrap();
        let mut envelope = vec![0_u8];
        envelope.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_be_bytes());
        envelope.extend_from_slice(&payload);
        self.input.send(Ok(envelope)).await.unwrap();
    }

    async fn send_message(&self, message: &[u8]) {
        self.send(&framed_bridge(message)).await;
    }

    /// The next message, or `None` once the stream has ended.
    async fn next(&mut self) -> Option<Value> {
        loop {
            if self.buffer.len() >= 5 && self.buffer.len() >= 5 + frame_len(&self.buffer) {
                let length = frame_len(&self.buffer);
                let message = serde_json::from_slice(&self.buffer[5..5 + length]).unwrap();
                self.buffer.drain(..5 + length);
                return Some(message);
            }
            match self.body.frame().await {
                Some(Ok(frame)) => {
                    if let Ok(data) = frame.into_data() {
                        self.buffer.extend_from_slice(&data);
                    }
                }
                _ => return None,
            }
        }
    }

    /// The attached frame and the Open, whose capabilities are returned.
    async fn attached(&mut self) -> Vec<String> {
        assert_eq!(self.next().await.unwrap(), json!({"attached": {}}));
        let open = self.next().await.unwrap();
        let frame = STANDARD.decode(open["bridge"].as_str().unwrap()).unwrap();
        let open =
            v1::CredentialBridgeHostMessage::decode(registry::frame_message(&frame).unwrap())
                .unwrap();
        let Some(v1::credential_bridge_host_message::Payload::Open(open)) = open.payload else {
            panic!("the Open comes first");
        };
        assert_eq!(open.environment_id, ENVIRONMENT);
        assert_eq!(
            open.environment_generation,
            u64::try_from(GENERATION).unwrap()
        );
        open.capabilities
    }
}

async fn bounded<F: std::future::Future>(future: F) -> F::Output {
    tokio::time::timeout(Duration::from_secs(30), future)
        .await
        .expect("bounded")
}

fn app_for(front_doors: &Arc<FrontDoorEpochs>) -> axum::Router {
    app_with(
        &Cluster::healthy(),
        Arc::new(Bound),
        Some(Arc::clone(front_doors)),
    )
}

#[tokio::test]
async fn a_session_opens_its_epoch_writes_the_open_and_consumes_the_ready() {
    let front_doors = Arc::new(FrontDoorEpochs::default());
    let (_epoch, asked) = epoch(&front_doors, key());
    let (joined, mut upstream) = upstream();
    serving(asked, joined);
    let mut live = Live::start(app_for(&front_doors)).await;
    assert_eq!(
        live.attached().await.len(),
        2,
        "the first upstream's capabilities"
    );
    live.send_message(&ready()).await;
    live.send_message(&request("r1")).await;
    assert_eq!(
        bounded(upstream.guests.recv()).await.unwrap(),
        request("r1"),
        "the front door's Ready is consumed, never forwarded"
    );
    upstream.host.send(Ok(response_end("r1"))).await.unwrap();
    assert_eq!(
        bounded(live.next()).await.unwrap(),
        framed_bridge(&response_end("r1"))
    );
}

#[tokio::test]
async fn a_renewal_moves_new_requests_to_the_successor_and_drains_the_old_epoch() {
    let front_doors = Arc::new(FrontDoorEpochs::default());
    let (_old_epoch, old_asked) = epoch(&front_doors, key());
    let (old_joined, mut old) = upstream();
    serving(old_asked, old_joined);
    let mut live = Live::start(app_for(&front_doors)).await;
    live.attached().await;
    live.send_message(&ready()).await;
    live.send_message(&request("old")).await;
    assert_eq!(bounded(old.guests.recv()).await.unwrap(), request("old"));

    // The successor is admitted while "old" is still in flight.
    let (_new_epoch, new_asked) = epoch(&front_doors, key());
    let (new_joined, mut new) = upstream();
    serving(new_asked, new_joined);
    live.send_message(&request("new")).await;
    assert_eq!(
        bounded(new.guests.recv()).await.unwrap(),
        request("new"),
        "the successor's first frame is the new request: the front door's Ready is not sent again"
    );
    // The old request's later frames still follow it.
    live.send_message(&request_body("old")).await;
    assert_eq!(
        bounded(old.guests.recv()).await.unwrap(),
        request_body("old")
    );
    assert!(!old.ended.is_cancelled());
    old.host.send(Ok(response_end("old"))).await.unwrap();
    assert_eq!(
        bounded(live.next()).await.unwrap(),
        framed_bridge(&response_end("old"))
    );
    // Drained, the old upstream is closed; the session goes on.
    bounded(old.ended.cancelled()).await;
    new.host.send(Ok(response_end("new"))).await.unwrap();
    assert_eq!(
        bounded(live.next()).await.unwrap(),
        framed_bridge(&response_end("new"))
    );
    assert!(!new.ended.is_cancelled());
}

#[tokio::test]
async fn a_session_must_start_with_its_bindings_ready() {
    let other = registry::binding_ready(key().environment_id, key().generation + 1);
    for (case, first) in [
        ("another generation", registry::framed(&other).unwrap()),
        (
            "a request before Ready",
            registry::framed(&request("r1")).unwrap(),
        ),
        ("a bad length", b"\0\0\0\x09short".to_vec()),
    ] {
        let front_doors = Arc::new(FrontDoorEpochs::default());
        let (_epoch, asked) = epoch(&front_doors, key());
        let (joined, mut upstream) = upstream();
        serving(asked, joined);
        let mut live = Live::start(app_for(&front_doors)).await;
        live.attached().await;
        live.send(&bridge(&first)).await;
        let end = bounded(live.next()).await.unwrap();
        assert_eq!(end["error"]["code"], "invalid_argument", "{case}: {end}");
        bounded(upstream.ended.cancelled()).await;
        assert!(
            upstream.guests.try_recv().is_err(),
            "{case}: nothing was forwarded"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn a_front_door_that_never_sends_ready_is_ended() {
    let front_doors = Arc::new(FrontDoorEpochs::default());
    let (_epoch, asked) = epoch(&front_doors, key());
    let (joined, upstream) = upstream();
    serving(asked, joined);
    let mut live = Live::start(app_for(&front_doors)).await;
    live.attached().await;
    let end = live.next().await.unwrap();
    assert_eq!(end["error"]["code"], "invalid_argument", "{end}");
    upstream.ended.cancelled().await;
}

#[tokio::test(start_paused = true)]
async fn a_cw_egress_that_takes_no_frame_ends_its_session() {
    let front_doors = Arc::new(FrontDoorEpochs::default());
    let (_epoch, asked) = epoch(&front_doors, key());
    let (joined, mut upstream) = upstream();
    serving(asked, joined);
    let mut live = Live::start(app_for(&front_doors)).await;
    live.attached().await;
    live.send_message(&ready()).await;
    for id in ["a", "b", "c"] {
        live.send_message(&request(id)).await;
        upstream.guests.recv().await.unwrap();
    }
    // Idle for longer than the bound with nothing to send: not a stall.
    tokio::time::sleep(super::super::front_door::STALL * 3).await;
    assert!(!upstream.ended.is_cancelled());
    // Now cw-egress reads nothing while the broker answers.
    for id in ["a", "b", "c"] {
        let _ = upstream.host.send(Ok(response_end(id))).await;
    }
    upstream.ended.cancelled().await;
}

#[tokio::test]
async fn the_session_and_its_upstreams_end_when_cw_egress_goes() {
    let front_doors = Arc::new(FrontDoorEpochs::default());
    let (_epoch, asked) = epoch(&front_doors, key());
    let (joined, upstream) = upstream();
    serving(asked, joined);
    let mut live = Live::start(app_for(&front_doors)).await;
    live.attached().await;
    assert!(!upstream.ended.is_cancelled());
    drop(live);
    bounded(upstream.ended.cancelled()).await;
}

#[tokio::test]
async fn an_upstream_that_fails_answers_its_requests_and_the_session_goes_on() {
    let front_doors = Arc::new(FrontDoorEpochs::default());
    let (_epoch, asked) = epoch(&front_doors, key());
    let (joined, mut upstream) = upstream();
    serving(asked, joined);
    let mut live = Live::start(app_for(&front_doors)).await;
    live.attached().await;
    live.send_message(&ready()).await;
    live.send_message(&request("r1")).await;
    bounded(upstream.guests.recv()).await.unwrap();
    upstream
        .host
        .send(Err(Status::unavailable("broker detail")))
        .await
        .unwrap();
    let answer = bounded(live.next()).await.unwrap();
    let failure = v1::CredentialBridgeHostMessage {
        payload: Some(
            v1::credential_bridge_host_message::Payload::ResponseFailure(
                v1::CredentialBridgeResponseFailure {
                    request_id: "r1".into(),
                    reason: v1::CredentialBridgeFailureReason::Unavailable as i32,
                    refusal: v1::CredentialBridgeRefusal::Unspecified as i32,
                    ..Default::default()
                },
            ),
        ),
    };
    assert_eq!(answer, framed_bridge(&failure.encode_to_vec()));
    assert!(
        !serde_json::to_string(&answer)
            .unwrap()
            .contains("broker detail")
    );
    // With no epoch left, a new request is answered, and the session stays.
    live.send_message(&request("r2")).await;
    let refused = bounded(live.next()).await.unwrap();
    assert!(refused.get("bridge").is_some(), "{refused}");
}

#[tokio::test]
async fn a_second_open_ends_the_session() {
    let front_doors = Arc::new(FrontDoorEpochs::default());
    let (_epoch, asked) = epoch(&front_doors, key());
    let (joined, _upstream) = upstream();
    serving(asked, joined);
    let mut live = Live::start(app_for(&front_doors)).await;
    live.attached().await;
    live.send(&open()).await;
    let end = bounded(live.next()).await.unwrap();
    assert_eq!(end["error"]["code"], "failed_precondition", "{end}");
}

#[tokio::test]
async fn a_frame_before_open_is_refused_and_no_epoch_is_asked() {
    let front_doors = Arc::new(FrontDoorEpochs::default());
    let (_epoch, mut asked) = epoch(&front_doors, key());
    let messages = session(app_for(&front_doors), &[framed_bridge(&ready())]).await;
    assert_eq!(refused(&messages), "failed_precondition", "{messages:?}");
    assert!(asked.try_recv().is_err());
}

#[tokio::test(start_paused = true)]
async fn a_successor_whose_join_fails_is_tried_again_after_a_backoff() {
    let front_doors = Arc::new(FrontDoorEpochs::default());
    let (_old_epoch, old_asked) = epoch(&front_doors, key());
    let (old_joined, mut old) = upstream();
    serving(old_asked, old_joined);
    let mut live = Live::start(app_for(&front_doors)).await;
    live.attached().await;
    live.send_message(&ready()).await;
    // The successor's first join fails.
    let (_new_epoch, mut new_asked) = epoch(&front_doors, key());
    let (new_joined, mut new) = upstream();
    live.send_message(&request("a")).await;
    let EpochRequest::Join(Join { reply }) = new_asked.recv().await.unwrap() else {
        panic!("the epoch was asked to join");
    };
    assert!(reply.send(Err(Status::unavailable("busy"))).is_ok());
    assert_eq!(
        old.guests.recv().await.unwrap(),
        request("a"),
        "the old epoch still serves"
    );
    // Within the backoff, nothing asks the successor again.
    live.send_message(&request("b")).await;
    assert_eq!(old.guests.recv().await.unwrap(), request("b"));
    assert!(new_asked.try_recv().is_err(), "no retry inside the backoff");
    // After it, the successor is joined and takes the next request.
    tokio::time::sleep(Duration::from_secs(2)).await;
    live.send_message(&request("c")).await;
    let EpochRequest::Join(Join { reply }) = new_asked.recv().await.unwrap() else {
        panic!("the epoch was asked to join");
    };
    assert!(reply.send(Ok(new_joined)).is_ok());
    assert_eq!(new.guests.recv().await.unwrap(), request("c"));
    assert!(
        old.guests.try_recv().is_err(),
        "the old epoch gets nothing new"
    );
}

#[tokio::test(start_paused = true)]
async fn an_idle_session_follows_a_renewal_without_ending() {
    let front_doors = Arc::new(FrontDoorEpochs::default());
    let (old_registration, old_asked) = epoch(&front_doors, key());
    let (old_joined, old) = upstream();
    serving(old_asked, old_joined);
    let mut live = Live::start(app_for(&front_doors)).await;
    live.attached().await;
    live.send_message(&ready()).await;
    // The successor is admitted, then the old epoch ends, with nothing sent.
    let (_new_epoch, new_asked) = epoch(&front_doors, key());
    let (new_joined, mut new) = upstream();
    serving(new_asked, new_joined);
    drop(old_registration);
    drop(old.host);
    // Well past the no-epoch bound, the quiet session is still open.
    assert!(
        tokio::time::timeout(super::super::front_door::NO_EPOCH * 3, live.next())
            .await
            .is_err(),
        "the session did not end"
    );
    live.send_message(&request("r")).await;
    assert_eq!(new.guests.recv().await.unwrap(), request("r"));
}

/// #6099: a release ends the relay's epoch and admits its successor about a
/// second later. A request in that gap waits and is sent on the successor.
#[tokio::test]
async fn a_request_between_epochs_is_sent_on_the_successor() {
    let front_doors = Arc::new(FrontDoorEpochs::default());
    let (ended_epoch, asked) = epoch(&front_doors, key());
    let (joined, ended) = upstream();
    serving(asked, joined);
    let mut live = Live::start(app_for(&front_doors)).await;
    live.attached().await;
    live.send_message(&ready()).await;
    drop(ended_epoch);
    drop(ended.host);
    bounded(ended.ended.cancelled()).await;
    live.send_message(&request("r")).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    let (_successor_epoch, successor_asked) = epoch(&front_doors, key());
    let (successor_joined, mut successor) = upstream();
    serving(successor_asked, successor_joined);
    assert_eq!(
        bounded(successor.guests.recv()).await.unwrap(),
        request("r"),
        "the request waited for the successor instead of being refused"
    );
    successor.host.send(Ok(response_end("r"))).await.unwrap();
    assert_eq!(
        bounded(live.next()).await.unwrap(),
        framed_bridge(&response_end("r"))
    );
}

/// With no successor, the request is refused once the wait's bound passes.
#[tokio::test(start_paused = true)]
async fn a_request_between_epochs_is_refused_at_the_bound_when_none_follows() {
    let front_doors = Arc::new(FrontDoorEpochs::default());
    let (ended_epoch, asked) = epoch(&front_doors, key());
    let (joined, ended) = upstream();
    serving(asked, joined);
    let mut live = Live::start(app_for(&front_doors)).await;
    live.attached().await;
    live.send_message(&ready()).await;
    drop(ended_epoch);
    drop(ended.host);
    ended.ended.cancelled().await;
    let started = tokio::time::Instant::now();
    live.send_message(&request("r")).await;
    let answer = live.next().await.unwrap();
    let frame = STANDARD.decode(answer["bridge"].as_str().unwrap()).unwrap();
    let message =
        v1::CredentialBridgeHostMessage::decode(registry::frame_message(&frame).unwrap()).unwrap();
    assert!(
        matches!(
            message.payload,
            Some(v1::credential_bridge_host_message::Payload::ResponseFailure(ref failure))
                if failure.request_id == "r"
        ),
        "{message:?}"
    );
    assert!(started.elapsed() >= codewire_credential_bridge::SUCCESSOR_EPOCH_WAIT);
}

#[tokio::test(start_paused = true)]
async fn a_session_with_no_epoch_left_ends_so_cw_egress_reads_the_binding_again() {
    let front_doors = Arc::new(FrontDoorEpochs::default());
    let (epoch_registration, asked) = epoch(&front_doors, key());
    let (joined, upstream) = upstream();
    serving(asked, joined);
    let mut live = Live::start(app_for(&front_doors)).await;
    live.attached().await;
    live.send_message(&ready()).await;
    // The binding moves on: its epoch ends and none follows.
    drop(epoch_registration);
    drop(upstream.host);
    let end = live.next().await.unwrap();
    assert_eq!(end["error"]["code"], "unavailable", "{end}");
}

#[tokio::test]
async fn a_third_epoch_waits_until_the_draining_one_is_gone() {
    let front_doors = Arc::new(FrontDoorEpochs::default());
    let (_a_epoch, a_asked) = epoch(&front_doors, key());
    let (a_joined, mut a) = upstream();
    serving(a_asked, a_joined);
    let mut live = Live::start(app_for(&front_doors)).await;
    live.attached().await;
    live.send_message(&ready()).await;
    live.send_message(&request("a")).await;
    assert_eq!(bounded(a.guests.recv()).await.unwrap(), request("a"));
    let (_b_epoch, b_asked) = epoch(&front_doors, key());
    let (b_joined, mut b) = upstream();
    serving(b_asked, b_joined);
    live.send_message(&request("b")).await;
    assert_eq!(bounded(b.guests.recv()).await.unwrap(), request("b"));
    // A third epoch while "a" still drains: new requests stay on B.
    let (_c_epoch, c_asked) = epoch(&front_doors, key());
    let (c_joined, mut c) = upstream();
    serving(c_asked, c_joined);
    live.send_message(&request("b2")).await;
    assert_eq!(bounded(b.guests.recv()).await.unwrap(), request("b2"));
    assert!(c.guests.try_recv().is_err());
    // Once "a" has drained, the third is joined.
    a.host.send(Ok(response_end("a"))).await.unwrap();
    assert_eq!(
        bounded(live.next()).await.unwrap(),
        framed_bridge(&response_end("a"))
    );
    bounded(a.ended.cancelled()).await;
    live.send_message(&request("c")).await;
    assert_eq!(bounded(c.guests.recv()).await.unwrap(), request("c"));
}

#[tokio::test]
async fn a_request_for_an_upstream_that_has_gone_is_answered_and_finished() {
    let front_doors = Arc::new(FrontDoorEpochs::default());
    let (_epoch, asked) = epoch(&front_doors, key());
    let (joined, upstream) = upstream();
    serving(asked, joined);
    let mut live = Live::start(app_for(&front_doors)).await;
    live.attached().await;
    live.send_message(&ready()).await;
    // The upstream stops taking frames: its broker leg has gone.
    drop(upstream.guests);
    live.send_message(&request("r1")).await;
    let failure = v1::CredentialBridgeHostMessage {
        payload: Some(
            v1::credential_bridge_host_message::Payload::ResponseFailure(
                v1::CredentialBridgeResponseFailure {
                    request_id: "r1".into(),
                    reason: v1::CredentialBridgeFailureReason::Unavailable as i32,
                    refusal: v1::CredentialBridgeRefusal::Unspecified as i32,
                    ..Default::default()
                },
            ),
        ),
    };
    assert_eq!(
        bounded(live.next()).await.unwrap(),
        framed_bridge(&failure.encode_to_vec())
    );
    // The id is finished: a late frame for it races that answer and is dropped.
    live.send_message(&request_body("r1")).await;
    live.send_message(&request("r2")).await;
    let next = bounded(live.next()).await.unwrap();
    let frame = STANDARD.decode(next["bridge"].as_str().unwrap()).unwrap();
    let message =
        v1::CredentialBridgeHostMessage::decode(registry::frame_message(&frame).unwrap()).unwrap();
    assert!(
        matches!(
            message.payload,
            Some(v1::credential_bridge_host_message::Payload::ResponseFailure(ref failure))
                if failure.request_id == "r2"
        ),
        "{message:?}"
    );
}

/// A live request's own frame outside the session's pin ends that request
/// once: cw-egress reads its answer, its upstream gets the Cancel, and the
/// upstream's late answer is dropped while the session serves on (#4909).
#[tokio::test]
async fn a_live_requests_frame_outside_the_pin_is_answered_once_and_cancelled_upstream() {
    let front_doors = Arc::new(FrontDoorEpochs::default());
    let (_epoch, asked) = epoch(&front_doors, key());
    let (mut joined, mut upstream) = upstream();
    // The pin is what the first upstream serves: no streamed request body.
    joined.capabilities.retain(|capability| {
        capability == codewire_daemon_proto::CREDENTIAL_BRIDGE_CAPABILITY_FRONT_DOOR
    });
    serving(asked, joined);
    let mut live = Live::start(app_for(&front_doors)).await;
    live.attached().await;
    live.send_message(&ready()).await;
    live.send_message(&request("r1")).await;
    assert_eq!(
        bounded(upstream.guests.recv()).await.unwrap(),
        request("r1")
    );

    live.send_message(&request_body("r1")).await;
    let failure = v1::CredentialBridgeHostMessage {
        payload: Some(
            v1::credential_bridge_host_message::Payload::ResponseFailure(
                v1::CredentialBridgeResponseFailure {
                    request_id: "r1".into(),
                    reason: v1::CredentialBridgeFailureReason::Unavailable as i32,
                    refusal: v1::CredentialBridgeRefusal::Unspecified as i32,
                    ..Default::default()
                },
            ),
        ),
    };
    assert_eq!(
        bounded(live.next()).await.unwrap(),
        framed_bridge(&failure.encode_to_vec())
    );
    let cancel = v1::CredentialBridgeGuestMessage {
        payload: Some(v1::credential_bridge_guest_message::Payload::Cancel(
            v1::CredentialBridgeCancel {
                request_id: "r1".into(),
            },
        )),
    };
    assert_eq!(
        bounded(upstream.guests.recv()).await.unwrap(),
        cancel.encode_to_vec(),
        "the body is never forwarded; the upstream is told to stop"
    );

    // The upstream's late answer for r1 is dropped, and it serves on.
    upstream.host.send(Ok(response_end("r1"))).await.unwrap();
    live.send_message(&request("r2")).await;
    assert_eq!(
        bounded(upstream.guests.recv()).await.unwrap(),
        request("r2")
    );
    upstream.host.send(Ok(response_end("r2"))).await.unwrap();
    assert_eq!(
        bounded(live.next()).await.unwrap(),
        framed_bridge(&response_end("r2")),
        "r1 is answered once"
    );
}

/// #4001: a newer session for the same Pod replaces the older one, which
/// only that Pod's node could have opened. The older ends and lets go of its
/// upstream, and the newer joins the epoch rather than being refused
/// `ALREADY_EXISTS`, so a restarted cw-egress is served at once.
#[tokio::test]
async fn a_newer_session_for_the_same_pod_replaces_the_older() {
    let front_doors = Arc::new(FrontDoorEpochs::default());
    let (_epoch, mut asked) = epoch(&front_doors, key());
    let (first_joined, first) = upstream();
    let (second_joined, mut second) = upstream();
    tokio::spawn(async move {
        for joined in [first_joined, second_joined] {
            let EpochRequest::Join(Join { reply }) = asked.recv().await.unwrap() else {
                panic!("the epoch was asked to join");
            };
            assert!(reply.send(Ok(joined)).is_ok());
        }
    });
    let mut older = Live::start(app_for(&front_doors)).await;
    older.attached().await;
    let mut newer = Live::start(app_for(&front_doors)).await;
    bounded(first.ended.cancelled()).await;
    newer.attached().await;
    while bounded(older.next()).await.is_some() {}
    newer.send_message(&ready()).await;
    newer.send_message(&request("r1")).await;
    assert_eq!(bounded(second.guests.recv()).await.unwrap(), request("r1"));
}

/// A Cancel for an upstream that has gone still answers its id once, and
/// that upstream's other requests are answered and finished as when a
/// forward to it fails; the session goes on (#4001).
#[tokio::test]
async fn a_cancel_for_an_upstream_that_has_gone_answers_its_other_requests() {
    let front_doors = Arc::new(FrontDoorEpochs::default());
    let (_epoch, asked) = epoch(&front_doors, key());
    let (mut joined, mut upstream) = upstream();
    // The pin is what the first upstream serves: no streamed request body.
    joined.capabilities.retain(|capability| {
        capability == codewire_daemon_proto::CREDENTIAL_BRIDGE_CAPABILITY_FRONT_DOOR
    });
    serving(asked, joined);
    let mut live = Live::start(app_for(&front_doors)).await;
    live.attached().await;
    live.send_message(&ready()).await;
    live.send_message(&request("r1")).await;
    live.send_message(&request("r2")).await;
    assert_eq!(
        bounded(upstream.guests.recv()).await.unwrap(),
        request("r1")
    );
    assert_eq!(
        bounded(upstream.guests.recv()).await.unwrap(),
        request("r2")
    );
    // The upstream stops taking frames: its broker leg has gone.
    drop(upstream.guests);

    live.send_message(&request_body("r1")).await;
    let failure = |id: &str| {
        v1::CredentialBridgeHostMessage {
            payload: Some(
                v1::credential_bridge_host_message::Payload::ResponseFailure(
                    v1::CredentialBridgeResponseFailure {
                        request_id: id.into(),
                        reason: v1::CredentialBridgeFailureReason::Unavailable as i32,
                        refusal: v1::CredentialBridgeRefusal::Unspecified as i32,
                        ..Default::default()
                    },
                ),
            ),
        }
        .encode_to_vec()
    };
    assert_eq!(
        bounded(live.next()).await.unwrap(),
        framed_bridge(&failure("r1")),
        "the cancelled id is answered once"
    );
    assert_eq!(
        bounded(live.next()).await.unwrap(),
        framed_bridge(&failure("r2")),
        "the gone upstream's other request is answered"
    );
    // With no epoch left, a new request is answered, and the session stays.
    live.send_message(&request("r3")).await;
    let refused = bounded(live.next()).await.unwrap();
    assert!(refused.get("bridge").is_some(), "{refused}");
}
