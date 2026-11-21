use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use codewire_daemon_proto::{
    CREDENTIAL_BRIDGE_CAPABILITY_FRONT_DOOR, CREDENTIAL_BRIDGE_CAPABILITY_WEBSOCKET,
    CREDENTIAL_BRIDGE_PROTOCOL_VERSION,
};
use futures::stream;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, DuplexStream};
use uuid::Uuid;

use super::*;

/// The front door's end of the session: framed guest messages out, framed
/// host messages in.
struct FrontDoor(DuplexStream);

impl FrontDoor {
    async fn send(&mut self, message: v1::CredentialBridgeGuestMessage) {
        let bytes = message.encode_to_vec();
        self.0.write_u32(bytes.len() as u32).await.unwrap();
        self.0.write_all(&bytes).await.unwrap();
    }

    /// The next host message, failing rather than hanging when none comes.
    async fn receive(&mut self) -> v1::CredentialBridgeHostMessage {
        within("the front door receives a frame", async {
            let length = self.0.read_u32().await.unwrap() as usize;
            let mut bytes = vec![0; length];
            self.0.read_exact(&mut bytes).await.unwrap();
            v1::CredentialBridgeHostMessage::decode(bytes.as_slice()).unwrap()
        })
        .await
    }

    /// The Open, then this binding's Ready.
    async fn attach(&mut self) -> v1::CredentialBridgeOpen {
        let open = self.receive().await;
        let Some(v1::credential_bridge_host_message::Payload::Open(open)) = open.payload else {
            panic!("the session starts with its Open");
        };
        self.send(ready(7)).await;
        open
    }
}

fn identity() -> BridgeIdentity {
    BridgeIdentity {
        environment_id: Uuid::from_u128(0x5ee5),
        environment_generation: 7,
    }
}

fn ready(generation: u64) -> v1::CredentialBridgeGuestMessage {
    v1::CredentialBridgeGuestMessage {
        payload: Some(v1::credential_bridge_guest_message::Payload::Ready(
            v1::CredentialBridgeReady {
                protocol_version: CREDENTIAL_BRIDGE_PROTOCOL_VERSION,
                environment_id: identity().environment_id.to_string(),
                environment_generation: generation,
            },
        )),
    }
}

fn request(id: &str) -> v1::CredentialBridgeGuestMessage {
    v1::CredentialBridgeGuestMessage {
        payload: Some(v1::credential_bridge_guest_message::Payload::Request(
            v1::CredentialBridgeRequest {
                request_id: id.into(),
                method: "POST".into(),
                path: "/v1/responses".into(),
                ..Default::default()
            },
        )),
    }
}

fn host(payload: v1::credential_bridge_host_message::Payload) -> v1::CredentialBridgeHostMessage {
    v1::CredentialBridgeHostMessage {
        payload: Some(payload),
    }
}

fn response_end(id: &str) -> v1::CredentialBridgeHostMessage {
    host(v1::credential_bridge_host_message::Payload::ResponseEnd(
        v1::CredentialBridgeResponseEnd {
            request_id: id.into(),
        },
    ))
}

fn failure_for(message: &v1::CredentialBridgeHostMessage, id: &str) -> bool {
    matches!(
        &message.payload,
        Some(v1::credential_bridge_host_message::Payload::ResponseFailure(failure))
            if failure.request_id == id
    )
}

fn pinned() -> Vec<&'static str> {
    CREDENTIAL_BRIDGE_DELEGATED_FRONT_DOOR_CAPABILITIES.to_vec()
}

/// One joined platform stream: what the relay sends it, and what it sends.
struct Platform {
    guest: mpsc::Receiver<v1::CredentialBridgeGuestMessage>,
    host: mpsc::Sender<Result<v1::CredentialBridgeHostMessage, ()>>,
}

fn platform(capabilities: &[&str]) -> (DelegatedFrontDoorUpstream, Platform) {
    let (guest, guest_frames) = mpsc::channel(8);
    let (host_frames, host) = mpsc::channel(8);
    let host = stream::unfold(host, |mut frames| async move {
        frames.recv().await.map(|frame| (frame, frames))
    })
    .boxed();
    (
        DelegatedFrontDoorUpstream {
            capabilities: capabilities.iter().map(|&c| c.to_owned()).collect(),
            guest,
            host,
        },
        Platform {
            guest: guest_frames,
            host: host_frames,
        },
    )
}

/// Joins answered from a queue the test fills; a join with nothing queued
/// waits, as an authority that never answers.
struct Joiner {
    joins: mpsc::UnboundedReceiver<Option<DelegatedFrontDoorUpstream>>,
    calls: Arc<AtomicUsize>,
}

impl DelegatedFrontDoorJoiner for Joiner {
    fn join(&mut self) -> BoxFuture<'_, Option<DelegatedFrontDoorUpstream>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move { self.joins.recv().await.flatten() })
    }
}

/// A relay serving one session, its joiner handed over and `first` queued
/// as its first join.
struct Relay {
    serving: tokio::task::JoinHandle<DelegatedFrontDoorEnd>,
    front_door: FrontDoor,
    joins: mpsc::UnboundedSender<Option<DelegatedFrontDoorUpstream>>,
    calls: Arc<AtomicUsize>,
}

fn relay(first: Option<DelegatedFrontDoorUpstream>) -> Relay {
    let (stream, front_door) = tokio::io::duplex(64 * 1024);
    let (serving, joins, calls) = relay_on(stream, first);
    Relay {
        serving,
        front_door: FrontDoor(front_door),
        joins,
        calls,
    }
}

type JoinQueue = mpsc::UnboundedSender<Option<DelegatedFrontDoorUpstream>>;

/// A relay serving the session on `stream`, its joiner handed over and
/// `first` queued as its first join.
fn relay_on<S: SessionStream>(
    stream: S,
    first: Option<DelegatedFrontDoorUpstream>,
) -> (
    tokio::task::JoinHandle<DelegatedFrontDoorEnd>,
    JoinQueue,
    Arc<AtomicUsize>,
) {
    let (hand_over, joiner) = oneshot::channel();
    let (joins, queued) = mpsc::unbounded_channel();
    let calls = Arc::new(AtomicUsize::new(0));
    if let Some(first) = first {
        joins.send(Some(first)).unwrap();
    }
    hand_over
        .send(Joiner {
            joins: queued,
            calls: Arc::clone(&calls),
        })
        .ok()
        .unwrap();
    let serving = tokio::spawn(serve_delegated_front_door(
        stream,
        identity(),
        joiner,
        Instant::now(),
    ));
    (serving, joins, calls)
}

fn joined(capabilities: &[&str]) -> (Relay, Platform) {
    let (upstream, platform) = platform(capabilities);
    (relay(Some(upstream)), platform)
}

#[tokio::test]
async fn the_open_waits_for_the_first_join_lists_the_pin_and_a_request_round_trips() {
    let (stream, front_door) = tokio::io::duplex(64 * 1024);
    let (hand_over, joiner) = oneshot::channel();
    let serving = tokio::spawn(serve_delegated_front_door(
        stream,
        identity(),
        joiner,
        Instant::now(),
    ));
    let mut front_door = FrontDoor(front_door);
    // Nothing reaches the front door before the relay has joined.
    let mut byte = [0; 1];
    assert!(
        tokio::time::timeout(Duration::from_millis(200), front_door.0.read(&mut byte))
            .await
            .is_err(),
        "no Open before the first join"
    );
    let (joins, queued) = mpsc::unbounded_channel();
    let (upstream, mut platform) = platform(&pinned());
    joins.send(Some(upstream)).unwrap();
    hand_over
        .send(Joiner {
            joins: queued,
            calls: Arc::new(AtomicUsize::new(0)),
        })
        .ok()
        .unwrap();
    let open = front_door.attach().await;
    assert_eq!(open.capabilities, pinned());
    assert_eq!(open.environment_generation, 7);
    front_door.send(request("a")).await;
    // The Ready stays with the relay; only the request reaches the platform.
    assert_eq!(
        within("the platform receives a frame", platform.guest.recv())
            .await
            .unwrap(),
        request("a")
    );
    let start = host(v1::credential_bridge_host_message::Payload::ResponseStart(
        v1::CredentialBridgeResponseStart {
            request_id: "a".into(),
            status_code: 200,
            ..Default::default()
        },
    ));
    platform.host.send(Ok(start.clone())).await.unwrap();
    platform.host.send(Ok(response_end("a"))).await.unwrap();
    assert_eq!(front_door.receive().await, start);
    assert_eq!(front_door.receive().await, response_end("a"));
    drop(front_door);
    assert_eq!(
        serving.await.unwrap(),
        DelegatedFrontDoorEnd::FrontDoorClosed
    );
    drop(joins);
}

#[tokio::test(start_paused = true)]
async fn a_join_that_never_answers_still_opens_at_the_hold_and_requests_are_answered() {
    let opened_from = Instant::now();
    let mut relay = relay(None);
    let open = relay.front_door.attach().await;
    assert_eq!(open.capabilities, pinned());
    assert!(Instant::now() - opened_from >= OPEN_HOLD);
    assert!(Instant::now() - opened_from < Duration::from_secs(10));
    // With no upstream, the request is answered, closed, after its own
    // bounded join.
    relay.front_door.send(request("a")).await;
    assert!(failure_for(&relay.front_door.receive().await, "a"));
}

#[tokio::test(start_paused = true)]
async fn a_join_admitting_less_than_the_pin_is_never_used() {
    let (mut relay, mut platform) = joined(&[CREDENTIAL_BRIDGE_CAPABILITY_FRONT_DOOR]);
    let open = relay.front_door.attach().await;
    assert_eq!(open.capabilities, pinned());
    relay.front_door.send(request("a")).await;
    assert!(failure_for(&relay.front_door.receive().await, "a"));
    assert!(platform.guest.try_recv().is_err());
}

#[tokio::test(start_paused = true)]
async fn after_the_platforms_idle_end_the_next_request_waits_for_a_rejoin_and_is_served() {
    let (mut relay, platform) = joined(&pinned());
    let _open = relay.front_door.attach().await;
    // The platform ends the stream after its idle spell.
    tokio::time::sleep(Duration::from_secs(120)).await;
    drop(platform);
    tokio::time::sleep(Duration::from_millis(50)).await;
    let (upstream, mut second) = self::platform(&pinned());
    relay.joins.send(Some(upstream)).unwrap();
    relay.front_door.send(request("a")).await;
    assert_eq!(
        within("the platform receives a frame", second.guest.recv())
            .await
            .unwrap(),
        request("a")
    );
    second.host.send(Ok(response_end("a"))).await.unwrap();
    assert_eq!(relay.front_door.receive().await, response_end("a"));
    assert_eq!(relay.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test(start_paused = true)]
async fn a_late_frame_for_an_ended_upstreams_request_cannot_land_on_the_next() {
    let (mut relay, mut first) = joined(&pinned());
    let _open = relay.front_door.attach().await;
    // The first stream serves for a while before it ends.
    tokio::time::sleep(Duration::from_secs(120)).await;
    relay.front_door.send(request("a")).await;
    assert_eq!(
        within("the platform receives a frame", first.guest.recv())
            .await
            .unwrap(),
        request("a")
    );
    // The first stream ends with "a" open: the relay answers it.
    drop(first);
    assert!(failure_for(&relay.front_door.receive().await, "a"));
    let (upstream, mut second) = self::platform(&pinned());
    relay.joins.send(Some(upstream)).unwrap();
    relay.front_door.send(request("b")).await;
    assert_eq!(
        within("the platform receives a frame", second.guest.recv())
            .await
            .unwrap(),
        request("b")
    );
    // A frame for "a" from the new stream is foreign to it: that stream
    // ends, "b" is answered, and nothing reaches the front door for "a".
    second.host.send(Ok(response_end("a"))).await.unwrap();
    assert!(failure_for(&relay.front_door.receive().await, "b"));
}

#[tokio::test]
async fn a_first_frame_that_is_not_this_bindings_ready_is_refused() {
    let (mut relay, mut platform) = joined(&pinned());
    let _open = relay.front_door.receive().await;
    relay.front_door.send(ready(8)).await;
    let ended = tokio::time::timeout(Duration::from_secs(10), relay.serving)
        .await
        .expect("a wrong Ready ends the session at once");
    assert_eq!(ended.unwrap(), DelegatedFrontDoorEnd::FrontDoorRefused);
    assert!(platform.guest.try_recv().is_err());
}

#[tokio::test]
async fn a_request_outside_the_pin_is_answered_by_the_relay() {
    let (mut relay, mut platform) = joined(&pinned());
    let open = relay.front_door.attach().await;
    assert!(
        !open
            .capabilities
            .iter()
            .any(|capability| capability == CREDENTIAL_BRIDGE_CAPABILITY_WEBSOCKET)
    );
    relay
        .front_door
        .send(v1::CredentialBridgeGuestMessage {
            payload: Some(v1::credential_bridge_guest_message::Payload::Upgrade(
                v1::CredentialBridgeUpgrade {
                    request_id: "socket".into(),
                    ..Default::default()
                },
            )),
        })
        .await;
    let answer = relay.front_door.receive().await;
    assert!(answer.payload.is_some(), "{answer:?}");
    assert!(platform.guest.try_recv().is_err());
}

#[tokio::test]
async fn a_frame_for_an_id_never_opened_is_answered_by_the_relay() {
    let (mut relay, mut platform) = joined(&pinned());
    let _open = relay.front_door.attach().await;
    relay
        .front_door
        .send(v1::CredentialBridgeGuestMessage {
            payload: Some(v1::credential_bridge_guest_message::Payload::RequestEnd(
                v1::CredentialBridgeRequestEnd {
                    request_id: "never".into(),
                },
            )),
        })
        .await;
    assert!(failure_for(&relay.front_door.receive().await, "never"));
    assert!(platform.guest.try_recv().is_err());
}

#[tokio::test(start_paused = true)]
async fn a_front_door_that_sends_no_ready_in_time_ends_the_session() {
    let (mut relay, _platform) = joined(&pinned());
    let _open = relay.front_door.receive().await;
    assert_eq!(
        relay.serving.await.unwrap(),
        DelegatedFrontDoorEnd::ReadyTimedOut
    );
}

/// `future`, or a failure naming `step`: a broken path fails rather than
/// hangs. The bound outlasts every wait the relay makes on purpose (the
/// Open's hold, a join), so it also holds under a paused clock.
async fn within<F: std::future::Future>(step: &str, future: F) -> F::Output {
    tokio::time::timeout(Duration::from_secs(60), future)
        .await
        .unwrap_or_else(|_| panic!("timed out: {step}"))
}

/// Serve each request the platform end receives with a 200, as the
/// platform broker would, telling `served` each id it answered.
fn answer_requests(mut platform: Platform, served: mpsc::UnboundedSender<String>) {
    tokio::spawn(async move {
        // The platform's answering loop waits for as long as the test runs.
        while let Some(frame) = platform.guest.recv().await {
            let Some(v1::credential_bridge_guest_message::Payload::Request(request)) =
                frame.payload
            else {
                continue;
            };
            let id = request.request_id;
            if !answer(&platform.host, &id).await {
                break;
            }
            let _ = served.send(id);
        }
    });
}

/// A 200 for request `id`.
async fn answer(
    host: &mpsc::Sender<Result<v1::CredentialBridgeHostMessage, ()>>,
    id: &str,
) -> bool {
    let start = self::host(v1::credential_bridge_host_message::Payload::ResponseStart(
        v1::CredentialBridgeResponseStart {
            request_id: id.into(),
            status_code: 200,
            ..Default::default()
        },
    ));
    host.send(Ok(start)).await.is_ok() && host.send(Ok(response_end(id))).await.is_ok()
}

fn intercepted() -> http::Request<axum::body::Body> {
    http::Request::post(format!(
        "{}/v1/messages",
        codewire_access::MANAGED_ANTHROPIC_API_PREFIX
    ))
    .header("content-type", "application/json")
    .body(axum::body::Body::from("{}"))
    .unwrap()
}

/// At a rotation the successor relay attaches while its predecessor is
/// still joined: a request in flight on the predecessor finishes there, new
/// requests move to the successor once it attaches, and no request fails
/// (#4884's drain, through two delegated relays).
#[tokio::test]
async fn a_successor_attaches_while_its_predecessor_is_joined_and_no_request_fails() {
    use codewire_credential_bridge::{CredentialBridge, serve_front_door_session};
    let front_door =
        CredentialBridge::new(identity().environment_id, identity().environment_generation)
            .unwrap();
    let request = |front_door: &CredentialBridge| {
        let front_door = front_door.clone();
        tokio::spawn(async move {
            front_door
                .respond_intercepted("api.anthropic.com", intercepted())
                .await
                .status()
        })
    };
    // The predecessor attaches; a request then stays in flight on it. Until
    // it has attached, the front door answers unavailable, so try again.
    let (door, relay) = tokio::io::duplex(64 * 1024);
    let serving = front_door.clone();
    tokio::spawn(async move { serve_front_door_session(&serving, door).await });
    let (upstream, mut first) = platform(&pinned());
    let (_first_relay, _first_joins, _) = relay_on(relay, Some(upstream));
    let (in_flight, held) = within("the predecessor attaches", async {
        loop {
            let mut pending = request(&front_door);
            tokio::select! {
                held = first.guest.recv() => break (pending, held.unwrap()),
                status = &mut pending => {
                    assert_eq!(status.unwrap(), http::StatusCode::SERVICE_UNAVAILABLE);
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            }
        }
    })
    .await;
    let Some(v1::credential_bridge_guest_message::Payload::Request(held)) = held.payload else {
        panic!("the predecessor holds the in-flight request");
    };
    // The predecessor answers anything new it still receives; the held
    // request is answered last.
    let first_host = first.host.clone();
    let (served_first, _) = mpsc::unbounded_channel();
    answer_requests(first, served_first);
    // The successor pairs, joins, and attaches; new requests move to it.
    let (door, relay) = tokio::io::duplex(64 * 1024);
    let serving = front_door.clone();
    tokio::spawn(async move { serve_front_door_session(&serving, door).await });
    let (upstream, second) = platform(&pinned());
    let (_second_relay, _second_joins, _) = relay_on(relay, Some(upstream));
    let (served_second, mut on_second) = mpsc::unbounded_channel();
    answer_requests(second, served_second);
    within("a new request reaches the successor", async {
        loop {
            let status = request(&front_door).await.unwrap();
            assert_eq!(
                status,
                http::StatusCode::OK,
                "no request fails at the rotation"
            );
            if on_second.try_recv().is_ok() {
                break;
            }
        }
    })
    .await;
    // The request in flight on the predecessor finishes there.
    assert!(answer(&first_host, &held.request_id).await);
    let finished = within(
        "the in-flight request finishes on the predecessor",
        in_flight,
    )
    .await;
    assert_eq!(finished.unwrap(), http::StatusCode::OK);
}

/// A delegation admitted after the Open's hold still serves the session: the
/// relay takes its joiner when it arrives, and the next request joins.
#[tokio::test(start_paused = true)]
async fn an_admission_after_the_hold_still_serves_the_next_request() {
    let (stream, front_door) = tokio::io::duplex(64 * 1024);
    let (hand_over, joiner) = oneshot::channel();
    let _serving = tokio::spawn(serve_delegated_front_door(
        stream,
        identity(),
        joiner,
        Instant::now(),
    ));
    let mut front_door = FrontDoor(front_door);
    let open = front_door.attach().await;
    assert_eq!(open.capabilities, pinned());
    // The admission lands after the hold, inside its own bound.
    tokio::time::sleep(Duration::from_secs(4)).await;
    let (joins, queued) = mpsc::unbounded_channel();
    let (upstream, mut platform) = platform(&pinned());
    joins.send(Some(upstream)).unwrap();
    hand_over
        .send(Joiner {
            joins: queued,
            calls: Arc::new(AtomicUsize::new(0)),
        })
        .ok()
        .unwrap();
    front_door.send(request("a")).await;
    assert_eq!(
        within("the platform receives a frame", platform.guest.recv())
            .await
            .unwrap(),
        request("a")
    );
}

/// Failed joins are spaced by the backoff, 1 second doubling: requests in
/// between are answered without a join.
#[tokio::test(start_paused = true)]
async fn failed_joins_are_spaced_by_the_backoff() {
    let mut relay = relay(None);
    for _ in 0..8 {
        relay.joins.send(None).unwrap();
    }
    let _open = relay.front_door.attach().await;
    // The join before the Open failed; the backoff is now 1 second.
    assert_eq!(relay.calls.load(Ordering::SeqCst), 1);
    for id in ["a", "b", "c"] {
        relay.front_door.send(request(id)).await;
        assert!(failure_for(&relay.front_door.receive().await, id));
    }
    assert_eq!(
        relay.calls.load(Ordering::SeqCst),
        1,
        "no join inside the backoff"
    );
    tokio::time::sleep(Duration::from_secs(1)).await;
    for id in ["d", "e"] {
        relay.front_door.send(request(id)).await;
        assert!(failure_for(&relay.front_door.receive().await, id));
    }
    // One join after a second, then the backoff is 2 seconds.
    assert_eq!(relay.calls.load(Ordering::SeqCst), 2);
    tokio::time::sleep(Duration::from_secs(1)).await;
    relay.front_door.send(request("f")).await;
    assert!(failure_for(&relay.front_door.receive().await, "f"));
    assert_eq!(relay.calls.load(Ordering::SeqCst), 2);
    tokio::time::sleep(Duration::from_secs(1)).await;
    relay.front_door.send(request("g")).await;
    assert!(failure_for(&relay.front_door.receive().await, "g"));
    assert_eq!(relay.calls.load(Ordering::SeqCst), 3);
}

/// An accepted join whose stream ends at once counts as failed, so a guest's
/// frames can't drive accepted joins faster than the backoff either.
#[tokio::test(start_paused = true)]
async fn an_accepted_join_that_ends_at_once_is_spaced_like_a_failed_one() {
    let (mut relay, first) = joined(&pinned());
    let _open = relay.front_door.attach().await;
    assert_eq!(relay.calls.load(Ordering::SeqCst), 1);
    // The stream ends at once, and every later join's stream does too.
    drop(first);
    tokio::time::sleep(Duration::from_millis(10)).await;
    let mut ended = Vec::new();
    for _ in 0..4 {
        let (upstream, platform) = platform(&pinned());
        relay.joins.send(Some(upstream)).unwrap();
        ended.push(platform);
    }
    drop(ended);
    for id in ["a", "b", "c"] {
        relay.front_door.send(request(id)).await;
        assert!(failure_for(&relay.front_door.receive().await, id));
    }
    assert_eq!(
        relay.calls.load(Ordering::SeqCst),
        1,
        "no join inside the backoff"
    );
    tokio::time::sleep(Duration::from_secs(1)).await;
    relay.front_door.send(request("d")).await;
    assert!(failure_for(&relay.front_door.receive().await, "d"));
    tokio::time::sleep(Duration::from_millis(10)).await;
    for id in ["e", "f"] {
        relay.front_door.send(request(id)).await;
        assert!(failure_for(&relay.front_door.receive().await, id));
    }
    // One more join after a second; its early end doubles the backoff.
    assert_eq!(relay.calls.load(Ordering::SeqCst), 2);
}
