use codewire_daemon_proto::{
    CREDENTIAL_BRIDGE_CAPABILITY_FRONT_DOOR, CREDENTIAL_BRIDGE_CAPABILITY_REQUEST_BODY_STREAM,
    CREDENTIAL_BRIDGE_CAPABILITY_WEBSOCKET,
};
use prost::Message as _;
use v1::credential_bridge_guest_message::Payload as Guest;
use v1::credential_bridge_host_message::Payload as Host;

use super::*;

const OLD: u8 = 1;
const NEW: u8 = 2;

fn pinned() -> Vec<String> {
    [
        CREDENTIAL_BRIDGE_CAPABILITY_FRONT_DOOR,
        CREDENTIAL_BRIDGE_CAPABILITY_REQUEST_BODY_STREAM,
    ]
    .map(str::to_owned)
    .to_vec()
}

fn guest(payload: Guest) -> Vec<u8> {
    v1::CredentialBridgeGuestMessage {
        payload: Some(payload),
    }
    .encode_to_vec()
}

fn host(payload: Host) -> Vec<u8> {
    v1::CredentialBridgeHostMessage {
        payload: Some(payload),
    }
    .encode_to_vec()
}

fn ready() -> Vec<u8> {
    guest(Guest::Ready(v1::CredentialBridgeReady::default()))
}

fn request(id: &str) -> Vec<u8> {
    guest(Guest::Request(v1::CredentialBridgeRequest {
        request_id: id.into(),
        ..Default::default()
    }))
}

fn body(id: &str) -> Vec<u8> {
    guest(Guest::RequestBody(v1::CredentialBridgeRequestBody {
        request_id: id.into(),
        ..Default::default()
    }))
}

fn cancel(id: &str) -> Vec<u8> {
    guest(Guest::Cancel(v1::CredentialBridgeCancel {
        request_id: id.into(),
    }))
}

fn response_end(id: &str) -> Vec<u8> {
    host(Host::ResponseEnd(v1::CredentialBridgeResponseEnd {
        request_id: id.into(),
    }))
}

fn response_start(id: &str) -> Vec<u8> {
    host(Host::ResponseStart(v1::CredentialBridgeResponseStart {
        request_id: id.into(),
        ..Default::default()
    }))
}

fn failure(id: &str) -> v1::CredentialBridgeHostMessage {
    answer(id.into(), Kind::Http)
}

/// A router past its Ready, opening new requests on `OLD`.
fn router() -> FrontDoorRouter<u8> {
    let mut router = FrontDoorRouter::new(pinned());
    assert_eq!(router.guest(&ready(), Instant::now()), GuestRoute::Ready);
    router.set_current(Some(OLD));
    router
}

#[test]
fn a_session_starts_with_one_ready_and_a_second_ends_it() {
    let now = Instant::now();
    let mut fresh = FrontDoorRouter::<u8>::new(pinned());
    assert_eq!(
        fresh.guest(&request("a"), now),
        GuestRoute::End,
        "Ready comes first"
    );
    let mut router = router();
    assert_eq!(router.guest(&ready(), now), GuestRoute::End);
}

#[test]
fn a_malformed_envelope_ends_the_session() {
    let now = Instant::now();
    let whole = request("a");
    let two_payloads = [request("a"), request("b")].concat();
    for (case, message) in [
        ("empty", Vec::new()),
        ("cut short", whole[..whole.len() - 1].to_vec()),
        ("two payloads", two_payloads),
        ("a varint payload", vec![0x10, 0x01]),
        ("a request with no id", request("")),
    ] {
        assert_eq!(router().guest(&message, now), GuestRoute::End, "{case}");
    }
}

#[test]
fn a_request_stays_on_the_upstream_it_opened_on_after_a_renewal() {
    let now = Instant::now();
    let mut router = router();
    assert_eq!(router.guest(&request("old"), now), GuestRoute::Forward(OLD));
    // The successor is admitted: new requests go to it at once.
    router.set_current(Some(NEW));
    assert_eq!(router.guest(&request("new"), now), GuestRoute::Forward(NEW));
    // The old request's later frames still follow it.
    assert_eq!(router.guest(&body("old"), now), GuestRoute::Forward(OLD));
    assert_eq!(
        router.host(OLD, &response_end("old"), now),
        HostRoute::Forward
    );
    assert!(!router.holds(OLD), "the old upstream has drained");
    assert!(router.holds(NEW));
}

#[test]
fn a_live_or_recently_finished_id_cannot_be_opened_again() {
    let now = Instant::now();
    let mut router = router();
    router.guest(&request("a"), now);
    assert_eq!(
        router.guest(&request("a"), now),
        GuestRoute::Drop(Refusal::ReusedId)
    );
    router.host(OLD, &response_end("a"), now);
    assert_eq!(
        router.guest(&request("a"), now),
        GuestRoute::Drop(Refusal::ReusedId)
    );
    // After the window it is a new id.
    let later = now + FINISHED_ID_WINDOW;
    assert_eq!(router.guest(&request("a"), later), GuestRoute::Forward(OLD));
}

#[test]
fn a_frame_racing_a_finished_requests_answer_is_dropped_unanswered() {
    let now = Instant::now();
    let mut router = router();
    router.guest(&request("a"), now);
    router.host(OLD, &response_end("a"), now);
    for frame in [body("a"), cancel("a")] {
        assert_eq!(
            router.guest(&frame, now + Duration::from_secs(59)),
            GuestRoute::Drop(Refusal::FinishedId)
        );
    }
    // Forgotten after the window: answered as never opened.
    assert_eq!(
        router.guest(&cancel("a"), now + FINISHED_ID_WINDOW),
        GuestRoute::Answer(failure("a"), Refusal::UnknownId)
    );
}

#[test]
fn the_finished_id_memory_is_capped_and_forgets_the_oldest_first() {
    let now = Instant::now();
    let mut router = router();
    for n in 0..=FINISHED_ID_CAP {
        let id = format!("r{n}");
        router.guest(&request(&id), now);
        router.host(OLD, &response_end(&id), now);
    }
    assert_eq!(
        router.guest(&cancel("r0"), now),
        GuestRoute::Answer(failure("r0"), Refusal::UnknownId),
        "the oldest is forgotten, and fails safe"
    );
    assert_eq!(
        router.guest(&cancel("r1"), now),
        GuestRoute::Drop(Refusal::FinishedId)
    );
}

#[test]
fn an_unknown_id_is_answered_by_its_own_kind() {
    let now = Instant::now();
    let mut pinned = pinned();
    pinned.push(CREDENTIAL_BRIDGE_CAPABILITY_WEBSOCKET.into());
    let mut router = FrontDoorRouter::new(pinned);
    router.guest(&ready(), now);
    router.set_current(Some(OLD));
    assert_eq!(
        router.guest(&cancel("x"), now),
        GuestRoute::Answer(failure("x"), Refusal::UnknownId)
    );
    let data = guest(Guest::StreamData(v1::CredentialBridgeStreamData {
        request_id: "s".into(),
        data: b"frame".to_vec(),
    }));
    assert_eq!(
        router.guest(&data, now),
        GuestRoute::Answer(answer("s".into(), Kind::Socket), Refusal::UnknownId)
    );
}

#[test]
fn without_an_upstream_a_new_request_is_answered() {
    let now = Instant::now();
    let mut router = router();
    router.set_current(None);
    assert_eq!(
        router.guest(&request("a"), now),
        GuestRoute::Answer(failure("a"), Refusal::NoUpstream)
    );
}

#[test]
fn a_frame_outside_the_pinned_capabilities_is_answered() {
    let now = Instant::now();
    let mut router = FrontDoorRouter::new(vec![CREDENTIAL_BRIDGE_CAPABILITY_FRONT_DOOR.into()]);
    router.guest(&ready(), now);
    router.set_current(Some(OLD));
    router.guest(&request("a"), now);
    assert_eq!(
        router.guest(&body("a"), now),
        GuestRoute::Answer(failure("a"), Refusal::OutsidePin)
    );
    let upgrade = guest(Guest::Upgrade(v1::CredentialBridgeUpgrade {
        request_id: "s".into(),
        ..Default::default()
    }));
    assert_eq!(
        router.guest(&upgrade, now),
        GuestRoute::Answer(answer("s".into(), Kind::Socket), Refusal::OutsidePin)
    );
}

#[test]
fn a_successor_that_serves_less_than_the_pin_is_not_accepted() {
    let router = router();
    assert!(router.accepts(&pinned()));
    let mut more = pinned();
    more.push(CREDENTIAL_BRIDGE_CAPABILITY_WEBSOCKET.into());
    assert!(router.accepts(&more));
    assert!(!router.accepts(&[CREDENTIAL_BRIDGE_CAPABILITY_FRONT_DOOR.into()]));
}

#[test]
fn a_frame_type_the_front_door_never_sends_is_answered() {
    let now = Instant::now();
    // Each kind the front-door entry never serves, by its own id (#4909,
    // cw-security): no SSH, projection or login flow crosses this carrier.
    for (id, payload) in [
        (
            "ssh",
            Guest::Ssh(v1::CredentialSshRequest {
                request_id: "ssh".into(),
                ..Default::default()
            }),
        ),
        (
            "projection",
            Guest::EnvironmentProjection(v1::EnvironmentProjectionRequest {
                request_id: "projection".into(),
                ..Default::default()
            }),
        ),
        (
            "codex",
            Guest::CodexLogin(v1::CodexLoginRequest {
                request_id: "codex".into(),
                ..Default::default()
            }),
        ),
        (
            "claude",
            Guest::ClaudeLogin(v1::ClaudeLoginRequest {
                request_id: "claude".into(),
                ..Default::default()
            }),
        ),
    ] {
        assert_eq!(
            router().guest(&guest(payload), now),
            GuestRoute::Answer(failure(id), Refusal::NotServed),
            "{id}"
        );
    }
}

#[test]
fn a_host_frame_for_an_id_its_upstream_does_not_own_ends_that_upstream() {
    let now = Instant::now();
    let mut router = router();
    router.guest(&request("old"), now);
    router.set_current(Some(NEW));
    router.guest(&request("new"), now);
    // NEW answers OLD's request: NEW is ended and its own request answered.
    assert_eq!(
        router.host(NEW, &response_start("old"), now),
        HostRoute::EndUpstream(vec![failure("new")], Refusal::ForeignHostFrame)
    );
    assert!(!router.holds(NEW));
    assert!(router.holds(OLD), "the other upstream keeps its request");
    // A frame for an id nobody holds ends its sender too.
    assert_eq!(
        router.host(OLD, &response_start("never"), now),
        HostRoute::EndUpstream(vec![failure("old")], Refusal::ForeignHostFrame)
    );
}

#[test]
fn an_ended_upstream_answers_its_requests_once() {
    let now = Instant::now();
    let mut router = router();
    router.guest(&request("a"), now);
    router.guest(&request("b"), now);
    let mut answered = router.upstream_ended(OLD, now);
    answered.sort_by_key(|message| format!("{message:?}"));
    assert_eq!(answered, vec![failure("a"), failure("b")]);
    // It no longer takes new requests, and late frames race the answers.
    assert_eq!(
        router.guest(&request("c"), now),
        GuestRoute::Answer(failure("c"), Refusal::NoUpstream)
    );
    assert_eq!(
        router.guest(&body("a"), now),
        GuestRoute::Drop(Refusal::FinishedId)
    );
}

#[test]
fn a_session_holds_at_most_its_cap_of_open_requests() {
    let now = Instant::now();
    let mut router = router();
    for n in 0..LIVE_ID_CAP {
        assert_eq!(
            router.guest(&request(&format!("r{n}")), now),
            GuestRoute::Forward(OLD)
        );
    }
    assert_eq!(
        router.guest(&request("over"), now),
        GuestRoute::Answer(failure("over"), Refusal::TooManyRequests)
    );
    router.host(OLD, &response_end("r0"), now);
    assert_eq!(
        router.guest(&request("next"), now),
        GuestRoute::Forward(OLD)
    );
}

#[test]
fn an_overlong_request_id_is_a_malformed_envelope() {
    let now = Instant::now();
    let longest = "a".repeat(MAX_ID_BYTES);
    assert_eq!(
        router().guest(&request(&longest), now),
        GuestRoute::Forward(OLD)
    );
    let over = "a".repeat(MAX_ID_BYTES + 1);
    assert_eq!(router().guest(&request(&over), now), GuestRoute::End);
}

#[test]
fn a_refused_upgrade_is_answered_on_its_socket_without_ending_the_upstream() {
    let now = Instant::now();
    let mut pinned = pinned();
    pinned.push(CREDENTIAL_BRIDGE_CAPABILITY_WEBSOCKET.into());
    let mut router = FrontDoorRouter::new(pinned);
    router.guest(&ready(), now);
    router.set_current(Some(OLD));
    let upgrade = |id: &str| {
        guest(Guest::Upgrade(v1::CredentialBridgeUpgrade {
            request_id: id.into(),
            ..Default::default()
        }))
    };
    router.guest(&upgrade("refused"), now);
    router.guest(&upgrade("accepted"), now);
    // The broker refuses one upgrade with an ordinary response.
    assert_eq!(
        router.host(OLD, &response_start("refused"), now),
        HostRoute::Forward
    );
    assert_eq!(
        router.host(OLD, &response_end("refused"), now),
        HostRoute::Forward
    );
    assert!(router.holds(OLD), "the other socket is untouched");
    // Once an upgrade is accepted, an ordinary response for it is foreign.
    let accepted = host(Host::UpgradeAccepted(v1::CredentialBridgeUpgradeAccepted {
        request_id: "accepted".into(),
        ..Default::default()
    }));
    assert_eq!(router.host(OLD, &accepted, now), HostRoute::Forward);
    assert!(matches!(
        router.host(OLD, &response_start("accepted"), now),
        HostRoute::EndUpstream(_, Refusal::ForeignHostFrame)
    ));
}

#[test]
fn a_socket_refused_with_an_ordinary_response_takes_no_socket_frame() {
    let now = Instant::now();
    let mut pinned = pinned();
    pinned.push(CREDENTIAL_BRIDGE_CAPABILITY_WEBSOCKET.into());
    let mut router = FrontDoorRouter::new(pinned);
    router.guest(&ready(), now);
    router.set_current(Some(OLD));
    router.guest(
        &guest(Guest::Upgrade(v1::CredentialBridgeUpgrade {
            request_id: "s".into(),
            ..Default::default()
        })),
        now,
    );
    assert_eq!(
        router.host(OLD, &response_start("s"), now),
        HostRoute::Forward
    );
    let accepted = host(Host::UpgradeAccepted(v1::CredentialBridgeUpgradeAccepted {
        request_id: "s".into(),
        ..Default::default()
    }));
    assert!(matches!(
        router.host(OLD, &accepted, now),
        HostRoute::EndUpstream(_, Refusal::ForeignHostFrame)
    ));
}

/// A frame of the other kind for a live id is dropped, never answered: its
/// own request would read the answer, and it stays served (#4909).
#[test]
fn a_frame_of_the_other_kind_for_a_live_id_is_dropped_and_the_id_stays_served() {
    let now = Instant::now();
    let mut router = router();
    router.set_current(Some(1));
    assert_eq!(router.guest(&request("a"), now), GuestRoute::Forward(1));
    let data = guest(Guest::StreamData(v1::CredentialBridgeStreamData {
        request_id: "a".into(),
        data: b"x".to_vec(),
    }));
    assert_eq!(
        router.guest(&data, now),
        GuestRoute::Drop(Refusal::UnknownId)
    );
    assert_eq!(router.guest(&body("a"), now), GuestRoute::Forward(1));
    assert_eq!(router.host(1, &response_end("a"), now), HostRoute::Forward);
}
