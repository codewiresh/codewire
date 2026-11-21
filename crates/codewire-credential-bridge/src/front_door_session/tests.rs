use std::future::Future;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use uuid::Uuid;
use v1::credential_bridge_guest_message::Payload as GuestPayload;
use v1::credential_bridge_host_message::Payload as HostPayload;

use super::*;
use crate::MANAGED_OPENAI_API_PREFIX;

const TIMEOUT: Duration = Duration::from_secs(2);
const HOST: &str = "api.openai.com";

async fn bounded<F: Future>(future: F) -> F::Output {
    tokio::time::timeout(TIMEOUT, future)
        .await
        .expect("bounded front-door session operation")
}

fn bridge() -> CredentialBridge {
    CredentialBridge::new(Uuid::new_v4(), 3).unwrap()
}

fn request() -> Request<Body> {
    Request::post(format!("{MANAGED_OPENAI_API_PREFIX}/responses"))
        .header("content-type", "application/json")
        .body(Body::from("{}"))
        .unwrap()
}

fn host_message(payload: HostPayload) -> v1::CredentialBridgeHostMessage {
    v1::CredentialBridgeHostMessage {
        payload: Some(payload),
    }
}

fn open(identity: BridgeIdentity, capabilities: &[&str]) -> v1::CredentialBridgeHostMessage {
    host_message(HostPayload::Open(v1::CredentialBridgeOpen {
        protocol_version: CREDENTIAL_BRIDGE_PROTOCOL_VERSION,
        environment_id: identity.environment_id.to_string(),
        environment_generation: identity.environment_generation,
        capabilities: capabilities.iter().map(|&name| name.to_owned()).collect(),
        placeholders: Vec::new(),
    }))
}

/// A guest serving `bridge` on one end of a fresh stream; the other end.
fn serve(
    bridge: &CredentialBridge,
) -> (
    tokio::task::JoinHandle<Result<(), FrontDoorSessionError>>,
    tokio::io::DuplexStream,
) {
    let (guest, host) = tokio::io::duplex(64 * 1024);
    let bridge = bridge.clone();
    let task = tokio::spawn(async move { serve_front_door_session(&bridge, guest).await });
    (task, host)
}

#[tokio::test]
async fn a_request_crosses_the_session_naming_its_intercepted_host_and_its_answer_returns() {
    let bridge = bridge();
    let (guest, stream) = serve(&bridge);
    let mut host = bounded(FrontDoorHostSession::open(
        stream,
        bridge.identity(),
        &front_door_capabilities(true),
    ))
    .await
    .unwrap();
    let Some(GuestPayload::Ready(ready)) = bounded(host.receive()).await.unwrap().unwrap().payload
    else {
        panic!("the guest answers Open with Ready");
    };
    assert_eq!(
        ready.environment_id,
        bridge.identity().environment_id.to_string()
    );

    let asking = bridge.clone();
    let response = tokio::spawn(async move { asking.respond_intercepted(HOST, request()).await });
    let Some(GuestPayload::Request(sent)) = bounded(host.receive()).await.unwrap().unwrap().payload
    else {
        panic!("the request crosses the session");
    };
    assert_eq!(sent.intercepted_host, HOST);
    let sender = host.sender();
    for payload in [
        HostPayload::ResponseStart(v1::CredentialBridgeResponseStart {
            request_id: sent.request_id.clone(),
            status_code: 200,
            headers: Vec::new(),
        }),
        HostPayload::ResponseBody(v1::CredentialBridgeResponseBody {
            request_id: sent.request_id.clone(),
            data: b"answer".to_vec(),
        }),
        HostPayload::ResponseEnd(v1::CredentialBridgeResponseEnd {
            request_id: sent.request_id.clone(),
        }),
    ] {
        sender.send(host_message(payload)).await.unwrap();
    }
    let response = bounded(response).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        to_bytes(response.into_body(), 64).await.unwrap(),
        &b"answer"[..]
    );

    drop(host);
    assert_eq!(bounded(guest).await.unwrap(), Ok(()));
}

#[tokio::test]
async fn a_loopback_request_names_no_host() {
    let bridge = bridge();
    let (_guest, stream) = serve(&bridge);
    let mut host = bounded(FrontDoorHostSession::open(
        stream,
        bridge.identity(),
        &front_door_capabilities(true),
    ))
    .await
    .unwrap();
    bounded(host.receive()).await.unwrap().unwrap();
    let asking = bridge.clone();
    drop(tokio::spawn(async move { asking.respond(request()).await }));
    let Some(GuestPayload::Request(sent)) = bounded(host.receive()).await.unwrap().unwrap().payload
    else {
        panic!("the request crosses the session");
    };
    assert_eq!(sent.intercepted_host, "");
}

#[tokio::test]
async fn an_open_for_another_identity_or_without_the_front_door_capability_is_refused() {
    let bridge = bridge();
    let identity = bridge.identity();
    let other_generation = BridgeIdentity {
        environment_generation: identity.environment_generation + 1,
        ..identity
    };
    let other_environment = BridgeIdentity {
        environment_id: Uuid::new_v4(),
        ..identity
    };
    for first in [
        open(other_generation, &[CREDENTIAL_BRIDGE_CAPABILITY_FRONT_DOOR]),
        open(
            other_environment,
            &[CREDENTIAL_BRIDGE_CAPABILITY_FRONT_DOOR],
        ),
        open(identity, &[]),
        open(identity, &["codex-login"]),
        host_message(HostPayload::ResponseEnd(v1::CredentialBridgeResponseEnd {
            request_id: "x".to_owned(),
        })),
    ] {
        let (guest, mut stream) = serve(&bridge);
        write_frame(&mut stream, &first).await.unwrap();
        assert_eq!(
            bounded(guest).await.unwrap(),
            Err(FrontDoorSessionError::InvalidOpen)
        );
    }
}

#[tokio::test(start_paused = true)]
async fn a_host_that_never_opens_is_refused_after_the_open_timeout() {
    let (guest, _stream) = serve(&bridge());
    assert_eq!(
        guest.await.unwrap(),
        Err(FrontDoorSessionError::InvalidOpen)
    );
}

#[tokio::test]
async fn a_length_over_the_bound_is_refused_before_its_bytes_arrive() {
    let (guest, mut stream) = serve(&bridge());
    let too_long = u32::try_from(CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES + 1).unwrap();
    stream.write_all(&too_long.to_be_bytes()).await.unwrap();
    assert_eq!(
        bounded(guest).await.unwrap(),
        Err(FrontDoorSessionError::InvalidFrame)
    );
}

#[tokio::test]
async fn a_frame_cut_short_by_the_peer_closing_is_invalid() {
    let (mut writer, reader) = tokio::io::duplex(1024);
    let mut frames = FrameReader::new(reader);
    let mut encoded = Vec::new();
    write_frame(&mut encoded, &open(bridge().identity(), &[]))
        .await
        .unwrap();
    writer
        .write_all(&encoded[..encoded.len() - 1])
        .await
        .unwrap();
    drop(writer);
    assert_eq!(
        frames.next::<v1::CredentialBridgeHostMessage>().await,
        Err(FrontDoorSessionError::InvalidFrame)
    );
}

#[tokio::test]
async fn a_receive_cancelled_mid_frame_keeps_what_it_read() {
    let (mut writer, reader) = tokio::io::duplex(1024);
    let mut frames = FrameReader::new(reader);
    let sent = open(
        bridge().identity(),
        &[CREDENTIAL_BRIDGE_CAPABILITY_FRONT_DOOR],
    );
    let mut encoded = Vec::new();
    write_frame(&mut encoded, &sent).await.unwrap();
    let (first, rest) = encoded.split_at(encoded.len() / 2);

    writer.write_all(first).await.unwrap();
    let cancelled = tokio::time::timeout(
        Duration::from_millis(50),
        frames.next::<v1::CredentialBridgeHostMessage>(),
    )
    .await;
    assert!(cancelled.is_err(), "half a frame is not a message");
    writer.write_all(rest).await.unwrap();
    assert_eq!(bounded(frames.next()).await, Ok(Some(sent)));
}

#[tokio::test]
async fn a_host_sender_never_writes_a_second_open() {
    let bridge = bridge();
    let (_guest, stream) = serve(&bridge);
    let host = bounded(FrontDoorHostSession::open(
        stream,
        bridge.identity(),
        &front_door_capabilities(true),
    ))
    .await
    .unwrap();
    assert_eq!(
        host.sender()
            .send(open(
                bridge.identity(),
                &[CREDENTIAL_BRIDGE_CAPABILITY_FRONT_DOOR]
            ))
            .await,
        Err(FrontDoorSessionError::InvalidFrame)
    );
}

// An Open lists websocket.v1 only for an executor that serves upgrades, and a
// list that is not a front door's opens nothing (#4973).
#[tokio::test]
async fn the_open_lists_websocket_only_when_the_executor_serves_upgrades() {
    for serves in [false, true] {
        let (guest, host) = tokio::io::duplex(64 * 1024);
        let listed = front_door_capabilities(serves);
        let _session = bounded(FrontDoorHostSession::open(
            host,
            bridge().identity(),
            &listed,
        ))
        .await
        .unwrap();
        let open: v1::CredentialBridgeHostMessage = bounded(FrameReader::new(guest).next())
            .await
            .unwrap()
            .unwrap();
        let Some(HostPayload::Open(open)) = open.payload else {
            panic!("the first host frame is the Open");
        };
        assert_eq!(open.capabilities, listed);
        assert!(
            open.capabilities
                .contains(&CREDENTIAL_BRIDGE_CAPABILITY_FRONT_DOOR.to_owned())
        );
        assert_eq!(
            open.capabilities
                .contains(&CREDENTIAL_BRIDGE_CAPABILITY_WEBSOCKET.to_owned()),
            serves
        );
    }
    let too_many =
        [CREDENTIAL_BRIDGE_CAPABILITY_FRONT_DOOR; CREDENTIAL_BRIDGE_MAX_CAPABILITIES + 1];
    for refused in [
        &[CREDENTIAL_BRIDGE_CAPABILITY_REQUEST_BODY_STREAM][..],
        &[CREDENTIAL_BRIDGE_CAPABILITY_FRONT_DOOR, "Not Valid"][..],
        &too_many[..],
    ] {
        let (_guest, host) = tokio::io::duplex(64 * 1024);
        assert!(matches!(
            bounded(FrontDoorHostSession::open(
                host,
                bridge().identity(),
                refused
            ))
            .await,
            Err(FrontDoorSessionError::InvalidOpen)
        ));
    }
}
