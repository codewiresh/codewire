//! A push larger than one credit window, through the relay (#4280): the real
//! guest bridge behind the synthetic daemon's RPC, the real epoch, and a
//! synthetic broker that grants credit exactly as the broker's runner does
//! (one window when the request starts, one frame for each frame it takes).
//! Its provider answers as `git http-backend` does: the response headers
//! first, then the body is read, and the result ends the response.
use super::*;
use axum::body::Body;
use axum::http::{Method, StatusCode};
use codewire_credential_bridge::CredentialBridge;
use codewire_daemon_proto::{
    CREDENTIAL_BRIDGE_CAPABILITY_REQUEST_BODY_STREAM, CREDENTIAL_BRIDGE_REQUEST_BODY_WINDOW_FRAMES,
};
use v1::credential_bridge_guest_message::Payload as Guest;
use v1::credential_bridge_host_message::Payload as Host;

const PUSH: &str = "/_codewire/github/owner/repo.git/git-receive-pack";

/// The broker's half: credit as the runner grants it, the response start as
/// soon as the request arrives, and its end once the body ends. Returns the body bytes it took, and its streams, which stay
/// open until the test ends.
async fn serve_push(
    mut input: Streaming<v1::CredentialBridgeGuestMessage>,
    output: mpsc::Sender<Result<v1::CredentialBridgeHostMessage, Status>>,
) -> (
    usize,
    Streaming<v1::CredentialBridgeGuestMessage>,
    mpsc::Sender<Result<v1::CredentialBridgeHostMessage, Status>>,
) {
    let send = |payload| {
        let output = output.clone();
        async move {
            output
                .send(Ok(v1::CredentialBridgeHostMessage {
                    payload: Some(payload),
                }))
                .await
                .unwrap();
        }
    };
    let mut received = 0;
    while let Ok(Some(frame)) = input.message().await {
        match frame.payload {
            Some(Guest::Request(request)) => {
                assert!(request.streamed_body);
                send(Host::RequestCredit(v1::CredentialBridgeRequestCredit {
                    request_id: request.request_id.clone(),
                    frames: CREDENTIAL_BRIDGE_REQUEST_BODY_WINDOW_FRAMES,
                }))
                .await;
                send(Host::ResponseStart(v1::CredentialBridgeResponseStart {
                    request_id: request.request_id,
                    status_code: 200,
                    headers: Vec::new(),
                }))
                .await;
            }
            Some(Guest::RequestBody(body)) => {
                received += body.data.len();
                send(Host::RequestCredit(v1::CredentialBridgeRequestCredit {
                    request_id: body.request_id,
                    frames: 1,
                }))
                .await;
            }
            Some(Guest::RequestEnd(end)) => {
                send(Host::ResponseEnd(v1::CredentialBridgeResponseEnd {
                    request_id: end.request_id,
                }))
                .await;
                return (received, input, output);
            }
            other => panic!("unexpected guest frame {other:?}"),
        }
    }
    panic!("the guest stream ended after {received} body bytes");
}

#[tokio::test]
async fn a_push_larger_than_one_window_streams_through_the_relay() {
    let mut fixture = Fixture::new().await;
    *fixture.broker_capabilities.lock().unwrap() =
        vec![CREDENTIAL_BRIDGE_CAPABILITY_REQUEST_BODY_STREAM];
    let (cancel, task) = fixture.epoch();
    let daemon = bounded(fixture.daemon_calls.recv()).await.unwrap();
    let BrokerCall {
        input,
        output,
        accept,
        ..
    } = bounded(fixture.broker_calls.recv()).await.unwrap();
    accept.send(Ok(())).unwrap();

    // The daemon's half, as its hosted path runs it: read the Open, then
    // activate the guest bridge on the rest of the host stream.
    let DaemonCall {
        input: mut host,
        output: daemon_output,
    } = daemon;
    let Some(Host::Open(open)) = bounded(host.message()).await.unwrap().unwrap().payload else {
        panic!("Open must come first");
    };
    let guest = CredentialBridge::new(fixture.config.environment_id, 7).unwrap();
    let (prepared, mut guest_output) = guest.prepare_connection().unwrap();
    // The synthetic daemon already sent its Ready.
    assert!(matches!(
        bounded(guest_output.next()).await.unwrap().unwrap().payload,
        Some(Guest::Ready(_))
    ));
    let connection = prepared
        .activate_with_capabilities(host, &open.capabilities)
        .await
        .unwrap();
    let guest_task = tokio::spawn(connection.run());
    let pump = tokio::spawn(async move {
        while let Some(frame) = guest_output.next().await {
            if daemon_output.send(frame).await.is_err() {
                break;
            }
        }
    });
    let broker = tokio::spawn(serve_push(input, output));

    let length = 5 * 1024 * 1024;
    let body: Vec<u8> = (0..length).map(|index| (index % 251) as u8).collect();
    let request = axum::http::Request::builder()
        .method(Method::POST)
        .uri(PUSH)
        .header("content-type", "application/x-git-receive-pack-request")
        .body(Body::from(body))
        .unwrap();
    let response = bounded(guest.respond(request)).await;
    assert_eq!(response.status(), StatusCode::OK);
    // The whole body reaches the provider although the response started first.
    let (received, input, output) = tokio::time::timeout(Duration::from_secs(20), broker)
        .await
        .expect("the push must not stall after its response starts")
        .unwrap();
    assert_eq!(received, length);
    let response = bounded(axum::body::to_bytes(response.into_body(), usize::MAX)).await;
    assert!(response.unwrap().is_empty(), "the response completes");

    cancel.cancel();
    bounded(task).await.unwrap().unwrap();
    drop((input, output));
    guest_task.abort();
    pump.abort();
    fixture.stop().await;
}
