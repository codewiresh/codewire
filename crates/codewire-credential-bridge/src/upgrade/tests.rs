use std::time::Duration;

use axum::http::header::AUTHORIZATION;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio_stream::StreamExt as _;
use uuid::Uuid;

use super::*;
use crate::{CredentialBridgeOutput, PreparedBridgeConnection};
use v1::credential_bridge_guest_message::Payload as GuestPayload;
use v1::credential_bridge_host_message::Payload as HostPayload;

/// A hang guard, far longer than any step takes.
const WAIT: Duration = Duration::from_secs(30);
const WINDOW: u32 = CREDENTIAL_BRIDGE_STREAM_WINDOW_BYTES;

async fn bounded<F: std::future::Future>(future: F) -> F::Output {
    tokio::time::timeout(WAIT, future)
        .await
        .expect("bounded test step")
}

/// A bridge whose admitted host this test plays.
struct Host {
    bridge: CredentialBridge,
    output: CredentialBridgeOutput,
    input: mpsc::Sender<Result<v1::CredentialBridgeHostMessage, Status>>,
    shutdown: oneshot::Sender<()>,
    task: tokio::task::JoinHandle<()>,
}

impl Host {
    /// A host whose Open lists WebSocket upgrades.
    async fn websockets() -> Self {
        Self::listing(&[CREDENTIAL_BRIDGE_CAPABILITY_WEBSOCKET]).await
    }

    async fn listing(capabilities: &[&str]) -> Self {
        let bridge = CredentialBridge::new(Uuid::new_v4(), 3).unwrap();
        let (prepared, mut output): (PreparedBridgeConnection, CredentialBridgeOutput) =
            bridge.prepare_connection().unwrap();
        let ready = bounded(output.next()).await.unwrap().unwrap();
        assert!(matches!(ready.payload, Some(GuestPayload::Ready(_))));
        let (input, receiver) = mpsc::channel(64);
        let capabilities = capabilities
            .iter()
            .map(|capability| (*capability).to_owned())
            .collect::<Vec<_>>();
        let connection = prepared
            .activate_with_capabilities(ReceiverStream::new(receiver), &capabilities)
            .await
            .unwrap();
        let (shutdown, stopped) = oneshot::channel();
        let task = tokio::spawn(connection.run_until(async {
            let _ = stopped.await;
        }));
        Self {
            bridge,
            output,
            input,
            shutdown,
            task,
        }
    }

    async fn next(&mut self) -> GuestPayload {
        bounded(self.output.next())
            .await
            .unwrap()
            .unwrap()
            .payload
            .unwrap()
    }

    /// Nothing was sent to the host, once every task is idle: the tests that
    /// call this run on paused time, so the wait is a progress check, not a
    /// race with the clock.
    async fn quiet(&mut self) {
        assert!(
            tokio::time::timeout(Duration::from_millis(50), self.output.next())
                .await
                .is_err(),
            "the bridge sent its host a frame"
        );
    }

    async fn send(&self, payload: HostPayload) {
        bounded(self.input.send(Ok(v1::CredentialBridgeHostMessage {
            payload: Some(payload),
        })))
        .await
        .unwrap();
    }

    /// Start an upgrade and return its task and the frame the host got.
    async fn upgrade(
        &mut self,
    ) -> (
        tokio::task::JoinHandle<UpgradeAnswer>,
        v1::CredentialBridgeUpgrade,
    ) {
        let bridge = self.bridge.clone();
        let task = tokio::spawn(async move {
            bridge
                .upgrade_intercepted("chatgpt.com", opening_request())
                .await
        });
        let GuestPayload::Upgrade(frame) = self.next().await else {
            panic!("expected an upgrade frame");
        };
        (task, frame)
    }

    /// Accept `id` as a host does: `UpgradeAccepted`, then a window.
    async fn accept(&self, id: &str) {
        self.send(HostPayload::UpgradeAccepted(
            v1::CredentialBridgeUpgradeAccepted {
                request_id: id.to_owned(),
                headers: vec![v1::CredentialHttpHeader {
                    name: "sec-websocket-accept".to_owned(),
                    value: b"test-accept".to_vec(),
                }],
            },
        ))
        .await;
        self.send(HostPayload::StreamCredit(
            v1::CredentialBridgeStreamCredit {
                request_id: id.to_owned(),
                credit_bytes: WINDOW,
            },
        ))
        .await;
    }

    /// An accepted socket.
    async fn open(&mut self) -> (UpgradedSocket, String) {
        let (task, frame) = self.upgrade().await;
        self.accept(&frame.request_id).await;
        let UpgradeAnswer::Switched {
            response: switched,
            socket,
        } = bounded(task).await.unwrap()
        else {
            panic!("the accepted upgrade was refused");
        };
        assert_eq!(switched.status(), StatusCode::SWITCHING_PROTOCOLS);
        (socket, frame.request_id)
    }

    async fn data(&self, id: &str, data: &[u8]) {
        self.send(HostPayload::StreamData(v1::CredentialBridgeStreamData {
            request_id: id.to_owned(),
            data: data.to_vec(),
        }))
        .await;
    }

    async fn stop(self) {
        let _ = self.shutdown.send(());
        bounded(self.task).await.unwrap();
    }
}

/// What a front door hands over: the route's managed path, no Host.
fn opening_request() -> Request<()> {
    Request::get("/v1/responses")
        .header(CONNECTION, "Upgrade")
        .header(UPGRADE, "websocket")
        .header("sec-websocket-key", "test-nonce")
        .header("sec-websocket-version", "13")
        .header(AUTHORIZATION, "Bearer placeholder")
        .body(())
        .unwrap()
}

#[tokio::test]
async fn an_accepted_upgrade_carries_bytes_both_ways() {
    let mut host = Host::websockets().await;
    let (task, frame) = host.upgrade().await;
    assert_eq!(frame.method, "GET");
    assert_eq!(
        (
            frame.capability_slot.as_str(),
            frame.route.as_str(),
            frame.path.as_str()
        ),
        ("codex", "openai-api", "/responses")
    );
    assert_eq!(frame.intercepted_host, "chatgpt.com");
    assert_eq!(frame.initial_credit_bytes, WINDOW);
    let names = frame
        .headers
        .iter()
        .map(|header| header.name.as_str())
        .collect::<Vec<_>>();
    // No framing: the host adds Connection and Upgrade itself.
    assert_eq!(
        names,
        [
            "sec-websocket-key",
            "sec-websocket-version",
            "authorization"
        ]
    );
    host.accept(&frame.request_id).await;
    let UpgradeAnswer::Switched {
        response: switched,
        mut socket,
    } = bounded(task).await.unwrap()
    else {
        panic!("the accepted upgrade was refused");
    };
    assert_eq!(switched.status(), StatusCode::SWITCHING_PROTOCOLS);
    assert_eq!(switched.headers()["sec-websocket-accept"], "test-accept");

    socket.write_all(b"hello").await.unwrap();
    let GuestPayload::StreamData(sent) = host.next().await else {
        panic!("expected stream data");
    };
    assert_eq!(
        (sent.request_id.as_str(), &sent.data[..]),
        (frame.request_id.as_str(), &b"hello"[..])
    );

    host.data(&frame.request_id, b"world").await;
    let mut received = [0_u8; 5];
    bounded(socket.read_exact(&mut received)).await.unwrap();
    assert_eq!(&received, b"world");

    // The front door's end closing half-closes the stream.
    socket.shutdown().await.unwrap();
    let GuestPayload::StreamClose(close) = host.next().await else {
        panic!("expected a half-close");
    };
    assert_eq!(
        close.kind,
        v1::CredentialBridgeStreamCloseKind::HalfClose as i32
    );
    host.stop().await;
}

#[tokio::test]
async fn a_refused_upgrade_returns_the_hosts_response() {
    let mut host = Host::websockets().await;
    let (task, frame) = host.upgrade().await;
    host.send(HostPayload::ResponseStart(
        v1::CredentialBridgeResponseStart {
            request_id: frame.request_id.clone(),
            status_code: 401,
            headers: Vec::new(),
        },
    ))
    .await;
    host.send(HostPayload::ResponseBody(
        v1::CredentialBridgeResponseBody {
            request_id: frame.request_id.clone(),
            data: b"no".to_vec(),
        },
    ))
    .await;
    host.send(HostPayload::ResponseEnd(v1::CredentialBridgeResponseEnd {
        request_id: frame.request_id,
    }))
    .await;
    let UpgradeAnswer::Refused(refused) = bounded(task).await.unwrap() else {
        panic!("a refused upgrade switched");
    };
    assert_eq!(refused.status(), StatusCode::UNAUTHORIZED);
    let body = axum::body::to_bytes(refused.into_body(), 1024)
        .await
        .unwrap();
    assert_eq!(&body[..], b"no");
    host.stop().await;
}

#[tokio::test(start_paused = true)]
async fn a_host_that_does_not_list_websockets_never_sees_the_upgrade() {
    let mut host = Host::listing(&[]).await;
    let UpgradeAnswer::Refused(refused) = bounded(
        host.bridge
            .upgrade_intercepted("chatgpt.com", opening_request()),
    )
    .await
    else {
        panic!("an upgrade went to a host without WebSockets");
    };
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    host.quiet().await;
    host.stop().await;
}

#[tokio::test(start_paused = true)]
async fn a_request_that_is_not_a_websocket_opening_is_refused_locally() {
    let mut host = Host::websockets().await;
    let mut request = opening_request();
    request
        .headers_mut()
        .insert(UPGRADE, "h2c".parse().unwrap());
    let UpgradeAnswer::Refused(refused) =
        bounded(host.bridge.upgrade_intercepted("chatgpt.com", request)).await
    else {
        panic!("an h2c upgrade was sent");
    };
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    host.quiet().await;
    host.stop().await;
}

#[tokio::test(start_paused = true)]
async fn open_sockets_are_bounded_apart_from_requests() {
    let mut host = Host::websockets().await;
    let mut sockets = Vec::new();
    for _ in 0..MAX_OPEN_SOCKETS {
        sockets.push(host.open().await);
    }
    let UpgradeAnswer::Refused(refused) = bounded(
        host.bridge
            .upgrade_intercepted("chatgpt.com", opening_request()),
    )
    .await
    else {
        panic!("a socket past the limit was sent");
    };
    assert_eq!(refused.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(refused.headers()["codewire-refusal"], "busy");
    let body = axum::body::to_bytes(refused.into_body(), 1024)
        .await
        .unwrap();
    assert_eq!(
        &body[..],
        b"Codewire: too many requests are in flight; try again.\n"
    );
    host.quiet().await;

    // Open sockets do not hold request slots: a request still goes out.
    let bridge = host.bridge.clone();
    let request = tokio::spawn(async move {
        bridge
            .respond(
                Request::post("/v1/responses")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
    });
    assert!(matches!(host.next().await, GuestPayload::Request(_)));
    request.abort();
    drop(sockets);
    host.stop().await;
}

#[tokio::test]
async fn losing_the_epoch_resets_its_sockets() {
    let mut host = Host::websockets().await;
    let (mut socket, _) = host.open().await;
    host.stop().await;
    let mut byte = [0_u8; 1];
    let read = bounded(socket.read(&mut byte)).await;
    assert!(matches!(read, Ok(0) | Err(_)), "{read:?}");
}

#[tokio::test]
async fn a_stream_frame_for_a_socket_never_opened_ends_the_epoch() {
    let mut host = Host::websockets().await;
    host.data(&Uuid::new_v4().to_string(), b"stray").await;
    let ended = bounded(host.output.next()).await.unwrap();
    assert_eq!(ended.unwrap_err().code(), tonic::Code::InvalidArgument);
    host.stop().await;
}

#[tokio::test]
async fn a_socket_whose_reader_stalls_never_delays_a_request() {
    let mut host = Host::websockets().await;
    // The front door never reads this socket: the host fills its window.
    let (_stalled, id) = host.open().await;
    let chunk = vec![7_u8; 64 * 1024];
    for _ in 0..(WINDOW as usize / chunk.len()) {
        host.data(&id, &chunk).await;
    }
    let bridge = host.bridge.clone();
    let request = tokio::spawn(async move {
        bridge
            .respond(
                Request::post("/v1/responses")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
    });
    let GuestPayload::Request(sent) = host.next().await else {
        panic!("expected the request");
    };
    host.send(HostPayload::ResponseStart(
        v1::CredentialBridgeResponseStart {
            request_id: sent.request_id.clone(),
            status_code: 200,
            headers: Vec::new(),
        },
    ))
    .await;
    host.send(HostPayload::ResponseEnd(v1::CredentialBridgeResponseEnd {
        request_id: sent.request_id,
    }))
    .await;
    let response = bounded(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    host.stop().await;
}

/// Frames that race a socket's end, whether the host reset it or the front
/// door let go of it, are dropped, and the epoch keeps serving: an ordinary
/// close never ends the session.
#[tokio::test]
async fn frames_racing_a_sockets_end_never_end_the_epoch() {
    for host_resets in [true, false] {
        let mut host = Host::websockets().await;
        let (socket, id) = host.open().await;
        let _kept = if host_resets {
            host.send(HostPayload::StreamClose(v1::CredentialBridgeStreamClose {
                request_id: id.clone(),
                kind: v1::CredentialBridgeStreamCloseKind::Reset.into(),
            }))
            .await;
            Some(socket)
        } else {
            drop(socket);
            // The pump tells the host the front door is gone.
            loop {
                if matches!(host.next().await, GuestPayload::StreamClose(_)) {
                    break;
                }
            }
            None
        };
        host.data(&id, b"late").await;
        host.send(HostPayload::StreamCredit(
            v1::CredentialBridgeStreamCredit {
                request_id: id.clone(),
                credit_bytes: 1024,
            },
        ))
        .await;
        let bridge = host.bridge.clone();
        let request = tokio::spawn(async move {
            bridge
                .respond(
                    Request::post("/v1/responses")
                        .body(Body::from("{}"))
                        .unwrap(),
                )
                .await
        });
        let sent = loop {
            if let GuestPayload::Request(sent) = host.next().await {
                break sent;
            }
        };
        host.send(HostPayload::ResponseStart(
            v1::CredentialBridgeResponseStart {
                request_id: sent.request_id.clone(),
                status_code: 200,
                headers: Vec::new(),
            },
        ))
        .await;
        host.send(HostPayload::ResponseEnd(v1::CredentialBridgeResponseEnd {
            request_id: sent.request_id,
        }))
        .await;
        let response = bounded(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "host resets: {host_resets}"
        );
        host.stop().await;
    }
}
