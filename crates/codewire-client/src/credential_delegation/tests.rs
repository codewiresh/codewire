//! Actual generated bidi calls over a synthetic, explicitly gated transport.
//! No database, real token, provider, listener or native runtime is involved.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use buffa::Message as _;
use connectrpc::client::{ClientBody, ClientConfig};
use connectrpc::{ConnectError, Protocol};
use futures_util::FutureExt as _;
use futures_util::future::BoxFuture;
use http::{Request, Response};
use http_body_util::BodyExt as _;
use tokio::sync::oneshot;

use super::*;

const TEST_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Clone)]
struct GatedTransport {
    request: Arc<std::sync::Mutex<Option<oneshot::Sender<Request<ClientBody>>>>>,
    response: Arc<std::sync::Mutex<Option<oneshot::Receiver<Response<reqwest::Body>>>>>,
    calls: Arc<AtomicUsize>,
}

struct Peer {
    request: oneshot::Receiver<Request<ClientBody>>,
    response: oneshot::Sender<Response<reqwest::Body>>,
}

impl ClientTransport for GatedTransport {
    type ResponseBody = reqwest::Body;
    type Error = ConnectError;

    fn send(
        &self,
        request: Request<ClientBody>,
    ) -> BoxFuture<'static, Result<Response<Self::ResponseBody>, Self::Error>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let captured = self.request.lock().unwrap().take().expect("one request");
        let response = self.response.lock().unwrap().take().expect("one response");
        Box::pin(async move {
            captured
                .send(request)
                .map_err(|_| ConnectError::unavailable("synthetic capture closed"))?;
            response
                .await
                .map_err(|_| ConnectError::unavailable("synthetic peer closed"))
        })
    }
}

fn transport() -> (GatedTransport, Peer) {
    let (request_tx, request_rx) = oneshot::channel();
    let (response_tx, response_rx) = oneshot::channel();
    (
        GatedTransport {
            request: Arc::new(std::sync::Mutex::new(Some(request_tx))),
            response: Arc::new(std::sync::Mutex::new(Some(response_rx))),
            calls: Arc::new(AtomicUsize::new(0)),
        },
        Peer {
            request: request_rx,
            response: response_tx,
        },
    )
}

fn generated(
    transport: GatedTransport,
    protocol: Protocol,
) -> CredentialDelegationServiceClient<GatedTransport> {
    CredentialDelegationServiceClient::new(
        transport,
        ClientConfig::new("http://synthetic.invalid".parse().unwrap()).with_protocol(protocol),
    )
}

fn opening() -> CredentialDelegationOpen {
    CredentialDelegationOpen {
        runtime: Some(bridge::CredentialBridgeOpen {
            protocol_version: 1,
            environment_id: "67edfdf2-61f6-453e-aae3-de09f7793659".into(),
            environment_generation: 7,
            ..Default::default()
        })
        .into(),
        org_id: "synthetic-organization".into(),
        selection_sha256: vec![7; 32],
        project_id: Some("90227c22-f003-443a-8b6b-31a7e49fae54".into()),
        user_secrets: true,
        organization_secrets: true,
        profile: Some(crate::CredentialDelegationProfile {
            profile_id: "84cf3736-8e4b-42da-8b64-c77a3b0267c2".into(),
            profile_revision: 9,
            ..Default::default()
        })
        .into(),
        ordinary_environment_keys: vec!["ORDINARY".into()],
        reserved_environment_keys: vec!["CODEWIRE_ENV_ID".into()],
        ..Default::default()
    }
}

async fn options() -> Result<CallOptions, ClientError> {
    CallOptions::default()
        .try_with_header("authorization", "Bearer synthetic-delegation-token")
        .map_err(ClientError::from)
}

async fn receive_open_and_ready(
    captured: oneshot::Receiver<Request<ClientBody>>,
    open: &CredentialDelegationOpen,
    protocol: Protocol,
) -> ClientBody {
    let request = tokio::time::timeout(TEST_TIMEOUT, captured)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(request.method(), http::Method::POST);
    assert_eq!(
        request.uri().path(),
        "/codewire.v1.CredentialDelegationService/DelegateCredentials"
    );
    assert_eq!(
        request.headers()["authorization"],
        "Bearer synthetic-delegation-token"
    );
    assert_eq!(
        request.headers()["content-type"],
        match protocol {
            Protocol::Connect => "application/connect+proto",
            Protocol::Grpc => "application/grpc+proto",
            _ => unreachable!("only the two admitted protocols are fixture inputs"),
        }
    );
    let mut body = request.into_body();
    for expected in [
        DelegateCredentialsRequest {
            input: Some(delegate_credentials_request::Input::Open(Box::new(
                open.clone(),
            ))),
            ..Default::default()
        },
        DelegateCredentialsRequest {
            input: Some(delegate_credentials_request::Input::Frame(Box::new(
                bridge::CredentialBridgeGuestMessage {
                    payload: Some(bridge::credential_bridge_guest_message::Payload::Ready(
                        Box::new(bridge::CredentialBridgeReady {
                            protocol_version: open.runtime.as_option().unwrap().protocol_version,
                            environment_id: open
                                .runtime
                                .as_option()
                                .unwrap()
                                .environment_id
                                .clone(),
                            environment_generation: open
                                .runtime
                                .as_option()
                                .unwrap()
                                .environment_generation,
                            ..Default::default()
                        }),
                    )),
                    ..Default::default()
                },
            ))),
            ..Default::default()
        },
    ] {
        let frame = tokio::time::timeout(TEST_TIMEOUT, body.frame())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let bytes = frame.into_data().unwrap();
        assert_eq!(bytes[0], 0);
        let length = u32::from_be_bytes(bytes[1..5].try_into().unwrap()) as usize;
        assert_eq!(bytes.len(), length + 5);
        assert_eq!(
            DelegateCredentialsRequest::decode_from_slice(&bytes[5..]).unwrap(),
            expected
        );
    }
    assert!(
        body.frame().now_or_never().is_none(),
        "no third setup frame or premature half-close"
    );
    body
}

fn envelope(payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0];
    bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

fn reply(protocol: Protocol, payload: &[u8]) -> Response<reqwest::Body> {
    Response::builder()
        .header(
            "content-type",
            match protocol {
                Protocol::Connect => "application/connect+proto",
                Protocol::Grpc => "application/grpc+proto",
                _ => unreachable!("only the two admitted protocols are fixture inputs"),
            },
        )
        .body(reqwest::Body::from(envelope(payload)))
        .unwrap()
}

fn admitted(open: CredentialDelegationOpen) -> DelegateCredentialsResponse {
    DelegateCredentialsResponse {
        output: Some(delegate_credentials_response::Output::Admitted(Box::new(
            open,
        ))),
        ..Default::default()
    }
}

async fn assert_input_closed(body: &mut ClientBody) {
    assert!(
        tokio::time::timeout(TEST_TIMEOUT, body.frame())
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn delegation_generated_setup_sends_open_then_ready_and_requires_exact_echo() {
    for protocol in [Protocol::Connect, Protocol::Grpc] {
        let (transport, peer) = transport();
        let calls = transport.calls.clone();
        let open = opening();
        let mut setup = Box::pin(setup(
            generated(transport, protocol),
            options(),
            open.clone(),
            Instant::now() + TEST_TIMEOUT,
        ));
        assert!(futures_util::poll!(setup.as_mut()).is_pending());
        let mut body = receive_open_and_ready(peer.request, &open, protocol).await;
        // Successfully enqueued Open/Ready does not return an admitted stream.
        assert!(futures_util::poll!(setup.as_mut()).is_pending());
        peer.response
            .send(reply(protocol, &admitted(open).encode_to_vec()))
            .unwrap();
        let mut stream = tokio::time::timeout(TEST_TIMEOUT, setup)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        stream.close_send();
        assert_input_closed(&mut body).await;
        drop(stream);
    }
}

#[tokio::test]
async fn delegation_admission_compares_every_selection_coordinate() {
    for attack in [
        "protocol",
        "environment",
        "generation",
        "org",
        "digest",
        "project",
        "user",
        "organization",
        "profile",
        "revision",
        "ordinary",
        "reserved",
    ] {
        let (transport, peer) = transport();
        let open = opening();
        let mut altered = open.clone();
        match attack {
            "protocol" => altered.runtime.as_option_mut().unwrap().protocol_version += 1,
            "environment" => {
                altered.runtime.as_option_mut().unwrap().environment_id =
                    uuid::Uuid::new_v4().to_string()
            }
            "generation" => {
                altered
                    .runtime
                    .as_option_mut()
                    .unwrap()
                    .environment_generation += 1
            }
            "org" => altered.org_id.push_str("-other"),
            "digest" => altered.selection_sha256[0] ^= 1,
            "project" => altered.project_id = None,
            "user" => altered.user_secrets = false,
            "organization" => altered.organization_secrets = false,
            "profile" => altered.profile = None.into(),
            "revision" => altered.profile.as_option_mut().unwrap().profile_revision += 1,
            "ordinary" => altered.ordinary_environment_keys.push("ADDED".into()),
            "reserved" => altered.reserved_environment_keys.push("ADDED".into()),
            _ => unreachable!(),
        }
        let mut setup = Box::pin(setup(
            generated(transport, Protocol::Connect),
            options(),
            open.clone(),
            Instant::now() + TEST_TIMEOUT,
        ));
        assert!(futures_util::poll!(setup.as_mut()).is_pending());
        let mut body = receive_open_and_ready(peer.request, &open, Protocol::Connect).await;
        peer.response
            .send(reply(Protocol::Connect, &admitted(altered).encode_to_vec()))
            .unwrap();
        assert_eq!(
            setup.await.unwrap_err().code(),
            ErrorCode::Internal,
            "{attack}"
        );
        assert_input_closed(&mut body).await;
    }
}

#[tokio::test]
async fn delegation_rejects_eof_rpc_error_unknown_empty_and_operation_before_ack() {
    for attack in ["eof", "rpc error", "unknown", "empty", "operation"] {
        let (transport, peer) = transport();
        let open = opening();
        let mut setup = Box::pin(setup(
            generated(transport, Protocol::Connect),
            options(),
            open.clone(),
            Instant::now() + TEST_TIMEOUT,
        ));
        assert!(futures_util::poll!(setup.as_mut()).is_pending());
        let mut body = receive_open_and_ready(peer.request, &open, Protocol::Connect).await;
        let response = match attack {
            "eof" | "rpc error" => {
                let terminal: &[u8] = if attack == "eof" {
                    b"{}"
                } else {
                    br#"{"error":{"code":"permission_denied","message":"synthetic denial"}}"#
                };
                let mut bytes = envelope(terminal);
                bytes[0] = 2;
                Response::builder()
                    .header("content-type", "application/connect+proto")
                    .body(reqwest::Body::from(bytes))
                    .unwrap()
            }
            "unknown" => reply(Protocol::Connect, &[0xfa, 0x07, 0]),
            "empty" => reply(Protocol::Connect, &[]),
            "operation" => reply(
                Protocol::Connect,
                &DelegateCredentialsResponse {
                    output: Some(delegate_credentials_response::Output::Frame(Box::default())),
                    ..Default::default()
                }
                .encode_to_vec(),
            ),
            _ => unreachable!(),
        };
        peer.response.send(response).unwrap();
        let error = setup.await.unwrap_err();
        assert_eq!(
            error.code(),
            if attack == "rpc error" {
                ErrorCode::PermissionDenied
            } else {
                ErrorCode::Internal
            },
            "{attack}"
        );
        assert_input_closed(&mut body).await;
    }
}

#[tokio::test]
async fn delegation_setup_cancel_aborts_pending_headers_and_closes_sole_input() {
    let (transport, mut peer) = transport();
    let open = opening();
    let mut setup = Box::pin(setup(
        generated(transport, Protocol::Grpc),
        options(),
        open.clone(),
        Instant::now() + TEST_TIMEOUT,
    ));
    assert!(futures_util::poll!(setup.as_mut()).is_pending());
    let mut body = receive_open_and_ready(peer.request, &open, Protocol::Grpc).await;
    // Enter the pinned client's first receive before cancelling the whole setup.
    assert!(futures_util::poll!(setup.as_mut()).is_pending());
    drop(setup);
    tokio::time::timeout(TEST_TIMEOUT, peer.response.closed())
        .await
        .unwrap();
    assert_input_closed(&mut body).await;
}

#[tokio::test]
async fn delegation_setup_timeout_aborts_pending_headers_without_restarting_budget() {
    let (transport, mut peer) = transport();
    let open = opening();
    let deadline = Instant::now() + TEST_TIMEOUT;
    let (auth_tx, auth_rx) = oneshot::channel();
    let mut setup = Box::pin(setup(
        generated(transport, Protocol::Connect),
        async {
            auth_rx.await.unwrap();
            options().await
        },
        open.clone(),
        deadline,
    ));
    assert!(futures_util::poll!(setup.as_mut()).is_pending());
    auth_tx.send(()).unwrap();
    assert!(futures_util::poll!(setup.as_mut()).is_pending());
    let mut body = receive_open_and_ready(peer.request, &open, Protocol::Connect).await;
    assert_eq!(
        tokio::time::timeout(TEST_TIMEOUT + TEST_TIMEOUT, setup)
            .await
            .unwrap()
            .unwrap_err()
            .code(),
        ErrorCode::DeadlineExceeded
    );
    tokio::time::timeout(TEST_TIMEOUT, peer.response.closed())
        .await
        .unwrap();
    assert_input_closed(&mut body).await;
}

#[tokio::test]
async fn delegation_original_deadline_covers_pending_auth_and_prevents_late_dispatch() {
    assert_eq!(SETUP_TIMEOUT, Duration::from_secs(15));
    let (pending_auth_transport, _peer) = transport();
    let calls = pending_auth_transport.calls.clone();
    let (auth_tx, auth_rx) = oneshot::channel::<()>();
    let mut auth_tx = auth_tx;
    let result = setup(
        generated(pending_auth_transport, Protocol::Connect),
        async {
            auth_rx.await.unwrap();
            options().await
        },
        opening(),
        Instant::now() + Duration::from_millis(20),
    )
    .await;
    assert_eq!(result.unwrap_err().code(), ErrorCode::DeadlineExceeded);
    tokio::time::timeout(TEST_TIMEOUT, auth_tx.closed())
        .await
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    let (transport, _peer) = transport();
    let calls = transport.calls.clone();
    let result = setup(
        generated(transport, Protocol::Connect),
        options(),
        opening(),
        Instant::now(),
    )
    .await;
    assert_eq!(result.unwrap_err().code(), ErrorCode::DeadlineExceeded);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn delegation_setup_cancel_drops_pending_shared_auth_without_transport_dispatch() {
    let (transport, _peer) = transport();
    let calls = transport.calls.clone();
    let (auth_tx, auth_rx) = oneshot::channel::<()>();
    let mut auth_tx = auth_tx;
    let mut setup = Box::pin(setup(
        generated(transport, Protocol::Connect),
        async {
            auth_rx.await.unwrap();
            options().await
        },
        opening(),
        Instant::now() + TEST_TIMEOUT,
    ));
    assert!(futures_util::poll!(setup.as_mut()).is_pending());
    drop(setup);
    tokio::time::timeout(TEST_TIMEOUT, auth_tx.closed())
        .await
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn delegation_auth_ready_after_original_deadline_does_not_dispatch() {
    let (transport, _peer) = transport();
    let calls = transport.calls.clone();
    let (auth_tx, auth_rx) = oneshot::channel::<()>();
    let deadline = Instant::now() + Duration::from_millis(20);
    let mut setup = Box::pin(setup(
        generated(transport, Protocol::Connect),
        async {
            auth_rx.await.unwrap();
            options().await
        },
        opening(),
        deadline,
    ));
    assert!(futures_util::poll!(setup.as_mut()).is_pending());
    // Do not poll setup during this wait: auth and the original timer will be
    // ready together. Even an immediately ready inner future cannot spend a
    // fresh setup budget or dispatch a request after the original deadline.
    tokio::time::sleep_until(deadline).await;
    auth_tx.send(()).unwrap();
    assert_eq!(setup.await.unwrap_err().code(), ErrorCode::DeadlineExceeded);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}
