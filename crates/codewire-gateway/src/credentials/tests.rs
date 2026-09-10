//! Synthetic generated-RPC fixtures. No provider, Kubernetes, credential store
//! or TLS topology is substituted here: the test peer checks transport shape,
//! and the production broker separately owns authentication and refresh proof.

use super::*;
use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::Router;
use axum::http::HeaderValue;
use codewire_gateway_proto::CREDENTIAL_BRIDGE_PROTOCOL_VERSION;
use codewire_gateway_proto::broker::v1::credential_broker_service_server::{
    CredentialBrokerService, CredentialBrokerServiceServer,
};
use codewire_gateway_proto::codewire::bridge::v1;
use http_body_util::{BodyExt, Full};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tempfile::TempDir;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};
use tonic::{Status, Streaming};
use v1::credential_bridge_guest_message::Payload as GuestPayload;
use v1::credential_bridge_host_message::Payload as HostPayload;

mod tls;

const TIMEOUT: Duration = Duration::from_secs(10);
const AUTHORITY: &str = "env-synthetic.gateway.internal:8443";
const WORKSPACE_ONE: &str = "Bearer workspace.projected.one";
const WORKSPACE_TWO: &str = "Bearer workspace.projected.two";
const GATEWAY_ONE: &str = "gateway.projected.one";
const GATEWAY_TWO: &str = "gateway.projected.two";

async fn bounded<F: Future>(future: F) -> F::Output {
    tokio::time::timeout(TIMEOUT, future)
        .await
        .expect("bounded synthetic credential-ingress operation")
}

fn request(workspace: &str) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri("/v1/responses")
        .header("host", AUTHORITY)
        .header("authorization", workspace)
        .header("content-type", "application/json")
        .body(Body::from("{}"))
        .unwrap()
}

pub(crate) struct PeerCall {
    ready: v1::CredentialBridgeReady,
    gateway: String,
    workspace: Vec<u8>,
    frames: mpsc::Receiver<v1::CredentialBridgeGuestMessage>,
    responses: mpsc::Sender<Result<v1::CredentialBridgeHostMessage, Status>>,
    headers: Option<oneshot::Sender<()>>,
    ended: oneshot::Receiver<()>,
}

impl PeerCall {
    pub(crate) fn accept(&mut self) {
        self.headers.take().unwrap().send(()).unwrap();
    }

    pub(crate) async fn request(&mut self) -> v1::CredentialBridgeRequest {
        let message = bounded(self.frames.recv()).await.unwrap();
        let Some(GuestPayload::Request(request)) = message.payload else {
            panic!("only a Request may follow admitted Ready");
        };
        request
    }

    async fn send(&self, payload: HostPayload) {
        bounded(self.responses.send(Ok(v1::CredentialBridgeHostMessage {
            payload: Some(payload),
        })))
        .await
        .unwrap();
    }

    pub(crate) async fn start(&self, request_id: &str) {
        self.send(HostPayload::ResponseStart(
            v1::CredentialBridgeResponseStart {
                request_id: request_id.into(),
                status_code: 200,
                headers: vec![v1::CredentialHttpHeader {
                    name: "content-type".into(),
                    value: b"text/event-stream".to_vec(),
                }],
            },
        ))
        .await;
    }

    async fn finish(&self, request_id: &str, data: &[u8]) {
        self.send(HostPayload::ResponseBody(
            v1::CredentialBridgeResponseBody {
                request_id: request_id.into(),
                data: data.to_vec(),
            },
        ))
        .await;
        self.send(HostPayload::ResponseEnd(v1::CredentialBridgeResponseEnd {
            request_id: request_id.into(),
        }))
        .await;
    }

    pub(crate) async fn closed(&mut self) {
        bounded(&mut self.ended).await.unwrap();
        // The retained response sender is deliberately still alive. Closing
        // only the incoming response half must not be mistaken for this proof.
    }
}

#[derive(Clone)]
struct Peer {
    calls: mpsc::Sender<PeerCall>,
    shutdown: CancellationToken,
    workers: TaskTracker,
    reject: bool,
}

#[tonic::async_trait]
impl CredentialBrokerService for Peer {
    type CredentialBridgeStream = ReceiverStream<Result<v1::CredentialBridgeHostMessage, Status>>;

    async fn credential_bridge(
        &self,
        request: tonic::Request<Streaming<v1::CredentialBridgeGuestMessage>>,
    ) -> Result<tonic::Response<Self::CredentialBridgeStream>, Status> {
        let gateway = request
            .metadata()
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| Status::unauthenticated("synthetic missing identity"))?
            .to_owned();
        let workspace = request
            .metadata()
            .get_bin(WORKSPACE_AUTHORIZATION)
            .ok_or_else(|| Status::unauthenticated("synthetic missing identity"))?
            .to_bytes()
            .map_err(|_| Status::unauthenticated("synthetic invalid identity"))?
            .to_vec();
        if request
            .metadata()
            .contains_key(ASCII_WORKSPACE_AUTHORIZATION)
        {
            return Err(Status::unauthenticated("synthetic ambiguous identity"));
        }
        let mut input = request.into_inner();
        let first = tokio::time::timeout(TIMEOUT, input.message())
            .await
            .map_err(|_| Status::deadline_exceeded("synthetic Ready timeout"))??;
        let Some(GuestPayload::Ready(ready)) = first.and_then(|message| message.payload) else {
            return Err(Status::invalid_argument("synthetic Ready required"));
        };
        let (responses, receiver) = mpsc::channel(32);
        let (frames_tx, frames) = mpsc::channel(32);
        let (headers, headers_rx) = oneshot::channel();
        let (ended_tx, ended) = oneshot::channel();
        let input_closed = CancellationToken::new();
        let closed = input_closed.clone();
        let shutdown = self.shutdown.clone();
        drop(self.workers.spawn(async move {
            loop {
                let message = tokio::select! {
                    _ = shutdown.cancelled() => break,
                    message = input.message() => match message {
                        Ok(Some(message)) => message,
                        Ok(None) | Err(_) => break,
                    }
                };
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    result = frames_tx.send(message) => if result.is_err() { break; },
                }
            }
            closed.cancel();
            let _ = ended_tx.send(());
        }));
        self.calls
            .send(PeerCall {
                ready,
                gateway,
                workspace,
                frames,
                responses,
                headers: Some(headers),
                ended,
            })
            .await
            .map_err(|_| Status::cancelled("synthetic fixture closed"))?;
        tokio::select! {
            _ = self.shutdown.cancelled() => return Err(Status::cancelled("synthetic fixture shutdown")),
            _ = input_closed.cancelled() => return Err(Status::cancelled("synthetic input closed")),
            result = headers_rx => result.map_err(|_| Status::cancelled("synthetic fixture closed"))?,
        }
        if self.reject {
            return Err(Status::permission_denied(
                "opaque-synthetic-upstream-canary",
            ));
        }
        Ok(tonic::Response::new(ReceiverStream::new(receiver)))
    }
}

pub(crate) struct Harness {
    ingress: CredentialIngress,
    calls: mpsc::Receiver<PeerCall>,
    shutdown: CancellationToken,
    peer_workers: TaskTracker,
    server: JoinHandle<Result<(), tonic::transport::Error>>,
    directory: TempDir,
    tls: Option<super::tls_test_support::Identity>,
    broker_origin: String,
}

impl Harness {
    async fn new(reject: bool) -> Self {
        Self::with_tls(reject, false).await
    }

    pub(crate) async fn with_tls(reject: bool, tls: bool) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let token_path = directory.path().join("token");
        std::fs::write(&token_path, GATEWAY_ONE).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let identity = tls.then(|| super::tls_test_support::Identity::new("localhost"));
        let files = identity.as_ref().map(|identity| identity.files());
        let roots = directory.path().join("broker-roots.pem");
        if let Some(identity) = &identity {
            std::fs::write(&roots, &identity.root_pem).unwrap();
        }
        let (calls_tx, calls) = mpsc::channel(32);
        let shutdown = CancellationToken::new();
        let peer_workers = TaskTracker::new();
        let peer = Peer {
            calls: calls_tx,
            shutdown: shutdown.clone(),
            workers: peer_workers.clone(),
            reject,
        };
        let service = CredentialBrokerServiceServer::new(peer)
            .max_decoding_message_size(CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES)
            .max_encoding_message_size(CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES);
        let server_shutdown = shutdown.clone();
        let server = tokio::spawn(async move {
            if let Some(files) = files {
                return tonic::transport::Server::builder()
                    .add_service(service)
                    .serve_with_incoming_shutdown(
                        codewire_tls::TlsIncoming::new(listener, files).unwrap(),
                        server_shutdown.cancelled_owned(),
                    )
                    .await;
            }
            tonic::transport::Server::builder()
                .add_service(service)
                .serve_with_incoming_shutdown(
                    TcpListenerStream::new(listener),
                    server_shutdown.cancelled_owned(),
                )
                .await
        });
        let config = if tls {
            CredentialIngressConfig::new(
                Uuid::new_v4(),
                7,
                AUTHORITY,
                token_path,
                ClientTlsEndpoint::new(format!("https://localhost:{}", address.port()), roots)
                    .unwrap(),
            )
            .unwrap()
        } else {
            let channel = bounded(
                Channel::from_shared(format!("http://{address}"))
                    .unwrap()
                    .connect(),
            )
            .await
            .unwrap();
            CredentialIngressConfig::for_test(Uuid::new_v4(), 7, AUTHORITY, token_path, channel)
                .unwrap()
        };
        Self {
            ingress: CredentialIngress::new(config),
            calls,
            shutdown,
            peer_workers,
            server,
            directory,
            tls: identity,
            broker_origin: format!("https://localhost:{}", address.port()),
        }
    }

    fn submit(&self, request: Request<Body>) -> JoinHandle<Response<Body>> {
        let ingress = self.ingress.clone();
        tokio::spawn(async move { ingress.respond(request).await })
    }

    pub(crate) async fn call(&mut self) -> PeerCall {
        let call = bounded(self.calls.recv()).await.unwrap();
        assert_eq!(
            call.ready.protocol_version,
            CREDENTIAL_BRIDGE_PROTOCOL_VERSION
        );
        assert_eq!(
            call.ready.environment_id,
            self.ingress.state.config.environment_id.to_string()
        );
        assert_eq!(call.ready.environment_generation, 7);
        call
    }

    pub(crate) fn runtime_coordinates(&self) -> (Uuid, PathBuf, String, PathBuf) {
        (
            self.ingress.state.config.environment_id,
            self.directory.path().join("token"),
            self.broker_origin.clone(),
            self.directory.path().join("broker-roots.pem"),
        )
    }

    pub(crate) async fn stop(self) {
        bounded(self.ingress.shutdown()).await;
        assert_eq!(
            self.ingress.state.permits.available_permits(),
            CREDENTIAL_BRIDGE_MAX_IN_FLIGHT
        );
        self.shutdown.cancel();
        self.peer_workers.close();
        bounded(self.peer_workers.wait()).await;
        bounded(self.server).await.unwrap().unwrap();
    }
}

#[tokio::test]
async fn config_requires_exact_trusted_coordinates_and_metadata_is_sensitive() {
    let channel = Channel::from_static("http://127.0.0.1:1").connect_lazy();
    let directory = tempfile::tempdir().unwrap();
    for (environment, generation, authority, path) in [
        (Uuid::nil(), 1, AUTHORITY, directory.path().join("token")),
        (Uuid::new_v4(), 0, AUTHORITY, directory.path().join("token")),
        (
            Uuid::new_v4(),
            u64::MAX,
            AUTHORITY,
            directory.path().join("token"),
        ),
        (
            Uuid::new_v4(),
            1,
            "https://wrong",
            directory.path().join("token"),
        ),
        (
            Uuid::new_v4(),
            1,
            "user@host:443",
            directory.path().join("token"),
        ),
        (Uuid::new_v4(), 1, "host:0", directory.path().join("token")),
        (
            Uuid::new_v4(),
            1,
            "host:65536",
            directory.path().join("token"),
        ),
        (
            Uuid::new_v4(),
            1,
            AUTHORITY,
            PathBuf::from("relative-token"),
        ),
    ] {
        assert!(
            CredentialIngressConfig::for_test(
                environment,
                generation,
                authority,
                path,
                channel.clone()
            )
            .is_err()
        );
    }
    let metadata = credential_metadata(GATEWAY_ONE, WORKSPACE_ONE.as_bytes()).unwrap();
    assert_eq!(metadata.len(), 2);
    let gateway = metadata.get("authorization").unwrap();
    assert!(gateway.is_sensitive());
    assert_eq!(gateway.to_str().unwrap(), format!("Bearer {GATEWAY_ONE}"));
    let workspace = metadata.get_bin(WORKSPACE_AUTHORIZATION).unwrap();
    assert!(workspace.is_sensitive());
    assert_eq!(
        workspace.to_bytes().unwrap().as_ref(),
        WORKSPACE_ONE.as_bytes()
    );
    assert!(!metadata.contains_key(ASCII_WORKSPACE_AUTHORIZATION));
}

#[cfg(unix)]
#[tokio::test]
async fn projected_gateway_fifo_is_denied_without_stranding_file_open_or_shutdown() {
    use std::os::unix::ffi::OsStrExt;
    let mut h = Harness::new(false).await;
    let path = h.directory.path().join("token");
    std::fs::remove_file(&path).unwrap();
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    // SAFETY: CString is NUL-terminated and lives through this call; the path
    // is an exact file in this fixture's private, owned temporary directory.
    assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
    let response = tokio::time::timeout(
        Duration::from_secs(1),
        h.ingress.respond(request(WORKSPACE_ONE)),
    )
    .await
    .expect("FIFO open blocked instead of failing closed");
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(h.calls.try_recv().is_err());
    h.stop().await;
}

#[test]
fn ingress_rejects_proxy_forms_foreign_authorities_queries_and_identity_ambiguity() {
    for (version, method, uri) in [
        (
            Version::HTTP_11,
            Method::POST,
            "https://env-synthetic.gateway.internal:8443/v1/responses",
        ),
        (Version::HTTP_11, Method::CONNECT, "/v1/responses"),
        (Version::HTTP_11, Method::POST, "/v1/responses?x=1"),
        (Version::HTTP_11, Method::POST, "/v1/responses?"),
        (Version::HTTP_11, Method::POST, "/v1/other"),
        (Version::HTTP_10, Method::POST, "/v1/responses"),
        (Version::HTTP_2, Method::POST, "/v1/responses"),
        (
            Version::HTTP_2,
            Method::POST,
            "http://env-synthetic.gateway.internal:8443/v1/responses",
        ),
        (
            Version::HTTP_2,
            Method::POST,
            "https://foreign.internal:8443/v1/responses",
        ),
    ] {
        let mut input = request(WORKSPACE_ONE);
        *input.version_mut() = version;
        *input.method_mut() = method;
        *input.uri_mut() = uri.parse().unwrap();
        assert_eq!(
            prepare_request(input, AUTHORITY).unwrap_err(),
            StatusCode::FORBIDDEN
        );
    }
    for name in [
        WORKSPACE_AUTHORIZATION,
        ASCII_WORKSPACE_AUTHORIZATION,
        DAEMON_AUTH_TOKEN_HEADER,
    ] {
        let mut input = request(WORKSPACE_ONE);
        input
            .headers_mut()
            .insert(name, HeaderValue::from_static("synthetic-canary"));
        assert_eq!(
            prepare_request(input, AUTHORITY).unwrap_err(),
            StatusCode::BAD_REQUEST
        );
    }
    let mut duplicate = request(WORKSPACE_ONE);
    duplicate
        .headers_mut()
        .append("authorization", HeaderValue::from_static(WORKSPACE_TWO));
    assert_eq!(
        prepare_request(duplicate, AUTHORITY).unwrap_err(),
        StatusCode::UNAUTHORIZED
    );
    for token in [
        "Bearer ",
        "bearer token",
        "Bearer two tokens",
        "Bearer token,token",
    ] {
        assert_eq!(
            prepare_request(request(token), AUTHORITY).unwrap_err(),
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(
        prepare_request(
            request(&format!("Bearer {}", "x".repeat(MAX_TOKEN_BYTES + 1))),
            AUTHORITY
        )
        .unwrap_err(),
        StatusCode::UNAUTHORIZED
    );
    let mut duplicate_host = request(WORKSPACE_ONE);
    duplicate_host
        .headers_mut()
        .append("host", HeaderValue::from_static(AUTHORITY));
    assert_eq!(
        prepare_request(duplicate_host, AUTHORITY).unwrap_err(),
        StatusCode::FORBIDDEN
    );
    let mut no_host = request(WORKSPACE_ONE);
    no_host.headers_mut().remove("host");
    assert_eq!(
        prepare_request(no_host, AUTHORITY).unwrap_err(),
        StatusCode::FORBIDDEN
    );
    let mut oversized_header = request(WORKSPACE_ONE);
    oversized_header.headers_mut().insert(
        "x-test",
        HeaderValue::from_str(&"x".repeat(CREDENTIAL_BRIDGE_MAX_HEADER_VALUE_BYTES + 1)).unwrap(),
    );
    assert_eq!(
        prepare_request(oversized_header, AUTHORITY).unwrap_err(),
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn ready_precedes_admitted_headers_and_identity_never_enters_request_frames() {
    let mut fixture = Harness::new(false).await;
    let mut input = request(WORKSPACE_ONE);
    input.headers_mut().insert(
        "cookie",
        HeaderValue::from_static("synthetic-cookie-canary"),
    );
    input.headers_mut().insert(
        "proxy-authorization",
        HeaderValue::from_static("synthetic-proxy-canary"),
    );
    let http = fixture.submit(input);
    let mut call = fixture.call().await;
    assert_eq!(call.gateway, format!("Bearer {GATEWAY_ONE}"));
    assert_eq!(call.workspace, WORKSPACE_ONE.as_bytes());
    assert!(matches!(
        call.frames.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
    assert!(!http.is_finished());
    call.accept();
    let forwarded = call.request().await;
    assert_eq!(forwarded.method, "POST");
    // Shared framing consumes the public /v1 prefix; the broker's selected
    // provider base supplies its own prefix for this private relative route.
    assert_eq!(forwarded.path, "/responses");
    assert!(forwarded.query.is_empty());
    assert_eq!(forwarded.body, b"{}");
    for header in &forwarded.headers {
        assert!(
            ![
                "authorization",
                "proxy-authorization",
                "cookie",
                WORKSPACE_AUTHORIZATION,
                ASCII_WORKSPACE_AUTHORIZATION,
                DAEMON_AUTH_TOKEN_HEADER
            ]
            .contains(&header.name.as_str())
        );
        assert!(!String::from_utf8_lossy(&header.value).contains("canary"));
    }
    call.start(&forwarded.request_id).await;
    let response = bounded(http).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    call.finish(&forwarded.request_id, b"data: synthetic\n\n")
        .await;
    let body = bounded(to_bytes(response.into_body(), 1024)).await.unwrap();
    assert_eq!(body.as_ref(), b"data: synthetic\n\n");
    call.closed().await;
    fixture.stop().await;
}

#[tokio::test]
async fn dropping_handler_before_rpc_headers_closes_outgoing_transport() {
    let mut fixture = Harness::new(false).await;
    let http = fixture.submit(request(WORKSPACE_ONE));
    let mut call = fixture.call().await;
    assert!(matches!(
        call.frames.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
    http.abort();
    assert!(bounded(http).await.unwrap_err().is_cancelled());
    call.closed().await;
    assert!(bounded(call.frames.recv()).await.is_none());
    fixture.stop().await;
}

#[tokio::test]
async fn dropping_response_body_closes_whole_call_with_peer_writer_retained() {
    let mut fixture = Harness::new(false).await;
    let http = fixture.submit(request(WORKSPACE_ONE));
    let mut call = fixture.call().await;
    call.accept();
    let forwarded = call.request().await;
    call.start(&forwarded.request_id).await;
    let response = bounded(http).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        fixture.ingress.state.permits.available_permits(),
        CREDENTIAL_BRIDGE_MAX_IN_FLIGHT - 1
    );
    drop(response);
    call.closed().await;
    fixture.stop().await;
}

#[tokio::test]
async fn rejected_private_headers_never_activate_or_expose_upstream_error_text() {
    let mut fixture = Harness::new(true).await;
    let http = fixture.submit(request(WORKSPACE_ONE));
    let mut call = fixture.call().await;
    call.accept();
    let response = bounded(http).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(
        bounded(to_bytes(response.into_body(), 1024))
            .await
            .unwrap()
            .is_empty()
    );
    call.closed().await;
    assert!(bounded(call.frames.recv()).await.is_none());
    fixture.stop().await;
}

#[tokio::test]
async fn real_h2_https_authority_is_normalized_only_after_exact_ingress_validation() {
    let mut fixture = Harness::new(false).await;
    let ingress = fixture.ingress.clone();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let shutdown = CancellationToken::new();
    let server_shutdown = shutdown.clone();
    // The socket is deliberately cleartext in this protocol-only fixture. A
    // real h2 client still sends :scheme=https and :authority; production TLS
    // listener establishment is a separate, not-yet-activated owner boundary.
    let router = Router::new().fallback(move |request: Request<Body>| {
        let ingress = ingress.clone();
        async move { ingress.respond(request).await }
    });
    let server = tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(server_shutdown.cancelled_owned())
            .await
            .unwrap();
    });
    let socket = bounded(TcpStream::connect(address)).await.unwrap();
    let (mut client, connection) = bounded(hyper::client::conn::http2::handshake::<
        _,
        _,
        Full<Bytes>,
    >(TokioExecutor::new(), TokioIo::new(socket)))
    .await
    .unwrap();
    let transport = tokio::spawn(connection);
    for (method, uri, slot, route, path, query) in [
        (
            Method::POST,
            "/v1/responses",
            "codex",
            "openai-api",
            "/responses",
            "",
        ),
        (
            Method::POST,
            "/_codewire/openai/v1/responses",
            "openai",
            "openai-api",
            "/responses",
            "",
        ),
        (
            Method::POST,
            "/v1/messages?beta=true",
            "anthropic",
            "anthropic-api",
            "/messages",
            "beta=true",
        ),
        (
            Method::GET,
            "/_codewire/github/owner/repo.git/info/refs?service=git-upload-pack",
            "github",
            "github-https",
            "/owner/repo.git/info/refs",
            "service=git-upload-pack",
        ),
    ] {
        let mut accepted = client.clone();
        let expected_method = method.clone();
        let http = tokio::spawn(async move {
            accepted
                .send_request(
                    Request::builder()
                        .method(method)
                        .uri(format!("https://{AUTHORITY}{uri}"))
                        .header("authorization", WORKSPACE_ONE)
                        .header("content-type", "application/json")
                        .body(Full::new(Bytes::from_static(b"{}")))
                        .unwrap(),
                )
                .await
                .unwrap()
        });
        let mut call = fixture.call().await;
        call.accept();
        let forwarded = call.request().await;
        assert_eq!(
            (
                forwarded.capability_slot.as_str(),
                forwarded.route.as_str(),
                forwarded.method.as_str(),
                forwarded.path.as_str(),
                forwarded.query.as_str()
            ),
            (slot, route, expected_method.as_str(), path, query)
        );
        call.start(&forwarded.request_id).await;
        let response = bounded(http).await.unwrap();
        assert_eq!(response.version(), Version::HTTP_2);
        assert_eq!(response.status(), StatusCode::OK);
        call.finish(&forwarded.request_id, b"synthetic-h2").await;
        assert_eq!(
            bounded(response.into_body().collect())
                .await
                .unwrap()
                .to_bytes()
                .as_ref(),
            b"synthetic-h2"
        );
        call.closed().await;
    }

    for uri in [
        "https://foreign.internal:8443/v1/responses",
        "http://env-synthetic.gateway.internal:8443/v1/responses",
        "https://env-synthetic.gateway.internal:8443/v1/responses?not=canonical",
        "https://api.github.com/graphql",
        "https://env-synthetic.gateway.internal:8443/v1/messages?beta=false",
        "https://env-synthetic.gateway.internal:8443/_codewire/github/owner/repo.git/arbitrary",
    ] {
        let response = bounded(
            client.send_request(
                Request::builder()
                    .method(Method::POST)
                    .uri(uri)
                    .header("authorization", WORKSPACE_ONE)
                    .body(Full::new(Bytes::from_static(b"{}")))
                    .unwrap(),
            ),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(
            bounded(response.into_body().collect())
                .await
                .unwrap()
                .to_bytes()
                .is_empty()
        );
    }
    assert!(matches!(
        fixture.calls.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
    drop(client);
    bounded(fixture.ingress.shutdown()).await;
    shutdown.cancel();
    bounded(transport).await.unwrap().unwrap();
    bounded(server).await.unwrap();
    fixture.stop().await;
}

#[cfg(unix)]
#[tokio::test]
async fn concurrent_calls_keep_workspace_identity_and_reread_rotated_projected_gateway_token() {
    use std::os::unix::fs::symlink;

    let mut fixture = Harness::new(false).await;
    let token = fixture.directory.path().join("token");
    std::fs::rename(&token, fixture.directory.path().join("version-one")).unwrap();
    symlink("version-one", &token).unwrap();
    let first_http = fixture.submit(request(WORKSPACE_ONE));
    let mut first = fixture.call().await;
    first.accept();
    let first_request = first.request().await;
    first.start(&first_request.request_id).await;
    let first_response = bounded(first_http).await.unwrap();

    std::fs::write(fixture.directory.path().join("version-two"), GATEWAY_TWO).unwrap();
    let replacement = fixture.directory.path().join("replacement");
    symlink("version-two", &replacement).unwrap();
    std::fs::rename(replacement, token).unwrap();
    let second_http = fixture.submit(request(WORKSPACE_TWO));
    let mut second = fixture.call().await;
    second.accept();
    let second_request = second.request().await;
    assert_eq!(first.gateway, format!("Bearer {GATEWAY_ONE}"));
    assert_eq!(second.gateway, format!("Bearer {GATEWAY_TWO}"));
    assert_eq!(first.workspace, WORKSPACE_ONE.as_bytes());
    assert_eq!(second.workspace, WORKSPACE_TWO.as_bytes());
    assert_ne!(first_request.request_id, second_request.request_id);
    second.start(&second_request.request_id).await;
    let second_response = bounded(second_http).await.unwrap();
    assert_eq!(
        fixture.ingress.state.permits.available_permits(),
        CREDENTIAL_BRIDGE_MAX_IN_FLIGHT - 2
    );
    drop(first_response);
    first.closed().await;
    second
        .finish(&second_request.request_id, b"only-second-workspace")
        .await;
    assert_eq!(
        bounded(to_bytes(second_response.into_body(), 1024))
            .await
            .unwrap()
            .as_ref(),
        b"only-second-workspace"
    );
    second.closed().await;
    fixture.stop().await;
}

#[tokio::test]
async fn peer_expiry_errors_body_and_ends_outgoing_without_reconnecting_with_new_identity() {
    let mut fixture = Harness::new(false).await;
    let http = fixture.submit(request(WORKSPACE_ONE));
    let mut call = fixture.call().await;
    call.accept();
    let forwarded = call.request().await;
    call.start(&forwarded.request_id).await;
    let response = bounded(http).await.unwrap();
    std::fs::write(fixture.directory.path().join("token"), GATEWAY_TWO).unwrap();
    // The production broker owns the verified original deadline. Its terminal
    // response is not permission to reopen this request under a rotated token.
    bounded(call.responses.send(Err(Status::unauthenticated(
        "opaque-synthetic-expiry-canary",
    ))))
    .await
    .unwrap();
    let failure = bounded(to_bytes(response.into_body(), 1024))
        .await
        .unwrap_err();
    assert!(
        !failure
            .to_string()
            .contains("opaque-synthetic-expiry-canary")
    );
    call.closed().await;
    assert!(matches!(
        fixture.calls.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
    fixture.stop().await;
}

struct PendingBody {
    polls: Arc<AtomicUsize>,
    drops: Arc<AtomicUsize>,
}

impl Stream for PendingBody {
    type Item = Result<Bytes, std::io::Error>;

    fn poll_next(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.polls.fetch_add(1, Ordering::SeqCst);
        Poll::Pending
    }
}

impl Drop for PendingBody {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}

#[tokio::test]
async fn global_admission_precedes_body_buffering_and_shutdown_drains_every_permit() {
    let mut fixture = Harness::new(false).await;
    let polls = Arc::new(AtomicUsize::new(0));
    let drops = Arc::new(AtomicUsize::new(0));
    let mut handlers = Vec::new();
    for _ in 0..CREDENTIAL_BRIDGE_MAX_IN_FLIGHT {
        let mut input = request(WORKSPACE_ONE);
        *input.body_mut() = Body::from_stream(PendingBody {
            polls: polls.clone(),
            drops: drops.clone(),
        });
        handlers.push(fixture.submit(input));
    }
    bounded(async {
        while fixture.ingress.state.permits.available_permits() != 0
            || polls.load(Ordering::SeqCst) < CREDENTIAL_BRIDGE_MAX_IN_FLIGHT
        {
            tokio::task::yield_now().await;
        }
    })
    .await;
    let rejected_polls = Arc::new(AtomicUsize::new(0));
    let rejected_drops = Arc::new(AtomicUsize::new(0));
    let mut input = request(WORKSPACE_ONE);
    *input.body_mut() = Body::from_stream(PendingBody {
        polls: rejected_polls.clone(),
        drops: rejected_drops.clone(),
    });
    assert_eq!(
        bounded(fixture.ingress.respond(input)).await.status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(rejected_polls.load(Ordering::SeqCst), 0);
    assert_eq!(rejected_drops.load(Ordering::SeqCst), 1);
    assert!(matches!(
        fixture.calls.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
    bounded(fixture.ingress.shutdown()).await;
    for handler in handlers {
        assert_eq!(
            bounded(handler).await.unwrap().status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }
    assert_eq!(
        drops.load(Ordering::SeqCst),
        CREDENTIAL_BRIDGE_MAX_IN_FLIGHT
    );
    assert_eq!(
        bounded(fixture.ingress.respond(request(WORKSPACE_ONE)))
            .await
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    fixture.stop().await;
}

#[tokio::test]
async fn body_and_identity_limits_fail_before_private_rpc_admission() {
    let mut fixture = Harness::new(false).await;
    let mut input = request(WORKSPACE_ONE);
    *input.body_mut() = Body::from(vec![b'x'; CREDENTIAL_BRIDGE_MAX_REQUEST_BYTES + 1]);
    assert_eq!(
        bounded(fixture.ingress.respond(input)).await.status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
    for workspace in [
        "Bearer ".to_owned(),
        format!("Bearer {}", "x".repeat(MAX_TOKEN_BYTES + 1)),
    ] {
        assert_eq!(
            bounded(fixture.ingress.respond(request(&workspace)))
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
    }
    for bytes in [b"".as_slice(), b"token with spaces", b"token\n", &[0xff]] {
        std::fs::write(fixture.directory.path().join("token"), bytes).unwrap();
        assert_eq!(
            bounded(fixture.ingress.respond(request(WORKSPACE_ONE)))
                .await
                .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }
    std::fs::write(
        fixture.directory.path().join("token"),
        vec![b'x'; MAX_TOKEN_BYTES + 1],
    )
    .unwrap();
    assert_eq!(
        bounded(fixture.ingress.respond(request(WORKSPACE_ONE)))
            .await
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    std::fs::remove_file(fixture.directory.path().join("token")).unwrap();
    assert_eq!(
        bounded(fixture.ingress.respond(request(WORKSPACE_ONE)))
            .await
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert!(matches!(
        fixture.calls.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
    fixture.stop().await;
}

#[tokio::test]
async fn maximum_request_body_fits_private_rpc_framing() {
    let mut fixture = Harness::new(false).await;
    let mut input = request(WORKSPACE_ONE);
    *input.body_mut() = Body::from(vec![b'x'; CREDENTIAL_BRIDGE_MAX_REQUEST_BYTES]);
    let http = fixture.submit(input);
    let mut call = fixture.call().await;
    call.accept();
    let forwarded = call.request().await;
    assert_eq!(forwarded.body.len(), CREDENTIAL_BRIDGE_MAX_REQUEST_BYTES);
    call.start(&forwarded.request_id).await;
    let response = bounded(http).await.unwrap();
    call.finish(&forwarded.request_id, b"bounded").await;
    assert_eq!(
        bounded(to_bytes(response.into_body(), 1024))
            .await
            .unwrap()
            .as_ref(),
        b"bounded"
    );
    call.closed().await;
    fixture.stop().await;
}

#[tokio::test]
async fn explicit_shutdown_closes_both_preheader_and_streaming_calls() {
    let mut fixture = Harness::new(false).await;
    let streaming_http = fixture.submit(request(WORKSPACE_ONE));
    let mut streaming = fixture.call().await;
    streaming.accept();
    let forwarded = streaming.request().await;
    streaming.start(&forwarded.request_id).await;
    let response = bounded(streaming_http).await.unwrap();
    let pending_http = fixture.submit(request(WORKSPACE_TWO));
    let mut pending = fixture.call().await;
    bounded(fixture.ingress.shutdown()).await;
    assert_eq!(
        bounded(pending_http).await.unwrap().status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    streaming.closed().await;
    pending.closed().await;
    assert!(bounded(to_bytes(response.into_body(), 1024)).await.is_err());
    assert_eq!(
        fixture.ingress.state.permits.available_permits(),
        CREDENTIAL_BRIDGE_MAX_IN_FLIGHT
    );
    fixture.stop().await;
}
