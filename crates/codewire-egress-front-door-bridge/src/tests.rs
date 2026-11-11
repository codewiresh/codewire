use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use codewire_credential_bridge::{CredentialBridgeOutput, classify_http_request};
use codewire_daemon_proto::codewire::bridge::v1;
use codewire_egress_front_door::{EnvironmentCa, FrontDoor, FrontDoorConfig};
use futures::{FutureExt, StreamExt};
use http::header::{CONNECTION, HOST, UPGRADE};
use http::{HeaderMap, Method, Request, Response, StatusCode, Uri};
use http_body_util::{BodyExt, Full};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::io::DuplexStream;
use tokio::sync::mpsc;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_stream::wrappers::ReceiverStream;
use tonic::Status;
use uuid::Uuid;
use v1::credential_bridge_guest_message::Payload as GuestPayload;
use v1::credential_bridge_host_message::Payload as HostPayload;

use super::*;

/// A failure guard, far longer than any step takes.
const WAIT: Duration = Duration::from_secs(30);
/// The loopback ingress's authority, as a client of it sends Host.
const LOOPBACK: &str = "127.0.0.1:38081";
const GITHUB_GIT_PREFIX: &str = "/_codewire/github";

async fn bounded<F: Future>(future: F) -> F::Output {
    tokio::time::timeout(WAIT, future)
        .await
        .expect("bounded test step")
}

/// A real credential bridge with an admitted host this test plays: it reads
/// the bridge's request frames and answers them.
struct Host {
    bridge: CredentialBridge,
    output: CredentialBridgeOutput,
    input: mpsc::Sender<Result<v1::CredentialBridgeHostMessage, Status>>,
}

impl Host {
    async fn start() -> Self {
        let bridge = CredentialBridge::new(Uuid::new_v4(), 1).unwrap();
        let (prepared, mut output) = bridge.prepare_connection().unwrap();
        let ready = bounded(output.next()).await.unwrap().unwrap();
        assert!(matches!(ready.payload, Some(GuestPayload::Ready(_))));
        let (input, receiver) = mpsc::channel(32);
        let connection = prepared
            .activate(ReceiverStream::new(receiver))
            .await
            .unwrap();
        tokio::spawn(connection.run());
        Self {
            bridge,
            output,
            input,
        }
    }

    /// The next request the bridge sent its host.
    async fn request(&mut self) -> v1::CredentialBridgeRequest {
        match bounded(self.output.next()).await.unwrap().unwrap().payload {
            Some(GuestPayload::Request(request)) => request,
            other => panic!("expected a request, got {other:?}"),
        }
    }

    /// Nothing reached the host: a request frame is queued before the
    /// bridge waits for its answer.
    fn assert_untouched(&mut self) {
        assert!(
            self.output.next().now_or_never().is_none(),
            "the bridge sent its host a frame"
        );
    }

    async fn send(&self, payload: HostPayload) {
        self.input
            .send(Ok(v1::CredentialBridgeHostMessage {
                payload: Some(payload),
            }))
            .await
            .unwrap();
    }

    async fn start_response(&self, id: &str) {
        self.send(HostPayload::ResponseStart(
            v1::CredentialBridgeResponseStart {
                request_id: id.to_owned(),
                status_code: 200,
                headers: vec![v1::CredentialHttpHeader {
                    name: "content-type".to_owned(),
                    value: b"text/plain".to_vec(),
                }],
            },
        ))
        .await;
    }

    async fn chunk(&self, id: &str, data: &[u8]) {
        self.send(HostPayload::ResponseBody(
            v1::CredentialBridgeResponseBody {
                request_id: id.to_owned(),
                data: data.to_vec(),
            },
        ))
        .await;
    }

    async fn end(&self, id: &str) {
        self.send(HostPayload::ResponseEnd(v1::CredentialBridgeResponseEnd {
            request_id: id.to_owned(),
        }))
        .await;
    }

    async fn answer(&self, id: &str) {
        self.start_response(id).await;
        self.chunk(id, b"hello, ").await;
        self.chunk(id, b"world").await;
        self.end(id).await;
    }

    fn backend(&self, routes: RouteTable) -> Arc<CredentialRouteBackend> {
        Arc::new(CredentialRouteBackend::new(routes, self.bridge.clone()))
    }
}

async fn body_of<B>(response: Response<B>) -> Bytes
where
    B: HttpBody<Data = Bytes>,
    B::Error: std::fmt::Debug,
{
    response.into_body().collect().await.unwrap().to_bytes()
}

/// One request through the back end; the bridge request and the answer.
async fn through_backend(
    host: &mut Host,
    backend: &Arc<CredentialRouteBackend>,
    bound: &str,
    request: Request<Full<Bytes>>,
) -> (v1::CredentialBridgeRequest, Bytes) {
    let task = tokio::spawn({
        let backend = backend.clone();
        let bound = bound.to_owned();
        async move { backend.forward(&bound, request).await }
    });
    let seen = host.request().await;
    host.answer(&seen.request_id).await;
    let response = bounded(task).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    (seen, body_of(response).await)
}

/// The same request as the loopback ingress hands it to the bridge.
async fn through_loopback(
    host: &mut Host,
    request: Request<Full<Bytes>>,
) -> v1::CredentialBridgeRequest {
    let task = tokio::spawn({
        let bridge = host.bridge.clone();
        async move { bridge.respond(request.map(Body::new)).await }
    });
    let seen = host.request().await;
    host.answer(&seen.request_id).await;
    let response = bounded(task).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_of(response).await, "hello, world");
    seen
}

/// A refused request: its status, an empty body, and nothing at the host.
async fn refused(
    host: &mut Host,
    backend: &CredentialRouteBackend,
    bound: &str,
    uri: &str,
) -> StatusCode {
    let request = Request::get(uri)
        .header(HOST, bound)
        .body(Full::default())
        .unwrap();
    let response = bounded(backend.forward(bound, request)).await;
    let status = response.status();
    assert_eq!(body_of(response).await, "", "{uri}");
    host.assert_untouched();
    status
}

fn header_names(request: &v1::CredentialBridgeRequest) -> Vec<&str> {
    request
        .headers
        .iter()
        .map(|header| header.name.as_str())
        .collect()
}

// ---------------------------------------------------------------------------
// The default routes

#[tokio::test]
async fn each_default_route_reaches_the_bridge_as_its_loopback_form_does() {
    let mut host = Host::start().await;
    let backend = host.backend(RouteTable::defaults());
    // (bound host, method, path and query, the loopback form, slot, route,
    // provider path, query)
    let cases = [
        (
            "api.anthropic.com",
            Method::POST,
            "/v1/messages?beta=true",
            "/_codewire/anthropic/v1/messages?beta=true",
            "anthropic",
            "anthropic-api",
            "/v1/messages",
            "beta=true",
        ),
        (
            "api.anthropic.com",
            Method::GET,
            "/api/oauth/usage",
            "/_codewire/anthropic/api/oauth/usage",
            "anthropic",
            "anthropic-api",
            "/api/oauth/usage",
            "",
        ),
        (
            "api.openai.com",
            Method::POST,
            "/v1/responses",
            "/_codewire/openai/v1/responses",
            "openai",
            "openai-api",
            "/responses",
            "",
        ),
        (
            "api.openai.com",
            Method::GET,
            "/v1/models?limit=2",
            "/_codewire/openai/v1/models?limit=2",
            "openai",
            "openai-api",
            "/models",
            "limit=2",
        ),
        (
            "chatgpt.com",
            Method::POST,
            "/backend-api/codex/responses",
            "/v1/responses",
            "codex",
            "openai-api",
            "/responses",
            "",
        ),
        (
            "chatgpt.com",
            Method::GET,
            "/backend-api/codex/models?client_version=1.0.0",
            "/v1/models?client_version=1.0.0",
            "codex",
            "openai-api",
            "/models",
            "client_version=1.0.0",
        ),
    ];
    for (bound, method, uri, loopback_uri, slot, route, path, query) in cases {
        let build = |uri: &str, authority: &str| {
            Request::builder()
                .method(method.clone())
                .uri(uri)
                .header(HOST, authority)
                .header("content-type", "application/json")
                .header("x-api-key", "placeholder")
                .header("anthropic-beta", "one")
                .header("anthropic-beta", "two")
                .header("accept", "text/event-stream")
                .body(Full::new(Bytes::from_static(b"{\"stream\":true}")))
                .unwrap()
        };
        let (seen, body) = through_backend(&mut host, &backend, bound, build(uri, bound)).await;
        assert_eq!(body, "hello, world");
        assert_eq!(
            (
                seen.capability_slot.as_str(),
                seen.route.as_str(),
                seen.path.as_str(),
                seen.query.as_str()
            ),
            (slot, route, path, query),
            "{bound}{uri}"
        );
        assert_eq!(seen.method, method.as_str());
        assert_eq!(seen.body, b"{\"stream\":true}");
        assert_eq!(
            header_names(&seen),
            [
                "content-type",
                "x-api-key",
                "anthropic-beta",
                "anthropic-beta",
                "accept"
            ],
            "every header but Host, in order"
        );

        let mut loopback = through_loopback(&mut host, build(loopback_uri, LOOPBACK)).await;
        // The loopback form differs only in its request id and in the Host
        // naming the loopback ingress, which the broker drops.
        assert_eq!(loopback.headers[0].name, "host");
        assert_eq!(loopback.headers[0].value, LOOPBACK.as_bytes());
        loopback.headers.remove(0);
        loopback.request_id.clone_from(&seen.request_id);
        assert_eq!(seen, loopback, "{bound}{uri}");
    }
}

#[test]
fn the_defaults_bind_three_hosts() {
    let defaults = RouteTable::defaults();
    assert_eq!(
        defaults.routes(),
        [
            HostRoute::new("api.anthropic.com", "/", "/_codewire/anthropic"),
            HostRoute::new("api.openai.com", "/v1", "/_codewire/openai/v1"),
            HostRoute::new("chatgpt.com", "/backend-api/codex", "/v1"),
        ]
    );
    assert_eq!(
        defaults.hosts(),
        ["api.anthropic.com", "api.openai.com", "chatgpt.com"]
    );
    EnvironmentCa::generate(defaults.hosts()).expect("the CA binds every default host");
}

/// The managed prefixes are partly a literal in the bridge's classifier:
/// each must still select its route there.
#[test]
fn every_route_prefix_is_recognised_by_the_bridge() {
    let cases = [
        (
            MANAGED_ANTHROPIC_API_PREFIX,
            Method::POST,
            "/v1/messages",
            "anthropic",
            "anthropic-api",
        ),
        (
            MANAGED_OPENAI_API_PREFIX,
            Method::POST,
            "/responses",
            "openai",
            "openai-api",
        ),
        (
            GITHUB_GIT_PREFIX,
            Method::GET,
            "/owner/repo.git/info/refs?service=git-upload-pack",
            "github",
            "github-https",
        ),
        (
            CODEX_PREFIX,
            Method::POST,
            "/responses",
            "codex",
            "openai-api",
        ),
    ];
    assert_eq!(cases.each_ref().map(|case| case.0), route_prefixes());
    for (prefix, method, rest, slot, route) in cases {
        let uri: Uri = format!("{prefix}{rest}").parse().unwrap();
        let classified = classify_http_request(&method, &uri, &HeaderMap::new())
            .unwrap_or_else(|status| panic!("{prefix} refused: {status}"));
        assert_eq!(
            (classified.capability_slot, classified.route),
            (slot, route),
            "{prefix}"
        );
    }
}

// ---------------------------------------------------------------------------
// Matching and refusals

fn rewrite(table: &RouteTable, host: &str, uri: &str) -> Result<String, StatusCode> {
    table
        .rewrite(host, &uri.parse().unwrap())
        .map(|uri| uri.to_string())
}

#[test]
fn the_longest_prefix_at_a_segment_boundary_wins() {
    let table = RouteTable::new([
        HostRoute::new("a.example.com", "/", MANAGED_ANTHROPIC_API_PREFIX),
        HostRoute::new("a.example.com", "/v1", MANAGED_OPENAI_API_PREFIX),
        HostRoute::new("a.example.com", "/v1/deep", CODEX_PREFIX),
        HostRoute::new("b.example.com", "/v1", CODEX_PREFIX),
    ])
    .unwrap();
    let cases = [
        ("a.example.com", "/", Ok("/_codewire/anthropic/")),
        ("a.example.com", "/x", Ok("/_codewire/anthropic/x")),
        ("a.example.com", "/v1x", Ok("/_codewire/anthropic/v1x")),
        ("a.example.com", "/v1", Ok("/_codewire/openai/v1")),
        ("a.example.com", "/v1/", Ok("/_codewire/openai/v1/")),
        ("a.example.com", "/v1/x", Ok("/_codewire/openai/v1/x")),
        (
            "a.example.com",
            "/v1/deeper",
            Ok("/_codewire/openai/v1/deeper"),
        ),
        ("a.example.com", "/v1/deep", Ok("/v1")),
        ("a.example.com", "/v1/deep/x/y", Ok("/v1/x/y")),
        ("b.example.com", "/v1/x", Ok("/v1/x")),
        ("b.example.com", "/v1x", Err(StatusCode::NOT_FOUND)),
        ("b.example.com", "/v2/x", Err(StatusCode::NOT_FOUND)),
        ("b.example.com", "/", Err(StatusCode::NOT_FOUND)),
        // Exact hosts only: the front door passes the canonical bound host.
        ("B.example.com", "/v1/x", Err(StatusCode::NOT_FOUND)),
        ("c.example.com", "/v1/x", Err(StatusCode::NOT_FOUND)),
    ];
    for (host, uri, expected) in cases {
        assert_eq!(
            rewrite(&table, host, uri),
            expected.map(str::to_owned),
            "{host}{uri}"
        );
    }
}

#[tokio::test]
async fn a_request_no_route_covers_is_404_and_never_reaches_the_bridge() {
    let mut host = Host::start().await;
    let backend = host.backend(RouteTable::defaults());
    for (bound, uri) in [
        ("other.example.com", "/v1/models"),
        ("api.openai.com", "/v2/models"),
        ("api.openai.com", "/v1x"),
        ("api.openai.com", "/"),
        ("chatgpt.com", "/backend-api/other"),
        ("chatgpt.com", "/backend-api/codexx"),
        ("chatgpt.com", "/"),
    ] {
        assert_eq!(
            refused(&mut host, &backend, bound, uri).await,
            StatusCode::NOT_FOUND,
            "{bound}{uri}"
        );
    }
}

#[tokio::test]
async fn a_path_decoding_or_resolution_could_change_is_400_and_never_reaches_the_bridge() {
    let mut host = Host::start().await;
    let backend = host.backend(RouteTable::defaults());
    let refused_paths = [
        "/v1/../x",
        "/v1/..",
        "/..",
        "/v1/./x",
        "/v1/.",
        "/.",
        "//v1/messages",
        "/v1//messages",
        "/v1/messages//",
        "/v1/%2e%2e/x",
        "/v1/%2E%2E/x",
        "/v1/%2e/x",
        "/v1/.%2e/x",
        "/v1%2fmessages",
        "/v1/a%2Fb",
        "/%2e",
        "/v1/x%2E",
    ];
    for path in refused_paths {
        let uri: Uri = path.parse().unwrap();
        assert_eq!(uri.path(), path, "the URI parser keeps the raw path");
        for bound in ["api.anthropic.com", "api.openai.com"] {
            assert_eq!(
                refused(&mut host, &backend, bound, path).await,
                StatusCode::BAD_REQUEST,
                "{bound}{path}"
            );
        }
    }
    // Dots and encodings inside a segment, and in the query, are ordinary.
    for (uri, path) in [
        ("/v1/files/file.v2..x", "/v1/files/file.v2..x"),
        (
            "/v1/files/file%2Dabc:content",
            "/v1/files/file%2Dabc:content",
        ),
        ("/v1/messages?next=%2e%2e%2F..", "/v1/messages"),
    ] {
        let request = Request::get(uri).body(Full::default()).unwrap();
        let (seen, _) = through_backend(&mut host, &backend, "api.anthropic.com", request).await;
        assert_eq!(seen.path, path);
    }
}

#[tokio::test]
async fn the_query_is_kept_byte_for_byte() {
    let mut host = Host::start().await;
    let backend = host.backend(RouteTable::defaults());
    let query = "a=1&b=%2F%2e%zz&c=x/y?z&d=:@!$'()*+,;=&e=&&f~-._&g=%E2%9C%93&a=2";
    let uri = format!("/v1/messages?{query}");
    let request = Request::post(uri.as_str()).body(Full::default()).unwrap();
    assert_eq!(request.uri().query(), Some(query));
    assert_eq!(
        rewrite(&RouteTable::defaults(), "api.anthropic.com", &uri),
        Ok(format!("/_codewire/anthropic/v1/messages?{query}"))
    );
    let (seen, _) = through_backend(&mut host, &backend, "api.anthropic.com", request).await;
    assert_eq!(seen.query, query);

    // An empty query keeps its `?`; the bridge reads it as no query.
    assert_eq!(
        rewrite(&RouteTable::defaults(), "api.openai.com", "/v1/models?"),
        Ok("/_codewire/openai/v1/models?".to_owned())
    );
    let request = Request::get("/v1/models?").body(Full::default()).unwrap();
    let (seen, _) = through_backend(&mut host, &backend, "api.openai.com", request).await;
    assert_eq!((seen.path.as_str(), seen.query.as_str()), ("/models", ""));
}

/// Without Host, the rewritten path alone picks the family: with it,
/// `api.github.com` would select the GitHub API family instead.
#[tokio::test]
async fn host_never_selects_the_route() {
    let mut host = Host::start().await;
    let backend = host.backend(
        RouteTable::new([HostRoute::new("api.github.com", "/", GITHUB_GIT_PREFIX)]).unwrap(),
    );
    let request = Request::get("/owner/repo.git/info/refs?service=git-upload-pack")
        .header(HOST, "api.github.com")
        .body(Full::default())
        .unwrap();
    let (seen, _) = through_backend(&mut host, &backend, "api.github.com", request).await;
    assert_eq!(
        (seen.capability_slot.as_str(), seen.route.as_str()),
        ("github", "github-https")
    );
    assert_eq!(seen.path, "/owner/repo.git/info/refs");
    assert!(header_names(&seen).is_empty());
}

#[tokio::test]
async fn an_upgrade_is_403_and_never_reaches_the_bridge() {
    let mut host = Host::start().await;
    let backend = host.backend(RouteTable::defaults());
    let request = Request::get("/backend-api/codex/responses")
        .header(HOST, "chatgpt.com")
        .header(CONNECTION, "Upgrade")
        .header(UPGRADE, "websocket")
        .body(())
        .unwrap();
    let Err(response) = bounded(backend.upgrade("chatgpt.com", request)).await else {
        panic!("an upgrade was accepted");
    };
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(body_of(response).await, "");
    host.assert_untouched();
}

// ---------------------------------------------------------------------------
// The route table

#[test]
fn route_tables_are_validated() {
    let route = |host: &str, strip: &str, add: &str| HostRoute::new(host, strip, add);
    let ok = |strip: &str| route("api.example.com", strip, CODEX_PREFIX);
    let invalid: Vec<(Vec<HostRoute>, RouteTableError)> = vec![
        (vec![], RouteTableError::Count),
        (
            (0..33)
                .map(|index| route(&format!("h{index}.example.com"), "/", CODEX_PREFIX))
                .collect(),
            RouteTableError::Count,
        ),
        (
            vec![route("API.example.com", "/", CODEX_PREFIX)],
            RouteTableError::Host,
        ),
        (
            vec![route("api.example.com.", "/", CODEX_PREFIX)],
            RouteTableError::Host,
        ),
        (
            vec![route("*.example.com", "/", CODEX_PREFIX)],
            RouteTableError::Host,
        ),
        (
            vec![route("192.0.2.1", "/", CODEX_PREFIX)],
            RouteTableError::Host,
        ),
        (vec![route("com", "/", CODEX_PREFIX)], RouteTableError::Host),
        (vec![route("", "/", CODEX_PREFIX)], RouteTableError::Host),
        (vec![ok("")], RouteTableError::Prefix),
        (vec![ok("v1")], RouteTableError::Prefix),
        (vec![ok("/v1/")], RouteTableError::Prefix),
        (vec![ok("//")], RouteTableError::Prefix),
        (vec![ok("/a//b")], RouteTableError::Prefix),
        (vec![ok("/a/../b")], RouteTableError::Prefix),
        (vec![ok("/a..b")], RouteTableError::Prefix),
        (vec![ok("/a/./b")], RouteTableError::Prefix),
        (vec![ok("/.")], RouteTableError::Prefix),
        (vec![ok("/a?b")], RouteTableError::Prefix),
        (vec![ok("/a#b")], RouteTableError::Prefix),
        (vec![ok("/a%2fb")], RouteTableError::Prefix),
        (vec![ok("/a b")], RouteTableError::Prefix),
        (
            vec![route("api.example.com", "/", "v1")],
            RouteTableError::Prefix,
        ),
        (
            vec![route("api.example.com", "/", "/_codewire/github/")],
            RouteTableError::Prefix,
        ),
        (
            vec![route("api.example.com", "/", "/")],
            RouteTableError::UnknownRoute,
        ),
        (
            vec![route("api.example.com", "/", "/_codewire/other")],
            RouteTableError::UnknownRoute,
        ),
        (
            vec![route("api.example.com", "/", "/v1/responses")],
            RouteTableError::UnknownRoute,
        ),
        (
            vec![route("api.example.com", "/", "/_codewire/openai")],
            RouteTableError::UnknownRoute,
        ),
        (vec![ok("/v1"), ok("/v1")], RouteTableError::Duplicate),
        (
            vec![
                route("api.example.com", "/v1", CODEX_PREFIX),
                route("api.example.com", "/v1", MANAGED_OPENAI_API_PREFIX),
            ],
            RouteTableError::Duplicate,
        ),
    ];
    for (routes, error) in invalid {
        let shown = format!("{routes:?}");
        assert_eq!(RouteTable::new(routes), Err(error), "{shown}");
    }

    let most: Vec<HostRoute> = (0..32)
        .map(|index| route(&format!("h{index}.example.com"), "/", CODEX_PREFIX))
        .collect();
    assert_eq!(RouteTable::new(most.clone()).unwrap().routes(), most);
    let shared = vec![
        route("api.example.com", "/", MANAGED_ANTHROPIC_API_PREFIX),
        route("api.example.com", "/v1", MANAGED_OPENAI_API_PREFIX),
        route("api.example.com", "/v1/a-b_c.d~e", CODEX_PREFIX),
        route("other.example.com", "/v1", MANAGED_OPENAI_API_PREFIX),
        route("other.example.com", "/git", GITHUB_GIT_PREFIX),
    ];
    let table = RouteTable::new(shared.clone()).unwrap();
    assert_eq!(table.routes(), shared);
    assert_eq!(table.hosts(), ["api.example.com", "other.example.com"]);
}

// ---------------------------------------------------------------------------
// Through a real front door

/// A client that trusts only `ca`.
fn client_config(ca: &EnvironmentCa, alpn: &[&[u8]]) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.add(ca.certificate_der().clone()).unwrap();
    let mut config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();
    Arc::new(config)
}

async fn connect(
    door: &Arc<FrontDoor<CredentialRouteBackend>>,
    bound: &'static str,
    alpn: &[&[u8]],
) -> TlsStream<DuplexStream> {
    let (client, server) = tokio::io::duplex(64 * 1024);
    tokio::spawn({
        let door = door.clone();
        async move { door.accept(server, bound).await }
    });
    bounded(
        TlsConnector::from(client_config(door.ca(), alpn))
            .connect(ServerName::try_from(bound).unwrap(), client),
    )
    .await
    .expect("handshake")
}

#[tokio::test]
async fn requests_through_a_front_door_reach_the_bridge_and_replies_stream_back() {
    let mut host = Host::start().await;
    let routes = RouteTable::defaults();
    let ca = EnvironmentCa::generate(routes.hosts()).unwrap();
    let door = Arc::new(FrontDoor::new(
        ca,
        CredentialRouteBackend::new(routes, host.bridge.clone()),
        FrontDoorConfig::default(),
    ));

    // HTTP/1.1: a GET whose reply streams, chunk by chunk.
    let tls = connect(&door, "api.openai.com", &[b"http/1.1"]).await;
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .unwrap();
    tokio::spawn(connection.with_upgrades());
    let request = Request::get("/v1/models?limit=2")
        .header(HOST, "api.openai.com")
        .header("accept", "application/json")
        .body(Full::<Bytes>::default())
        .unwrap();
    let response = tokio::spawn(sender.send_request(request));
    let seen = host.request().await;
    assert_eq!(
        (
            seen.capability_slot.as_str(),
            seen.route.as_str(),
            seen.method.as_str(),
            seen.path.as_str(),
            seen.query.as_str()
        ),
        ("openai", "openai-api", "GET", "/models", "limit=2")
    );
    assert_eq!(header_names(&seen), ["accept"]);
    host.start_response(&seen.request_id).await;
    host.chunk(&seen.request_id, b"hello, ").await;
    let response = bounded(response).await.unwrap().unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["content-type"], "text/plain");
    let mut body = response.into_body();
    let first = bounded(body.frame()).await.unwrap().unwrap();
    assert_eq!(
        first.into_data().unwrap(),
        "hello, ",
        "before the rest exists"
    );
    host.chunk(&seen.request_id, b"world").await;
    host.end(&seen.request_id).await;
    assert_eq!(body.collect().await.unwrap().to_bytes(), "world");

    // A WebSocket opening request on the same connection is refused there.
    bounded(sender.ready()).await.unwrap();
    let websocket = Request::get("/v1/responses")
        .header(HOST, "api.openai.com")
        .header(CONNECTION, "Upgrade")
        .header(UPGRADE, "websocket")
        .header("sec-websocket-version", "13")
        .body(Full::default())
        .unwrap();
    let response = bounded(sender.send_request(websocket)).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    host.assert_untouched();

    // HTTP/2, with no Host header: a POST whose body reaches the bridge.
    let tls = connect(&door, "chatgpt.com", &[b"h2"]).await;
    let (mut sender, connection) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
            .await
            .unwrap();
    tokio::spawn(connection);
    let request = Request::post("https://chatgpt.com/backend-api/codex/responses")
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from_static(b"{\"input\":\"hi\"}")))
        .unwrap();
    let response = tokio::spawn(sender.send_request(request));
    let seen = host.request().await;
    assert_eq!(
        (
            seen.capability_slot.as_str(),
            seen.route.as_str(),
            seen.method.as_str(),
            seen.path.as_str()
        ),
        ("codex", "openai-api", "POST", "/responses")
    );
    assert_eq!(seen.body, b"{\"input\":\"hi\"}");
    assert_eq!(header_names(&seen), ["content-type"]);
    host.answer(&seen.request_id).await;
    let response = bounded(response).await.unwrap().unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_of(response).await, "hello, world");
    door.close();
}
