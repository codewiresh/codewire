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
        Self::start_with(&[]).await
    }

    /// A host whose Open lists `capabilities`.
    async fn start_with(capabilities: &[&str]) -> Self {
        let capabilities = capabilities
            .iter()
            .map(|capability| (*capability).to_owned())
            .collect::<Vec<_>>();
        let bridge = CredentialBridge::new(Uuid::new_v4(), 1).unwrap();
        let (prepared, mut output) = bridge.prepare_connection().unwrap();
        let ready = bounded(output.next()).await.unwrap().unwrap();
        assert!(matches!(ready.payload, Some(GuestPayload::Ready(_))));
        let (input, receiver) = mpsc::channel(32);
        let connection = prepared
            .activate_with_capabilities(ReceiverStream::new(receiver), &capabilities)
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

/// A refused request: its status, the spec's sentence for it, naming the
/// bound host and nothing of the request, and nothing at the host.
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
    let (reason, sentence) = match status {
        StatusCode::NOT_FOUND => (
            "path_not_served",
            format!("this path on {bound} isn't one Codewire forwards."),
        ),
        StatusCode::FORBIDDEN => (
            "route_not_served",
            format!("requests to {bound} can't use this environment's credentials yet."),
        ),
        _ => (
            "request_not_forwarded",
            format!("this request to {bound} isn't one Codewire forwards."),
        ),
    };
    assert_eq!(response.headers()["codewire-refusal"], reason, "{uri}");
    assert_eq!(
        body_of(response).await,
        format!("Codewire: {sentence}\n"),
        "{uri}"
    );
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

/// One default route's request: (bound host, method, path and query, the
/// loopback form, slot, route, provider path, query).
type RouteCase = (
    &'static str,
    Method,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
);

#[tokio::test]
async fn each_default_route_reaches_the_bridge_as_its_loopback_form_does() {
    reach_the_bridge_as_their_loopback_forms_do([
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
            "platform.claude.com",
            Method::POST,
            "/v1/oauth/token",
            "/_codewire/anthropic-oauth/v1/oauth/token",
            "anthropic",
            "claude-oauth-token",
            "/v1/oauth/token",
            "",
        ),
        (
            "platform.claude.com",
            Method::GET,
            "/v1/oauth/profile?account=1",
            "/_codewire/anthropic-oauth/v1/oauth/profile?account=1",
            "anthropic",
            "claude-oauth-token",
            "/v1/oauth/profile",
            "account=1",
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
        // chatgpt.com maps whole: the broker narrows it to Codex's paths.
        (
            "chatgpt.com",
            Method::POST,
            "/backend-api/codex/responses",
            "/v1/backend-api/codex/responses",
            "codex",
            "openai-api",
            "/backend-api/codex/responses",
            "",
        ),
        (
            "chatgpt.com",
            Method::GET,
            "/backend-api/codex/models?client_version=1.0.0",
            "/v1/backend-api/codex/models?client_version=1.0.0",
            "codex",
            "openai-api",
            "/backend-api/codex/models",
            "client_version=1.0.0",
        ),
        (
            "chatgpt.com",
            Method::GET,
            "/backend-api/wham/usage",
            "/v1/backend-api/wham/usage",
            "codex",
            "openai-api",
            "/backend-api/wham/usage",
            "",
        ),
    ])
    .await;
}

/// Codex's token host maps whole on the Codex route too (#6197).
#[tokio::test]
async fn codexs_token_host_reaches_the_bridge_as_its_loopback_form_does() {
    reach_the_bridge_as_their_loopback_forms_do([
        (
            "auth.openai.com",
            Method::POST,
            "/oauth/token",
            "/v1/oauth/token",
            "codex",
            "openai-api",
            "/oauth/token",
            "",
        ),
        (
            "auth.openai.com",
            Method::GET,
            "/oauth/authorize?response_type=code",
            "/v1/oauth/authorize?response_type=code",
            "codex",
            "openai-api",
            "/oauth/authorize",
            "response_type=code",
        ),
    ])
    .await;
}

/// Each case reaches the bridge, through the defaults and Claude's token host
/// as a Claude sign-in binds them, exactly as its loopback form does.
async fn reach_the_bridge_as_their_loopback_forms_do(cases: impl IntoIterator<Item = RouteCase>) {
    let mut host = Host::start().await;
    let backend = host.backend(RouteTable::with_optional_hosts(true, false));
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
        // The loopback form differs only in its request id, in the Host
        // naming the loopback ingress, which the broker drops, and in naming
        // no intercepted host.
        assert_eq!(loopback.headers[0].name, "host");
        assert_eq!(loopback.headers[0].value, LOOPBACK.as_bytes());
        loopback.headers.remove(0);
        loopback.request_id.clone_from(&seen.request_id);
        assert_eq!(seen.intercepted_host, bound);
        assert_eq!(loopback.intercepted_host, "");
        loopback.intercepted_host.clone_from(&seen.intercepted_host);
        assert_eq!(seen, loopback, "{bound}{uri}");
    }
}

#[test]
fn the_defaults_bind_four_hosts() {
    let defaults = RouteTable::defaults();
    assert_eq!(
        defaults.routes(),
        [
            HostRoute::new("api.anthropic.com", "/", "/_codewire/anthropic"),
            HostRoute::new("api.openai.com", "/v1", "/_codewire/openai/v1"),
            HostRoute::new("chatgpt.com", "/", "/v1"),
            HostRoute::new("auth.openai.com", "/", "/v1"),
        ]
    );
    assert_eq!(
        defaults.hosts(),
        [
            "api.anthropic.com",
            "api.openai.com",
            "chatgpt.com",
            "auth.openai.com"
        ]
    );
    assert_eq!(defaults.suffixes(), ["chatgpt.com"]);
    EnvironmentCa::generate_with_suffixes(defaults.hosts(), defaults.suffixes())
        .expect("the CA binds every default host and suffix");
    let intercepts = defaults.intercepts().unwrap();
    for host in [
        "api.anthropic.com",
        "api.openai.com",
        "chatgpt.com",
        "auth.openai.com",
        "routed.chatgpt.com",
    ] {
        assert!(intercepts.binds(host, 443), "{host}");
        assert!(!intercepts.binds(host, 80), "{host}");
    }
    assert!(!intercepts.binds("routed.anthropic.com", 443));
}

/// A canonical name exactly one label under the `chatgpt.com` suffix maps
/// whole to the Codex route, as `chatgpt.com` does; no other name falls to a
/// suffix route (#6195). The front door hands over only the canonical name,
/// so any other form is refused here, not normalised: no route covers it, so
/// it is refused by name (#6421).
#[test]
fn a_subname_under_a_suffix_maps_as_its_suffix_does() {
    let defaults = RouteTable::defaults();
    for refused in [
        "a.b.chatgpt.com",
        ".chatgpt.com",
        "routed.chatgpt.com.",
        "Routed.ChatGPT.com",
        "chatgpt.com.example",
        "routed.xn--chatgt-frf.com",
    ] {
        assert_eq!(
            rewrite(&defaults, refused, "/backend-api/codex/responses"),
            Err(StatusCode::FORBIDDEN),
            "{refused}"
        );
    }
    for (host, uri, rewritten) in [
        (
            "routed.chatgpt.com",
            "/backend-api/codex/responses",
            Ok("/v1/backend-api/codex/responses".to_owned()),
        ),
        (
            "xchatgpt.com",
            "/backend-api/codex/responses",
            Err(StatusCode::FORBIDDEN),
        ),
        (
            "routed.anthropic.com",
            "/v1/messages",
            Err(StatusCode::FORBIDDEN),
        ),
        (
            "routed.api.openai.com",
            "/v1/responses",
            Err(StatusCode::FORBIDDEN),
        ),
    ] {
        assert_eq!(rewrite(&defaults, host, uri), rewritten, "{host}{uri}");
    }
    let exact = RouteTable::new([HostRoute::new("chatgpt.com", "/", "/v1")]).unwrap();
    assert_eq!(
        exact
            .clone()
            .with_suffixes([HostRoute::new("other.example.com", "/", "/v1")]),
        Err(RouteTableError::Suffix)
    );
    assert_eq!(
        rewrite(&exact, "routed.chatgpt.com", "/backend-api/codex/responses"),
        Err(StatusCode::FORBIDDEN),
        "without the suffix route a subname is unrouted"
    );
}

/// A request for a subname reaches the bridge naming that subname and the
/// address its dial was admitted to; one without an admitted address names
/// none.
#[tokio::test]
async fn a_subname_request_carries_its_admitted_destination() {
    let mut host = Host::start().await;
    let backend = host.backend(RouteTable::defaults());
    let admitted = std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 7));
    let mut request = Request::post("/backend-api/codex/responses")
        .header(HOST, "routed.chatgpt.com")
        .body(Full::new(Bytes::from_static(b"{}")))
        .unwrap();
    request
        .extensions_mut()
        .insert(codewire_egress_front_door::InterceptedDestination(admitted));
    let (seen, _) = through_backend(&mut host, &backend, "routed.chatgpt.com", request).await;
    assert_eq!(
        (
            seen.capability_slot.as_str(),
            seen.path.as_str(),
            seen.intercepted_host.as_str(),
            seen.destination_ip.as_str()
        ),
        (
            "codex",
            "/backend-api/codex/responses",
            "routed.chatgpt.com",
            "192.0.2.7"
        )
    );
    let request = Request::get("/backend-api/wham/usage")
        .header(HOST, "chatgpt.com")
        .body(Full::default())
        .unwrap();
    let (seen, _) = through_backend(&mut host, &backend, "chatgpt.com", request).await;
    assert_eq!(seen.destination_ip, "");
}

/// Claude's token host is routed, and so bound, only when the Anthropic
/// slot holds a Claude sign-in: never for an API key, a subscription token
/// or no Anthropic client, whose agents reach it as without a front door.
#[test]
fn claudes_token_host_is_routed_only_for_a_claude_sign_in() {
    let none = ManagedCredentialClients::from_profile_slots(["openai", "ssh"]).unwrap();
    let api_key = ManagedCredentialClients::from_profile_slots(["anthropic"]).unwrap();
    let subscription = api_key.with_anthropic_subscription_token().unwrap();
    let sign_in = api_key.with_anthropic_sign_in().unwrap();
    for clients in [none, api_key, subscription] {
        let routes = RouteTable::for_clients(clients).unwrap();
        assert!(
            !routes.hosts().contains(&"platform.claude.com"),
            "{clients:?}"
        );
    }
    let routes = RouteTable::for_clients(sign_in).unwrap();
    assert_eq!(routes.hosts(), ["api.anthropic.com", "platform.claude.com"]);
    assert!(
        routes
            .routes()
            .iter()
            .any(|route| route.host == "platform.claude.com"
                && route.add_prefix == MANAGED_ANTHROPIC_OAUTH_PREFIX)
    );
    EnvironmentCa::generate(routes.hosts()).expect("the CA binds every sign-in host");
}

/// A provider's hosts are routed, and so bound, only when a selected
/// credential names them, and a selection that names none routes nothing
/// (#5215). Codex's suffix routes follow `chatgpt.com`.
#[test]
fn only_a_selected_providers_hosts_are_routed() {
    let clients = |slots: &[&str]| {
        ManagedCredentialClients::from_profile_slots(slots.iter().copied()).unwrap()
    };
    assert_eq!(RouteTable::for_clients(clients(&[])), None);
    assert_eq!(RouteTable::for_clients(clients(&["ssh"])), None);
    for (slot, hosts) in [
        ("anthropic", &["api.anthropic.com"][..]),
        ("openai", &["api.openai.com"][..]),
        ("codex", &["chatgpt.com", "auth.openai.com"][..]),
    ] {
        let routes = RouteTable::for_clients(clients(&[slot, "ssh"])).unwrap();
        assert_eq!(routes.hosts(), hosts, "{slot}");
        assert_eq!(routes.suffixes().is_empty(), slot != "codex", "{slot}");
    }
    let every = RouteTable::for_clients(clients(&["anthropic", "openai", "codex"])).unwrap();
    assert_eq!(every, RouteTable::defaults());
}

/// GitHub's two hosts are routed, and so bound, only with a GitHub
/// connection, and always together (#4001). Each covers every path with no
/// prefix: the bridge selects the route from the bound host.
#[test]
fn githubs_hosts_are_routed_only_with_a_github_connection() {
    let without = ManagedCredentialClients::from_profile_slots(["anthropic", "openai"]).unwrap();
    let routes = RouteTable::for_clients(without).unwrap();
    assert!(!routes.hosts().iter().any(|host| host.contains("github")));

    let with = ManagedCredentialClients::from_profile_slots(["github"]).unwrap();
    assert_eq!(
        RouteTable::for_clients(with).unwrap().hosts(),
        ["github.com", "api.github.com"]
    );
    let routes = RouteTable::with_optional_hosts(false, true);
    assert_eq!(
        routes.hosts(),
        [
            "api.anthropic.com",
            "api.openai.com",
            "chatgpt.com",
            "auth.openai.com",
            "github.com",
            "api.github.com"
        ]
    );
    assert_eq!(
        routes.routes()[4..],
        [
            HostRoute::by_host("github.com"),
            HostRoute::by_host("api.github.com")
        ]
    );
    EnvironmentCa::generate(routes.hosts()).expect("the CA binds GitHub's hosts");
    for (host, uri) in [
        (
            "github.com",
            "/owner/repo.git/info/refs?service=git-upload-pack",
        ),
        ("github.com", "/owner/repo/releases/download/v1/a%20b.tgz"),
        ("api.github.com", "/"),
        ("api.github.com", "/search/code?q=a%20b+c&x=%7E&empty="),
    ] {
        assert_eq!(
            rewrite(&routes, host, uri),
            Ok(uri.to_owned()),
            "{host}{uri}"
        );
    }
    // The refusal of ambiguous paths holds for them too.
    for uri in [
        "/owner/../other",
        "/owner//repo",
        "/owner/%2e%2e/x",
        "/a%2Fb",
    ] {
        assert_eq!(
            rewrite(&routes, "github.com", uri),
            Err(StatusCode::BAD_REQUEST),
            "{uri}"
        );
    }
}

/// A GitHub request reaches the bridge on the route its bound host selects,
/// its path and query as received, whatever its Host header says, and a
/// body-carrying method streams where the session's host takes streams.
#[tokio::test]
async fn a_github_request_reaches_the_bridge_on_the_route_its_host_selects() {
    let mut host = Host::start().await;
    let backend = host.backend(RouteTable::with_optional_hosts(false, true));
    for (bound, uri, route, path, query) in [
        (
            "github.com",
            "/owner/repo.git/info/refs?service=git-upload-pack",
            "github-https",
            "/owner/repo.git/info/refs",
            "service=git-upload-pack",
        ),
        (
            "github.com",
            "/owner/repo.git/info/lfs/objects/batch",
            "github-https",
            "/owner/repo.git/info/lfs/objects/batch",
            "",
        ),
        (
            "api.github.com",
            "/rate_limit",
            "github-api",
            "/rate_limit",
            "",
        ),
        (
            "api.github.com",
            "/search/code?q=a%20b+c",
            "github-api",
            "/search/code",
            "q=a%20b+c",
        ),
    ] {
        for claimed in [bound, "api.github.com", "github.com", "api.anthropic.com"] {
            let request = Request::get(uri)
                .header(HOST, claimed)
                .header("authorization", "token placeholder")
                .body(Full::default())
                .unwrap();
            let (seen, _) = through_backend(&mut host, &backend, bound, request).await;
            assert_eq!(
                (
                    seen.capability_slot.as_str(),
                    seen.route.as_str(),
                    seen.path.as_str(),
                    seen.query.as_str(),
                    seen.intercepted_host.as_str()
                ),
                ("github", route, path, query, bound),
                "{bound}{uri} claiming {claimed}"
            );
            assert_eq!(header_names(&seen), ["authorization"]);
        }
    }
}

/// Mapping `chatgpt.com` whole (#3999) changes no other host's rewrite: the
/// Anthropic API still maps every path under its prefix, and the OpenAI API
/// only `/v1` and below. Codex's paths now reach the bridge whole, and the
/// broker admits only the ones Codex sends its credential to.
#[test]
fn only_chatgpt_com_maps_its_whole_path() {
    let defaults = RouteTable::defaults();
    for (host, uri, rewritten) in [
        (
            "api.anthropic.com",
            "/v1/messages?beta=true",
            Ok("/_codewire/anthropic/v1/messages?beta=true".to_owned()),
        ),
        (
            "api.anthropic.com",
            "/api/oauth/usage",
            Ok("/_codewire/anthropic/api/oauth/usage".to_owned()),
        ),
        (
            "api.anthropic.com",
            "/",
            Ok("/_codewire/anthropic/".to_owned()),
        ),
        (
            "api.openai.com",
            "/v1/responses",
            Ok("/_codewire/openai/v1/responses".to_owned()),
        ),
        (
            "api.openai.com",
            "/v1",
            Ok("/_codewire/openai/v1".to_owned()),
        ),
        ("api.openai.com", "/v2/models", Err(StatusCode::NOT_FOUND)),
        ("api.openai.com", "/", Err(StatusCode::NOT_FOUND)),
        (
            "chatgpt.com",
            "/backend-api/codex/responses",
            Ok("/v1/backend-api/codex/responses".to_owned()),
        ),
        (
            "chatgpt.com",
            "/backend-api/wham/usage",
            Ok("/v1/backend-api/wham/usage".to_owned()),
        ),
        ("chatgpt.com", "/", Ok("/v1/".to_owned())),
    ] {
        assert_eq!(rewrite(&defaults, host, uri), rewritten, "{host}{uri}");
    }
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
            MANAGED_ANTHROPIC_OAUTH_PREFIX,
            Method::POST,
            "",
            "anthropic",
            "claude-oauth-token",
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
            .unwrap_or_else(|refusal| panic!("{prefix} refused: {refusal:?}"));
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
        .map_err(|refusal| StatusCode::from_u16(refusal.status()).unwrap())
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
        // A host with no route at all is refused by name (#6421).
        ("B.example.com", "/v1/x", Err(StatusCode::FORBIDDEN)),
        ("c.example.com", "/v1/x", Err(StatusCode::FORBIDDEN)),
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
async fn a_path_no_route_of_a_routed_host_covers_is_404_and_never_reaches_the_bridge() {
    let mut host = Host::start().await;
    let backend = host.backend(RouteTable::defaults());
    for (bound, uri) in [
        ("api.openai.com", "/v2/models"),
        ("api.openai.com", "/v1x"),
        ("api.openai.com", "/"),
    ] {
        assert_eq!(
            refused(&mut host, &backend, bound, uri).await,
            StatusCode::NOT_FOUND,
            "{bound}{uri}"
        );
    }
}

/// A bound host this table has no route for at all, as after its cw-egress
/// lost the route (#6421), is refused by name on every path, and nothing of
/// the request, its placeholder included, reaches the bridge.
#[tokio::test]
async fn a_bound_host_with_no_route_is_refused_by_name_and_never_reaches_the_bridge() {
    let mut host = Host::start().await;
    let backend = host.backend(RouteTable::defaults());
    for (bound, uri) in [
        ("other.example.com", "/v1/models"),
        // Without a Claude sign-in, Claude's token host has no route at all.
        ("platform.claude.com", "/v1/oauth/token"),
        ("platform.claude.com", "/"),
        ("platform.claude.com", "/v1/oauth"),
        ("platform.claude.com", "/v1/oauth/tokens"),
        ("platform.claude.com", "/v1/oauth/revoke"),
        ("platform.claude.com", "/v1/oauth/authorize"),
        ("platform.claude.com", "/oauth/code/callback"),
        ("platform.claude.com", "/v1/messages"),
    ] {
        assert_eq!(
            refused(&mut host, &backend, bound, uri).await,
            StatusCode::FORBIDDEN,
            "{bound}{uri}"
        );
    }
    // A front door whose every bound host lost its route refuses each too.
    let backend = host.backend(RouteTable::unrouted());
    let request = Request::post("/v1/messages")
        .header(HOST, "api.anthropic.com")
        .header("x-api-key", "cwp1_placeholder-that-must-stay-here")
        .body(Full::new(Bytes::from_static(b"a body that must stay here")))
        .unwrap();
    let response = bounded(backend.forward("api.anthropic.com", request)).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(response.headers()["codewire-refusal"], "route_not_served");
    host.assert_untouched();
    // A WebSocket upgrade takes the same route, so the same refusal.
    let upgrade = Request::get("/v1/realtime")
        .header(HOST, "api.anthropic.com")
        .header(CONNECTION, "upgrade")
        .header(UPGRADE, "websocket")
        .header(
            "authorization",
            "Bearer cwp1_placeholder-that-must-stay-here",
        )
        .body(Full::default())
        .unwrap();
    let response = bounded(backend.forward("api.anthropic.com", upgrade)).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(response.headers()["codewire-refusal"], "route_not_served");
    host.assert_untouched();
}

/// For a Claude sign-in every path and method of Claude's token host reaches
/// the bridge on the token route, which the broker answers only for a
/// managed refresh and otherwise forwards untouched.
#[tokio::test]
async fn every_path_of_claudes_token_host_reaches_the_bridge_for_a_sign_in() {
    let mut host = Host::start().await;
    let backend = host.backend(RouteTable::with_optional_hosts(true, false));
    for (method, uri, path, query) in [
        (Method::GET, "/v1/oauth/token", "/v1/oauth/token", ""),
        (Method::DELETE, "/v1/oauth/token", "/v1/oauth/token", ""),
        (Method::POST, "/v1/oauth/token/x", "/v1/oauth/token/x", ""),
        (
            Method::POST,
            "/v1/oauth/token?grant_type=refresh_token",
            "/v1/oauth/token",
            "grant_type=refresh_token",
        ),
        (Method::PUT, "/v1/oauth/revoke", "/v1/oauth/revoke", ""),
        (Method::GET, "/", "/", ""),
    ] {
        let request = Request::builder()
            .method(method.clone())
            .uri(uri)
            .header(HOST, "platform.claude.com")
            .body(Full::default())
            .unwrap();
        let (seen, _) = through_backend(&mut host, &backend, "platform.claude.com", request).await;
        assert_eq!(
            (
                seen.capability_slot.as_str(),
                seen.route.as_str(),
                seen.method.as_str(),
                seen.path.as_str(),
                seen.query.as_str()
            ),
            (
                "anthropic",
                "claude-oauth-token",
                method.as_str(),
                path,
                query
            ),
            "{method} {uri}"
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
        for bound in ["api.anthropic.com", "api.openai.com", "chatgpt.com"] {
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
        RouteTable::new([HostRoute::new("git.example.com", "/", GITHUB_GIT_PREFIX)]).unwrap(),
    );
    let request = Request::get("/owner/repo.git/info/refs?service=git-upload-pack")
        .header(HOST, "api.github.com")
        .body(Full::default())
        .unwrap();
    let (seen, _) = through_backend(&mut host, &backend, "git.example.com", request).await;
    assert_eq!(
        (seen.capability_slot.as_str(), seen.route.as_str()),
        ("github", "github-https")
    );
    assert_eq!(seen.path, "/owner/repo.git/info/refs");
    assert!(header_names(&seen).is_empty());
}

#[tokio::test]
async fn an_upgrade_on_a_session_without_websockets_is_403_and_never_reaches_the_host() {
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
    assert_eq!(
        response.headers()["codewire-refusal"],
        "websocket_not_served"
    );
    assert_eq!(
        body_of(response).await,
        "Codewire: WebSockets to chatgpt.com aren't carried yet.\n"
    );
    host.assert_untouched();
}

/// An opening request takes the route a request to the same path takes,
/// and its accepted socket carries bytes to the host.
#[tokio::test]
async fn an_upgrade_takes_the_request_route_and_its_socket_reaches_the_host() {
    use tokio::io::AsyncWriteExt as _;

    let mut host =
        Host::start_with(&[codewire_daemon_proto::CREDENTIAL_BRIDGE_CAPABILITY_WEBSOCKET]).await;
    let backend = host.backend(RouteTable::defaults());
    let request = Request::get("/backend-api/codex/responses?stream=1")
        .header(HOST, "chatgpt.com")
        .header(CONNECTION, "Upgrade")
        .header(UPGRADE, "websocket")
        .header("sec-websocket-key", "test-nonce")
        .header("sec-websocket-version", "13")
        .header("authorization", "Bearer placeholder")
        .body(())
        .unwrap();
    let upgrading = tokio::spawn({
        let backend = backend.clone();
        async move { backend.upgrade("chatgpt.com", request).await }
    });
    let upgrade = match bounded(host.output.next()).await.unwrap().unwrap().payload {
        Some(GuestPayload::Upgrade(upgrade)) => upgrade,
        other => panic!("expected an upgrade, got {other:?}"),
    };
    assert_eq!(
        (
            upgrade.capability_slot.as_str(),
            upgrade.route.as_str(),
            upgrade.path.as_str(),
            upgrade.query.as_str(),
            upgrade.intercepted_host.as_str(),
        ),
        (
            "codex",
            "openai-api",
            "/backend-api/codex/responses",
            "stream=1",
            "chatgpt.com"
        )
    );
    let names = upgrade
        .headers
        .iter()
        .map(|header| header.name.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        names,
        [
            "sec-websocket-key",
            "sec-websocket-version",
            "authorization"
        ]
    );
    host.send(HostPayload::UpgradeAccepted(
        v1::CredentialBridgeUpgradeAccepted {
            request_id: upgrade.request_id.clone(),
            headers: vec![v1::CredentialHttpHeader {
                name: "sec-websocket-accept".to_owned(),
                value: b"test-accept".to_vec(),
            }],
        },
    ))
    .await;
    host.send(HostPayload::StreamCredit(
        v1::CredentialBridgeStreamCredit {
            request_id: upgrade.request_id.clone(),
            credit_bytes: 1024,
        },
    ))
    .await;
    let Ok((switched, mut socket)) = bounded(upgrading).await.unwrap() else {
        panic!("the accepted upgrade was refused");
    };
    assert_eq!(switched.status(), StatusCode::SWITCHING_PROTOCOLS);
    assert_eq!(switched.headers()["sec-websocket-accept"], "test-accept");
    socket.write_all(b"ping").await.unwrap();
    match bounded(host.output.next()).await.unwrap().unwrap().payload {
        Some(GuestPayload::StreamData(data)) => {
            assert_eq!(data.request_id, upgrade.request_id);
            assert_eq!(data.data, b"ping");
        }
        other => panic!("expected stream data, got {other:?}"),
    }
}

#[tokio::test]
async fn an_upgrade_to_a_path_no_route_covers_is_404() {
    let mut host =
        Host::start_with(&[codewire_daemon_proto::CREDENTIAL_BRIDGE_CAPABILITY_WEBSOCKET]).await;
    let backend = host.backend(RouteTable::defaults());
    let request = Request::get("/elsewhere")
        .header(CONNECTION, "Upgrade")
        .header(UPGRADE, "websocket")
        .body(())
        .unwrap();
    let Err(response) = bounded(backend.upgrade("api.openai.com", request)).await else {
        panic!("an unrouted upgrade was accepted");
    };
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(response.headers()["codewire-refusal"], "path_not_served");
    assert_eq!(
        body_of(response).await,
        "Codewire: this path on api.openai.com isn't one Codewire forwards.\n"
    );
    host.assert_untouched();
}

/// What the front door refuses itself reads the same as the bridge's
/// refusals, naming the bound host, never the request's.
#[tokio::test]
async fn the_front_doors_own_refusals_are_readable() {
    let host = Host::start().await;
    let backend = host.backend(RouteTable::defaults());
    for (refusal, status) in [
        (FrontDoorRefusal::Malformed, StatusCode::BAD_REQUEST),
        (FrontDoorRefusal::Forbidden, StatusCode::FORBIDDEN),
        (
            FrontDoorRefusal::Misdirected,
            StatusCode::MISDIRECTED_REQUEST,
        ),
    ] {
        let response = backend.refuse("api.anthropic.com", refusal);
        assert_eq!(response.status(), status);
        assert_eq!(
            response.headers()["codewire-refusal"],
            "request_not_forwarded"
        );
        assert_eq!(
            body_of(response).await,
            "Codewire: this request to api.anthropic.com isn't one Codewire forwards.\n"
        );
    }
    let response = backend.refuse("api.anthropic.com", FrontDoorRefusal::NotSwitched);
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(response.headers()["codewire-refusal"], "upstream_failed");
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

    // A host that selects its own route covers every path and adds no
    // prefix; no other host may go without one.
    for routes in [
        vec![route("github.com", "/", GITHUB_GIT_PREFIX)],
        vec![route("api.github.com", "/", CODEX_PREFIX)],
        vec![route("github.com", "/owner", "")],
    ] {
        assert_eq!(RouteTable::new(routes), Err(RouteTableError::HostRoute));
    }
    assert_eq!(
        RouteTable::new([HostRoute::by_host("api.example.com")]),
        Err(RouteTableError::Prefix)
    );

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
        (
            "codex",
            "openai-api",
            "POST",
            "/backend-api/codex/responses"
        )
    );
    assert_eq!(seen.body, b"{\"input\":\"hi\"}");
    assert_eq!(header_names(&seen), ["content-type"]);
    host.answer(&seen.request_id).await;
    let response = bounded(response).await.unwrap().unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_of(response).await, "hello, world");
    door.close();
}

/// The route table and the hosted bindings serve the same hosts and
/// suffixes for every client selection, because both are
/// [`codewire_access::front_door_hosts`] (#4001 step P, #6195).
#[test]
fn the_route_table_serves_exactly_the_shared_selection() {
    let slots = ["codex", "openai", "anthropic", "ssh", "github"];
    for bits in 0..(1_u8 << slots.len()) {
        let chosen: Vec<&str> = (0..slots.len())
            .filter(|bit| bits & (1 << bit) != 0)
            .map(|bit| slots[bit])
            .collect();
        let base = ManagedCredentialClients::from_profile_slots(chosen.iter().copied()).unwrap();
        let forms = [
            Some(base),
            base.with_anthropic_subscription_token().ok(),
            base.with_anthropic_sign_in().ok(),
        ];
        for clients in forms.into_iter().flatten() {
            let selected = codewire_access::front_door_hosts(clients);
            let named = |suffix: bool| {
                let mut names: Vec<&str> = selected
                    .iter()
                    .filter(|host| host.suffix == suffix)
                    .map(|host| host.host)
                    .collect();
                names.sort_unstable();
                names
            };
            let table = RouteTable::for_clients(clients);
            let mut routed = table.as_ref().map(RouteTable::hosts).unwrap_or_default();
            routed.sort_unstable();
            assert_eq!(routed, named(false), "{clients:?}");
            let mut suffixes = table.as_ref().map(RouteTable::suffixes).unwrap_or_default();
            suffixes.sort_unstable();
            assert_eq!(suffixes, named(true), "{clients:?}");
        }
    }
}

// ---------------------------------------------------------------------------
// The request id (#6181)

/// The response's `codewire-request-id`, which must be one canonical UUID.
fn named_id<B>(response: &Response<B>) -> Uuid {
    let values = response
        .headers()
        .get_all(REQUEST_ID_HEADER)
        .iter()
        .collect::<Vec<_>>();
    assert_eq!(values.len(), 1, "one request id");
    let text = values[0].to_str().unwrap();
    let id = Uuid::parse_str(text).unwrap();
    assert_eq!(id.to_string(), text, "a canonical UUID");
    assert_eq!(id.get_version_num(), 4, "a random UUID");
    id
}

/// Each answer names its own random id, the one its bridge frame carried,
/// so the credential service's line for the request carries it too. The
/// provider's own value for the header never reaches the client.
#[tokio::test]
async fn an_intercepted_answer_names_the_id_its_frame_carried() {
    let mut host = Host::start().await;
    let backend = host.backend(RouteTable::defaults());
    let mut ids = Vec::new();
    for _ in 0..2 {
        let request = Request::get("/v1/models")
            .header(HOST, "api.anthropic.com")
            .body(Full::default())
            .unwrap();
        let task = tokio::spawn({
            let backend = backend.clone();
            async move { backend.forward("api.anthropic.com", request).await }
        });
        let seen = host.request().await;
        host.send(HostPayload::ResponseStart(
            v1::CredentialBridgeResponseStart {
                request_id: seen.request_id.clone(),
                status_code: 401,
                headers: vec![v1::CredentialHttpHeader {
                    name: "codewire-request-id".to_owned(),
                    value: b"the-providers".to_vec(),
                }],
            },
        ))
        .await;
        host.end(&seen.request_id).await;
        let response = bounded(task).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let id = named_id(&response);
        assert_eq!(id.to_string(), seen.request_id);
        ids.push(id);
    }
    assert_ne!(ids[0], ids[1], "each request has its own id");
}

/// A client's own `codewire-request-id` goes neither to the frame, and so
/// the provider, nor back in the answer.
#[tokio::test]
async fn a_clients_request_id_is_neither_forwarded_nor_echoed() {
    let mut host = Host::start().await;
    let backend = host.backend(RouteTable::defaults());
    let chosen = Uuid::new_v4().to_string();
    let request = Request::get("/v1/models")
        .header(HOST, "api.anthropic.com")
        .header("codewire-request-id", chosen.as_str())
        .header("anthropic-version", "2023-06-01")
        .body(Full::default())
        .unwrap();
    let task = tokio::spawn({
        let backend = backend.clone();
        async move { backend.forward("api.anthropic.com", request).await }
    });
    let seen = host.request().await;
    assert_eq!(header_names(&seen), ["anthropic-version"]);
    assert_ne!(seen.request_id, chosen);
    host.answer(&seen.request_id).await;
    let response = bounded(task).await.unwrap();
    assert_eq!(named_id(&response).to_string(), seen.request_id);
}

/// The front door's own refusals name an id too, a fresh one each, whether
/// the request was refused before its route or on it.
#[tokio::test]
async fn a_front_door_refusal_names_a_fresh_id() {
    let mut host = Host::start().await;
    let backend = host.backend(RouteTable::defaults());
    let before = backend.refuse("api.anthropic.com", FrontDoorRefusal::Forbidden);
    let again = backend.refuse("api.anthropic.com", FrontDoorRefusal::Forbidden);
    assert_ne!(named_id(&before), named_id(&again));
    let request = Request::get("/nowhere")
        .header(HOST, "platform.claude.com")
        .body(Full::default())
        .unwrap();
    let response = bounded(backend.forward("platform.claude.com", request)).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    named_id(&response);
    host.assert_untouched();
}

/// The loopback ingress, which no front door stands in front of, answers
/// without one.
#[tokio::test]
async fn a_loopback_answer_names_no_id() {
    let mut host = Host::start().await;
    let task = tokio::spawn({
        let bridge = host.bridge.clone();
        let request = Request::get("/_codewire/anthropic/v1/models")
            .header(HOST, LOOPBACK)
            .body(Body::empty())
            .unwrap();
        async move { bridge.respond(request).await }
    });
    let seen = host.request().await;
    host.answer(&seen.request_id).await;
    let response = bounded(task).await.unwrap();
    assert!(response.headers().get(REQUEST_ID_HEADER).is_none());
}

// ---------------------------------------------------------------------------
// Reported refusals (#5058)

/// What a sink was told: the bound name, its port and the code, which is all
/// a sink can be told.
#[derive(Default)]
struct Collected(std::sync::Mutex<Vec<(String, u16, codewire_access::RefusalCode)>>);

impl RefusalSink for Collected {
    fn refused(&self, host: &str, port: u16, code: codewire_access::RefusalCode) {
        self.0.lock().unwrap().push((host.to_owned(), port, code));
    }
}

impl Collected {
    fn take(&self) -> Vec<(String, u16, codewire_access::RefusalCode)> {
        std::mem::take(&mut *self.0.lock().unwrap())
    }
}

fn reporting(host: &Host) -> (Arc<CredentialRouteBackend>, Arc<Collected>) {
    let sink = Arc::new(Collected::default());
    let backend = CredentialRouteBackend::new(
        RouteTable::with_optional_hosts(true, false),
        host.bridge.clone(),
    )
    .reporting_refusals(sink.clone());
    (Arc::new(backend), sink)
}

fn row(
    host: &str,
    code: codewire_access::RefusalCode,
) -> (String, u16, codewire_access::RefusalCode) {
    (host.to_owned(), 443, code)
}

/// A request that names everything it can: another host, a method, a path,
/// a query, headers, a placeholder-shaped value and a body.
fn crafted(path: &str) -> Request<Full<Bytes>> {
    Request::post(format!("{path}?secret-query=q1"))
        .header(HOST, "evil.example.org")
        .header("x-secret-header", "h1")
        .header("authorization", format!("Bearer cwp1_{}A", "D".repeat(42)))
        .body(Full::new(Bytes::from_static(b"secret-body")))
        .unwrap()
}

/// The front door's own refusals are reported under the route's bound host,
/// whatever the request's Host said, with their code and nothing else.
#[tokio::test]
async fn the_front_doors_own_refusals_are_reported_under_the_bound_host() {
    use codewire_access::RefusalCode;
    let mut host = Host::start().await;
    let (backend, sink) = reporting(&host);

    let response = bounded(backend.forward("api.openai.com", crafted("/v2/secret-path"))).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    host.assert_untouched();
    let _ = backend.refuse("api.anthropic.com", FrontDoorRefusal::Misdirected);
    let response = bounded(backend.forward("api.anthropic.com", crafted("/a/../b"))).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        sink.take(),
        [
            row("api.openai.com", RefusalCode::PathNotServed),
            row("api.anthropic.com", RefusalCode::RequestNotForwarded),
            row("api.anthropic.com", RefusalCode::RequestNotForwarded),
        ]
    );
}

/// A name under a bound suffix is reported as the suffix, the table's own
/// name, never the name the connection was for.
#[tokio::test]
async fn a_name_under_a_suffix_is_reported_as_the_suffix() {
    use codewire_access::RefusalCode;
    let host = Host::start().await;
    let (backend, sink) = reporting(&host);
    let _ = backend.refuse("workspace-1.chatgpt.com", FrontDoorRefusal::Forbidden);
    // A host the table doesn't route is never reported.
    let _ = backend.refuse("example.org", FrontDoorRefusal::Forbidden);
    assert_eq!(
        sink.take(),
        [row("chatgpt.com", RefusalCode::RequestNotForwarded)]
    );
}

/// The broker's refusals are reported by their code: one in a failure
/// frame, and those it answers with its header, as a 403 or, for a
/// credential conflict, a 400. A provider's answer is not a refusal,
/// whatever header it carries, and each status claims only the codes the
/// broker answers with it.
#[tokio::test]
async fn the_brokers_refusals_are_reported_and_a_providers_answers_are_not() {
    use codewire_access::RefusalCode;
    let mut host = Host::start().await;
    let (backend, sink) = reporting(&host);
    let answers = [
        (403, "name_not_allowed", None),
        (200, "no_credential_selected", None),
        (
            403,
            "no_credential_selected",
            Some(RefusalCode::NoCredentialSelected),
        ),
        (
            400,
            "credential_conflict",
            Some(RefusalCode::CredentialConflict),
        ),
        (403, "credential_conflict", None),
        (400, "no_credential_selected", None),
    ];
    for (status, header, expected) in answers {
        let task = tokio::spawn({
            let backend = backend.clone();
            async move {
                backend
                    .forward("api.anthropic.com", crafted("/v1/messages"))
                    .await
            }
        });
        let seen = host.request().await;
        host.send(HostPayload::ResponseStart(
            v1::CredentialBridgeResponseStart {
                request_id: seen.request_id.clone(),
                status_code: status,
                headers: vec![v1::CredentialHttpHeader {
                    name: "codewire-refusal".to_owned(),
                    value: header.as_bytes().to_vec(),
                }],
            },
        ))
        .await;
        host.end(&seen.request_id).await;
        let response = bounded(task).await.unwrap();
        assert_eq!(response.status().as_u16(), u16::try_from(status).unwrap());
        assert_eq!(
            sink.take(),
            expected
                .map(|code| row("api.anthropic.com", code))
                .into_iter()
                .collect::<Vec<_>>(),
            "{status} {header}"
        );
    }

    let task = tokio::spawn({
        let backend = backend.clone();
        async move {
            backend
                .forward("api.anthropic.com", crafted("/v1/messages"))
                .await
        }
    });
    let seen = host.request().await;
    host.send(HostPayload::ResponseFailure(
        v1::CredentialBridgeResponseFailure {
            request_id: seen.request_id,
            reason: v1::CredentialBridgeFailureReason::Denied as i32,
            refusal: v1::CredentialBridgeRefusal::NameNotAllowed as i32,
            retry_after_seconds: 0,
        },
    ))
    .await;
    let response = bounded(task).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        sink.take(),
        [row("api.anthropic.com", RefusalCode::NameNotAllowed)]
    );
}
