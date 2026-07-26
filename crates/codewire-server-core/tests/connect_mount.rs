//! Connect mount integration tests (doc 03 WI-1 acceptance).
//!
//! Mounts the never-routed probe service (`codewire.testing.v1.PingService`,
//! D8) behind the full [`AppBuilder`] middleware stack and proves:
//!
//! - `x-request-id` and `x-codewire-service` on RPC responses (D7 parity),
//! - a panicking handler yields the CatchPanic 500,
//! - `/healthz` is unaffected by the Connect mount,
//! - an h2c prior-knowledge request is served on the same listener (D2),
//! - the per-RPC INFO log event fires with service/method/code/duration and
//!   `credential=none`, preserving a valid request `User-Agent` and using
//!   `unknown` for missing or non-UTF-8 values (D7),
//! - a non-Connect content type is rejected before any handler runs (D6b),
//!   including gRPC content types (D9 — Connect protocol only),
//! - `Connect-Protocol-Version` is validated when present but never
//!   required (the D6b decision recorded at WI-1).

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use buffa::Message;
use codewire_proto::codewire::testing::v1::{
    AdminPingRequest, AdminPingResponse, PingRequest, PingResponse, PingService, PingServiceClient,
    PublicPingRequest, PublicPingResponse, StreamPingRequest, StreamPingResponse,
};
use codewire_server_core::AppBuilder;
use codewire_server_core::auth::AuthState;
use codewire_server_core::connect::ConnectAuthLayer;
use connectrpc::client::{ClientConfig, ClientTransport, HttpClient, full_body};
use connectrpc::{Protocol, RequestContext, ServiceRequest, ServiceResult};

const SERVICE: &str = "codewire.testing.v1.PingService";

/// Test implementation of the D8 probe service. `Ping` counts invocations so
/// tests can assert a rejected request never reached the handler; a `panic`
/// message panics to exercise the CatchPanic backstop.
#[derive(Default)]
struct ProbePing {
    ping_calls: AtomicUsize,
}

#[allow(refining_impl_trait)]
impl PingService for ProbePing {
    async fn public_ping(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, PublicPingRequest>,
    ) -> ServiceResult<PublicPingResponse> {
        connectrpc::Response::ok(PublicPingResponse {
            message: "public pong".into(),
            ..Default::default()
        })
    }

    async fn ping(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, PingRequest>,
    ) -> ServiceResult<PingResponse> {
        self.ping_calls.fetch_add(1, Ordering::SeqCst);
        let message = request.view().message;
        if message.is_empty() {
            // The google.rpc.BadRequest detail rides on 01's error renderer
            // (WI-2+); WI-1 exercises the bare code only.
            return Err(connectrpc::ConnectError::invalid_argument(
                "message must not be empty",
            ));
        }
        if message == "panic" {
            panic!("probe handler panic requested");
        }
        if message == "deadline" {
            let remaining = ctx
                .time_remaining()
                .map(|duration| duration.as_millis().to_string())
                .unwrap_or_else(|| "none".into());
            return connectrpc::Response::ok(PingResponse {
                message: remaining,
                ..Default::default()
            });
        }
        connectrpc::Response::ok(PingResponse {
            message: message.to_owned(),
            ..Default::default()
        })
    }

    async fn admin_ping(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, AdminPingRequest>,
    ) -> ServiceResult<AdminPingResponse> {
        connectrpc::Response::ok(AdminPingResponse {
            message: "admin pong".into(),
            ..Default::default()
        })
    }

    async fn stream_ping(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, StreamPingRequest>,
    ) -> ServiceResult<connectrpc::ServiceStream<StreamPingResponse>> {
        // Single-message stream: this file exercises the mount, not pacing
        // (the paced production probe lives in connect_testing).
        connectrpc::Response::stream_ok(futures::stream::iter([Ok(StreamPingResponse {
            sequence: 0,
            total: 1,
            ..Default::default()
        })]))
    }
}

// --- log capture -----------------------------------------------------------

static LOG_BUFFER: OnceLock<Arc<Mutex<Vec<u8>>>> = OnceLock::new();

struct SharedWriter(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for SharedWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Installs a process-global INFO subscriber writing into a shared buffer.
/// Tests in this binary share it; assertions scan for a matching line.
fn init_log_capture() -> Arc<Mutex<Vec<u8>>> {
    LOG_BUFFER
        .get_or_init(|| {
            let buffer = Arc::new(Mutex::new(Vec::new()));
            let writer_buffer = Arc::clone(&buffer);
            let subscriber = tracing_subscriber::fmt()
                .with_ansi(false)
                .with_max_level(tracing::Level::INFO)
                .with_writer(move || SharedWriter(Arc::clone(&writer_buffer)))
                .finish();
            // Another test may have raced the install; capture still works
            // because the winner is also backed by this OnceLock closure.
            let _ = tracing::subscriber::set_global_default(subscriber);
            buffer
        })
        .clone()
}

/// Asserts some captured `connect_rpc` log line contains every fragment.
fn assert_log_line(fragments: &[&str]) {
    let logs = String::from_utf8_lossy(&init_log_capture().lock().unwrap()).into_owned();
    let found = logs
        .lines()
        .filter(|line| line.contains("connect_rpc"))
        .any(|line| fragments.iter().all(|fragment| line.contains(fragment)));
    assert!(
        found,
        "no connect_rpc log line contains {fragments:?}; captured connect_rpc lines:\n{}",
        logs.lines()
            .filter(|line| line.contains("connect_rpc"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

// --- harness ----------------------------------------------------------------

/// Starts the full stack (AppBuilder middleware + health + Connect mount) on
/// an ephemeral port via `serve_with_listener` — the same code path service
/// binaries use.
async fn start_app() -> (SocketAddr, Arc<ProbePing>) {
    init_log_capture();
    let probe = Arc::new(ProbePing::default());
    let connect = connectrpc::Router::new().add_service(Arc::clone(&probe));
    let app = AppBuilder::new("codewire-server-core-test")
        .with_health()
        .with_connect_routes(connect)
        .into_router();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(codewire_server_core::serve_with_listener(app, listener));
    (addr, probe)
}

async fn start_app_with_policy(
    protocol_policy: codewire_server_core::connect::ProtocolPolicy,
) -> (SocketAddr, Arc<ProbePing>) {
    init_log_capture();
    let probe = Arc::new(ProbePing::default());
    let connect = connectrpc::Router::new().add_service(Arc::clone(&probe));
    let routes = codewire_server_core::connect::connect_router_with_protocol_policy(
        connect,
        protocol_policy,
    );
    let app = AppBuilder::new("codewire-server-core-test")
        .with_health()
        .with_routes(routes)
        .into_router();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(codewire_server_core::serve_with_listener(app, listener));
    (addr, probe)
}

async fn start_unary_deadline_app() -> (SocketAddr, Arc<ProbePing>) {
    init_log_capture();
    let probe = Arc::new(ProbePing::default());
    let connect = connectrpc::Router::new().add_service(Arc::clone(&probe));
    let pool = sqlx::PgPool::connect_lazy("postgres://postgres@127.0.0.1/codewire")
        .expect("syntactically valid lazy Postgres URL");
    let auth = ConnectAuthLayer::authenticated(AuthState { pool })
        .allow_public([format!("/{SERVICE}/Ping")]);
    let app = AppBuilder::new("codewire-server-core-test")
        .with_health()
        .with_unary_connect_routes_auth(connect, auth)
        .into_router();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(codewire_server_core::serve_with_listener(app, listener));
    (addr, probe)
}

fn ping_url(addr: SocketAddr, method: &str) -> String {
    format!("http://{addr}/{SERVICE}/{method}")
}

// --- tests -------------------------------------------------------------------

#[tokio::test]
async fn unary_json_roundtrip_with_standard_middleware() {
    let (addr, _probe) = start_app().await;

    // No Connect-Protocol-Version header: the request must still succeed
    // (D6b decision — the header is validated when present, never required).
    let resp = reqwest::Client::new()
        .post(ping_url(addr, "Ping"))
        .header("content-type", "application/json")
        .body(r#"{"message":"hi"}"#)
        .send()
        .await
        .expect("request");

    assert_eq!(resp.status(), 200);
    assert!(
        resp.headers().get("x-request-id").is_some(),
        "x-request-id must be minted for RPC responses"
    );
    assert_eq!(
        resp.headers()
            .get("x-codewire-service")
            .and_then(|v| v.to_str().ok()),
        Some("codewire-server-core-test")
    );
    let body: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(body["message"], "hi");

    assert_log_line(&[
        &format!("service={SERVICE}"),
        "method=Ping",
        "protocol=connect",
        "code=ok",
        "http_status=200",
        "duration_ms=",
        "credential=none",
        "principal_fingerprint=unknown",
        "synthetic=false",
    ]);
}

async fn remaining_deadline_ms(
    client: &reqwest::Client,
    addr: SocketAddr,
    asserted_timeout_ms: Option<u64>,
) -> u64 {
    let mut request = client
        .post(ping_url(addr, "Ping"))
        .header("content-type", "application/json")
        .body(r#"{"message":"deadline"}"#);
    if let Some(timeout_ms) = asserted_timeout_ms {
        request = request.header("connect-timeout-ms", timeout_ms);
    }
    let response = request.send().await.expect("deadline probe request");
    assert_eq!(response.status(), 200);
    let body: serde_json::Value = response.json().await.expect("deadline probe JSON");
    body["message"]
        .as_str()
        .expect("deadline probe message")
        .parse()
        .expect("remaining deadline milliseconds")
}

#[tokio::test]
async fn unary_dispatcher_applies_default_preserves_shorter_and_clamps_above_max() {
    let (addr, _probe) = start_unary_deadline_app().await;
    let client = reqwest::Client::new();

    let absent = remaining_deadline_ms(&client, addr, None).await;
    assert!(
        (55_000..=60_000).contains(&absent),
        "absent header did not receive the 60s default: {absent}ms"
    );

    let shorter = remaining_deadline_ms(&client, addr, Some(5_000)).await;
    assert!(
        (4_000..=5_000).contains(&shorter),
        "shorter client deadline was not preserved: {shorter}ms"
    );

    let clamped = remaining_deadline_ms(&client, addr, Some(120_000)).await;
    assert!(
        (55_000..=60_000).contains(&clamped),
        "deadline above the maximum was not clamped to 60s: {clamped}ms"
    );
}

#[tokio::test]
async fn ordinary_connect_mount_has_no_server_default_deadline() {
    let (addr, _probe) = start_app().await;
    let response = reqwest::Client::new()
        .post(ping_url(addr, "Ping"))
        .header("content-type", "application/json")
        .body(r#"{"message":"deadline"}"#)
        .send()
        .await
        .expect("ordinary mount deadline probe");
    assert_eq!(response.status(), 200);
    let body: serde_json::Value = response.json().await.expect("deadline probe JSON");
    assert_eq!(body["message"], "none");
}

#[tokio::test]
async fn rpc_log_captures_user_agent_with_stable_unknown_fallback() {
    let (addr, _probe) = start_app().await;
    let client = reqwest::Client::new();

    let exact_user_agent = "codewire-cli/0.42.7-test";
    let resp = client
        .post(ping_url(addr, "TelemetryExactUserAgent"))
        .header("content-type", "application/json")
        .header("user-agent", exact_user_agent)
        .header("x-codewire-synthetic", "true")
        .header("x-codewire-principal-fingerprint", "forged-by-caller")
        .body("{}")
        .send()
        .await
        .expect("request with valid user agent");
    assert_eq!(resp.status(), 404);
    assert_log_line(&[
        "method=TelemetryExactUserAgent",
        &format!("user_agent={exact_user_agent}"),
        "principal_fingerprint=unknown",
        "synthetic=false",
    ]);

    let resp = client
        .post(ping_url(addr, "TelemetryMissingUserAgent"))
        .header("content-type", "application/json")
        .body("{}")
        .send()
        .await
        .expect("request without user agent");
    assert_eq!(resp.status(), 404);
    assert_log_line(&["method=TelemetryMissingUserAgent", "user_agent=unknown"]);

    let invalid_user_agent = reqwest::header::HeaderValue::from_bytes(b"codewire-cli/\xff")
        .expect("opaque non-UTF-8 header value");
    assert!(invalid_user_agent.to_str().is_err());
    let resp = client
        .post(ping_url(addr, "TelemetryInvalidUserAgent"))
        .header("content-type", "application/json")
        .header("user-agent", invalid_user_agent)
        .body("{}")
        .send()
        .await
        .expect("request with non-UTF-8 user agent");
    assert_eq!(resp.status(), 404);
    assert_log_line(&["method=TelemetryInvalidUserAgent", "user_agent=unknown"]);
}

#[tokio::test]
async fn public_ping_and_admin_ping_are_mounted() {
    let (addr, _probe) = start_app().await;
    let client = reqwest::Client::new();

    for (method, expected) in [("PublicPing", "public pong"), ("AdminPing", "admin pong")] {
        let resp = client
            .post(ping_url(addr, method))
            .header("content-type", "application/json")
            .body("{}")
            .send()
            .await
            .expect("request");
        assert_eq!(resp.status(), 200, "{method}");
        let body: serde_json::Value = resp.json().await.expect("json body");
        assert_eq!(body["message"], expected, "{method}");
    }
}

#[tokio::test]
async fn non_connect_content_type_rejected_before_handler() {
    let (addr, probe) = start_app().await;

    for content_type in [
        "text/plain",
        "application/x-www-form-urlencoded",
        "multipart/form-data",
        "application/connect+thrift",
        // D9: the Connect protocol alone is served; gRPC and gRPC-Web are
        // refused at the mount even though the library could speak them.
        "application/grpc",
        "application/grpc+proto",
        "application/grpc+json",
        "application/grpc-web+proto",
    ] {
        let resp = reqwest::Client::new()
            .post(ping_url(addr, "Ping"))
            .header("content-type", content_type)
            .body(r#"{"message":"hi"}"#)
            .send()
            .await
            .expect("request");
        assert_eq!(resp.status(), 415, "{content_type}");
        assert_eq!(
            resp.headers()
                .get("accept-post")
                .and_then(|v| v.to_str().ok()),
            Some(codewire_server_core::connect::ACCEPT_POST),
            "{content_type}"
        );
    }

    // A POST with no content type at all is a non-Connect request too.
    let resp = reqwest::Client::new()
        .post(ping_url(addr, "Ping"))
        .send()
        .await
        .expect("request");
    assert_eq!(resp.status(), 415);

    assert_eq!(
        probe.ping_calls.load(Ordering::SeqCst),
        0,
        "rejected content types must never reach the handler"
    );
    assert_log_line(&[
        &format!("service={SERVICE}"),
        "method=Ping",
        "protocol=unknown",
        "code=unknown",
        "http_status=415",
    ]);
}

#[tokio::test]
async fn coordinator_policy_accepts_connect_and_native_grpc_but_never_grpc_web() {
    let (addr, probe) =
        start_app_with_policy(codewire_server_core::connect::ProtocolPolicy::ConnectAndGrpc).await;

    for protocol in [Protocol::Connect, Protocol::Grpc] {
        let client = PingServiceClient::new(
            HttpClient::plaintext_http2_only(),
            ClientConfig::new(format!("http://{addr}").parse().unwrap()).with_protocol(protocol),
        );
        let response = client
            .ping(PingRequest {
                message: format!("via {protocol:?}"),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(response.view().message, format!("via {protocol:?}"));
        let expected_protocol = match protocol {
            Protocol::Connect => "connect",
            Protocol::Grpc => "grpc",
            _ => unreachable!(),
        };
        assert_log_line(&[
            &format!("service={SERVICE}"),
            "method=Ping",
            &format!("protocol={expected_protocol}"),
            "code=ok",
        ]);
    }

    for content_type in [
        "application/grpc-web",
        "application/grpc-web+proto",
        "application/grpc-web-text",
        "application/grpc+json",
        "application/connect+thrift",
        "text/plain",
    ] {
        let response = reqwest::Client::new()
            .post(ping_url(addr, "Ping"))
            .header("content-type", content_type)
            .body("")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 415, "{content_type}");
        assert_eq!(
            response
                .headers()
                .get("accept-post")
                .and_then(|value| value.to_str().ok()),
            Some(codewire_server_core::connect::ACCEPT_POST_WITH_GRPC),
            "{content_type}"
        );
    }

    assert_eq!(probe.ping_calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn coordinator_policy_canonicalizes_mixed_case_connect_and_grpc_content_types() {
    let (addr, probe) =
        start_app_with_policy(codewire_server_core::connect::ProtocolPolicy::ConnectAndGrpc).await;
    let client = reqwest::Client::new();

    let response = client
        .post(ping_url(addr, "Ping"))
        .header("content-type", "Application/JSON; Charset=UTF-8")
        .body(r#"{"message":"mixed-case Connect"}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert!(response.headers().get("accept-post").is_none());
    assert_eq!(
        response.json::<serde_json::Value>().await.unwrap(),
        serde_json::json!({"message": "mixed-case Connect"})
    );

    let payload = PingRequest {
        message: "mixed-case gRPC".into(),
        ..Default::default()
    }
    .encode_to_vec();
    let mut grpc_frame = Vec::with_capacity(5 + payload.len());
    grpc_frame.push(0);
    grpc_frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    grpc_frame.extend_from_slice(&payload);
    let request = http::Request::post(ping_url(addr, "Ping"))
        .header("content-type", "Application/GRPC+PROTO; Version=1")
        .header("te", "trailers")
        .body(full_body(grpc_frame.into()))
        .unwrap();
    let response = HttpClient::plaintext_http2_only()
        .send(request)
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert!(response.headers().get("accept-post").is_none());
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("application/grpc+proto")
    );

    assert_eq!(probe.ping_calls.load(Ordering::SeqCst), 2);
    assert_log_line(&[
        &format!("service={SERVICE}"),
        "method=Ping",
        "protocol=connect",
        "code=ok",
    ]);
    assert_log_line(&[
        &format!("service={SERVICE}"),
        "method=Ping",
        "protocol=grpc",
        "code=ok",
    ]);
}

#[tokio::test]
async fn panicking_handler_yields_catch_panic_500() {
    let (addr, _probe) = start_app().await;

    let resp = reqwest::Client::new()
        .post(ping_url(addr, "Ping"))
        .header("content-type", "application/json")
        .body(r#"{"message":"panic"}"#)
        .send()
        .await
        .expect("request");

    assert_eq!(resp.status(), 500, "CatchPanicLayer must convert the panic");
    assert_eq!(
        resp.headers()
            .get("x-codewire-service")
            .and_then(|v| v.to_str().ok()),
        Some("codewire-server-core-test"),
        "service header middleware sits outside the panic backstop"
    );
}

#[tokio::test]
async fn healthz_unaffected_by_connect_mount() {
    let (addr, _probe) = start_app().await;

    let resp = reqwest::get(format!("http://{addr}/healthz"))
        .await
        .expect("request");
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn h2c_prior_knowledge_request_served() {
    let (addr, _probe) = start_app().await;

    // HTTP/2 prior-knowledge over cleartext on the same listener that just
    // served HTTP/1.1 (D2): the h2c-only Connect client must round-trip.
    let transport = HttpClient::plaintext_http2_only();
    let config = ClientConfig::new(format!("http://{addr}").parse().expect("uri"));
    let client = PingServiceClient::new(transport, config);

    let resp = client
        .ping(PingRequest {
            message: "over h2c".into(),
            ..Default::default()
        })
        .await
        .expect("h2c ping");
    assert!(
        resp.headers().get("x-request-id").is_some(),
        "middleware stack must apply to h2c requests"
    );
    assert_eq!(resp.into_owned().message, "over h2c");
}

#[tokio::test]
async fn connect_get_served_for_no_side_effects_read() {
    let (addr, _probe) = start_app().await;

    // Connect GET: message as percent-encoded JSON query parameters. Ping
    // carries `idempotency_level = NO_SIDE_EFFECTS`, so the dispatcher
    // accepts GET for it.
    let url = format!(
        "{}?connect=v1&encoding=json&message=%7B%22message%22%3A%22via-get%22%7D",
        ping_url(addr, "Ping")
    );
    let resp = reqwest::get(url).await.expect("request");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(body["message"], "via-get");
}

#[tokio::test]
async fn unknown_method_of_mounted_service_is_connect_shaped() {
    let (addr, _probe) = start_app().await;

    let resp = reqwest::Client::new()
        .post(ping_url(addr, "Nope"))
        .header("content-type", "application/json")
        .body("{}")
        .send()
        .await
        .expect("request");

    assert_eq!(resp.status(), 404);
    let body: serde_json::Value = resp.json().await.expect("connect error body");
    assert_eq!(body["code"], "unimplemented");

    // The log event reads the authoritative code out of the error document.
    assert_log_line(&[
        &format!("service={SERVICE}"),
        "method=Nope",
        "code=unimplemented",
        "http_status=404",
    ]);
}

#[tokio::test]
async fn invalid_argument_code_is_logged_from_error_body() {
    let (addr, _probe) = start_app().await;

    let resp = reqwest::Client::new()
        .post(ping_url(addr, "Ping"))
        .header("content-type", "application/json")
        .body(r#"{"message":""}"#)
        .send()
        .await
        .expect("request");

    assert_eq!(resp.status(), 400);
    let body: serde_json::Value = resp.json().await.expect("connect error body");
    assert_eq!(body["code"], "invalid_argument");

    assert_log_line(&[
        &format!("service={SERVICE}"),
        "method=Ping",
        "code=invalid_argument",
        "http_status=400",
    ]);
}

#[tokio::test]
async fn protocol_version_validated_when_present_never_required() {
    let (addr, _probe) = start_app().await;
    let client = reqwest::Client::new();

    // Correct version accepted.
    let resp = client
        .post(ping_url(addr, "Ping"))
        .header("content-type", "application/json")
        .header("connect-protocol-version", "1")
        .body(r#"{"message":"v1"}"#)
        .send()
        .await
        .expect("request");
    assert_eq!(resp.status(), 200);

    // Wrong version rejected by the dispatcher (validated when present).
    let resp = client
        .post(ping_url(addr, "Ping"))
        .header("content-type", "application/json")
        .header("connect-protocol-version", "2")
        .body(r#"{"message":"v2"}"#)
        .send()
        .await
        .expect("request");
    assert_eq!(resp.status(), 400);
    let body: serde_json::Value = resp.json().await.expect("connect error body");
    assert_eq!(body["code"], "invalid_argument");

    // Absence is fine — proven throughout this file; asserted explicitly in
    // unary_json_roundtrip_with_standard_middleware.
}
