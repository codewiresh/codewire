//! HTTP application builder.
//!
//! Encodes the standard middleware stack every Codewire backend service
//! wants: request IDs (mirrored to response headers + tracing fields),
//! request tracing, and panic recovery. Health routes are opt-in via
//! [`AppBuilder::with_health`].
//!
//! Browsers reach every service through the dashboard's own origin, so by
//! default no service answers CORS at all (codewire#3258). A deployment whose
//! browser front end lives on another origin names it, exactly, in
//! [`CORS_ALLOWED_ORIGINS_ENV`]; nothing else is ever allowed.

use axum::Router;
use tower::ServiceBuilder;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};
use tower_http::set_header::{MakeHeaderValue, SetResponseHeader};
use tower_http::trace::TraceLayer;

use crate::health::{HealthState, ReadinessProbe, router as health_router};
use crate::metrics::router as metrics_router;

/// Fluent builder for the per-service `axum::Router`.
pub struct AppBuilder {
    service_name: String,
    health: Option<HealthState>,
    user_routes: Router,
    connect_routes: Vec<Router>,
    cors_allowed_origins: Vec<http::HeaderValue>,
    /// Whether the router also serves `/metrics`; see [`Self::without_metrics`].
    metrics: bool,
}

/// Comma-separated browser origins (`scheme://host[:port]`, no path) allowed
/// to call a service cross-origin. Unset or empty: no CORS. Any other value
/// stops the service at startup.
pub const CORS_ALLOWED_ORIGINS_ENV: &str = "CODEWIRE_CORS_ALLOWED_ORIGINS";

/// Parses [`CORS_ALLOWED_ORIGINS_ENV`]: each entry an exact `http` or
/// `https` origin with no path, query, fragment, credentials or wildcard.
pub fn parse_cors_allowed_origins(raw: &str) -> Result<Vec<http::HeaderValue>, String> {
    let mut origins = Vec::new();
    for entry in raw
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
    {
        let url = url::Url::parse(entry).map_err(|error| format!("{entry}: {error}"))?;
        let exact = matches!(url.scheme(), "http" | "https")
            && url.host_str().is_some_and(|host| !host.contains('*'))
            && url.username().is_empty()
            && url.password().is_none()
            && url.path() == "/"
            && url.query().is_none()
            && url.fragment().is_none();
        if !exact {
            return Err(format!("{entry}: not an exact http(s) origin"));
        }
        let origin = url.origin().ascii_serialization();
        let value =
            http::HeaderValue::from_str(&origin).map_err(|error| format!("{entry}: {error}"))?;
        if !origins.contains(&value) {
            origins.push(value);
        }
    }
    Ok(origins)
}

fn cors_allowed_origins_from_env() -> Vec<http::HeaderValue> {
    let raw = std::env::var(CORS_ALLOWED_ORIGINS_ENV).unwrap_or_default();
    parse_cors_allowed_origins(&raw)
        .unwrap_or_else(|error| panic!("invalid {CORS_ALLOWED_ORIGINS_ENV}: {error}"))
}

impl AppBuilder {
    /// Creates a builder for a service with the given logical name (used
    /// in span fields and a `service` response header).
    pub fn new(service_name: impl Into<String>) -> Self {
        Self {
            service_name: service_name.into(),
            health: None,
            user_routes: Router::new(),
            connect_routes: Vec::new(),
            cors_allowed_origins: cors_allowed_origins_from_env(),
            metrics: true,
        }
    }

    /// Leaves `/metrics` off this router, for a service that serves it on a
    /// listener of its own, so the API port and the metrics port each serve
    /// only their own routes (#4901).
    pub fn without_metrics(mut self) -> Self {
        self.metrics = false;
        self
    }

    /// Replaces the CORS origin allowlist read from
    /// [`CORS_ALLOWED_ORIGINS_ENV`]. Empty means no CORS.
    pub fn with_cors_allowed_origins(
        mut self,
        origins: impl IntoIterator<Item = http::HeaderValue>,
    ) -> Self {
        self.cors_allowed_origins = origins.into_iter().collect();
        self
    }

    /// Adds `/healthz` and `/readyz` routes.
    pub fn with_health(mut self) -> Self {
        self.health = Some(HealthState::default());
        self
    }

    /// Adds health routes whose `/readyz` asks one caller-owned probe, with
    /// no database.
    pub fn with_health_probe<F, Fut>(mut self, probe: F) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = bool> + Send + 'static,
    {
        self.health = Some(HealthState {
            pool: None,
            readiness_probe: Some(ReadinessProbe::new(probe)),
        });
        self
    }

    /// Adds health routes that probe the given database pool in
    /// `/readyz`.
    pub fn with_health_and_db(mut self, pool: sqlx::PgPool) -> Self {
        self.health = Some(HealthState {
            pool: Some(pool),
            readiness_probe: None,
        });
        self
    }

    /// Adds health routes whose readiness requires both Postgres and one
    /// caller-owned asynchronous dependency probe.
    pub fn with_health_and_db_probe<F, Fut>(mut self, pool: sqlx::PgPool, probe: F) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = bool> + Send + 'static,
    {
        self.health = Some(HealthState {
            pool: Some(pool),
            readiness_probe: Some(ReadinessProbe::new(probe)),
        });
        self
    }

    /// Merges the caller's own router into the application. Mount it
    /// last so health routes win on path conflicts.
    pub fn with_routes(mut self, routes: Router) -> Self {
        self.user_routes = routes;
        self
    }

    /// Mounts a Connect-RPC router into the application
    /// (`docs/dev/CONNECT-SERVER.md`, D1).
    ///
    /// Each registered Connect service is served at
    /// `/{package}.{Service}/{Method}` behind the standard middleware stack
    /// plus the Connect-specific content-type gate and per-RPC log event —
    /// see [`crate::connect::connect_router`]. May be called once per mount;
    /// RPC paths never collide with REST routes or the health endpoints.
    ///
    /// This mount carries **no user-auth layer** (D3's internal /
    /// self-authenticating mode — handlers validate their own credentials).
    /// User-facing services mount via
    /// [`AppBuilder::with_connect_routes_auth`].
    pub fn with_connect_routes(mut self, connect: connectrpc::Router) -> Self {
        self.connect_routes
            .push(crate::connect::connect_router(connect));
        self
    }

    /// [`with_connect_routes`](AppBuilder::with_connect_routes) with an
    /// explicit wire-protocol policy for a self-authenticating generated
    /// service.
    ///
    /// The ordinary unauthenticated mount remains Connect-only. No protocol
    /// policy admits gRPC-Web.
    pub fn with_connect_routes_and_protocol_policy(
        mut self,
        connect: connectrpc::Router,
        protocol_policy: crate::connect::ProtocolPolicy,
    ) -> Self {
        self.connect_routes
            .push(crate::connect::connect_router_with_protocol_policy(
                connect,
                protocol_policy,
            ));
        self
    }

    /// [`with_connect_routes`](AppBuilder::with_connect_routes) behind a
    /// [`ConnectAuthLayer`](crate::connect::ConnectAuthLayer) — one mount per
    /// auth mode (doc 03 D3): `authenticated` for user-facing services,
    /// `admin` for `codewire.admin.v1` services, with the layer's explicit
    /// allowlist for public methods inside otherwise-authenticated services.
    pub fn with_connect_routes_auth(
        mut self,
        connect: connectrpc::Router,
        auth: crate::connect::ConnectAuthLayer,
    ) -> Self {
        self.connect_routes
            .push(crate::connect::connect_router_with_auth(connect, auth));
        self
    }

    /// [`with_connect_routes_auth`](AppBuilder::with_connect_routes_auth) with
    /// an explicit wire-protocol policy for an evidence-approved first-party
    /// bidi mount.
    ///
    /// The ordinary authenticated mount remains Connect-only. No protocol
    /// policy admits gRPC-Web.
    pub fn with_connect_routes_auth_and_protocol_policy(
        mut self,
        connect: connectrpc::Router,
        auth: crate::connect::ConnectAuthLayer,
        protocol_policy: crate::connect::ProtocolPolicy,
    ) -> Self {
        self.connect_routes.push(
            crate::connect::connect_router_with_auth_and_protocol_policy(
                connect,
                auth,
                protocol_policy,
            ),
        );
        self
    }

    /// Mounts an all-unary product service behind Connect authentication and
    /// the bounded unary dispatcher policy.
    ///
    /// The dispatcher supplies and caps deadlines at 60 seconds. Keep any
    /// server-streaming, bidi, file-transfer, SSE, or exec surface on the
    /// ordinary mount methods so established streams never inherit an
    /// absolute unary lifetime.
    pub fn with_unary_connect_routes_auth(
        mut self,
        connect: connectrpc::Router,
        auth: crate::connect::ConnectAuthLayer,
    ) -> Self {
        self.connect_routes
            .push(crate::connect::connect_unary_router_with_auth(
                connect, auth,
            ));
        self
    }

    /// Mounts one all-unary, cluster-local generated service behind the
    /// Mesh authorization HMAC/forwarded-metadata boundary.
    ///
    /// The boundary authenticates a scoped service hop and removes the raw
    /// caller credential before Connect dispatch. This helper is deliberately
    /// separate from product and environment mounts: it must never be used to
    /// expose a public route or to give a handler access to raw headers.
    pub fn with_unary_connect_routes_mesh_authorization(
        mut self,
        connect: connectrpc::Router,
        authorization: crate::connect::MeshAuthorizationLayer,
    ) -> Self {
        self.connect_routes.push(
            crate::connect::connect_unary_router_with_mesh_authorization(connect, authorization),
        );
        self
    }

    /// Mounts one all-unary, cluster-local generated service reachable only
    /// with a scoped service-only HMAC credential. Like the Mesh
    /// authorization mount, it must never expose a public route.
    pub fn with_unary_connect_routes_internal_service(
        mut self,
        connect: connectrpc::Router,
        layer: crate::connect::InternalServiceLayer,
    ) -> Self {
        self.connect_routes
            .push(crate::connect::connect_unary_router_with_internal_service(
                connect, layer,
            ));
        self
    }

    /// Mounts the never-routed Connect conformance probe
    /// (`codewire.testing.v1.PingService`, doc 03 D8) when
    /// `CONNECT_TESTING_SURFACE=1`; a no-op otherwise, leaving the router
    /// byte-identical to a build without the probe. The flag is set by
    /// dev-stack, the migration-integration gate, and the kind/local-kind
    /// test manifests — never by base or production deploy manifests.
    pub fn with_connect_testing_surface(self, auth: crate::auth::AuthState) -> Self {
        if !crate::connect_testing::enabled() {
            return self;
        }
        tracing::info!("CONNECT_TESTING_SURFACE=1: mounting codewire.testing.v1.PingService");
        let (connect, layer) = crate::connect_testing::router(auth);
        self.with_connect_routes_auth(connect, layer)
    }

    /// Builds the final `Router` with the standard middleware stack.
    pub fn into_router(self) -> Router {
        let header = http::HeaderName::from_static("x-request-id");

        let middleware = ServiceBuilder::new()
            .layer(SetRequestIdLayer::new(header.clone(), MakeRequestUuid))
            .layer(request_trace_layer())
            .layer(PropagateRequestIdLayer::new(header))
            .option_layer(cors_layer(self.cors_allowed_origins))
            .layer(CatchPanicLayer::new());

        // Metrics are mounted after caller routes, alongside health, so an
        // application cannot accidentally shadow the operational endpoint.
        let mut app = Router::new().merge(self.user_routes);
        for connect in self.connect_routes {
            app = app.merge(connect);
        }
        if let Some(health) = self.health {
            app = app.merge(health_router(health));
        }
        if self.metrics {
            app = app.merge(metrics_router(&self.service_name));
        }
        app.layer(middleware)
            .layer(axum::middleware::from_fn(move |req, next| {
                let service = self.service_name.clone();
                set_service_header(req, next, service)
            }))
    }
}

/// The standard request tracing, for a server that does not use
/// [`AppBuilder`]: the [`RequestSpan`] around each request until its response
/// starts, tower-http's request log lines inside it, and the
/// [`TRACE_ID_HEADER`] on the response of a request whose span is exported.
///
/// The span ends when the handler has answered, before the response body is
/// sent, so a streamed response holds no span open and nothing its body does
/// later joins the request's trace: a session that lasts hours is a trace of
/// its setup (docs/CONFIGURATION.md, "Tracing"). A handler that wants a
/// bounded stream's work in the trace instruments that stream itself.
pub fn request_trace_layer() -> RequestTraceLayer {
    RequestTraceLayer
}

/// The response header that names the request's trace: the server's own id,
/// never one a caller sent (docs/CONFIGURATION.md, "Tracing").
pub const TRACE_ID_HEADER: http::HeaderName = http::HeaderName::from_static("x-codewire-trace-id");

/// See [`request_trace_layer`].
#[derive(Clone, Copy, Debug, Default)]
pub struct RequestTraceLayer;

impl<S> tower::Layer<S> for RequestTraceLayer {
    type Service = RequestTrace<
        SetResponseHeader<
            tower_http::trace::Trace<
                S,
                tower_http::classify::SharedClassifier<
                    tower_http::classify::ServerErrorsAsFailures,
                >,
                CallersSpan,
            >,
            TraceIdHeader,
        >,
    >;

    fn layer(&self, inner: S) -> Self::Service {
        let traced = TraceLayer::new_for_http()
            .make_span_with(CallersSpan)
            .layer(inner);
        RequestTrace {
            inner: SetResponseHeader::overriding(traced, TRACE_ID_HEADER, TraceIdHeader),
        }
    }
}

/// The value of [`TRACE_ID_HEADER`]. It is made while the response future is
/// polled inside the [`RequestSpan`], so the current span is the request's.
#[derive(Clone, Copy, Debug, Default)]
pub struct TraceIdHeader;

impl<T> MakeHeaderValue<T> for TraceIdHeader {
    fn make_header_value(&mut self, _message: &T) -> Option<http::HeaderValue> {
        crate::obs::exported_trace_id().and_then(|id| http::HeaderValue::try_from(id).ok())
    }
}

/// Runs each request's handler inside its [`RequestSpan`], and drops the span
/// with the handler's future: when the response starts.
#[derive(Clone, Debug)]
pub struct RequestTrace<S> {
    inner: S,
}

impl<S, B> tower::Service<http::Request<B>> for RequestTrace<S>
where
    S: tower::Service<http::Request<B>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = tracing::instrument::Instrumented<S::Future>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: http::Request<B>) -> Self::Future {
        use tower_http::trace::MakeSpan as _;
        use tracing::Instrument as _;

        let span = RequestSpan.make_span(&request);
        let response = span.in_scope(|| self.inner.call(request));
        response.instrument(span)
    }
}

/// Gives tower-http's [`TraceLayer`] no span of its own. Its log lines for a
/// request and for the start of its response are written inside the caller's
/// span, the [`RequestSpan`]; the layer would otherwise keep a span of its
/// own alive until the response body ended.
#[derive(Clone, Copy, Debug, Default)]
pub struct CallersSpan;

impl<B> tower_http::trace::MakeSpan<B> for CallersSpan {
    fn make_span(&mut self, _request: &http::Request<B>) -> tracing::Span {
        tracing::Span::none()
    }
}

/// The per-request span: tower-http's default `request` span at the same
/// `DEBUG` level (so the default `info` logs are unchanged), plus the
/// OpenTelemetry name (method and path, never the query) and kind. While
/// trace export is on it continues an incoming W3C `traceparent`, and probes
/// and scrapes get no span at all.
///
/// `uri` holds the path only. A query string can be a credential (a
/// verification token, an OAuth code), and a span's fields are written into
/// every log line inside it once `RUST_LOG` admits the span.
#[derive(Clone, Copy, Debug, Default)]
pub struct RequestSpan;

impl<B> tower_http::trace::MakeSpan<B> for RequestSpan {
    fn make_span(&mut self, request: &http::Request<B>) -> tracing::Span {
        let exporting = crate::obs::export_active();
        if exporting && crate::obs::untraced_path(request.uri().path()) {
            return tracing::Span::none();
        }
        let span = tracing::debug_span!(
            "request",
            method = %request.method(),
            uri = %request.uri().path(),
            version = ?request.version(),
            otel.name = %format_args!("{} {}", request.method(), request.uri().path()),
            otel.kind = "server",
        );
        if exporting {
            crate::obs::attach_http_parent(&span, request.headers());
        }
        span
    }
}

/// Only the configured origins, only for what a Connect or JSON browser
/// client sends; never credentials. `None` (no origins) adds no CORS headers.
fn cors_layer(origins: Vec<http::HeaderValue>) -> Option<CorsLayer> {
    if origins.is_empty() {
        return None;
    }
    Some(
        CorsLayer::new()
            .allow_origin(AllowOrigin::list(origins))
            .allow_methods([http::Method::GET, http::Method::POST])
            .allow_headers([
                http::header::CONTENT_TYPE,
                http::header::AUTHORIZATION,
                http::HeaderName::from_static("connect-protocol-version"),
                http::HeaderName::from_static("connect-timeout-ms"),
            ]),
    )
}

async fn set_service_header(
    req: axum::extract::Request,
    next: axum::middleware::Next,
    service: String,
) -> axum::response::Response {
    let mut resp = next.run(req).await;
    if let Ok(v) = http::HeaderValue::from_str(&service) {
        resp.headers_mut().insert("x-codewire-service", v);
    }
    resp
}

/// Keeps every answer of `router` out of shared caches: each response,
/// including errors, redirects and the 404 fallback, carries
/// `Cache-Control: no-store, private`, replacing any directive a handler
/// set, and no `ETag` or `Last-Modified`.
///
/// For a router whose answers depend on the caller, where a shared cache
/// that stored one would serve it to the next caller (#5054; the rule is in
/// `docs/dev/AUTH-POLICY.md`, "Credential rules"). It does not look at the
/// path, so health and metrics routes in the same router are marked too,
/// which costs nothing. Apply it after the last `merge`: routes merged in
/// later are not covered, and once this router is merged into another, only
/// its own routes keep the layer.
pub fn never_shared_cached(router: Router) -> Router {
    router.layer(axum::middleware::from_fn(mark_never_shared_cached))
}

/// The standard request tracing for a listener whose callers are outside
/// callers, such as a workspace daemon inside a user's environment: their
/// [`CALLER_TRACE_HEADERS`] are removed before anything reads them, so each
/// request is a trace of its own and the response names it with
/// [`TRACE_ID_HEADER`] (docs/CONFIGURATION.md, "Tracing").
pub fn traced_as_outside_callers(router: Router) -> Router {
    router
        .layer(request_trace_layer())
        .layer(axum::middleware::from_fn(remove_caller_trace_context))
}

/// A caller's trace context. A deployment's public edge must remove the same
/// headers, and its own configuration check pins this list, so a change here
/// changes that list too.
pub const CALLER_TRACE_HEADERS: [&str; 3] = ["traceparent", "tracestate", "baggage"];

async fn remove_caller_trace_context(
    mut req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    for name in CALLER_TRACE_HEADERS {
        req.headers_mut().remove(name);
    }
    next.run(req).await
}

async fn mark_never_shared_cached(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let mut resp = next.run(req).await;
    let headers = resp.headers_mut();
    headers.insert(
        http::header::CACHE_CONTROL,
        http::HeaderValue::from_static("no-store, private"),
    );
    headers.remove(http::header::ETAG);
    headers.remove(http::header::LAST_MODIFIED);
    resp
}

#[cfg(test)]
mod request_trace_tests;
#[cfg(test)]
mod tests;

#[cfg(test)]
mod cors_origin_tests {
    use super::parse_cors_allowed_origins;

    #[test]
    fn only_exact_http_origins_parse() {
        let parsed = parse_cors_allowed_origins(
            " https://app.example.com, http://localhost:5173/ ,,https://APP.example.com",
        )
        .unwrap();
        assert_eq!(parsed, ["https://app.example.com", "http://localhost:5173"]);
        assert!(parse_cors_allowed_origins("").unwrap().is_empty());
        for refused in [
            "*",
            "https://*.example.com",
            "app.example.com",
            "ftp://example.com",
            "https://example.com/dashboard",
            "https://example.com/?x=1",
            "https://example.com/#top",
            "https://user@example.com",
            "null",
        ] {
            assert!(parse_cors_allowed_origins(refused).is_err(), "{refused}");
        }
    }
}
