//! Connect-RPC mount helper.
//!
//! Program doc: `connect-rpc/03-connect-server-infrastructure.md`
//! (WI-1; design decisions D1, D6b, D7, D9). Connect services mount into the
//! same axum binaries as REST — same port, same [`crate::AppBuilder`] middleware
//! stack — via [`crate::AppBuilder::with_connect_routes`], which delegates to
//! [`connect_router`] here.
//!
//! What the mount adds around the raw `connectrpc` service:
//!
//! - **Per-service routing.** One axum route per registered Connect service
//!   (`/{package}.{Service}/{*method}`), never a catch-all fallback, so the
//!   REST surface's 404 behavior is untouched and only real RPC paths reach
//!   the Connect dispatcher.
//! - **Content-type enforcement (D6b/D9).** POSTs whose `Content-Type` is
//!   not admitted by the mount's explicit protocol policy are rejected with
//!   `415 Unsupported Media Type` + `Accept-Post` before any handler or
//!   dispatcher code runs. The shared policy admits only Connect protocol
//!   content types (`application/json`, `application/proto`,
//!   `application/connect+json`, `application/connect+proto`); exactly the
//!   Coordinator, EnvironmentSessionService and CredentialDelegationService mounts opt into native gRPC
//!   (`application/grpc`, `application/grpc+proto`) for their public CLI edge.
//!   No policy admits gRPC-Web. This makes every accepted POST non-simple in the
//!   CSRF sense (a browser cannot emit one without a preflight) and
//!   mechanically enforces D9's default "Connect protocol only" posture.
//!   `Connect-Protocol-Version` is validated when present (the library
//!   rejects values other than `1`) but is **not required** — decision
//!   recorded at D6b: the content-type gate already closes the residual
//!   CSRF vector, and requiring the header would break the ADR's plain-curl
//!   property for no additional security.
//! - **Per-RPC log event (D7).** Every request to a mounted Connect path
//!   emits one INFO event (target `connect_rpc`) carrying the service,
//!   method, wire protocol (`connect` or `grpc` after admission; `unknown`
//!   for pre-admission rejection), Connect status code, duration, credential
//!   kind, privacy-conscious principal fingerprint, server-derived synthetic
//!   classification, and request user agent — the evidence substrate for the
//!   migration's production-rollout gates.
//! - **Auth layer (D3, WI-2).** [`ConnectAuthLayer`] wraps the existing
//!   [`authenticate()`](crate::auth::authenticate) credential stack (session
//!   cookie, `cw_` API key, opaque OIDC bearer)
//!   in front of the Connect dispatcher — mount modes `authenticated` and
//!   `admin`, plus an explicit per-method public allowlist. Rejections are
//!   rendered through 01's Connect error renderer (D4): canonical code +
//!   `google.rpc.ErrorInfo` detail carrying today's `code`/`hint` and the
//!   request id — never the REST JSON envelope. Handlers read the
//!   authenticated caller back via [`auth_user`].

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::Response;
use base64::Engine as _;
use http::{HeaderValue, Method, StatusCode, header};
use sha2::{Digest, Sha256};

use crate::auth::{
    AuthState, AuthUser, CredentialContext, CredentialMutationAuthority, OAuthBearerAuthority,
    authenticate_product_credential, bearer_token, require_product_access, resolve_authentication,
    resolve_credential_mutation_authentication, resolve_oauth_bearer_authentication,
    session_cookie,
};
use crate::connect_error::{ConnectCode, ConnectError, ConnectErrorDetail};
use crate::error::AppError;
use crate::internal_hmac::verify_internal_hmac_token;

/// `Accept-Post` value advertised on a 415 rejection: the Connect protocol
/// content types this mount accepts (D9 — Connect only; gRPC and gRPC-Web
/// are deliberately absent).
pub const ACCEPT_POST: &str =
    "application/connect+json, application/connect+proto, application/json, application/proto";
/// `Accept-Post` for an explicit first-party native-gRPC exception.
pub const ACCEPT_POST_WITH_GRPC: &str = "application/connect+json, application/connect+proto, application/json, application/proto, application/grpc, application/grpc+proto";

/// Wire protocols admitted by one Connect-RPC mount.
///
/// Every mount defaults to [`Self::ConnectOnly`]. CoordinatorService and
/// EnvironmentSessionService and CredentialDelegationService are explicit exceptions: their public-edge
/// CLI legs need native gRPC while their direct h2c legs continue to use
/// Connect. gRPC-Web is never admitted.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ProtocolPolicy {
    /// Connect protocol only (the shared default).
    #[default]
    ConnectOnly,
    /// Connect plus native gRPC; reserved for an evidence-approved first-party
    /// bidi service mount.
    ConnectAndGrpc,
}

impl ProtocolPolicy {
    fn accept_post(self) -> &'static str {
        match self {
            Self::ConnectOnly => ACCEPT_POST,
            Self::ConnectAndGrpc => ACCEPT_POST_WITH_GRPC,
        }
    }

    fn protocol_for(
        self,
        method: &Method,
        content_type: Option<&HeaderValue>,
    ) -> Option<&'static str> {
        if method == Method::GET {
            return Some("connect");
        }
        if method != Method::POST {
            return None;
        }
        let essence = content_type_essence(content_type?)?;
        if is_connect_essence(&essence) {
            return Some("connect");
        }
        if self == Self::ConnectAndGrpc && is_native_grpc_essence(&essence) {
            return Some("grpc");
        }
        None
    }
}

/// Cap for buffering unary error bodies in [`log_rpc`]'s Connect-code
/// sniffing. Connect unary errors are small JSON documents; anything larger
/// falls back to the HTTP-status mapping instead of being buffered.
const MAX_ERROR_SNIFF_BYTES: u64 = 64 * 1024;

const PRINCIPAL_FINGERPRINT_DOMAIN: &[u8] = b"codewire.connect_rpc.principal.v1\0";

/// Server-side default and maximum for bounded unary product RPCs.
///
/// Only all-unary services mounted through [`connect_unary_router_with_auth`]
/// receive this policy. Streaming, bidi, SSE, file-transfer, and exec paths
/// remain outside it.
pub const CONNECT_UNARY_SERVER_TIMEOUT: Duration = Duration::from_secs(60);

/// Maximum time spent resolving a Connect credential before dispatcher entry.
///
/// Authentication deliberately runs before method dispatch, so the
/// dispatcher [`connectrpc::DeadlinePolicy`] cannot cover this database work.
pub const CONNECT_AUTH_RESOLUTION_TIMEOUT: Duration = Duration::from_secs(10);

/// Response extension carrying the validated credential kind for the
/// per-RPC log event (D7).
#[derive(Debug, Clone, Copy)]
pub struct RpcCredentialKind(pub &'static str);

/// Response extension carrying the server-validated principal evidence for
/// the per-RPC event (doc 05 D9).
#[derive(Debug, Clone)]
struct RpcPrincipalEvidence {
    principal_fingerprint: String,
    synthetic: bool,
}

impl RpcPrincipalEvidence {
    fn authenticated(user_id: &str, synthetic_user_ids: &BTreeSet<String>) -> Self {
        Self {
            principal_fingerprint: principal_fingerprint(user_id),
            synthetic: synthetic_user_ids.contains(user_id),
        }
    }
}

fn principal_fingerprint(user_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(PRINCIPAL_FINGERPRINT_DOMAIN);
    hasher.update(user_id.as_bytes());
    let digest = hasher.finalize();
    let mut fingerprint = String::with_capacity(32);
    for byte in &digest[..16] {
        write!(&mut fingerprint, "{byte:02x}").expect("writing to a String cannot fail");
    }
    fingerprint
}

#[derive(Debug, Clone, Copy)]
struct ValidatedRpcProtocol(&'static str);

/// Builds the axum router that serves a [`connectrpc::Router`] behind the
/// standard middleware stack.
///
/// Registers one route per Connect service present in `connect`
/// (`/{package}.{Service}/{*method}`) and layers the D6b content-type gate
/// and the D7 per-RPC log event around the Connect dispatcher. Merge the
/// result into an [`AppBuilder`](crate::AppBuilder) via
/// [`with_connect_routes`](crate::AppBuilder::with_connect_routes) so
/// request-id, tracing, CORS, panic recovery, and the `x-codewire-service`
/// header apply to RPCs exactly as they do to REST (D1).
///
/// Unknown *methods* of a mounted service reach the Connect dispatcher and
/// get a Connect-shaped `unimplemented` error; unknown *services* fall
/// through to the enclosing router (today's 404 behavior) until the edge
/// work (WI-4) routes them.
///
/// This mount carries **no user-auth layer** — D3's third mode (internal /
/// self-authenticating services, where the handler validates its own
/// credential). User-facing mounts go through
/// [`connect_router_with_auth`].
pub fn connect_router(connect: connectrpc::Router) -> axum::Router {
    build_connect_router(connect, None, None, ProtocolPolicy::ConnectOnly, None, None)
}

/// [`connect_router`] with an explicit wire-protocol policy.
///
/// This exists for a documented native-gRPC public-edge exception. Callers
/// must opt in per mount; the shared default stays Connect-only and no policy
/// admits gRPC-Web.
pub fn connect_router_with_protocol_policy(
    connect: connectrpc::Router,
    protocol_policy: ProtocolPolicy,
) -> axum::Router {
    build_connect_router(connect, None, None, protocol_policy, None, None)
}

/// [`connect_router`] with a [`ConnectAuthLayer`] in front of the dispatcher
/// (D3 mount modes `authenticated` / `admin`, plus the per-method public
/// allowlist). The layer sits inside the D6b content-type gate — a
/// non-Connect POST is 415 before any credential is examined — and inside
/// the D7 log event, which reads the layer's validated credential kind from
/// the [`RpcCredentialKind`] response extension and its principal evidence
/// from a separate response extension.
pub fn connect_router_with_auth(
    connect: connectrpc::Router,
    auth: ConnectAuthLayer,
) -> axum::Router {
    build_connect_router(
        connect,
        Some(auth),
        None,
        ProtocolPolicy::ConnectOnly,
        None,
        None,
    )
}

/// [`connect_router_with_auth`] with an explicit wire-protocol policy.
///
/// This is reserved for an evidence-approved authenticated first-party bidi
/// mount. The policy changes only protocol admission; the same auth layer,
/// canonical error renderer, generated handler, and state serve both admitted
/// protocols.
pub fn connect_router_with_auth_and_protocol_policy(
    connect: connectrpc::Router,
    auth: ConnectAuthLayer,
    protocol_policy: ProtocolPolicy,
) -> axum::Router {
    build_connect_router(connect, Some(auth), None, protocol_policy, None, None)
}

/// An explicitly bounded authenticated streaming mount. The caller supplies
/// its checked protocol envelope ceiling; other mounts retain the unchanged
/// dispatcher defaults. This changes neither authentication nor deadline policy.
pub fn connect_router_with_auth_protocol_and_limits(
    connect: connectrpc::Router,
    auth: ConnectAuthLayer,
    protocol_policy: ProtocolPolicy,
    limits: connectrpc::Limits,
) -> axum::Router {
    build_connect_router(
        connect,
        Some(auth),
        None,
        protocol_policy,
        None,
        Some(limits),
    )
}

/// [`connect_router_with_auth`] for an all-unary product service.
///
/// The dispatcher applies the owner-approved 60-second default and maximum.
/// This entry point is intentionally separate from the ordinary mount so an
/// established streaming or bidi response can never inherit the unary
/// lifetime policy accidentally.
pub fn connect_unary_router_with_auth(
    connect: connectrpc::Router,
    auth: ConnectAuthLayer,
) -> axum::Router {
    let deadline_policy = connectrpc::DeadlinePolicy::new()
        .with_default_timeout(CONNECT_UNARY_SERVER_TIMEOUT)
        .with_max(CONNECT_UNARY_SERVER_TIMEOUT);
    build_connect_router(
        connect,
        Some(auth),
        None,
        ProtocolPolicy::ConnectOnly,
        Some(deadline_policy),
        None,
    )
}

/// A self-authenticating all-unary mount with explicit message limits.
///
/// Like [`connect_router`] it carries no user-auth layer: the handler
/// validates its own credential. It adds the unary 60-second deadline policy
/// and the caller's [`connectrpc::Limits`], for a small closed surface such as
/// a tenant-reachable cluster listener.
pub fn connect_unary_router_with_limits(
    connect: connectrpc::Router,
    limits: connectrpc::Limits,
) -> axum::Router {
    let deadline_policy = connectrpc::DeadlinePolicy::new()
        .with_default_timeout(CONNECT_UNARY_SERVER_TIMEOUT)
        .with_max(CONNECT_UNARY_SERVER_TIMEOUT);
    build_connect_router(
        connect,
        None,
        None,
        ProtocolPolicy::ConnectOnly,
        Some(deadline_policy),
        Some(limits),
    )
}

/// Builds an all-unary private Connect mount whose outer authentication layer
/// validates the scoped HMAC service hop and removes forwarded credential
/// metadata before generated-service dispatch. Handlers can observe only a
/// typed [`MeshAuthorizationPrincipal`].
pub fn connect_unary_router_with_mesh_authorization(
    connect: connectrpc::Router,
    authorization: MeshAuthorizationLayer,
) -> axum::Router {
    let deadline_policy = connectrpc::DeadlinePolicy::new()
        .with_default_timeout(CONNECT_UNARY_SERVER_TIMEOUT)
        .with_max(CONNECT_UNARY_SERVER_TIMEOUT);
    build_connect_router(
        connect,
        None,
        Some(authorization),
        ProtocolPolicy::ConnectOnly,
        Some(deadline_policy),
        None,
    )
}

fn build_connect_router(
    connect: connectrpc::Router,
    auth: Option<ConnectAuthLayer>,
    mesh_authorization: Option<MeshAuthorizationLayer>,
    protocol_policy: ProtocolPolicy,
    deadline_policy: Option<connectrpc::DeadlinePolicy>,
    limits: Option<connectrpc::Limits>,
) -> axum::Router {
    // Distinct fully-qualified service names, e.g.
    // "codewire.testing.v1.PingService" from "codewire.testing.v1.PingService/Ping".
    let services: BTreeSet<String> = connect
        .methods()
        .filter_map(|path| path.split('/').next())
        .map(str::to_owned)
        .collect();

    let mut service = connectrpc::ConnectRpcService::new(connect);
    if let Some(limits) = limits {
        service = service.with_limits(limits);
    }
    if let Some(deadline_policy) = deadline_policy {
        service = service.with_deadline_policy(deadline_policy);
    }
    let mut router = axum::Router::new();
    for name in &services {
        router = router.route_service(&format!("/{name}/{{*method}}"), service.clone());
    }

    if let Some(auth) = auth {
        router = auth.apply(router);
    }
    if let Some(authorization) = mesh_authorization {
        router = authorization.apply(router);
    }

    // `.layer` wraps outside-in as written bottom-to-top, so the log event
    // (added last) is outermost and also observes content-type rejections;
    // the auth layer (applied above) is innermost — a request must be a
    // well-formed Connect POST/GET before any credential is examined.
    router
        .layer(axum::middleware::from_fn_with_state(
            protocol_policy,
            unbuffer_streaming_responses,
        ))
        .layer(axum::middleware::from_fn_with_state(
            protocol_policy,
            enforce_connect_content_type,
        ))
        .layer(axum::middleware::from_fn(log_rpc))
}

/// Marks streaming-protocol responses with `X-Accel-Buffering: no` so
/// nginx-family proxies deliver frames as the server paces them instead of
/// buffering the response (doc 03 D5 — the whole program's
/// `Stream*`/`Watch*` surface dies if the edge buffers). Shared mounts mark
/// exact `application/connect+json` / `application/connect+proto` responses;
/// a first-party bidi opt-in also marks exact native gRPC response types.
/// gRPC-Web is never included.
/// Mirrors the SSE precedent in `codewire-orchestration::api::proxy`. The
/// Connect edge Ingress additionally sets `proxy-buffering: off`; the
/// header makes the posture per-response and independent of edge
/// annotation drift. Handlers that set the header themselves win.
async fn unbuffer_streaming_responses(
    State(protocol_policy): State<ProtocolPolicy>,
    req: Request,
    next: Next,
) -> Response {
    let mut resp = next.run(req).await;
    let is_streaming = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(content_type_essence)
        .is_some_and(|essence| {
            is_connect_streaming_essence(&essence)
                || (protocol_policy == ProtocolPolicy::ConnectAndGrpc
                    && is_native_grpc_essence(&essence))
        });
    if is_streaming && !resp.headers().contains_key("x-accel-buffering") {
        resp.headers_mut()
            .insert("x-accel-buffering", HeaderValue::from_static("no"));
    }
    resp
}

// --- auth layer (D3, WI-2) ---------------------------------------------------

/// Tower/axum auth layer for Connect mounts (doc 03 D3).
///
/// Wraps the shared credential stack —
/// the same cookie / `cw_` API key / OIDC-bearer resolution and
/// product-authorization policy REST's `require_auth` uses —
/// in front of a Connect router. On success the validated [`AuthUser`] and
/// [`CredentialContext`] are inserted into request extensions (readable in
/// handlers via [`auth_user`] and [`auth_context`]) and the credential kind is
/// reported to the D7 per-RPC log event through the [`RpcCredentialKind`]
/// response extension.
///
/// Mount modes, mirroring today's REST router topology:
///
/// - [`ConnectAuthLayer::authenticated`] — reject with Connect
///   `unauthenticated` unless a product credential validates (`require_auth`
///   twin).
/// - [`ConnectAuthLayer::admin`] — additionally reject non-admin users with
///   `permission_denied` for every method of the mount (`require_admin`
///   twin). Admin gating is per-Service: `codewire.admin.v1` services use
///   this whole-mount mode (D3).
/// - [`ConnectAuthLayer::oauth_bearer_only`] — isolated services accept only
///   an opaque OAuth bearer with product scope. Cookies never supply identity;
///   API keys never enter their lookup or bookkeeping paths.
/// - [`ConnectAuthLayer::credential_mutation`] — the isolated credential
///   mutation service accepts exact-Origin browser sessions or OAuth bearers;
///   API keys remain denied before lookup.
/// - self-authenticating internal services mount without this product-user
///   auth layer ([`connect_router`]); their handlers must validate their
///   dedicated machine identity before any domain lookup.
///
/// Two explicit per-method sets refine a mount, both defaulting to empty
/// (secure by default) and both reviewed like a route registration:
///
/// - [`allow_public`](ConnectAuthLayer::allow_public) — full
///   `/{package}.{Service}/{Method}` paths that bypass authentication
///   entirely (D3's public-method allowlist; e.g. the invitation token
///   lookup). No `AuthUser` is inserted for them.
/// - [`admin_only`](ConnectAuthLayer::admin_only) — full paths elevated to
///   the admin check inside an `authenticated` mount. Product admin gating
///   stays per-Service per D3; this elevation exists for the D8 probe
///   service, which deliberately spans all three modes in one Service so
///   the infrastructure can be conformance-tested end to end.
///
/// Rejections are rendered through 01's Connect renderer (D4): the same
/// `AppError` source REST renders its envelope from, mapped to a canonical
/// Connect code with a `google.rpc.ErrorInfo` detail (reason/hint/request
/// id) — never the REST JSON envelope. Org-membership checks stay in
/// handlers, unchanged.
#[derive(Clone)]
pub struct ConnectAuthLayer {
    state: AuthState,
    credential_policy: ConnectCredentialPolicy,
    session_origin: Option<HeaderValue>,
    admin_mount: bool,
    public_methods: BTreeSet<String>,
    admin_methods: BTreeSet<String>,
    synthetic_user_ids: BTreeSet<String>,
}

#[derive(Clone, Copy)]
enum ConnectCredentialPolicy {
    Product,
    OAuthBearerOnly,
    CredentialMutation,
}

impl ConnectAuthLayer {
    /// D3 `authenticated` mount: any valid user credential passes.
    pub fn authenticated(state: AuthState) -> Self {
        Self {
            state,
            credential_policy: ConnectCredentialPolicy::Product,
            session_origin: None,
            admin_mount: false,
            public_methods: BTreeSet::new(),
            admin_methods: BTreeSet::new(),
            synthetic_user_ids: BTreeSet::new(),
        }
    }

    /// Accept only the existing opaque Codewire OAuth bearer, with a live
    /// subject/client, fixed token expiry and exact `codewire.api` scope.
    ///
    /// Unlike `authenticated`, this mount ignores cookies entirely and rejects
    /// API keys before database access. Its pool needs only identity SELECTs:
    /// `oidc_access_tokens(token_hash,user_id,client_id,scopes,expires_at)`,
    /// `users(id,is_admin,enabled)` and `oidc_clients(id,disabled)`. No session, API-key,
    /// refresh-token or signing-key authority is needed. Handlers must still
    /// authorize the authenticated owner and resource; payload IDs confer none.
    pub fn oauth_bearer_only(state: AuthState) -> Self {
        Self {
            credential_policy: ConnectCredentialPolicy::OAuthBearerOnly,
            ..Self::authenticated(state)
        }
    }

    /// Credential-mutation mount: accept either an exact original OAuth bearer
    /// or a live browser session arriving from the configured public origin.
    /// API keys are rejected before lookup. This mode is intentionally not
    /// reusable by delegation or general product mounts.
    pub fn credential_mutation(state: AuthState, session_origin: HeaderValue) -> Self {
        Self {
            credential_policy: ConnectCredentialPolicy::CredentialMutation,
            session_origin: Some(session_origin),
            ..Self::authenticated(state)
        }
    }

    /// Finite account-owned GitHub metadata operations inside the isolated
    /// authority. Keep the same exact-Origin session/original-OAuth policy and
    /// opaque retained authority as credential mutations; this does not admit
    /// browser sessions to delegation or ordinary runtime grants.
    pub fn github_repository(state: AuthState, session_origin: HeaderValue) -> Self {
        Self::credential_mutation(state, session_origin)
    }

    /// D3 `admin` mount: every method additionally requires `is_admin`
    /// (non-admin users get `permission_denied`).
    pub fn admin(state: AuthState) -> Self {
        Self {
            admin_mount: true,
            ..Self::authenticated(state)
        }
    }

    /// Allowlist full `/{package}.{Service}/{Method}` paths that bypass
    /// authentication (D3). Handlers behind these paths see no
    /// [`AuthUser`]; the D7 event logs `credential=none` for them.
    #[must_use]
    pub fn allow_public<I, S>(mut self, methods: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.public_methods
            .extend(methods.into_iter().map(|m| normalize_method_path(m.into())));
        self
    }

    /// Elevate full `/{package}.{Service}/{Method}` paths to the admin check
    /// inside an `authenticated` mount. See the type-level docs for why this
    /// exists (D8 probe); product `codewire.admin.v1` services mount with
    /// [`ConnectAuthLayer::admin`] instead.
    #[must_use]
    pub fn admin_only<I, S>(mut self, methods: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.admin_methods
            .extend(methods.into_iter().map(|m| normalize_method_path(m.into())));
        self
    }

    /// Configures the exact authenticated user IDs classified as synthetic
    /// in the `connect_rpc` event (doc 05 D9).
    ///
    /// Classification is performed from the [`AuthUser`] returned by the
    /// shared authenticator. Request headers and API-key metadata are never
    /// consulted.
    #[must_use]
    pub fn synthetic_user_ids<I, S>(mut self, user_ids: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.synthetic_user_ids
            .extend(user_ids.into_iter().map(Into::into));
        self
    }

    /// Applies this layer to `router` as axum middleware. Used by
    /// [`connect_router_with_auth`]; public so DB-backed integration tests
    /// (and, later, self-contained harnesses) can wrap a minimal router in
    /// exactly the middleware the real mounts use.
    pub fn apply(self, router: axum::Router) -> axum::Router {
        let layer = Arc::new(self);
        router.layer(axum::middleware::from_fn(
            move |req: Request, next: Next| {
                let layer = Arc::clone(&layer);
                async move { enforce_connect_auth(layer, req, next).await }
            },
        ))
    }
}

/// Typed original-caller identity attached by [`MeshAuthorizationLayer`].
///
/// It contains no raw credential material. The private Mesh authorization
/// service consumes this value plus the request's organization ID; it never
/// reads an HTTP credential header after middleware dispatch.
#[derive(Clone, Debug)]
pub enum MeshAuthorizationPrincipal {
    User {
        user: AuthUser,
        credential: CredentialContext,
    },
}

/// Extracts the original caller identity established by
/// [`MeshAuthorizationLayer`].
pub fn mesh_authorization_principal(
    ctx: &connectrpc::RequestContext,
) -> Result<&MeshAuthorizationPrincipal, connectrpc::ConnectError> {
    ctx.extensions()
        .get::<MeshAuthorizationPrincipal>()
        .ok_or_else(|| connectrpc::ConnectError::unauthenticated("request has no Mesh principal"))
}

/// Reserved binary metadata carrying the canonical browser session token.
///
/// Its value is standard base64 without padding. It exists only on the
/// private Mesh-to-control-plane hop and is removed before Connect dispatch.
pub const MESH_FORWARDED_SESSION_METADATA: &str = "codewire-forwarded-session-bin";

/// Reserved binary metadata carrying the full canonical Authorization value.
///
/// Its value is standard base64 without padding. It is mutually exclusive
/// with [`MESH_FORWARDED_SESSION_METADATA`] and is removed before dispatch.
pub const MESH_FORWARDED_AUTHORIZATION_METADATA: &str = "codewire-forwarded-authorization-bin";

/// HMAC-authenticated metadata boundary for the private Mesh authorization
/// service.
///
/// The ordinary `Authorization` header is the short-lived HMAC service
/// credential. Exactly one original caller credential must arrive in one of
/// the reserved binary metadata lanes. The middleware validates the exact
/// service/method scope, removes all raw credentials, resolves the original
/// credential through canonical stores, and inserts only a typed principal.
#[derive(Clone)]
pub struct MeshAuthorizationLayer {
    state: AuthState,
    hmac_secret: String,
    expected_service: String,
    expected_method: String,
}

impl std::fmt::Debug for MeshAuthorizationLayer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MeshAuthorizationLayer")
            .field("expected_service", &self.expected_service)
            .field("expected_method", &self.expected_method)
            .field("hmac_secret", &"[redacted]")
            .finish()
    }
}

impl MeshAuthorizationLayer {
    /// Constructs the boundary for one private calling service and one exact
    /// generated RPC method.
    pub fn new(
        state: AuthState,
        hmac_secret: impl Into<String>,
        expected_service: impl Into<String>,
        expected_method: impl Into<String>,
    ) -> Self {
        Self {
            state,
            hmac_secret: hmac_secret.into(),
            expected_service: expected_service.into(),
            expected_method: expected_method.into(),
        }
    }

    /// Applies the boundary inside the normal Connect content-type and
    /// per-RPC observability layers.
    pub fn apply(self, router: axum::Router) -> axum::Router {
        let layer = Arc::new(self);
        router.layer(axum::middleware::from_fn(
            move |req: Request, next: Next| {
                let layer = Arc::clone(&layer);
                async move { enforce_mesh_authorization(layer, req, next).await }
            },
        ))
    }
}

async fn enforce_mesh_authorization(
    layer: Arc<MeshAuthorizationLayer>,
    mut req: Request,
    next: Next,
) -> Response {
    let request_id = req
        .headers()
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    // Never pass a credential-bearing header set to error rendering, tracing,
    // or the generated dispatcher. This sanitized copy is the only header
    // view used by a rejection below.
    let mut safe_headers = req.headers().clone();
    safe_headers.remove(header::AUTHORIZATION);
    safe_headers.remove(header::COOKIE);
    safe_headers.remove(MESH_FORWARDED_SESSION_METADATA);
    safe_headers.remove(MESH_FORWARDED_AUTHORIZATION_METADATA);

    if req.uri().path() != format!("/{}", layer.expected_method) {
        return rejection_response(
            &AppError::Unauthorized,
            request_id.as_deref(),
            &safe_headers,
        );
    }

    let hmac_bearer = match exactly_one_header(req.headers(), header::AUTHORIZATION.as_str()) {
        Ok(value) => value,
        Err(error) => return rejection_response(&error, request_id.as_deref(), &safe_headers),
    };
    let hmac_bearer = match hmac_bearer
        .strip_prefix("Bearer ")
        .or_else(|| hmac_bearer.strip_prefix("bearer "))
    {
        Some(token) if !token.is_empty() => token,
        None | Some(_) => {
            return rejection_response(
                &AppError::Unauthorized,
                request_id.as_deref(),
                &safe_headers,
            );
        }
    };
    if verify_internal_hmac_token(
        &layer.hmac_secret,
        hmac_bearer,
        &layer.expected_service,
        &layer.expected_method,
        chrono::Utc::now(),
    )
    .is_err()
    {
        return rejection_response(
            &AppError::Unauthorized,
            request_id.as_deref(),
            &safe_headers,
        );
    }

    // A browser cookie belongs only in the dedicated binary metadata lane.
    // Rejecting a raw Cookie prevents it surviving beside a typed principal.
    if req.headers().contains_key(header::COOKIE) {
        return rejection_response(
            &AppError::Unauthorized,
            request_id.as_deref(),
            &safe_headers,
        );
    }

    let forwarded = match forwarded_credential(req.headers()) {
        Ok(credential) => credential,
        Err(error) => return rejection_response(&error, request_id.as_deref(), &safe_headers),
    };

    // Remove both the hop and original credential before the request reaches
    // Connect dispatch, error serialization, or handler code.
    req.headers_mut().remove(header::AUTHORIZATION);
    req.headers_mut().remove(header::COOKIE);
    req.headers_mut().remove(MESH_FORWARDED_SESSION_METADATA);
    req.headers_mut()
        .remove(MESH_FORWARDED_AUTHORIZATION_METADATA);

    let auth_timeout = connect_auth_resolution_timeout(req.headers());
    let principal = match forwarded {
        ForwardedCredential::Session(session) => bounded_authentication(
            authenticate_product_credential(&layer.state, Some(session.as_str()), None),
            auth_timeout,
        )
        .await
        .map(|authentication| MeshAuthorizationPrincipal::User {
            user: authentication.user,
            credential: authentication.credential,
        }),
        ForwardedCredential::Authorization(authorization) => {
            let bearer = match authorization
                .as_str()
                .strip_prefix("Bearer ")
                .or_else(|| authorization.as_str().strip_prefix("bearer "))
            {
                Some(token) if !token.is_empty() => token,
                None | Some(_) => {
                    return rejection_response(
                        &AppError::Unauthorized,
                        request_id.as_deref(),
                        &safe_headers,
                    );
                }
            };
            bounded_authentication(
                authenticate_product_credential(&layer.state, None, Some(bearer)),
                auth_timeout,
            )
            .await
            .map(|authentication| MeshAuthorizationPrincipal::User {
                user: authentication.user,
                credential: authentication.credential,
            })
        }
    };
    let principal = match principal {
        Ok(principal) => principal,
        Err(failure) => {
            return connect_auth_failure_response(
                failure,
                auth_timeout,
                request_id.as_deref(),
                &safe_headers,
            );
        }
    };

    let MeshAuthorizationPrincipal::User { user, credential } = &principal;
    let credential = RpcCredentialKind(credential.kind().as_str());
    let principal_evidence = RpcPrincipalEvidence::authenticated(&user.user_id, &BTreeSet::new());
    req.extensions_mut().insert(principal);
    let mut response = next.run(req).await;
    response.extensions_mut().insert(credential);
    response.extensions_mut().insert(principal_evidence);
    response
}

fn exactly_one_header<'a>(headers: &'a http::HeaderMap, name: &str) -> Result<&'a str, AppError> {
    let mut values = headers.get_all(name).iter();
    let value = values.next().ok_or(AppError::Unauthorized)?;
    if values.next().is_some() {
        return Err(AppError::Unauthorized);
    }
    value.to_str().map_err(|_| AppError::Unauthorized)
}

fn forwarded_credential(headers: &http::HeaderMap) -> Result<ForwardedCredential, AppError> {
    let session = binary_metadata(headers, MESH_FORWARDED_SESSION_METADATA)?;
    let authorization = binary_metadata(headers, MESH_FORWARDED_AUTHORIZATION_METADATA)?;
    match (session, authorization) {
        (Some(session), None) => Ok(ForwardedCredential::Session(RedactedCredential(session))),
        (None, Some(authorization)) => Ok(ForwardedCredential::Authorization(RedactedCredential(
            authorization,
        ))),
        _ => Err(AppError::Unauthorized),
    }
}

fn binary_metadata(headers: &http::HeaderMap, name: &str) -> Result<Option<String>, AppError> {
    let mut values = headers.get_all(name).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(AppError::Unauthorized);
    }
    let encoded = value.to_str().map_err(|_| AppError::Unauthorized)?;
    let decoded = base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(encoded)
        .map_err(|_| AppError::Unauthorized)?;
    String::from_utf8(decoded)
        .map(Some)
        .map_err(|_| AppError::Unauthorized)
}

struct RedactedCredential(String);

impl RedactedCredential {
    fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for RedactedCredential {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("[redacted]")
    }
}

enum ForwardedCredential {
    Session(RedactedCredential),
    Authorization(RedactedCredential),
}

impl std::fmt::Debug for ForwardedCredential {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Session(_) => formatter.write_str("ForwardedCredential::Session([redacted])"),
            Self::Authorization(_) => {
                formatter.write_str("ForwardedCredential::Authorization([redacted])")
            }
        }
    }
}

/// Paths are matched against `Request::uri().path()`, which always starts
/// with `/`; accept registrations with or without the leading slash.
fn normalize_method_path(path: String) -> String {
    if path.starts_with('/') {
        path
    } else {
        format!("/{path}")
    }
}

async fn enforce_connect_auth(
    layer: Arc<ConnectAuthLayer>,
    mut req: Request,
    next: Next,
) -> Response {
    if layer.public_methods.contains(req.uri().path()) {
        // D3 allowlist bypass: no authentication attempted, no AuthUser.
        return next.run(req).await;
    }

    // Pull everything out of the request before the first await (the body is
    // !Sync; holding &Request across an await would make this future !Send).
    let request_id = req
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let request_headers = req.headers().clone();
    let auth_timeout = connect_auth_resolution_timeout(req.headers());
    let is_get = req.method() == Method::GET;
    let resolved = match bounded_authentication(
        async {
            match layer.credential_policy {
                ConnectCredentialPolicy::Product => resolve_authentication(
                    &layer.state,
                    session_cookie(&request_headers),
                    bearer_token(&request_headers),
                )
                .await
                .map(|auth| (auth, None)),
                ConnectCredentialPolicy::OAuthBearerOnly => {
                    resolve_oauth_bearer_authentication(&layer.state, &request_headers)
                        .await
                        .map(|auth| (auth, None))
                }
                ConnectCredentialPolicy::CredentialMutation => {
                    let origin = layer
                        .session_origin
                        .as_ref()
                        .expect("credential mutation policy has a session origin");
                    resolve_credential_mutation_authentication(
                        &layer.state,
                        &request_headers,
                        origin,
                    )
                    .await
                    .map(|(auth, authority)| (auth, Some(authority)))
                }
            }
        },
        auth_timeout,
    )
    .await
    {
        Ok(outcome) => outcome,
        Err(failure) => {
            return connect_auth_failure_response(
                failure,
                auth_timeout,
                request_id.as_deref(),
                &request_headers,
            );
        }
    };
    let (auth, mutation_authority) = resolved;

    let credential = RpcCredentialKind(auth.credential.kind().as_str());
    let principal_evidence =
        RpcPrincipalEvidence::authenticated(&auth.user.user_id, &layer.synthetic_user_ids);

    if let Err(err) = require_product_access(&auth) {
        let mut resp = rejection_response(&err, request_id.as_deref(), &request_headers);
        // Authentication succeeded even though authorization failed, so the
        // event retains the validated credential and principal evidence.
        resp.extensions_mut().insert(credential);
        resp.extensions_mut().insert(principal_evidence);
        return resp;
    }

    if (layer.admin_mount || layer.admin_methods.contains(req.uri().path()))
        && let Err(err) = auth.user.require_global_admin()
    {
        let mut resp = rejection_response(&err, request_id.as_deref(), &request_headers);
        // Authentication succeeded even though authorization failed, so the
        // event retains the validated principal classification.
        resp.extensions_mut().insert(credential);
        resp.extensions_mut().insert(principal_evidence);
        return resp;
    }

    if let Some(authority) = auth.oauth_bearer_authority {
        req.extensions_mut().insert(authority);
    }
    if let Some(authority) = mutation_authority {
        req.extensions_mut().insert(authority);
    }
    req.extensions_mut().insert(auth.credential);
    req.extensions_mut().insert(auth.user);
    let mut resp = next.run(req).await;
    resp.extensions_mut().insert(credential);
    resp.extensions_mut().insert(principal_evidence);

    // D6b cache posture: a credentialed Connect GET response must never be
    // cacheable by a shared cache. Handlers that need a stricter directive
    // (e.g. `no-store` on credential-bearing payloads) set their own header,
    // which wins here.
    if is_get && !resp.headers().contains_key(header::CACHE_CONTROL) {
        resp.headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("private"));
    }
    resp
}

/// Returns the authentication budget without extending a caller's asserted
/// Connect deadline. Authenticated mounts are Connect-only today, and the
/// content-type gate runs before this layer, so `connect-timeout-ms` is the
/// only protocol timeout header admitted here. Invalid headers remain the
/// dispatcher's concern and fall back to the server's 10-second auth ceiling.
fn connect_auth_resolution_timeout(headers: &http::HeaderMap) -> Duration {
    headers
        .get("connect-timeout-ms")
        .and_then(|value| value.to_str().ok())
        .and_then(parse_connect_timeout)
        .map(|asserted| asserted.min(CONNECT_AUTH_RESOLUTION_TIMEOUT))
        .unwrap_or(CONNECT_AUTH_RESOLUTION_TIMEOUT)
}

/// Mirrors connectrpc 0.8.1's Connect timeout grammar: an unsigned
/// millisecond value of at most ten ASCII digits.
fn parse_connect_timeout(value: &str) -> Option<Duration> {
    if value.is_empty() || value.len() > 10 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    value.parse::<u64>().ok().map(Duration::from_millis)
}

#[derive(Debug)]
enum AuthResolutionFailure {
    Authentication(AppError),
    DeadlineExceeded,
}

async fn bounded_authentication<T, F>(
    future: F,
    timeout: Duration,
) -> Result<T, AuthResolutionFailure>
where
    F: Future<Output = Result<T, AppError>>,
{
    match tokio::time::timeout(timeout, future).await {
        Ok(result) => result.map_err(AuthResolutionFailure::Authentication),
        Err(_) => Err(AuthResolutionFailure::DeadlineExceeded),
    }
}

fn connect_auth_failure_response(
    failure: AuthResolutionFailure,
    timeout: Duration,
    request_id: Option<&str>,
    request_headers: &http::HeaderMap,
) -> Response {
    match failure {
        // Absent/invalid credential renders `unauthenticated`; an
        // infrastructure fault during validation (e.g. the DB lookup
        // failing) renders through the same D2 mapping (`internal`) —
        // protocol-native either way, never the REST envelope (D4).
        AuthResolutionFailure::Authentication(err) => {
            rejection_response(&err, request_id, request_headers)
        }
        AuthResolutionFailure::DeadlineExceeded => {
            tracing::warn!(
                timeout_milliseconds = timeout.as_millis() as u64,
                "Connect credential resolution deadline exceeded"
            );
            rejection_response(&authentication_timeout_error(), request_id, request_headers)
        }
    }
}

fn authentication_timeout_error() -> AppError {
    AppError::Coded {
        status: StatusCode::GATEWAY_TIMEOUT,
        code: "authentication_timeout",
        detail: "authentication deadline exceeded".into(),
    }
}

/// Extracts the [`AuthUser`] that [`ConnectAuthLayer`] attached to this RPC.
///
/// Connect handlers call this instead of re-implementing credential logic —
/// the tower layer's request extensions are copied verbatim into the
/// dispatcher's [`connectrpc::RequestContext`]. Returns `unauthenticated`
/// when no user is present: an unauthenticated mount, or an allowlisted
/// public method (which bypasses authentication and must not require a
/// caller identity).
pub fn auth_user(ctx: &connectrpc::RequestContext) -> Result<&AuthUser, connectrpc::ConnectError> {
    ctx.extensions().get::<AuthUser>().ok_or_else(|| {
        connectrpc::ConnectError::unauthenticated("request has no authenticated user")
    })
}

/// Extracts the validated credential authority attached by
/// [`ConnectAuthLayer`]. OAuth client/scopes live here rather than on the
/// resource principal so future service-specific checks do not conflate
/// delegated authority with user identity.
pub fn auth_context(
    ctx: &connectrpc::RequestContext,
) -> Result<&CredentialContext, connectrpc::ConnectError> {
    ctx.extensions().get::<CredentialContext>().ok_or_else(|| {
        connectrpc::ConnectError::unauthenticated("request has no authenticated credential")
    })
}

/// Extract the original OAuth authority, with no raw bearer or digest exposed.
/// Only successfully authorized OAuth requests receive this extension; cookies,
/// API keys and public methods cannot supply it. Long-running handlers should
/// clone this value and release their request context, not retain raw headers.
pub fn oauth_bearer_authority(
    ctx: &connectrpc::RequestContext,
) -> Result<&OAuthBearerAuthority, connectrpc::ConnectError> {
    ctx.extensions()
        .get::<OAuthBearerAuthority>()
        .ok_or_else(|| {
            connectrpc::ConnectError::unauthenticated("request has no original OAuth authority")
        })
}

/// Extract the exact session-or-OAuth authority installed only by the
/// credential-mutation mount.
pub fn credential_mutation_authority(
    ctx: &connectrpc::RequestContext,
) -> Result<&CredentialMutationAuthority, connectrpc::ConnectError> {
    ctx.extensions()
        .get::<CredentialMutationAuthority>()
        .ok_or_else(|| {
            connectrpc::ConnectError::unauthenticated(
                "request has no original credential-mutation authority",
            )
        })
}

// --- error wire bridge (01 renderer → Connect wire, D4) ----------------------

/// Renders an [`AppError`] onto the Connect wire via 01's renderer: D2 code
/// mapping, D3 field paths, D4 `ErrorInfo` (reason/hint/`request_id`), with
/// details protobuf-encoded from the vendored `google.rpc` types.
pub fn app_error_to_wire(err: &AppError, request_id: Option<&str>) -> connectrpc::ConnectError {
    wire_error(&ConnectError::from_app_error(err, request_id))
}

/// [`app_error_to_wire`] for Connect handlers: pulls the request id from the
/// dispatcher's [`connectrpc::RequestContext`] headers (minted by the
/// standard middleware stack, D7).
pub fn rpc_app_error(err: &AppError, ctx: &connectrpc::RequestContext) -> connectrpc::ConnectError {
    let request_id = ctx
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok());
    app_error_to_wire(err, request_id)
}

/// Converts 01's transport-agnostic [`ConnectError`] into connectrpc's wire
/// error: canonical code, message, and `details` entries carrying the bare
/// fully-qualified type name plus the base64-encoded protobuf value — the
/// Connect protocol's JSON error shape.
pub fn wire_error(rendered: &ConnectError) -> connectrpc::ConnectError {
    let mut wire =
        connectrpc::ConnectError::new(wire_code(rendered.code), rendered.message.clone());
    for detail in &rendered.details {
        wire = wire.with_detail(wire_detail(detail));
    }
    wire
}

/// 01's [`ConnectCode`] → connectrpc's wire enum (same 16 canonical codes).
fn wire_code(code: ConnectCode) -> connectrpc::ErrorCode {
    match code {
        ConnectCode::Canceled => connectrpc::ErrorCode::Canceled,
        ConnectCode::Unknown => connectrpc::ErrorCode::Unknown,
        ConnectCode::InvalidArgument => connectrpc::ErrorCode::InvalidArgument,
        ConnectCode::DeadlineExceeded => connectrpc::ErrorCode::DeadlineExceeded,
        ConnectCode::NotFound => connectrpc::ErrorCode::NotFound,
        ConnectCode::AlreadyExists => connectrpc::ErrorCode::AlreadyExists,
        ConnectCode::PermissionDenied => connectrpc::ErrorCode::PermissionDenied,
        ConnectCode::ResourceExhausted => connectrpc::ErrorCode::ResourceExhausted,
        ConnectCode::FailedPrecondition => connectrpc::ErrorCode::FailedPrecondition,
        ConnectCode::Aborted => connectrpc::ErrorCode::Aborted,
        ConnectCode::OutOfRange => connectrpc::ErrorCode::OutOfRange,
        ConnectCode::Unimplemented => connectrpc::ErrorCode::Unimplemented,
        ConnectCode::Internal => connectrpc::ErrorCode::Internal,
        ConnectCode::Unavailable => connectrpc::ErrorCode::Unavailable,
        ConnectCode::DataLoss => connectrpc::ErrorCode::DataLoss,
        ConnectCode::Unauthenticated => connectrpc::ErrorCode::Unauthenticated,
    }
}

/// Encodes one typed detail carrier as a Connect wire detail. The `type`
/// field carries the bare fully-qualified message name (the Connect JSON
/// convention; the gRPC path re-adds the `type.googleapis.com/` prefix),
/// `value` the base64 of the protobuf encoding.
fn wire_detail(detail: &ConnectErrorDetail) -> connectrpc::ErrorDetail {
    use codewire_proto::google::rpc;

    let bare_name = detail
        .type_url()
        .rsplit('/')
        .next()
        .expect("rsplit yields at least one segment");
    match detail {
        ConnectErrorDetail::BadRequest(bad) => {
            let msg = rpc::BadRequest {
                field_violations: bad
                    .field_violations
                    .iter()
                    .map(|v| rpc::bad_request::FieldViolation {
                        field: v.field.clone(),
                        description: v.description.clone(),
                        ..Default::default()
                    })
                    .collect(),
                ..Default::default()
            };
            connectrpc::ErrorDetail::from_message(bare_name, &msg)
        }
        ConnectErrorDetail::ErrorInfo(info) => {
            let mut msg = rpc::ErrorInfo {
                reason: info.reason.clone(),
                domain: info.domain.clone(),
                ..Default::default()
            };
            msg.metadata
                .extend(info.metadata.iter().map(|(k, v)| (k.clone(), v.clone())));
            connectrpc::ErrorDetail::from_message(bare_name, &msg)
        }
        ConnectErrorDetail::RetryInfo(retry) => {
            let msg = rpc::RetryInfo {
                retry_delay: buffa::MessageField::some(buffa_types::google::protobuf::Duration {
                    seconds: retry.retry_delay.as_secs() as i64,
                    nanos: retry.retry_delay.subsec_nanos() as i32,
                    ..Default::default()
                }),
                ..Default::default()
            };
            connectrpc::ErrorDetail::from_message(bare_name, &msg)
        }
    }
}

/// Builds the protocol-native HTTP response for an auth-layer rejection.
///
/// The content-type gate already validated and canonicalized the request
/// headers. Delegating the final encoding to connectrpc preserves the same
/// canonical error and `google.rpc` details as a handler rejection while
/// selecting the correct wire shape: unary/streaming Connect or native gRPC.
fn rejection_response(
    err: &AppError,
    request_id: Option<&str>,
    request_headers: &http::HeaderMap,
) -> Response {
    app_error_to_wire(err, request_id)
        .into_http_response(request_headers)
        .map(Body::new)
}

/// D6b/D9 gate: reject POSTs that are not admitted by this mount's explicit
/// protocol policy before any dispatcher or handler code runs.
///
/// GET passes through (Connect GET carries no body and is validated by the
/// dispatcher's query-parameter parsing); other verbs pass through to the
/// dispatcher's uniform `405 Method Not Allowed`.
async fn enforce_connect_content_type(
    State(protocol_policy): State<ProtocolPolicy>,
    mut req: Request,
    next: Next,
) -> Response {
    let protocol =
        protocol_policy.protocol_for(req.method(), req.headers().get(header::CONTENT_TYPE));
    if req.method() == Method::POST && protocol.is_none() {
        let mut resp = Response::new(Body::empty());
        *resp.status_mut() = StatusCode::UNSUPPORTED_MEDIA_TYPE;
        resp.headers_mut().insert(
            "accept-post",
            HeaderValue::from_static(protocol_policy.accept_post()),
        );
        return resp;
    }
    // Media types are case-insensitive, but connectrpc 0.8.1 detects its
    // protocol from the original header with case-sensitive prefix checks.
    // Canonicalize every admitted POST to the exact lowercase essence owned
    // by this gate so the dispatcher cannot re-reject it with the library's
    // broader (gRPC-Web-inclusive) Accept-Post advertisement. Parameters are
    // intentionally dropped: both this gate and connectrpc ignore them.
    if req.method() == Method::POST {
        let canonical_content_type = req
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(content_type_essence)
            .expect("an admitted POST has a valid content type");
        req.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_str(&canonical_content_type)
                .expect("an admitted content-type essence is a valid header value"),
        );
    }
    let mut resp = next.run(req).await;
    if let Some(protocol) = protocol {
        resp.extensions_mut().insert(ValidatedRpcProtocol(protocol));
    }
    resp
}

fn content_type_essence(content_type: &HeaderValue) -> Option<String> {
    let content_type = content_type.to_str().ok()?;
    // Media-type "essence": drop parameters (`; charset=utf-8`), normalize
    // case per RFC 9110.
    Some(
        content_type
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase(),
    )
}

fn is_connect_essence(essence: &str) -> bool {
    essence == "application/json"
        || essence == "application/proto"
        || essence == "application/connect+json"
        || essence == "application/connect+proto"
}

fn is_connect_streaming_essence(essence: &str) -> bool {
    essence == "application/connect+json" || essence == "application/connect+proto"
}

fn is_native_grpc_essence(essence: &str) -> bool {
    essence == "application/grpc" || essence == "application/grpc+proto"
}

/// D7: one INFO event per RPC request — service, method, admitted wire
/// protocol (or `unknown` for a pre-admission rejection), Connect status code,
/// duration, credential kind, privacy-conscious principal fingerprint,
/// server-derived synthetic classification, and user agent. Target
/// `connect_rpc`; the
/// Connect twin of workstream 13's `rest_sunset` REST-traffic event.
async fn log_rpc(req: Request, next: Next) -> Response {
    // Mounted paths are always "/{package}.{Service}/{method...}".
    let path = req.uri().path().to_owned();
    let mut parts = path.trim_start_matches('/').splitn(2, '/');
    let service = parts.next().unwrap_or("").to_owned();
    let method = parts.next().unwrap_or("").to_owned();
    let user_agent = req
        .headers()
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("unknown")
        .to_owned();
    let start = Instant::now();
    let resp = next.run(req).await;
    let duration_ms = (start.elapsed().as_secs_f64() * 1_000_000.0).round() / 1000.0;

    let http_status = resp.status().as_u16();
    let credential = resp
        .extensions()
        .get::<RpcCredentialKind>()
        .map(|kind| kind.0)
        .unwrap_or("none");
    let principal_evidence = resp.extensions().get::<RpcPrincipalEvidence>();
    let principal_fingerprint = principal_evidence
        .map(|evidence| evidence.principal_fingerprint.clone())
        .unwrap_or_else(|| "unknown".to_owned());
    let synthetic = principal_evidence
        .map(|evidence| evidence.synthetic)
        .unwrap_or(false);
    let protocol = resp
        .extensions()
        .get::<ValidatedRpcProtocol>()
        .map(|protocol| protocol.0)
        .unwrap_or("unknown");
    let (code, resp) = connect_code_for_response(resp).await;

    tracing::info!(
        target: "connect_rpc",
        service = %service,
        method = %method,
        protocol = %protocol,
        code = %code,
        http_status,
        duration_ms,
        credential = %credential,
        principal_fingerprint = %principal_fingerprint,
        synthetic,
        user_agent = %user_agent,
        "connect rpc"
    );
    resp
}

/// Derives the Connect status code for a served response.
///
/// A native-gRPC trailers-only response echoes `grpc-status` in its response
/// headers, and that canonical status takes precedence over HTTP 200.
/// Otherwise HTTP 200 is `ok` (streaming end-of-stream errors that exist only
/// in body trailers are not visible at this layer).
/// Unary errors are `application/json` Connect error documents, so for
/// small JSON error bodies the authoritative `code` field is read from the
/// body (which is then restored untouched); anything else falls back to the
/// Connect spec's HTTP-to-code table.
async fn connect_code_for_response(resp: Response) -> (String, Response) {
    let status = resp.status();
    if let Some(code) = grpc_code_for_response_headers(resp.headers()) {
        return (code.to_owned(), resp);
    }
    if status == StatusCode::OK {
        return ("ok".to_owned(), resp);
    }

    // Connect unary errors are always small `application/json` documents;
    // anything through this mount with that shape came from the Connect
    // dispatcher (or WI-2's auth layer), so buffering under the cap is safe.
    // (The dispatcher's body does not advertise an exact `size_hint`, so the
    // cap — not the hint — is the guard.)
    let is_json = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| {
            ct.split(';')
                .next()
                .unwrap_or("")
                .trim()
                .eq_ignore_ascii_case("application/json")
        });

    if is_json {
        let (parts, body) = resp.into_parts();
        match axum::body::to_bytes(body, MAX_ERROR_SNIFF_BYTES as usize).await {
            Ok(bytes) => {
                let code = serde_json::from_slice::<serde_json::Value>(&bytes)
                    .ok()
                    .and_then(|v| v.get("code")?.as_str().map(str::to_owned))
                    .unwrap_or_else(|| connect_code_for_http_status(status).to_owned());
                return (code, Response::from_parts(parts, Body::from(bytes)));
            }
            Err(err) => {
                // The original body is unrecoverable; surface an explicit
                // internal error rather than a truncated response.
                tracing::error!(error = %err, "failed to buffer Connect error body");
                let mut resp = Response::new(Body::empty());
                *resp.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                return ("internal".to_owned(), resp);
            }
        }
    }

    (connect_code_for_http_status(status).to_owned(), resp)
}

fn grpc_code_for_response_headers(headers: &http::HeaderMap) -> Option<&'static str> {
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(content_type_essence)?;
    if !is_native_grpc_essence(&content_type) {
        return None;
    }

    let raw = headers.get("grpc-status")?.to_str().ok()?;
    let Ok(status) = raw.parse::<u32>() else {
        return Some("unknown");
    };
    if status == 0 {
        return Some("ok");
    }
    Some(
        connectrpc::ErrorCode::from_grpc_code(status)
            .map(|code| code.as_str())
            .unwrap_or("unknown"),
    )
}

/// The Connect protocol's HTTP-to-error-code table (used when a response
/// carries no readable Connect error document).
fn connect_code_for_http_status(status: StatusCode) -> &'static str {
    match status.as_u16() {
        400 => "internal",
        401 => "unauthenticated",
        403 => "permission_denied",
        404 => "unimplemented",
        408 | 504 => "deadline_exceeded",
        429 | 502 | 503 => "unavailable",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn mesh_authorization_debug_values_redact_hop_and_forwarded_credentials() {
        let hop_secret = "test-mesh-hop-secret";
        let forwarded_secret = "test-forwarded-credential";
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://codewire:codewire@localhost/codewire")
            .expect("lazy PostgreSQL pool");
        let layer = MeshAuthorizationLayer::new(
            AuthState { pool },
            hop_secret,
            "codewire-mesh",
            "codewire.internal.v1.MeshAuthorizationService/ResolveMeshAuthorization",
        );
        let forwarded =
            ForwardedCredential::Authorization(RedactedCredential(forwarded_secret.to_owned()));

        let layer_debug = format!("{layer:?}");
        let forwarded_debug = format!("{forwarded:?}");
        assert!(!layer_debug.contains(hop_secret));
        assert!(!forwarded_debug.contains(forwarded_secret));
        assert!(layer_debug.contains("[redacted]"));
        assert!(forwarded_debug.contains("[redacted]"));
    }

    #[tokio::test]
    async fn stalled_authentication_is_bounded_and_renders_deadline_exceeded() {
        let result = bounded_authentication(
            std::future::pending::<Result<crate::auth::Authentication, AppError>>(),
            Duration::from_millis(5),
        )
        .await;
        assert!(matches!(
            result,
            Err(AuthResolutionFailure::DeadlineExceeded)
        ));

        let wire = app_error_to_wire(&authentication_timeout_error(), Some("req_auth_timeout"));
        assert_eq!(wire.http_status(), StatusCode::GATEWAY_TIMEOUT);
        let doc: serde_json::Value = serde_json::from_slice(&wire.to_json()).unwrap();
        assert_eq!(doc["code"], "deadline_exceeded");
        assert_eq!(doc["message"], "authentication deadline exceeded");

        let details = doc["details"].as_array().expect("details array");
        assert_eq!(details.len(), 1);
        let info = decode_error_info(details[0]["value"].as_str().expect("base64 value"));
        assert_eq!(info.reason, "AUTHENTICATION_TIMEOUT");
        assert_eq!(
            info.metadata.get("request_id").map(String::as_str),
            Some("req_auth_timeout")
        );
        assert_eq!(CONNECT_AUTH_RESOLUTION_TIMEOUT, Duration::from_secs(10));
    }

    #[tokio::test]
    async fn auth_rejection_renderer_follows_the_admitted_request_protocol() {
        let mut connect_headers = http::HeaderMap::new();
        connect_headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        let connect = rejection_response(
            &AppError::Unauthorized,
            Some("req_connect_auth"),
            &connect_headers,
        );
        assert_eq!(connect.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            connect.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
        let connect_body =
            axum::body::to_bytes(connect.into_body(), MAX_ERROR_SNIFF_BYTES as usize)
                .await
                .expect("Connect auth body");
        let connect_doc: serde_json::Value =
            serde_json::from_slice(&connect_body).expect("Connect auth JSON");
        assert_eq!(connect_doc["code"], "unauthenticated");
        assert_eq!(connect_doc["message"], "unauthorized");

        let mut grpc_headers = http::HeaderMap::new();
        grpc_headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/grpc+proto"),
        );
        let grpc = rejection_response(
            &AppError::Unauthorized,
            Some("req_grpc_auth"),
            &grpc_headers,
        );
        assert_eq!(grpc.status(), StatusCode::OK);
        assert_eq!(
            grpc.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/grpc+proto"
        );
        assert_eq!(grpc.headers().get("grpc-status").unwrap(), "16");
        let (code, _) = connect_code_for_response(grpc).await;
        assert_eq!(code, "unauthenticated");
    }

    #[tokio::test]
    async fn grpc_status_header_precedes_http_success_for_rpc_telemetry() {
        for (raw, expected) in [
            ("0", "ok"),
            ("3", "invalid_argument"),
            ("7", "permission_denied"),
            ("16", "unauthenticated"),
            ("99", "unknown"),
            ("garbage", "unknown"),
        ] {
            let mut response = Response::new(Body::empty());
            response.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/grpc+proto"),
            );
            response
                .headers_mut()
                .insert("grpc-status", HeaderValue::from_str(raw).unwrap());
            let (code, _) = connect_code_for_response(response).await;
            assert_eq!(code, expected, "grpc-status {raw}");
        }
    }

    #[test]
    fn authentication_timeout_honors_shorter_connect_deadline_without_extending_it() {
        let headers = |value: Option<&str>| {
            let mut headers = http::HeaderMap::new();
            if let Some(value) = value {
                headers.insert("connect-timeout-ms", HeaderValue::from_str(value).unwrap());
            }
            headers
        };

        assert_eq!(
            connect_auth_resolution_timeout(&headers(None)),
            Duration::from_secs(10)
        );
        assert_eq!(
            connect_auth_resolution_timeout(&headers(Some("25"))),
            Duration::from_millis(25)
        );
        assert_eq!(
            connect_auth_resolution_timeout(&headers(Some("20000"))),
            Duration::from_secs(10)
        );
        for invalid in ["", "-1", "1.5", "00000000001"] {
            assert_eq!(
                connect_auth_resolution_timeout(&headers(Some(invalid))),
                Duration::from_secs(10),
                "invalid header {invalid:?} must not replace the auth ceiling"
            );
        }
    }

    #[test]
    fn principal_fingerprint_is_stable_domain_separated_and_distinct() {
        let alpha = principal_fingerprint("user-alpha");
        let beta = principal_fingerprint("user-beta");

        assert_eq!(alpha, "ddfa907efdb3a1715c3833a7f18f1dc0");
        assert_eq!(principal_fingerprint("user-alpha"), alpha);
        assert_eq!(beta, "5f045a8eab2a531fa2ff7b499a3bcd75");
        assert_ne!(alpha, beta);
        assert_eq!(alpha.len(), 32);
        assert!(alpha.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert!(!alpha.contains("user-alpha"));
    }

    #[test]
    fn auth_telemetry_classification_uses_only_authenticated_user_id() {
        let synthetic_ids = BTreeSet::from(["synthetic-user".to_owned()]);
        let synthetic = RpcPrincipalEvidence::authenticated("synthetic-user", &synthetic_ids);
        let real = RpcPrincipalEvidence::authenticated("real-user", &synthetic_ids);

        assert!(synthetic.synthetic);
        assert!(!real.synthetic);
        assert_ne!(synthetic.principal_fingerprint, real.principal_fingerprint);
    }

    #[test]
    fn content_type_essence_matching() {
        let protocol = |policy: ProtocolPolicy, ct: Option<&str>| {
            let value = ct.map(|ct| HeaderValue::from_str(ct).unwrap());
            policy.protocol_for(&Method::POST, value.as_ref())
        };

        for allowed in [
            "application/json",
            "application/json; charset=utf-8",
            "Application/JSON",
            "application/proto",
            "application/connect+proto",
            "application/connect+json",
        ] {
            assert_eq!(
                protocol(ProtocolPolicy::ConnectOnly, Some(allowed)),
                Some("connect"),
                "{allowed}"
            );
            assert_eq!(
                protocol(ProtocolPolicy::ConnectAndGrpc, Some(allowed)),
                Some("connect"),
                "{allowed}"
            );
        }
        for allowed in ["application/grpc", "application/grpc+proto"] {
            assert_eq!(
                protocol(ProtocolPolicy::ConnectAndGrpc, Some(allowed)),
                Some("grpc"),
                "{allowed}"
            );
            assert_eq!(
                protocol(ProtocolPolicy::ConnectOnly, Some(allowed)),
                None,
                "{allowed}"
            );
        }
        for rejected in [
            "text/plain",
            "application/x-www-form-urlencoded",
            "multipart/form-data",
            "application/connect+thrift",
            "application/connect+garbage",
            "application/grpc+json",
            "application/grpc-web",
            "application/grpc-web+proto",
            "application/xml",
            "",
        ] {
            assert_eq!(
                protocol(ProtocolPolicy::ConnectOnly, Some(rejected)),
                None,
                "{rejected}"
            );
            assert_eq!(
                protocol(ProtocolPolicy::ConnectAndGrpc, Some(rejected)),
                None,
                "{rejected}"
            );
        }
        assert_eq!(protocol(ProtocolPolicy::ConnectOnly, None), None);
        assert_eq!(
            ProtocolPolicy::ConnectAndGrpc.protocol_for(&Method::GET, None),
            Some("connect")
        );
    }

    /// The exact JSON wire shape of the auth layer's `unauthenticated`
    /// rejection (WI-2 acceptance): canonical code, envelope `detail` as the
    /// message, one `google.rpc.ErrorInfo` detail whose protobuf value
    /// carries D4's reason/hint/request_id.
    #[test]
    fn unauthenticated_rejection_wire_shape() {
        let wire = app_error_to_wire(&AppError::Unauthorized, Some("req_123"));
        assert_eq!(wire.http_status(), StatusCode::UNAUTHORIZED);

        let doc: serde_json::Value = serde_json::from_slice(&wire.to_json()).unwrap();
        assert_eq!(doc["code"], "unauthenticated");
        assert_eq!(doc["message"], "unauthorized");
        let details = doc["details"].as_array().expect("details array");
        assert_eq!(details.len(), 1);
        assert_eq!(details[0]["type"], "google.rpc.ErrorInfo");

        let info = decode_error_info(details[0]["value"].as_str().expect("base64 value"));
        assert_eq!(info.reason, "SESSION_EXPIRED");
        assert_eq!(info.domain, "codewire.sh");
        assert_eq!(
            info.metadata.get("hint").map(String::as_str),
            Some("Run 'cw login' to re-authenticate")
        );
        assert_eq!(
            info.metadata.get("request_id").map(String::as_str),
            Some("req_123")
        );
    }

    /// The exact JSON wire shape of the admin layer's `permission_denied`
    /// rejection (WI-2 acceptance).
    #[test]
    fn permission_denied_rejection_wire_shape() {
        let wire = app_error_to_wire(&AppError::Forbidden, Some("req_9"));
        assert_eq!(wire.http_status(), StatusCode::FORBIDDEN);

        let doc: serde_json::Value = serde_json::from_slice(&wire.to_json()).unwrap();
        assert_eq!(doc["code"], "permission_denied");
        assert_eq!(doc["message"], "forbidden");
        let details = doc["details"].as_array().expect("details array");
        assert_eq!(details.len(), 1);
        assert_eq!(details[0]["type"], "google.rpc.ErrorInfo");

        let info = decode_error_info(details[0]["value"].as_str().expect("base64 value"));
        assert_eq!(info.reason, "FORBIDDEN");
        assert_eq!(info.domain, "codewire.sh");
        assert_eq!(
            info.metadata.get("hint").map(String::as_str),
            Some("Only org owners/admins can perform this action")
        );
        assert_eq!(
            info.metadata.get("request_id").map(String::as_str),
            Some("req_9")
        );
    }

    fn decode_error_info(b64: &str) -> codewire_proto::google::rpc::ErrorInfo {
        use base64::Engine;
        let bytes = base64::engine::general_purpose::STANDARD_NO_PAD
            .decode(b64)
            .or_else(|_| base64::engine::general_purpose::STANDARD.decode(b64))
            .expect("base64 detail value");
        buffa::Message::decode_from_slice(&bytes).expect("protobuf ErrorInfo")
    }

    /// Every canonical code crosses the bridge to the same wire spelling.
    #[test]
    fn wire_code_bridge_is_total_and_name_preserving() {
        let codes = [
            ConnectCode::Canceled,
            ConnectCode::Unknown,
            ConnectCode::InvalidArgument,
            ConnectCode::DeadlineExceeded,
            ConnectCode::NotFound,
            ConnectCode::AlreadyExists,
            ConnectCode::PermissionDenied,
            ConnectCode::ResourceExhausted,
            ConnectCode::FailedPrecondition,
            ConnectCode::Aborted,
            ConnectCode::OutOfRange,
            ConnectCode::Unimplemented,
            ConnectCode::Internal,
            ConnectCode::Unavailable,
            ConnectCode::DataLoss,
            ConnectCode::Unauthenticated,
        ];
        for code in codes {
            assert_eq!(code.as_str(), wire_code(code).as_str(), "{code:?}");
        }
    }

    /// BadRequest field violations survive the wire encoding (D2's 422 row
    /// end to end: renderer carrier → protobuf detail → decode).
    #[test]
    fn bad_request_detail_round_trips() {
        use crate::connect_error::{BadRequest, FieldViolation};
        use base64::Engine;

        let detail = ConnectErrorDetail::BadRequest(BadRequest {
            field_violations: vec![
                FieldViolation {
                    field: "spec.name".into(),
                    description: "missing required property".into(),
                },
                FieldViolation {
                    field: "ports[0].target".into(),
                    description: "must be >= 1".into(),
                },
            ],
        });
        let wire = wire_detail(&detail);
        assert_eq!(wire.type_url, "google.rpc.BadRequest");

        let bytes = base64::engine::general_purpose::STANDARD_NO_PAD
            .decode(wire.value.expect("value"))
            .expect("base64");
        let decoded: codewire_proto::google::rpc::BadRequest =
            buffa::Message::decode_from_slice(&bytes).expect("protobuf BadRequest");
        assert_eq!(decoded.field_violations.len(), 2);
        assert_eq!(decoded.field_violations[0].field, "spec.name");
        assert_eq!(
            decoded.field_violations[0].description,
            "missing required property"
        );
        assert_eq!(decoded.field_violations[1].field, "ports[0].target");
    }

    /// RetryInfo carries the delay as a google.protobuf.Duration.
    #[test]
    fn retry_info_detail_round_trips() {
        use base64::Engine;
        use std::time::Duration;

        let detail = ConnectErrorDetail::RetryInfo(crate::connect_error::RetryInfo {
            retry_delay: Duration::new(60, 250_000_000),
        });
        let wire = wire_detail(&detail);
        assert_eq!(wire.type_url, "google.rpc.RetryInfo");

        let bytes = base64::engine::general_purpose::STANDARD_NO_PAD
            .decode(wire.value.expect("value"))
            .expect("base64");
        let decoded: codewire_proto::google::rpc::RetryInfo =
            buffa::Message::decode_from_slice(&bytes).expect("protobuf RetryInfo");
        let delay = decoded.retry_delay.as_option().expect("retry_delay set");
        assert_eq!(delay.seconds, 60);
        assert_eq!(delay.nanos, 250_000_000);
    }

    /// Method paths registered with or without a leading slash match the
    /// request path form.
    #[test]
    fn method_path_normalization() {
        assert_eq!(
            normalize_method_path("codewire.testing.v1.PingService/PublicPing".into()),
            "/codewire.testing.v1.PingService/PublicPing"
        );
        assert_eq!(
            normalize_method_path("/codewire.testing.v1.PingService/PublicPing".into()),
            "/codewire.testing.v1.PingService/PublicPing"
        );
    }

    #[test]
    fn http_status_fallback_table() {
        assert_eq!(
            connect_code_for_http_status(StatusCode::BAD_REQUEST),
            "internal"
        );
        assert_eq!(
            connect_code_for_http_status(StatusCode::UNAUTHORIZED),
            "unauthenticated"
        );
        assert_eq!(
            connect_code_for_http_status(StatusCode::FORBIDDEN),
            "permission_denied"
        );
        assert_eq!(
            connect_code_for_http_status(StatusCode::NOT_FOUND),
            "unimplemented"
        );
        assert_eq!(
            connect_code_for_http_status(StatusCode::UNSUPPORTED_MEDIA_TYPE),
            "unknown"
        );
        assert_eq!(
            connect_code_for_http_status(StatusCode::SERVICE_UNAVAILABLE),
            "unavailable"
        );
        assert_eq!(
            connect_code_for_http_status(StatusCode::GATEWAY_TIMEOUT),
            "deadline_exceeded"
        );
    }
}
