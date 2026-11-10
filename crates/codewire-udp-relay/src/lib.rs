use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use codewire_tailnet::disco::{DiscoPrivate, UDPRelayEndpoint};
use codewire_tailnet::node::DiscoPublic;
use codewire_tailnet::udp_relay::{self, SocketHandle, SocketOptions, SocketServer};
use codewire_tls::{ServerTlsFiles, TlsPeer};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

pub const DEFAULT_UDP_BIND_ADDR: &str = "0.0.0.0:41641";
pub const DEFAULT_ALLOCATOR_BIND_ADDR: &str = "0.0.0.0:8095";
pub const DEFAULT_OPS_BIND_ADDR: &str = "0.0.0.0:8096";
pub const DEFAULT_ALLOCATOR_TLS_BIND_ADDR: &str = "0.0.0.0:8097";

pub const UDP_BIND_ADDR_ENV: &str = "CODEWIRE_UDP_RELAY_BIND_ADDR";
pub const UDP_ADVERTISE_ADDRS_ENV: &str = "CODEWIRE_UDP_RELAY_ADVERTISE_ADDRS";
pub const ALLOCATOR_BIND_ADDR_ENV: &str = "CODEWIRE_UDP_RELAY_ALLOCATOR_ADDR";
pub const OPS_BIND_ADDR_ENV: &str = "CODEWIRE_UDP_RELAY_OPS_ADDR";
pub const ALLOCATOR_TOKEN_ENV: &str = "CODEWIRE_UDP_RELAY_ALLOCATOR_TOKEN";
pub const DISCO_PRIVATE_KEY_HEX_ENV: &str = "CODEWIRE_UDP_RELAY_DISCO_PRIVATE_KEY_HEX";
pub const ALLOCATOR_TLS_BIND_ADDR_ENV: &str = "CODEWIRE_UDP_RELAY_ALLOCATOR_TLS_ADDR";
pub const ALLOCATOR_TLS_CERT_ENV: &str = "CODEWIRE_UDP_RELAY_ALLOCATOR_TLS_CERT";
pub const ALLOCATOR_TLS_KEY_ENV: &str = "CODEWIRE_UDP_RELAY_ALLOCATOR_TLS_KEY";
pub const ALLOCATOR_CLIENT_ROOTS_ENV: &str = "CODEWIRE_UDP_RELAY_ALLOCATOR_CLIENT_ROOTS";
pub const ALLOCATOR_CLIENT_NAME_ENV: &str = "CODEWIRE_UDP_RELAY_ALLOCATOR_CLIENT_NAME";

/// The allocator's TLS listener (#4011): the relay's own mounted identity,
/// the mounted roots that sign client certificates, and the one DNS name a
/// client certificate must carry to be orchestration's. It allocates for
/// that certificate and for no other caller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AllocatorTls {
    pub bind_addr: SocketAddr,
    pub cert_chain: PathBuf,
    pub key: PathBuf,
    pub client_roots: PathBuf,
    pub client_name: String,
}

impl AllocatorTls {
    pub fn files(&self) -> Result<ServerTlsFiles, codewire_tls::TlsError> {
        ServerTlsFiles::new(self.cert_chain.clone(), self.key.clone())?
            .with_client_roots(self.client_roots.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    pub udp_bind_addr: SocketAddr,
    pub udp_advertise_addr_ports: Vec<SocketAddr>,
    pub allocator_bind_addr: SocketAddr,
    pub ops_bind_addr: SocketAddr,
    pub allocator_token: Option<String>,
    /// Set by naming all four of its files and names, or none of them.
    pub allocator_tls: Option<AllocatorTls>,
    pub disco_private_key_hex: Option<String>,
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_getenv(|key| std::env::var(key).ok())
    }

    pub fn from_getenv<F>(getenv: F) -> Result<Self, ConfigError>
    where
        F: Fn(&str) -> Option<String>,
    {
        let udp_bind_addr = parse_socket_addr_env(
            UDP_BIND_ADDR_ENV,
            getenv(UDP_BIND_ADDR_ENV)
                .as_deref()
                .unwrap_or(DEFAULT_UDP_BIND_ADDR),
        )?;
        let udp_advertise_addr_ports =
            parse_socket_addr_list_env(UDP_ADVERTISE_ADDRS_ENV, getenv(UDP_ADVERTISE_ADDRS_ENV))?;
        let allocator_bind_addr = parse_socket_addr_env(
            ALLOCATOR_BIND_ADDR_ENV,
            getenv(ALLOCATOR_BIND_ADDR_ENV)
                .as_deref()
                .unwrap_or(DEFAULT_ALLOCATOR_BIND_ADDR),
        )?;
        let ops_bind_addr = parse_socket_addr_env(
            OPS_BIND_ADDR_ENV,
            getenv(OPS_BIND_ADDR_ENV)
                .as_deref()
                .unwrap_or(DEFAULT_OPS_BIND_ADDR),
        )?;
        let allocator_token = trim_env(&getenv, ALLOCATOR_TOKEN_ENV);
        const ALLOCATOR_TLS_ENVS: [&str; 5] = [
            ALLOCATOR_TLS_BIND_ADDR_ENV,
            ALLOCATOR_TLS_CERT_ENV,
            ALLOCATOR_TLS_KEY_ENV,
            ALLOCATOR_CLIENT_ROOTS_ENV,
            ALLOCATOR_CLIENT_NAME_ENV,
        ];
        let allocator_tls = if ALLOCATOR_TLS_ENVS
            .iter()
            .all(|name| trim_env(&getenv, name).is_none())
        {
            None
        } else {
            // A partly configured listener never falls back to serving none.
            let required =
                |name| trim_env(&getenv, name).ok_or(ConfigError::MissingAllocatorTls { name });
            Some(AllocatorTls {
                bind_addr: parse_socket_addr_env(
                    ALLOCATOR_TLS_BIND_ADDR_ENV,
                    getenv(ALLOCATOR_TLS_BIND_ADDR_ENV)
                        .as_deref()
                        .unwrap_or(DEFAULT_ALLOCATOR_TLS_BIND_ADDR),
                )?,
                cert_chain: required(ALLOCATOR_TLS_CERT_ENV)?.into(),
                key: required(ALLOCATOR_TLS_KEY_ENV)?.into(),
                client_roots: required(ALLOCATOR_CLIENT_ROOTS_ENV)?.into(),
                client_name: allocator_client_name(required(ALLOCATOR_CLIENT_NAME_ENV)?)?,
            })
        };
        let disco_private_key_hex = trim_env(&getenv, DISCO_PRIVATE_KEY_HEX_ENV);

        if let Some(raw) = &disco_private_key_hex {
            parse_hex_32(DISCO_PRIVATE_KEY_HEX_ENV, raw)?;
        }

        Ok(Self {
            udp_bind_addr,
            udp_advertise_addr_ports,
            allocator_bind_addr,
            ops_bind_addr,
            allocator_token,
            allocator_tls,
            disco_private_key_hex,
        })
    }

    pub fn disco_private(&self) -> Result<DiscoPrivate, ConfigError> {
        match &self.disco_private_key_hex {
            Some(raw) => Ok(DiscoPrivate::from_raw(parse_hex_32(
                DISCO_PRIVATE_KEY_HEX_ENV,
                raw,
            )?)),
            None => Ok(DiscoPrivate::generate(&mut OsRng)),
        }
    }

    pub fn socket_options(&self) -> SocketOptions {
        SocketOptions::new(self.udp_bind_addr)
            .with_advertise_addr_ports(self.udp_advertise_addr_ports.clone())
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("{name} must be an IP socket address, got {value:?}: {message}")]
    InvalidSocketAddr {
        name: &'static str,
        value: String,
        message: String,
    },
    #[error("{name} contains invalid socket address {value:?}: {message}")]
    InvalidSocketAddrListEntry {
        name: &'static str,
        value: String,
        message: String,
    },
    #[error("{name} must be 64 hex characters")]
    InvalidHexKey { name: &'static str },
    #[error("{name} is required once any allocator TLS setting is present")]
    MissingAllocatorTls { name: &'static str },
    #[error("{ALLOCATOR_CLIENT_NAME_ENV} must be an exact DNS name, got {value:?}")]
    InvalidAllocatorClientName { value: String },
}

/// Who made one allocation request, for the `caller` label of
/// `codewire_udp_relay_allocator_calls_total`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AllocatorCaller {
    /// The plain listener, where no caller is identified.
    Plain,
    /// The TLS listener, with orchestration's verified certificate.
    Orchestration,
    /// The TLS listener, without a client certificate. Refused.
    NoCertificate,
    /// The TLS listener, with a verified certificate that does not carry
    /// orchestration's name. Refused.
    AnotherCertificate,
}

impl AllocatorCaller {
    const ALL: [Self; 4] = [
        Self::Plain,
        Self::Orchestration,
        Self::NoCertificate,
        Self::AnotherCertificate,
    ];

    const fn label(self) -> &'static str {
        match self {
            Self::Plain => "plain",
            Self::Orchestration => "orchestration",
            Self::NoCertificate => "no_certificate",
            Self::AnotherCertificate => "another_certificate",
        }
    }
}

#[derive(Default)]
struct AllocatorCallCounters([AtomicU64; 4]);

impl AllocatorCallCounters {
    fn record(&self, result: AllocatorCaller) {
        self.0[result as usize].fetch_add(1, Ordering::Relaxed);
    }

    fn get(&self, result: AllocatorCaller) -> u64 {
        self.0[result as usize].load(Ordering::Relaxed)
    }
}

#[derive(Clone)]
pub struct AppState {
    handle: SocketHandle,
    allocator_token: Option<Arc<str>>,
    /// The DNS name orchestration's client certificate carries.
    allocator_client_name: Option<Arc<str>>,
    allocator_calls: Arc<AllocatorCallCounters>,
}

impl AppState {
    pub fn new(handle: SocketHandle, allocator_token: Option<String>) -> Self {
        Self {
            handle,
            allocator_token: allocator_token.map(Arc::from),
            allocator_client_name: None,
            allocator_calls: Arc::default(),
        }
    }

    /// The TLS listener allocates only for a client certificate that carries
    /// `client_name`. Without this it allocates for nobody.
    pub fn with_allocator_client(mut self, client_name: &str) -> Self {
        self.allocator_client_name = Some(Arc::from(client_name));
        self
    }

    pub fn handle(&self) -> &SocketHandle {
        &self.handle
    }
}

pub struct RelayRuntime {
    server: SocketServer,
    state: AppState,
}

impl RelayRuntime {
    pub async fn bind(config: &Config) -> anyhow::Result<Self> {
        let server = SocketServer::bind(config.disco_private()?, config.socket_options()).await?;
        if config.allocator_token.is_none() {
            tracing::warn!(
                "udp-relay: {ALLOCATOR_TOKEN_ENV} is not set; the plain allocator listener accepts unauthenticated requests"
            );
        }
        let mut state = AppState::new(server.handle(), config.allocator_token.clone());
        if let Some(tls) = &config.allocator_tls {
            state = state.with_allocator_client(&tls.client_name);
        }
        Ok(Self { server, state })
    }

    pub fn allocator_app(&self) -> Router {
        allocator_router(self.state.clone())
    }

    /// The allocator for [`codewire_tls::PeerTlsListener`]; serve it with
    /// `into_make_service_with_connect_info::<TlsPeer>()`.
    pub fn allocator_tls_app(&self) -> Router {
        allocator_tls_router(self.state.clone())
    }

    pub fn ops_app(&self) -> Router {
        ops_router(self.state.clone())
    }

    pub fn state(&self) -> &AppState {
        &self.state
    }

    pub fn into_server(self) -> SocketServer {
        self.server
    }
}

/// Only orchestration calls this. Its own port lets the NetworkPolicy keep the
/// allocator closed while read-only endpoints stay open to Prometheus, which
/// runs on host networking and so matches no Pod selector (#3926).
pub fn allocator_router(state: AppState) -> Router {
    Router::new()
        .route("/internal/udp-relay/allocations", post(allocate))
        .with_state(state)
}

/// The same allocator behind the TLS listener, where the handshake has
/// verified the caller's client certificate, if it presented one. Only
/// orchestration's certificate allocates here (#4011).
pub fn allocator_tls_router(state: AppState) -> Router {
    Router::new()
        .route("/internal/udp-relay/allocations", post(allocate_tls))
        .with_state(state)
}

/// Read-only: probes and metrics.
pub fn ops_router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics))
        .with_state(state)
}

async fn healthz() -> &'static str {
    "OK"
}

async fn readyz(State(state): State<AppState>) -> impl IntoResponse {
    Json(ReadyResponse {
        status: "ok",
        disco_key: state.handle.disco_public(),
        local_addr: state.handle.local_addr().to_string(),
    })
}

async fn metrics(State(state): State<AppState>) -> Response {
    let stats = state.handle.stats();
    let mut body = format!(
        concat!(
            "codewire_udp_relay_allocations {}\n",
            "codewire_udp_relay_sessions_opened {}\n",
            "codewire_udp_relay_sessions_expired {}\n",
            "codewire_udp_relay_packets_forwarded {}\n",
            "codewire_udp_relay_bytes_forwarded {}\n",
            "codewire_udp_relay_drops_unknown_vni {}\n",
            "codewire_udp_relay_drops_unknown_source {}\n",
            "codewire_udp_relay_drops_handshake {}\n",
            "codewire_udp_relay_drops_unbound {}\n",
            "codewire_udp_relay_drops_malformed {}\n",
        ),
        stats.allocations,
        stats.sessions_opened,
        stats.sessions_expired,
        stats.packets_forwarded,
        stats.bytes_forwarded,
        stats.drops_unknown_vni,
        stats.drops_unknown_source,
        stats.drops_handshake,
        stats.drops_unbound,
        stats.drops_malformed,
    );
    for caller in AllocatorCaller::ALL {
        body.push_str(&format!(
            "codewire_udp_relay_allocator_calls_total{{caller=\"{}\"}} {}\n",
            caller.label(),
            state.allocator_calls.get(caller),
        ));
    }
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        body,
    )
        .into_response()
}

async fn allocate(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<AllocationRequest>,
) -> Result<Json<AllocationResponse>, ApiError> {
    state.allocator_calls.record(AllocatorCaller::Plain);
    authorize_static(&state, &headers)?;
    allocate_endpoint(&state, request)
}

/// The caller is decided, counted and refused before its body is read, so
/// the counter sees every request and only orchestration's are parsed.
async fn allocate_tls(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<TlsPeer>,
    body: Bytes,
) -> Result<Json<AllocationResponse>, ApiError> {
    let caller = match (&peer.client, &state.allocator_client_name) {
        (None, _) => AllocatorCaller::NoCertificate,
        (Some(client), Some(name)) if client.is_named(name) => AllocatorCaller::Orchestration,
        (Some(_), _) => AllocatorCaller::AnotherCertificate,
    };
    state.allocator_calls.record(caller);
    if caller != AllocatorCaller::Orchestration {
        tracing::warn!(
            caller = caller.label(),
            "udp relay refused an allocation without orchestration's client certificate"
        );
        return Err(ApiError::Unauthorized);
    }
    let request = serde_json::from_slice(&body).map_err(|_| ApiError::BadRequest)?;
    allocate_endpoint(&state, request)
}

fn allocate_endpoint(
    state: &AppState,
    request: AllocationRequest,
) -> Result<Json<AllocationResponse>, ApiError> {
    let endpoint = state
        .handle
        .allocate_endpoint(request.client_disco[0], request.client_disco[1])
        .map_err(ApiError::Relay)?;
    Ok(Json(AllocationResponse {
        generation: request.generation,
        endpoint: RelayEndpointResponse::from_endpoint(endpoint),
    }))
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct AllocationRequest {
    pub client_disco: [DiscoPublic; 2],
    #[serde(default)]
    pub generation: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct AllocationResponse {
    pub generation: u32,
    pub endpoint: RelayEndpointResponse,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct RelayEndpointResponse {
    pub server_disco: DiscoPublic,
    pub client_disco: [DiscoPublic; 2],
    pub lamport_id: u64,
    pub vni: u32,
    pub bind_lifetime_ns: u64,
    pub steady_state_lifetime_ns: u64,
    pub addr_ports: Vec<String>,
}

impl RelayEndpointResponse {
    pub fn from_endpoint(endpoint: UDPRelayEndpoint) -> Self {
        Self {
            server_disco: endpoint.server_disco,
            client_disco: endpoint.client_disco,
            lamport_id: endpoint.lamport_id,
            vni: endpoint.vni,
            bind_lifetime_ns: duration_nanos(endpoint.bind_lifetime),
            steady_state_lifetime_ns: duration_nanos(endpoint.steady_state_lifetime),
            addr_ports: endpoint
                .addr_ports
                .into_iter()
                .map(|addr| addr.to_string())
                .collect(),
        }
    }
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
struct ReadyResponse {
    status: &'static str,
    disco_key: DiscoPublic,
    local_addr: String,
}

#[derive(Debug)]
enum ApiError {
    Unauthorized,
    BadRequest,
    Relay(udp_relay::Error),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        match self {
            Self::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({ "error": "unauthorized" })),
            )
                .into_response(),
            Self::BadRequest => (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "invalid allocation request" })),
            )
                .into_response(),
            Self::Relay(err) => {
                let status = match err {
                    udp_relay::Error::NotReady => StatusCode::SERVICE_UNAVAILABLE,
                    udp_relay::Error::ClientEqualsServerDisco
                    | udp_relay::Error::VniPoolExhausted => StatusCode::BAD_REQUEST,
                    _ => StatusCode::INTERNAL_SERVER_ERROR,
                };
                (
                    status,
                    Json(serde_json::json!({ "error": err.to_string() })),
                )
                    .into_response()
            }
        }
    }
}

fn authorize_static(state: &AppState, headers: &HeaderMap) -> Result<(), ApiError> {
    let Some(token) = &state.allocator_token else {
        return Ok(());
    };
    let Some(value) = headers.get(header::AUTHORIZATION) else {
        return Err(ApiError::Unauthorized);
    };
    let Ok(value) = value.to_str() else {
        return Err(ApiError::Unauthorized);
    };
    match value.strip_prefix("Bearer ") {
        Some(candidate) if token_matches(candidate.as_bytes(), token.as_bytes()) => Ok(()),
        _ => Err(ApiError::Unauthorized),
    }
}

/// Compares a presented token in time that does not depend on where it first
/// differs from the configured one. Only the length can be learned.
fn token_matches(candidate: &[u8], token: &[u8]) -> bool {
    if candidate.len() != token.len() {
        return false;
    }
    let diff = candidate
        .iter()
        .zip(token)
        .fold(0u8, |acc, (a, b)| acc | (a ^ b));
    std::hint::black_box(diff) == 0
}

/// A client name that could never match a certificate would leave the TLS
/// listener allocating for nobody without saying why, so it is refused at
/// startup: lowercase DNS labels only, no wildcard and no IP address.
fn allocator_client_name(value: String) -> Result<String, ConfigError> {
    let label = |label: &str| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    };
    if value.len() <= 253
        && value.contains('.')
        && value.split('.').all(label)
        && value.parse::<std::net::IpAddr>().is_err()
    {
        Ok(value)
    } else {
        Err(ConfigError::InvalidAllocatorClientName { value })
    }
}

fn duration_nanos(duration: Duration) -> u64 {
    let nanos = duration.as_nanos();
    nanos.min(u128::from(u64::MAX)) as u64
}

fn parse_socket_addr_env(name: &'static str, value: &str) -> Result<SocketAddr, ConfigError> {
    SocketAddr::from_str(value).map_err(|err| ConfigError::InvalidSocketAddr {
        name,
        value: value.to_string(),
        message: err.to_string(),
    })
}

fn parse_socket_addr_list_env(
    name: &'static str,
    value: Option<String>,
) -> Result<Vec<SocketAddr>, ConfigError> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let mut addrs = Vec::new();
    for raw in value.split(',') {
        let raw = raw.trim();
        if raw.is_empty() {
            continue;
        }
        let addr =
            SocketAddr::from_str(raw).map_err(|err| ConfigError::InvalidSocketAddrListEntry {
                name,
                value: raw.to_string(),
                message: err.to_string(),
            })?;
        addrs.push(addr);
    }
    Ok(addrs)
}

fn parse_hex_32(name: &'static str, value: &str) -> Result<[u8; 32], ConfigError> {
    if value.len() != 64 {
        return Err(ConfigError::InvalidHexKey { name });
    }
    let mut out = [0u8; 32];
    for idx in 0..32 {
        let byte = u8::from_str_radix(&value[idx * 2..idx * 2 + 2], 16)
            .map_err(|_| ConfigError::InvalidHexKey { name })?;
        out[idx] = byte;
    }
    Ok(out)
}

fn trim_env<F>(getenv: &F, name: &str) -> Option<String>
where
    F: Fn(&str) -> Option<String>,
{
    getenv(name)
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    #[test]
    fn config_uses_defaults_and_parses_advertised_addrs() {
        let cfg = Config::from_getenv(|key| match key {
            UDP_ADVERTISE_ADDRS_ENV => Some("203.0.113.34:41641, [2001:db8::1]:41641".into()),
            _ => None,
        })
        .unwrap();

        assert_eq!(cfg.udp_bind_addr, "0.0.0.0:41641".parse().unwrap());
        assert_eq!(cfg.allocator_bind_addr, "0.0.0.0:8095".parse().unwrap());
        assert_eq!(cfg.ops_bind_addr, "0.0.0.0:8096".parse().unwrap());
        assert_eq!(
            cfg.udp_advertise_addr_ports,
            vec![
                "203.0.113.34:41641".parse::<SocketAddr>().unwrap(),
                "[2001:db8::1]:41641".parse::<SocketAddr>().unwrap(),
            ]
        );
    }

    #[test]
    fn config_rejects_bad_private_key() {
        let err = Config::from_getenv(|key| match key {
            DISCO_PRIVATE_KEY_HEX_ENV => Some("not-hex".into()),
            _ => None,
        })
        .unwrap_err();
        assert_eq!(
            err,
            ConfigError::InvalidHexKey {
                name: DISCO_PRIVATE_KEY_HEX_ENV
            }
        );
    }

    #[tokio::test]
    async fn ops_listener_serves_read_only_endpoints_and_cannot_allocate() {
        let app = ops_router(test_state(None).await);
        for path in ["/healthz", "/readyz", "/metrics"] {
            let request = Request::builder().uri(path).body(Body::empty()).unwrap();
            let response = app.clone().oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK, "{path}");
        }

        let response = app.oneshot(allocation_request(None)).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn allocator_listener_serves_only_allocations() {
        let app = allocator_router(test_state(None).await);
        for path in ["/healthz", "/readyz", "/metrics"] {
            let request = Request::builder().uri(path).body(Body::empty()).unwrap();
            let response = app.clone().oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
        }

        let response = app.oneshot(allocation_request(None)).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn allocation_requires_bearer_when_configured() {
        let app = test_router(Some("secret-token".into())).await;
        let request = allocation_request(None);
        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn allocation_returns_reusable_endpoint_descriptor() {
        let app = test_router(Some("secret-token".into())).await;
        let request = allocation_request(Some("Bearer secret-token"));
        let response = app.clone().oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: AllocationResponse = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body.generation, 7);
        assert_eq!(body.endpoint.vni, 1);
        assert_eq!(body.endpoint.addr_ports, vec!["127.0.0.1:41641"]);

        let second = app
            .oneshot(allocation_request(Some("Bearer secret-token")))
            .await
            .unwrap();
        let bytes = axum::body::to_bytes(second.into_body(), usize::MAX)
            .await
            .unwrap();
        let second_body: AllocationResponse = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(second_body.endpoint.vni, body.endpoint.vni);
        assert_eq!(second_body.endpoint.lamport_id, body.endpoint.lamport_id);
    }

    #[tokio::test]
    async fn allocation_rejects_near_miss_tokens() {
        let app = test_router(Some("secret-token".into())).await;
        for auth in [
            "Bearer secret-tokem",
            "Bearer secret-toke",
            "Bearer secret-token2",
            "Bearer ",
            "secret-token",
        ] {
            let response = app
                .clone()
                .oneshot(allocation_request(Some(auth)))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{auth:?}");
        }
    }

    #[test]
    fn token_matches_only_identical_tokens() {
        assert!(token_matches(b"secret-token", b"secret-token"));
        assert!(!token_matches(b"secret-tokem", b"secret-token"));
        assert!(!token_matches(b"secret-toke", b"secret-token"));
        assert!(!token_matches(b"", b"secret-token"));
    }

    const ORCHESTRATION: &str = "codewire-orchestration.codewire.svc";

    fn tls_env(key: &str) -> Option<String> {
        match key {
            ALLOCATOR_TLS_CERT_ENV => Some("/tls/tls.crt".into()),
            ALLOCATOR_TLS_KEY_ENV => Some("/tls/tls.key".into()),
            ALLOCATOR_CLIENT_ROOTS_ENV => Some("/roots/ca.crt".into()),
            ALLOCATOR_CLIENT_NAME_ENV => Some(ORCHESTRATION.into()),
            _ => None,
        }
    }

    #[test]
    fn the_allocator_tls_listener_needs_its_whole_configuration_or_none() {
        assert_eq!(Config::from_getenv(|_| None).unwrap().allocator_tls, None);

        let tls = Config::from_getenv(tls_env).unwrap().allocator_tls.unwrap();
        assert_eq!(tls.bind_addr, "0.0.0.0:8097".parse().unwrap());
        assert_eq!(tls.client_name, ORCHESTRATION);
        tls.files().unwrap();

        for name in [
            ALLOCATOR_TLS_CERT_ENV,
            ALLOCATOR_TLS_KEY_ENV,
            ALLOCATOR_CLIENT_ROOTS_ENV,
            ALLOCATOR_CLIENT_NAME_ENV,
        ] {
            let err = Config::from_getenv(|key| if key == name { None } else { tls_env(key) })
                .unwrap_err();
            assert_eq!(err, ConfigError::MissingAllocatorTls { name });
        }

        // The listener's address alone asks for the listener too.
        let err = Config::from_getenv(|key| match key {
            ALLOCATOR_TLS_BIND_ADDR_ENV => Some("0.0.0.0:9000".into()),
            _ => None,
        })
        .unwrap_err();
        assert_eq!(
            err,
            ConfigError::MissingAllocatorTls {
                name: ALLOCATOR_TLS_CERT_ENV
            }
        );

        // A name no certificate could carry is refused, not served for nobody.
        for value in [
            "10.0.0.7",
            "*.codewire.internal",
            "Orchestration.internal",
            "orchestration",
            "a..b",
        ] {
            let err = Config::from_getenv(|key| match key {
                ALLOCATOR_CLIENT_NAME_ENV => Some(value.into()),
                key => tls_env(key),
            })
            .unwrap_err();
            assert_eq!(
                err,
                ConfigError::InvalidAllocatorClientName {
                    value: value.into()
                }
            );
        }
    }

    /// The allocator behind a real TLS listener that asks for client
    /// certificates, and the three kinds of caller.
    struct Mutual {
        pki: codewire_tls::test_support::SyntheticPki,
        state: AppState,
        url: String,
    }

    impl Mutual {
        async fn start(token: Option<String>) -> Self {
            let pki = codewire_tls::test_support::SyntheticPki::new("localhost");
            let state = test_state(token).await.with_allocator_client(ORCHESTRATION);
            let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = socket.local_addr().unwrap().port();
            let files = pki
                .files
                .clone()
                .with_client_roots(pki.roots.clone())
                .unwrap();
            let listener = codewire_tls::PeerTlsListener::new(socket, files).unwrap();
            let app = allocator_tls_router(state.clone());
            tokio::spawn(async move {
                let _ = axum::serve(
                    listener,
                    app.into_make_service_with_connect_info::<TlsPeer>(),
                )
                .await;
            });
            Self {
                pki,
                state,
                url: format!("https://localhost:{port}/internal/udp-relay/allocations"),
            }
        }

        /// One allocation on a fresh connection, as the client certificate
        /// named `client`, or with none.
        async fn allocate(&self, client: Option<&str>) -> StatusCode {
            let origin = self.url.split("/internal").next().unwrap().to_owned();
            let mut endpoint =
                codewire_tls::ClientTlsEndpoint::new(origin, self.pki.roots.clone()).unwrap();
            if let Some(name) = client {
                let (certificate, key) = self.pki.client_identity(name);
                endpoint = endpoint.with_client_identity(certificate, key).unwrap();
            }
            let response = reqwest::Client::builder()
                .no_proxy()
                .use_preconfigured_tls(endpoint.rustls_config().await.unwrap())
                .build()
                .unwrap()
                .post(&self.url)
                .json(&serde_json::json!({
                    "generation": 7,
                    "client_disco": [
                        DiscoPublic::from_raw([0x11; 32]),
                        DiscoPublic::from_raw([0x22; 32]),
                    ]
                }))
                .send()
                .await
                .unwrap();
            StatusCode::from_u16(response.status().as_u16()).unwrap()
        }

        async fn calls(&self) -> [u64; 4] {
            let request = Request::builder()
                .uri("/metrics")
                .body(Body::empty())
                .unwrap();
            let response = ops_router(self.state.clone())
                .oneshot(request)
                .await
                .unwrap();
            let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            let body = String::from_utf8(bytes.to_vec()).unwrap();
            AllocatorCaller::ALL.map(|caller| {
                let result = caller.label();
                let prefix =
                    format!("codewire_udp_relay_allocator_calls_total{{caller=\"{result}\"}} ");
                body.lines()
                    .find_map(|line| line.strip_prefix(&prefix))
                    .unwrap_or_else(|| panic!("{result} is missing from {body}"))
                    .parse()
                    .unwrap()
            })
        }
    }

    #[tokio::test]
    async fn the_tls_listener_allocates_only_for_orchestrations_certificate() {
        // The certificate is the whole rule there: no static token is asked for.
        let relay = Mutual::start(Some("secret-token".into())).await;
        assert_eq!(relay.allocate(Some(ORCHESTRATION)).await, StatusCode::OK);
        assert_eq!(relay.allocate(None).await, StatusCode::UNAUTHORIZED);
        assert_eq!(
            relay.allocate(Some("codewire-mesh.codewire.svc")).await,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(relay.calls().await, [0, 1, 1, 1]);
    }

    #[tokio::test]
    async fn the_plain_listener_keeps_its_rule_and_is_counted() {
        let relay = Mutual::start(Some("secret-token".into())).await;
        let plain = allocator_router(relay.state.clone());
        let response = plain
            .clone()
            .oneshot(allocation_request(None))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let response = plain
            .oneshot(allocation_request(Some("Bearer secret-token")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(relay.calls().await, [2, 0, 0, 0]);
    }

    #[tokio::test]
    async fn a_tls_listener_without_a_client_name_allocates_for_nobody() {
        let relay = Mutual::start(None).await;
        let mut state = relay.state.clone();
        state.allocator_client_name = None;
        let peer = TlsPeer {
            address: "127.0.0.1:1".parse().unwrap(),
            client: None,
        };
        let mut request = allocation_request(None);
        request.extensions_mut().insert(ConnectInfo(peer));
        let response = allocator_tls_router(state).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn the_tls_listener_refuses_and_counts_a_caller_before_reading_its_body() {
        let relay = Mutual::start(None).await;
        let malformed = |peer: TlsPeer| {
            let mut request = Request::builder()
                .method("POST")
                .uri("/internal/udp-relay/allocations")
                .body(Body::from("not json"))
                .unwrap();
            request.extensions_mut().insert(ConnectInfo(peer));
            request
        };
        let anonymous = TlsPeer {
            address: "127.0.0.1:1".parse().unwrap(),
            client: None,
        };
        let response = allocator_tls_router(relay.state.clone())
            .oneshot(malformed(anonymous))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(relay.calls().await, [0, 0, 1, 0]);
    }

    async fn test_router(token: Option<String>) -> Router {
        allocator_router(test_state(token).await)
    }

    async fn test_state(token: Option<String>) -> AppState {
        let server = SocketServer::bind(
            DiscoPrivate::from_raw([0x55; 32]),
            SocketOptions::new("127.0.0.1:0".parse().unwrap())
                .with_advertise_addr_ports(vec!["127.0.0.1:41641".parse().unwrap()]),
        )
        .await
        .unwrap();
        AppState::new(server.handle(), token)
    }

    fn allocation_request(auth: Option<&str>) -> Request<Body> {
        let body = serde_json::json!({
            "generation": 7,
            "client_disco": [
                serde_json::to_value(DiscoPublic::from_raw([0x11; 32])).unwrap(),
                serde_json::to_value(DiscoPublic::from_raw([0x22; 32])).unwrap(),
            ]
        });
        let mut builder = Request::builder()
            .method("POST")
            .uri("/internal/udp-relay/allocations")
            .header(header::CONTENT_TYPE, "application/json");
        if let Some(auth) = auth {
            builder = builder.header(header::AUTHORIZATION, auth);
        }
        builder.body(Body::from(body.to_string())).unwrap()
    }
}
