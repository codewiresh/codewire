use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use codewire_tailnet::disco::{DiscoPrivate, UDPRelayEndpoint};
use codewire_tailnet::node::DiscoPublic;
use codewire_tailnet::udp_relay::{self, SocketHandle, SocketOptions, SocketServer};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

pub const DEFAULT_UDP_BIND_ADDR: &str = "0.0.0.0:41641";
pub const DEFAULT_HTTP_BIND_ADDR: &str = "0.0.0.0:8095";

pub const UDP_BIND_ADDR_ENV: &str = "CODEWIRE_UDP_RELAY_BIND_ADDR";
pub const UDP_ADVERTISE_ADDRS_ENV: &str = "CODEWIRE_UDP_RELAY_ADVERTISE_ADDRS";
pub const HTTP_BIND_ADDR_ENV: &str = "CODEWIRE_UDP_RELAY_HTTP_ADDR";
pub const ALLOCATOR_TOKEN_ENV: &str = "CODEWIRE_UDP_RELAY_ALLOCATOR_TOKEN";
pub const DISCO_PRIVATE_KEY_HEX_ENV: &str = "CODEWIRE_UDP_RELAY_DISCO_PRIVATE_KEY_HEX";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    pub udp_bind_addr: SocketAddr,
    pub udp_advertise_addr_ports: Vec<SocketAddr>,
    pub http_bind_addr: SocketAddr,
    pub allocator_token: Option<String>,
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
        let http_bind_addr = parse_socket_addr_env(
            HTTP_BIND_ADDR_ENV,
            getenv(HTTP_BIND_ADDR_ENV)
                .as_deref()
                .unwrap_or(DEFAULT_HTTP_BIND_ADDR),
        )?;
        let allocator_token = trim_env(&getenv, ALLOCATOR_TOKEN_ENV);
        let disco_private_key_hex = trim_env(&getenv, DISCO_PRIVATE_KEY_HEX_ENV);

        if let Some(raw) = &disco_private_key_hex {
            parse_hex_32(DISCO_PRIVATE_KEY_HEX_ENV, raw)?;
        }

        Ok(Self {
            udp_bind_addr,
            udp_advertise_addr_ports,
            http_bind_addr,
            allocator_token,
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
}

#[derive(Clone)]
pub struct AppState {
    handle: SocketHandle,
    allocator_token: Option<Arc<str>>,
}

impl AppState {
    pub fn new(handle: SocketHandle, allocator_token: Option<String>) -> Self {
        Self {
            handle,
            allocator_token: allocator_token.map(Arc::from),
        }
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
                "udp-relay: {ALLOCATOR_TOKEN_ENV} is not set; the allocator accepts unauthenticated requests"
            );
        }
        let state = AppState::new(server.handle(), config.allocator_token.clone());
        Ok(Self { server, state })
    }

    pub fn app(&self) -> Router {
        router(self.state.clone())
    }

    pub fn state(&self) -> &AppState {
        &self.state
    }

    pub fn into_server(self) -> SocketServer {
        self.server
    }
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics))
        .route("/internal/udp-relay/allocations", post(allocate))
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
    let body = format!(
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
    authorize(&state, &headers)?;
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

fn authorize(state: &AppState, headers: &HeaderMap) -> Result<(), ApiError> {
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
        assert_eq!(cfg.http_bind_addr, "0.0.0.0:8095".parse().unwrap());
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

    async fn test_router(token: Option<String>) -> Router {
        let server = SocketServer::bind(
            DiscoPrivate::from_raw([0x55; 32]),
            SocketOptions::new("127.0.0.1:0".parse().unwrap())
                .with_advertise_addr_ports(vec!["127.0.0.1:41641".parse().unwrap()]),
        )
        .await
        .unwrap();
        router(AppState::new(server.handle(), token))
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
