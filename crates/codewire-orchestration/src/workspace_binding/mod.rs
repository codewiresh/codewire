//! Claim-time workspace binding listener (Program #2238 B1).
//!
//! An identity-free workspace Pod long-polls `BindWorkspace` on this
//! dedicated listener, presenting a Pod-bound projected token with the exact
//! audience `codewire.internal.workspace-binding.v1`. The Pod's identity comes
//! only from TokenReview. Orchestration's recorded binding, not the Pod,
//! decides which environment it serves, and the daemon credential is derived
//! from that environment and the reviewed Pod UID.
//!
//! Once bound, the same Pod refreshes its tailnet access grant, records its
//! SSH host key and asks for UDP peer-relay slots here (daemon-hosted access
//! §3 and §5). Every method requires the TCP peer to be the bound Pod's own
//! address.
//!
//! The port stays reachable from every tenant workload for the Pod's life, so
//! the listener serves this one service and nothing else, over TLS with
//! orchestration's internal identity, under connection limits enforced at
//! accept ([`LISTENER_LIMITS`]), per-method body limits ([`max_body_bytes`]),
//! request limits enforced before any TokenReview ([`limits`]), and its own
//! small database pool. Every check fails closed and every error is
//! value-blind.

mod access;
mod authorize;
pub mod limits;
mod metrics;
mod service;
mod store;

use std::time::Duration;

use codewire_server_core::bounded_http1::{BoundedHttp1Limits, ConnectionUpgrade};
use codewire_tls::{ServerTlsFiles, ServerTlsStream};

pub use access::{AccessSettings, HttpRelayAllocator, RelayAllocator};
pub(crate) use authorize::canonical_uid;
pub use service::{WorkspaceBindingState, workspace_binding_router};
pub use store::{
    BindingNotifications, BindingStore, HostKeyRecord, PgBindingStore, WORKSPACE_BINDINGS_CHANNEL,
    current_host_key, spawn_binding_notification_listener,
};

/// Environment variable selecting the listener port; the default is
/// [`codewire_gateway_proto::WORKSPACE_BINDING_PORT`].
pub const ORCHESTRATION_WORKSPACE_BINDING_PORT_ENV: &str = "ORCHESTRATION_WORKSPACE_BINDING_PORT";

/// Longest server-side wait for an unbound Pod. Well inside the 60s Connect
/// unary limit and the connection deadline.
pub const MAX_BIND_WAIT: Duration = Duration::from_secs(20);

/// Waiters re-query at this interval in case a notification is missed.
pub const BINDING_REQUERY_INTERVAL: Duration = Duration::from_secs(2);

/// Connection bounds for the tenant-reachable listener (design §3.5): HTTP/1.1
/// only, two connections per peer IP and 512 in total, a 5s header timeout,
/// 16 headers, a head bounded below 32 KiB, a body of at most the largest
/// per-method limit ([`max_body_bytes`]), the TLS handshake and the whole
/// request (head and body) within 5s of accept and before any
/// authentication, one request per connection and a 35s connection deadline
/// (the 20s wait plus margin).
pub const LISTENER_LIMITS: BoundedHttp1Limits = BoundedHttp1Limits {
    max_connections: 512,
    max_connections_per_peer: 2,
    header_read_timeout: Duration::from_secs(5),
    max_headers: 16,
    // hyper accepts a head below twice its read buffer.
    max_header_bytes: 16 * 1024,
    max_body_bytes: ALLOCATE_PEER_RELAY_BODY_BYTES,
    request_read_timeout: Duration::from_secs(5),
    connection_deadline: Duration::from_secs(35),
};

/// The listener's TLS: orchestration's internal identity, whose leaf names
/// the binding Service, reloaded for every handshake and offering HTTP/1.1
/// only. The handshake runs inside the connection's limits and deadline.
#[derive(Clone)]
pub struct WorkspaceBindingTls(pub ServerTlsFiles);

impl ConnectionUpgrade for WorkspaceBindingTls {
    type Io = ServerTlsStream;

    async fn upgrade(&self, stream: tokio::net::TcpStream) -> std::io::Result<ServerTlsStream> {
        self.0
            .accept_http1_only(stream)
            .await
            .map_err(std::io::Error::other)
    }
}

/// Body limit of every method without a key in its request.
pub const DEFAULT_BODY_BYTES: usize = 64;
/// One Ed25519 OpenSSH public key line (80 bytes) in either encoding.
pub const RECORD_HOST_KEY_BODY_BYTES: usize = 128;
/// Two disco public keys (73 bytes each) and a generation in either encoding.
pub const ALLOCATE_PEER_RELAY_BODY_BYTES: usize = 256;

const RECORD_HOST_KEY_PATH: &str = "/codewire.internal.v1.WorkspaceBindingService/RecordHostKey";
const ALLOCATE_PEER_RELAY_PATH: &str =
    "/codewire.internal.v1.WorkspaceBindingService/AllocatePeerRelay";

/// The request body limit of the method at `path` (daemon-hosted access
/// N5): the smallest that fits its largest valid request.
pub fn max_body_bytes(path: &str) -> usize {
    match path {
        RECORD_HOST_KEY_PATH => RECORD_HOST_KEY_BODY_BYTES,
        ALLOCATE_PEER_RELAY_PATH => ALLOCATE_PEER_RELAY_BODY_BYTES,
        _ => DEFAULT_BODY_BYTES,
    }
}

/// The axum application served on the workspace-binding listener: the one
/// generated service and nothing else. There is no health, metrics, REST,
/// mesh or gateway route; unknown paths are 404.
pub fn app(router: connectrpc::Router) -> axum::Router {
    codewire_server_core::connect::connect_unary_router_with_limits(
        router,
        connectrpc::Limits::default()
            .with_max_request_body_size(LISTENER_LIMITS.max_body_bytes)
            .with_max_message_size(LISTENER_LIMITS.max_body_bytes),
    )
    .layer(axum::middleware::from_fn(per_method_body_limit))
}

/// Refuses a body over its method's limit before routing. The listener has
/// already read the whole body under its own cap.
async fn per_method_body_limit(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::response::IntoResponse as _;
    let limit = max_body_bytes(request.uri().path());
    let (parts, body) = request.into_parts();
    match axum::body::to_bytes(body, limit).await {
        Ok(bytes) => {
            next.run(axum::extract::Request::from_parts(
                parts,
                axum::body::Body::from(bytes),
            ))
            .await
        }
        Err(_) => axum::http::StatusCode::PAYLOAD_TOO_LARGE.into_response(),
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod fairness_tests;
