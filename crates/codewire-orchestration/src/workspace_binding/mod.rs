//! Claim-time workspace binding listener (Program #2238 B1).
//!
//! An identity-free workspace Pod long-polls `BindWorkspace` on this
//! dedicated listener, presenting a Pod-bound projected token with the exact
//! audience `codewire.internal.workspace-binding.v1`. The Pod's identity comes
//! only from TokenReview. Orchestration's recorded binding, not the Pod,
//! decides which environment it serves, and the daemon credential is derived
//! from that environment and the reviewed Pod UID.
//!
//! The port stays reachable from every tenant workload for the Pod's life, so
//! the listener serves this one RPC and nothing else, under connection limits
//! enforced at accept ([`LISTENER_LIMITS`]), request limits enforced before
//! any TokenReview ([`limits`]), and its own small database pool. Every check
//! fails closed and every error is value-blind.
//!
//! B1 adds the listener without a caller: no workspace Pod is rendered with the
//! binding token until the B2 cutover, so nothing changes at runtime.

mod authorize;
pub mod limits;
mod metrics;
mod service;
mod store;

use std::time::Duration;

use codewire_server_core::bounded_http1::BoundedHttp1Limits;

pub use service::{WorkspaceBindingState, workspace_binding_router};
pub use store::{
    BindingNotifications, BindingStore, PgBindingStore, WORKSPACE_BINDINGS_CHANNEL,
    spawn_binding_notification_listener,
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
/// 16 headers, a head bounded below 32 KiB, a 64-byte body, the whole request
/// (head and body) within 5s of accept and before any authentication, one
/// request per connection and a 35s connection deadline (the 20s wait plus
/// margin).
pub const LISTENER_LIMITS: BoundedHttp1Limits = BoundedHttp1Limits {
    max_connections: 512,
    max_connections_per_peer: 2,
    header_read_timeout: Duration::from_secs(5),
    max_headers: 16,
    // hyper accepts a head below twice its read buffer.
    max_header_bytes: 16 * 1024,
    max_body_bytes: 64,
    request_read_timeout: Duration::from_secs(5),
    connection_deadline: Duration::from_secs(35),
};

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
}

#[cfg(test)]
mod tests;
