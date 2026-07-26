//! Server-streaming probe pacing (doc 03 WI-4, D5).
//!
//! Proves `codewire.testing.v1.PingService/StreamPing` — the D5 edge
//! buffering fixture — streams incrementally through the full serving stack
//! (AppBuilder middleware + content-type gate + allowlisted auth layer +
//! Connect dispatcher): all messages arrive, in order, and the arrival
//! window spans the server's pacing rather than collapsing into one flush.
//! The kind e2e (WI-4) runs the same probe through ingress-nginx; this test
//! pins the in-process half so an edge failure is attributable to the edge.
//!
//! Needs no database: StreamPing is on the public allowlist, so the auth
//! layer never touches the (lazily-constructed, never-connected) pool.

use std::time::Instant;

use codewire_proto::codewire::testing::v1::{
    PingServiceClient, StreamPingRequest, StreamPingResponse,
};
use codewire_server_core::AppBuilder;
use codewire_server_core::auth::AuthState;
use codewire_server_core::connect_testing::{self, STREAM_PING_INTERVAL, STREAM_PING_TOTAL};
use connectrpc::client::{ClientConfig, HttpClient};

#[tokio::test]
async fn stream_ping_arrives_incrementally() {
    // Never connected: the allowlisted method bypasses authentication.
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect_lazy("postgres://unused:unused@127.0.0.1:1/unused")
        .expect("lazy pool");
    let (connect, layer) = connect_testing::router(AuthState { pool });
    let app = AppBuilder::new("codewire-server-core-test")
        .with_connect_routes_auth(connect, layer)
        .into_router();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(codewire_server_core::serve_with_listener(app, listener));

    let client = PingServiceClient::new(
        HttpClient::plaintext(),
        ClientConfig::new(format!("http://{addr}").parse().expect("uri")),
    );

    let start = Instant::now();
    let mut stream = client
        .stream_ping(StreamPingRequest::default())
        .await
        .expect("open stream");

    // D5 edge posture: streaming responses tell nginx-family proxies not to
    // buffer, per-response (mirrors the repo's SSE handlers).
    assert_eq!(
        stream
            .headers()
            .get("x-accel-buffering")
            .and_then(|v| v.to_str().ok()),
        Some("no"),
        "streaming responses must carry X-Accel-Buffering: no"
    );

    let mut arrivals = Vec::new();
    let mut sequences = Vec::new();
    while let Some(msg) = stream
        .message::<StreamPingResponse>()
        .await
        .expect("stream message")
    {
        arrivals.push(start.elapsed());
        sequences.push(msg.view().sequence);
    }

    assert_eq!(
        sequences,
        (0..STREAM_PING_TOTAL).collect::<Vec<_>>(),
        "all paced messages arrive in order"
    );
    let spread = *arrivals.last().unwrap() - arrivals[0];
    // 5 messages at 300ms pacing span 1.2s server-side; require at least
    // half of it client-side so a buffered single flush (spread ~0) fails
    // loudly while slow-CI jitter does not.
    assert!(
        spread >= STREAM_PING_INTERVAL * (STREAM_PING_TOTAL - 1) / 2,
        "stream arrived as one burst (spread {spread:?}); expected incremental delivery"
    );
}
