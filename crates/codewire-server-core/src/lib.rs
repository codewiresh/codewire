//! # codewire-server-core
//!
//! Shared platform for Codewire backend services written in Rust. Provides
//! the pieces every Phase 2+ service would otherwise re-implement: an
//! `axum` app builder with a standard middleware stack, a bearer-token auth
//! extractor compatible with the existing `cw_`-prefixed API keys, a typed
//! error envelope matching the Go SDKs' wire shape, structured tracing with
//! optional OpenTelemetry export, and connection helpers for Postgres and
//! NATS.
//!
//! ## Quick start
//!
//! ```no_run
//! use codewire_server_core::{AppBuilder, ServiceConfig};
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let cfg = ServiceConfig::from_env("billing")?;
//!     codewire_server_core::obs::init(&cfg)?;
//!
//!     let app = AppBuilder::new("codewire-billing")
//!         .with_health()
//!         .into_router();
//!
//!     codewire_server_core::serve(app, cfg.bind_addr).await
//! }
//! ```
//!
//! Each module is documented at its own level; this crate root just
//! re-exports the most common entry points.

pub mod auth;
pub mod bounded_http1;
pub mod config;
pub mod connect;
pub mod connect_error;
pub mod connect_testing;
pub mod db;
pub mod error;
pub mod health;
pub mod http;
pub mod internal_hmac;
pub mod kek;
pub mod metrics;
pub mod migrate;
pub mod nats;
pub mod obs;
pub mod org;
pub mod org_deletion;
pub mod organization_slug;
pub mod peer_token;
#[cfg(feature = "kubernetes-identity")]
pub mod pod_identity;
pub mod rest_sunset;
pub mod runtime_images;
pub mod validation;

pub use config::ServiceConfig;
pub use connect_error::{ConnectCode, ConnectError};
pub use error::{AppError, AppResult, ErrorEnvelope, ValidationIssue};
pub use http::AppBuilder;
pub use validation::ValidatedJson;

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::Context;
use axum::Router;

/// Bind to `addr` and serve `app` until the process receives SIGTERM/SIGINT.
///
/// This is the canonical service entry point — each `cmd/` binary calls
/// `serve(...)` once and returns. Graceful shutdown is built in; in-flight
/// requests finish before the listener returns.
pub async fn serve(app: Router, addr: SocketAddr) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind {addr}"))?;
    tracing::info!(%addr, "server listening");
    serve_with_listener(app, listener).await
}

/// [`serve`] on an already-bound listener (tests bind port 0 and read the
/// local address back).
///
/// The listener is h2c-capable (`codewire/plans:connect-rpc/03-connect-server-
/// infrastructure.md` D2): `axum::serve` drives hyper-util's auto connection
/// builder, which sniffs the HTTP/2 prior-knowledge preface on plaintext
/// connections, so HTTP/1.1 and cleartext HTTP/2 share every service port.
/// This requires axum's `http2` feature, enabled in the workspace pin; the
/// in-crate `connect_mount` integration test proves it end to end.
pub async fn serve_with_listener(
    app: Router,
    listener: tokio::net::TcpListener,
) -> anyhow::Result<()> {
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("axum::serve")?;
    Ok(())
}

/// [`serve_with_listener`] on any axum listener, such as one that completes a
/// TLS handshake before HTTP, with the same graceful shutdown.
pub async fn serve_with_axum_listener<L>(app: Router, listener: L) -> anyhow::Result<()>
where
    L: axum::serve::Listener,
    L::Addr: std::fmt::Debug,
{
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("axum::serve")?;
    Ok(())
}

/// HTTP/2 keepalive settings for the narrowly opt-in auto-protocol server.
///
/// The canonical [`serve`] / [`serve_with_listener`] path intentionally does
/// not use this configuration. It exists for long-lived bidi services that
/// need hop-local HTTP/2 PINGs while retaining HTTP/1.1 upgrades on the same
/// listener; the coordinator is the first and only caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Http2KeepaliveConfig {
    /// Interval between HTTP/2 keepalive PING frames.
    pub interval: Duration,
    /// Maximum wait for a keepalive acknowledgement before closing.
    pub timeout: Duration,
}

impl Http2KeepaliveConfig {
    /// Construct explicit HTTP/2 keepalive settings.
    pub const fn new(interval: Duration, timeout: Duration) -> Self {
        Self { interval, timeout }
    }

    fn auto_builder(
        self,
    ) -> hyper_util::server::conn::auto::Builder<hyper_util::rt::TokioExecutor> {
        let mut builder =
            hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new());
        builder
            .http2()
            .timer(hyper_util::rt::TokioTimer::new())
            .keep_alive_interval(self.interval)
            .keep_alive_timeout(self.timeout);
        builder
    }
}

/// Bind and serve with HTTP/1.1 + prior-knowledge HTTP/2 auto selection and
/// configured HTTP/2 keepalive. This is an opt-in sibling of [`serve`]; it
/// does not alter the shared default path used by other services.
pub async fn serve_with_h2_keepalive(
    app: Router,
    addr: SocketAddr,
    keepalive: Http2KeepaliveConfig,
) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind {addr}"))?;
    tracing::info!(%addr, "server listening");
    serve_with_listener_h2_keepalive(app, listener, keepalive).await
}

/// [`serve_with_h2_keepalive`] on an already-bound listener.
pub async fn serve_with_listener_h2_keepalive(
    app: Router,
    listener: tokio::net::TcpListener,
    keepalive: Http2KeepaliveConfig,
) -> anyhow::Result<()> {
    use hyper_util::rt::TokioIo;
    use hyper_util::server::graceful::GracefulShutdown;

    let builder = keepalive.auto_builder();
    let graceful = GracefulShutdown::new();
    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, peer_addr) = match accepted {
                    Ok(accepted) => accepted,
                    Err(err) => {
                        tracing::warn!(error = ?err, "server accept failed");
                        continue;
                    }
                };
                let app = app.clone();
                let service = hyper::service::service_fn(move |request: hyper::Request<hyper::body::Incoming>| {
                    let app = app.clone();
                    async move {
                        use tower::ServiceExt;
                        app.oneshot(request.map(axum::body::Body::new)).await
                    }
                });
                let connection = builder
                    .serve_connection_with_upgrades(TokioIo::new(stream), service)
                    .into_owned();
                let watched = graceful.watcher().watch(connection);
                tokio::spawn(async move {
                    if let Err(err) = watched.await {
                        tracing::debug!(error = ?err, %peer_addr, "server connection ended");
                    }
                });
            }
            _ = &mut shutdown => break,
        }
    }

    drop(listener);
    graceful.shutdown().await;
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut sig) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            sig.recv().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    tracing::info!("shutdown signal received");
}

#[cfg(test)]
mod keepalive_tests {
    use super::*;

    #[test]
    fn opt_in_builder_keeps_auto_protocol_selection_with_configured_keepalive() {
        let config = Http2KeepaliveConfig::new(Duration::from_secs(15), Duration::from_secs(20));
        let builder = config.auto_builder();

        assert_eq!(config.interval, Duration::from_secs(15));
        assert_eq!(config.timeout, Duration::from_secs(20));
        assert!(builder.is_http1_available());
        assert!(builder.is_http2_available());
    }
}
