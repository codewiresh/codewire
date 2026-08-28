use std::error::Error;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use axum::Json;
use axum::http::StatusCode;
use axum::routing::get;
use codewire_gateway_proto::daemon::v1::daemon_service_server::DaemonServiceServer;
use serde_json::json;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpListener;
use tokio::sync::futures::OwnedNotified;
use tokio::sync::{Notify, oneshot};
use tokio::time::timeout;
use tokio_stream::{Stream, StreamExt};
use tonic::service::Routes;
use tonic::transport::Server;
use tonic::transport::server::Connected;

use crate::Config;
use crate::env::default_shell;
use crate::service::{DaemonRuntimeState, DaemonServiceImpl};

type DaemonGrpcService = DaemonServiceServer<DaemonServiceImpl>;

const GRPC_GRACEFUL_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);
const GRPC_FORCED_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);

struct TransportShutdown {
    triggered: AtomicBool,
    notify: Arc<Notify>,
}

impl TransportShutdown {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            triggered: AtomicBool::new(false),
            notify: Arc::new(Notify::new()),
        })
    }

    fn trigger(&self) {
        self.triggered.store(true, Ordering::Release);
        self.notify.notify_waiters();
    }
}

struct ShutdownIo<IO> {
    inner: IO,
    shutdown: Arc<TransportShutdown>,
    notified: Pin<Box<OwnedNotified>>,
}

impl<IO> ShutdownIo<IO> {
    fn new(inner: IO, shutdown: Arc<TransportShutdown>) -> Self {
        let notified = Box::pin(shutdown.notify.clone().notified_owned());
        Self {
            inner,
            shutdown,
            notified,
        }
    }

    fn poll_shutdown_signal(&mut self, cx: &mut TaskContext<'_>) -> Poll<()> {
        if self.shutdown.triggered.load(Ordering::Acquire) {
            return Poll::Ready(());
        }
        self.notified.as_mut().poll(cx)
    }

    fn shutdown_error() -> io::Error {
        io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "daemon transport shut down",
        )
    }
}

impl<IO> AsyncRead for ShutdownIo<IO>
where
    IO: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        if this.poll_shutdown_signal(cx).is_ready() {
            return Poll::Ready(Err(Self::shutdown_error()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<IO> AsyncWrite for ShutdownIo<IO>
where
    IO: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.as_mut().get_mut();
        if this.poll_shutdown_signal(cx).is_ready() {
            return Poll::Ready(Err(Self::shutdown_error()));
        }
        Pin::new(&mut this.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        if this.poll_shutdown_signal(cx).is_ready() {
            return Poll::Ready(Err(Self::shutdown_error()));
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        if this.poll_shutdown_signal(cx).is_ready() {
            return Poll::Ready(Err(Self::shutdown_error()));
        }
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

impl<IO> Connected for ShutdownIo<IO>
where
    IO: Connected,
{
    type ConnectInfo = IO::ConnectInfo;

    fn connect_info(&self) -> Self::ConnectInfo {
        self.inner.connect_info()
    }
}

pub async fn run<F>(config: Config, shutdown: F) -> Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    let listener = TcpListener::bind(&config.listen_addr)
        .await
        .with_context(|| format!("listen daemon {}", config.listen_addr))?;
    let local_addr = listener.local_addr().context("read daemon listener addr")?;
    tracing::info!(shim_listen_addr = %local_addr, "workspace daemon listening");

    axum::serve(listener, router(config))
        .with_graceful_shutdown(shutdown)
        .await
        .context("serve workspace daemon")?;
    Ok(())
}

/// Serve only the private daemon gRPC API over a caller-owned incoming
/// transport.
///
/// The caller owns listener creation and transport-level authorization. This
/// entrypoint does not bind a socket or mount the legacy HTTP health and
/// executable diagnostic routes. Per-RPC daemon-token authorization remains
/// enforced by [`DaemonServiceImpl`].
pub async fn serve_grpc_with_incoming<I, IO, IE, F>(
    config: Config,
    incoming: I,
    shutdown: F,
) -> Result<()>
where
    I: Stream<Item = std::result::Result<IO, IE>> + Send + 'static,
    IO: AsyncRead + AsyncWrite + Connected + Unpin + Send + 'static,
    IE: Into<Box<dyn Error + Send + Sync>>,
    F: Future<Output = ()> + Send + 'static,
{
    serve_grpc_with_incoming_and_runtime_state(
        config,
        DaemonRuntimeState::ready(),
        incoming,
        shutdown,
    )
    .await
}

async fn serve_grpc_with_incoming_and_runtime_state<I, IO, IE, F>(
    config: Config,
    runtime_state: DaemonRuntimeState,
    incoming: I,
    shutdown: F,
) -> Result<()>
where
    I: Stream<Item = std::result::Result<IO, IE>> + Send + 'static,
    IO: AsyncRead + AsyncWrite + Connected + Unpin + Send + 'static,
    IE: Into<Box<dyn Error + Send + Sync>>,
    F: Future<Output = ()> + Send + 'static,
{
    validate_injected_config(&config)?;
    let transport_shutdown = TransportShutdown::new();
    let incoming_shutdown = Arc::clone(&transport_shutdown);
    let incoming = incoming
        .map(move |result| result.map(|io| ShutdownIo::new(io, Arc::clone(&incoming_shutdown))));
    let (shutdown_started_tx, shutdown_started_rx) = oneshot::channel();
    let observed_shutdown = async move {
        shutdown.await;
        let _ = shutdown_started_tx.send(());
    };
    let serving = Server::builder()
        .add_service(grpc_service_with_runtime_state(config, runtime_state))
        .serve_with_incoming_shutdown(incoming, observed_shutdown);
    tokio::pin!(serving);

    tokio::select! {
        result = &mut serving => {
            result.context("serve workspace daemon gRPC transport")?;
        }
        _ = shutdown_started_rx => {
            match timeout(GRPC_GRACEFUL_SHUTDOWN_TIMEOUT, &mut serving).await {
                Ok(result) => {
                    result.context("serve workspace daemon gRPC transport")?;
                }
                Err(error) => {
                    tracing::warn!(%error, "workspace daemon gRPC graceful shutdown timed out; closing active transports");
                    transport_shutdown.trigger();
                    timeout(GRPC_FORCED_SHUTDOWN_TIMEOUT, &mut serving)
                        .await
                        .context("force-close workspace daemon gRPC transports timed out")?
                        .context("serve workspace daemon gRPC transport")?;
                }
            }
        }
    }
    Ok(())
}

fn grpc_service_with_runtime_state(
    config: Config,
    runtime_state: DaemonRuntimeState,
) -> DaemonGrpcService {
    DaemonServiceServer::new(DaemonServiceImpl::with_runtime_state(config, runtime_state))
}

fn validate_injected_config(config: &Config) -> Result<()> {
    let auth_token = config.auth_token.as_deref().unwrap_or_default();
    ensure!(
        !auth_token.trim().is_empty(),
        "workspace daemon gRPC transport requires an auth token"
    );
    ensure!(
        auth_token == auth_token.trim(),
        "workspace daemon gRPC transport auth token contains surrounding whitespace"
    );
    Ok(())
}

pub fn router(config: Config) -> axum::Router {
    router_with_runtime_state(config, DaemonRuntimeState::ready())
}

pub fn router_with_runtime_state(
    config: Config,
    runtime_state: DaemonRuntimeState,
) -> axum::Router {
    let daemon = grpc_service_with_runtime_state(config.clone(), runtime_state);
    let grpc = Routes::new(daemon).into_axum_router();

    axum::Router::new()
        .route(
            "/health",
            get({
                let listen_addr = config.listen_addr.clone();
                move || health(listen_addr.clone())
            }),
        )
        .route("/exec-check", get(exec_check))
        .merge(grpc)
}

async fn health(listen_addr: String) -> Json<serde_json::Value> {
    Json(json!({
        "status": "ok",
        "addr": listen_addr,
    }))
}

async fn exec_check() -> (StatusCode, Json<serde_json::Value>) {
    let shell = default_shell();
    let shell_info = match std::fs::metadata(&shell) {
        Ok(metadata) => json!({
            "path": shell,
            "mode": format!("{:o}", mode(&metadata)),
            "size": metadata.len(),
        }),
        Err(err) => json!({
            "path": shell,
            "stat_error": err.to_string(),
        }),
    };

    let output = tokio::process::Command::new(default_shell())
        .arg("-c")
        .arg("echo ok")
        .stdin(Stdio::null())
        .output()
        .await;

    let mut result = json!({
        "shell": shell_info,
        "pid": std::process::id(),
        "uid": uid(),
        "gid": gid(),
    });

    match output {
        Ok(output) if output.status.success() => {
            result["exec_ok"] = json!(true);
            result["output"] = json!(String::from_utf8_lossy(&output.stdout).trim());
            (StatusCode::OK, Json(result))
        }
        Ok(output) => {
            result["exec_ok"] = json!(false);
            result["error"] = json!(String::from_utf8_lossy(&output.stderr).trim());
            (StatusCode::INTERNAL_SERVER_ERROR, Json(result))
        }
        Err(err) => {
            result["exec_ok"] = json!(false);
            result["error"] = json!(err.to_string());
            (StatusCode::INTERNAL_SERVER_ERROR, Json(result))
        }
    }
}

#[cfg(unix)]
fn mode(metadata: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode()
}

#[cfg(not(unix))]
fn mode(_metadata: &std::fs::Metadata) -> u32 {
    0
}

#[cfg(unix)]
fn uid() -> u32 {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata("/proc/self")
        .map(|m| m.uid())
        .unwrap_or(0)
}

#[cfg(not(unix))]
fn uid() -> u32 {
    0
}

#[cfg(unix)]
fn gid() -> u32 {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata("/proc/self")
        .map(|m| m.gid())
        .unwrap_or(0)
}

#[cfg(not(unix))]
fn gid() -> u32 {
    0
}
