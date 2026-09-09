use std::error::Error;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use anyhow::{Context, Result};
use codewire_gateway_proto::CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES;
use codewire_gateway_proto::daemon::v1::daemon_service_server::DaemonServiceServer;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::futures::OwnedNotified;
use tokio::sync::{Notify, watch};
use tokio::time::timeout;
use tokio_stream::{Stream, StreamExt};
use tokio_util::task::AbortOnDropHandle;
use tonic::transport::Server;
use tonic::transport::server::Connected;

use crate::Config;
use crate::service::{DaemonRuntimeState, DaemonServiceImpl};

type DaemonGrpcService = DaemonServiceServer<DaemonServiceImpl>;

const GRPC_GRACEFUL_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);
const GRPC_FORCED_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);

pub(super) struct TransportShutdown {
    triggered: AtomicBool,
    notify: Arc<Notify>,
}

impl TransportShutdown {
    pub(super) fn new() -> Arc<Self> {
        Arc::new(Self {
            triggered: AtomicBool::new(false),
            notify: Arc::new(Notify::new()),
        })
    }

    pub(super) fn trigger(&self) {
        self.triggered.store(true, Ordering::Release);
        self.notify.notify_waiters();
    }
}

pub(super) struct ShutdownIo<IO> {
    inner: IO,
    shutdown: Arc<TransportShutdown>,
    notified: Pin<Box<OwnedNotified>>,
}

impl<IO> ShutdownIo<IO> {
    pub(super) fn new(inner: IO, shutdown: Arc<TransportShutdown>) -> Self {
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

#[doc(hidden)]
pub async fn serve_grpc_with_incoming_and_runtime_state<I, IO, IE, F>(
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
    let selected_ssh = config
        .managed_credential_clients
        .contains(codewire_access::ManagedCredentialClient::Ssh);
    if selected_ssh && (config.credential_bridge.is_none() || config.launch_projection.is_none()) {
        anyhow::bail!("selected SSH ingress has no launch authority");
    }
    #[cfg(target_os = "linux")]
    let startup_config = config.clone();
    let implementation = DaemonServiceImpl::with_runtime_state(config, runtime_state);
    let bridge_owner = implementation.credential_bridge();
    // Also cancel admission/registered work if this entire server future is
    // dropped. Normal exits below still await the actual owner drain.
    let _bridge_cancellation = bridge_owner.cancel_on_drop();
    let ingress = implementation
        .credential_bridge()
        .prepare_ingress(selected_ssh)
        .context("prepare credential bridge guest ingress")?;
    #[cfg(target_os = "linux")]
    let startup = crate::execution::StartupProjectionIngress::prepare(
        &startup_config,
        implementation.credential_bridge(),
    )
    .context("prepare bootstrap environment launch ingress")?;
    #[cfg(target_os = "linux")]
    drop(startup_config);
    let transport_shutdown = TransportShutdown::new();
    let incoming_shutdown = Arc::clone(&transport_shutdown);
    let incoming = incoming
        .map(move |result| result.map(|io| ShutdownIo::new(io, Arc::clone(&incoming_shutdown))));
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let observer_tx = shutdown_tx.clone();
    let shutdown_observer = AbortOnDropHandle::new(tokio::spawn(async move {
        shutdown.await;
        let _ = observer_tx.send(true);
    }));
    let observed_shutdown = wait_for_shutdown(shutdown_rx.clone());
    let serving = Server::builder()
        .add_service(configure_grpc_service(implementation))
        .serve_with_incoming_shutdown(incoming, observed_shutdown);
    let mut shutdown_started = shutdown_rx.clone();
    let ingress_shutdown = shutdown_rx.clone();
    let startup_shutdown = shutdown_rx.clone();
    let combined_shutdown = shutdown_rx.clone();
    let combined_shutdown_tx = shutdown_tx.clone();
    let ingress_serving = async move {
        let http_serving = async move {
            match ingress {
                Some(ingress) => ingress
                    .serve(wait_for_shutdown(ingress_shutdown))
                    .await
                    .context("serve credential bridge guest ingress"),
                None => {
                    wait_for_shutdown(ingress_shutdown).await;
                    Ok(())
                }
            }
        };
        #[cfg(target_os = "linux")]
        let startup_serving = async move {
            if let Some(startup) = startup {
                startup
                    .serve(wait_for_shutdown(startup_shutdown.clone()))
                    .await
                    .context("serve bootstrap environment launch ingress")?;
            }
            // Successful bootstrap Finish is expected; it must not stop the
            // long-lived daemon or its provider HTTP ingress.
            wait_for_shutdown(startup_shutdown).await;
            Ok::<(), anyhow::Error>(())
        };
        #[cfg(not(target_os = "linux"))]
        let startup_serving = async move {
            wait_for_shutdown(startup_shutdown).await;
            Ok::<(), anyhow::Error>(())
        };
        tokio::pin!(http_serving);
        tokio::pin!(startup_serving);
        tokio::select! {
            result = &mut http_serving => {
                let expected = *combined_shutdown.borrow();
                let _ = combined_shutdown_tx.send(true);
                timeout(GRPC_GRACEFUL_SHUTDOWN_TIMEOUT, &mut startup_serving).await
                    .context("drain bootstrap environment launch ingress timed out")??;
                result?;
                if !expected { return Err(anyhow::anyhow!("credential ingress stopped unexpectedly")); }
                Ok(())
            }
            result = &mut startup_serving => {
                let expected = *combined_shutdown.borrow();
                let _ = combined_shutdown_tx.send(true);
                timeout(GRPC_GRACEFUL_SHUTDOWN_TIMEOUT, &mut http_serving).await
                    .context("stop credential ingress after bootstrap shutdown timed out")??;
                result?;
                if !expected { return Err(anyhow::anyhow!("bootstrap environment launch ingress stopped unexpectedly")); }
                Ok(())
            }
        }
    };
    tokio::pin!(serving);
    tokio::pin!(ingress_serving);

    let result = async { tokio::select! {
        result = &mut serving => {
            let _ = shutdown_tx.send(true);
            bridge_owner.shutdown().await;
            timeout(GRPC_GRACEFUL_SHUTDOWN_TIMEOUT, &mut ingress_serving)
                .await
                .context("stop credential bridge guest ingress timed out")??;
            result.context("serve workspace daemon gRPC transport")
        }
        ingress_result = &mut ingress_serving => {
            let shutting_down = *shutdown_rx.borrow();
            let _ = shutdown_tx.send(true);
            bridge_owner.shutdown().await;
            match timeout(GRPC_GRACEFUL_SHUTDOWN_TIMEOUT, &mut serving).await {
                Ok(result) => result.context("serve workspace daemon gRPC transport")?,
                Err(error) => {
                    tracing::warn!(%error, "workspace daemon gRPC shutdown after credential ingress exit timed out; closing active transports");
                    transport_shutdown.trigger();
                    timeout(GRPC_FORCED_SHUTDOWN_TIMEOUT, &mut serving)
                        .await
                        .context("force-close workspace daemon gRPC transports timed out")?
                        .context("serve workspace daemon gRPC transport")?;
                }
            }
            ingress_result?;
            if shutting_down {
                Ok(())
            } else {
                Err(anyhow::anyhow!("credential bridge guest ingress stopped unexpectedly"))
            }
        }
        _ = shutdown_started.changed() => {
            bridge_owner.shutdown().await;
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
            timeout(GRPC_GRACEFUL_SHUTDOWN_TIMEOUT, &mut ingress_serving)
                .await
                .context("stop credential bridge guest ingress timed out")??;
            Ok(())
        }
    } }.await;
    // `?` inside a branch must not bypass the owner finalizer. This includes
    // prepared hosted Open waiters as well as both local/hosted active epochs.
    bridge_owner.shutdown().await;
    shutdown_observer.abort();
    let _ = shutdown_observer.await;
    result
}

async fn wait_for_shutdown(mut shutdown: watch::Receiver<bool>) {
    while !*shutdown.borrow() {
        if shutdown.changed().await.is_err() {
            return;
        }
    }
}

fn configure_grpc_service(implementation: DaemonServiceImpl) -> DaemonGrpcService {
    DaemonServiceServer::new(implementation)
        .max_decoding_message_size(CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES)
        .max_encoding_message_size(CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES)
}
