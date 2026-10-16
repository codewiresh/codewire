use std::error::Error;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use anyhow::{Context, Result};
use codewire_daemon_proto::CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES;
use codewire_daemon_proto::daemon::v1::daemon_service_server::DaemonServiceServer;
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
    serve(config, runtime_state, None, None, None, incoming, shutdown).await
}

/// Dedicated owner-private Linux trusted-host control. The binding is the
/// saved environment UUID selected by its owning lifecycle. Generic guest and
/// platform entrypoints never register this service.
#[cfg(target_os = "linux")]
pub async fn serve_host_control_grpc_with_incoming<I, IO, IE, F>(
    config: Config,
    binding: crate::host_control::HostControlBinding,
    incoming: I,
    shutdown: F,
) -> Result<()>
where
    I: Stream<Item = std::result::Result<IO, IE>> + Send + 'static,
    IO: AsyncRead + AsyncWrite + Connected + Unpin + Send + 'static,
    IE: Into<Box<dyn Error + Send + Sync>>,
    F: Future<Output = ()> + Send + 'static,
{
    anyhow::ensure!(
        config.host.is_some(),
        "host control requires trusted-host configuration"
    );
    serve(
        config,
        DaemonRuntimeState::ready(),
        None,
        Some(binding),
        None,
        incoming,
        shutdown,
    )
    .await
}

/// The hosted workspace daemon: [`serve_grpc_with_incoming`] plus, on a hosted
/// bridge, the tasks that keep the agents' own logins: Codex's ChatGPT login
/// in `codex_home` while Codex is selected ([`crate::codex_home::login`]), and
/// Claude Code's claude.ai login in the home's `~/.claude` while the Anthropic
/// client is selected in its sign-in form ([`crate::claude_home::login`]). The
/// caller listens first and prepares both homes before that.
#[cfg(target_os = "linux")]
pub async fn serve_hosted_grpc_with_incoming<I, IO, IE, F>(
    config: Config,
    codex_home: crate::codex_home::CodexHome,
    incoming: I,
    shutdown: F,
) -> Result<()>
where
    I: Stream<Item = std::result::Result<IO, IE>> + Send + 'static,
    IO: AsyncRead + AsyncWrite + Connected + Unpin + Send + 'static,
    IE: Into<Box<dyn Error + Send + Sync>>,
    F: Future<Output = ()> + Send + 'static,
{
    let logins = HostedLogins::from_env(codex_home)?;
    serve(
        config,
        DaemonRuntimeState::ready(),
        Some(logins),
        None,
        None,
        incoming,
        shutdown,
    )
    .await
}

/// [`serve_hosted_grpc_with_incoming`] for a bound daemon that serves the
/// environment's application ports: `SetAppPorts` replaces the set in
/// `app_ports`. `pod_uid` is this Pod's downward-API UID, which its binding
/// was checked against; the platform managed service keeps this Pod's own
/// request book under it.
#[cfg(target_os = "linux")]
pub async fn serve_bound_hosted_grpc_with_incoming<I, IO, IE, F>(
    config: Config,
    pod_uid: &str,
    codex_home: crate::codex_home::CodexHome,
    app_ports: crate::app_ports::AppPortsSender,
    incoming: I,
    shutdown: F,
) -> Result<()>
where
    I: Stream<Item = std::result::Result<IO, IE>> + Send + 'static,
    IO: AsyncRead + AsyncWrite + Connected + Unpin + Send + 'static,
    IE: Into<Box<dyn Error + Send + Sync>>,
    F: Future<Output = ()> + Send + 'static,
{
    let logins = HostedLogins::from_env(codex_home)?;
    serve(
        config,
        DaemonRuntimeState::ready(),
        Some(logins),
        None,
        Some((app_ports, pod_uid)),
        incoming,
        shutdown,
    )
    .await
}

/// A local VM's guest daemon: [`serve_grpc_with_incoming`] plus, while Codex
/// is selected, the task that keeps Codex's own ChatGPT login in the native
/// `codex_home` on the workload user's behalf ([`crate::codex_home::login`]),
/// through the one listed direct delivery exception
/// (docs/dev/SECRETS-AND-CREDENTIALS.md, "Direct delivery exceptions").
#[cfg(target_os = "linux")]
pub async fn serve_native_grpc_with_incoming<I, IO, IE, F>(
    config: Config,
    codex_home: crate::codex_home::CodexHome,
    incoming: I,
    shutdown: F,
) -> Result<()>
where
    I: Stream<Item = std::result::Result<IO, IE>> + Send + 'static,
    IO: AsyncRead + AsyncWrite + Connected + Unpin + Send + 'static,
    IE: Into<Box<dyn Error + Send + Sync>>,
    F: Future<Output = ()> + Send + 'static,
{
    anyhow::ensure!(
        codex_home.owner().is_some(),
        "a local VM's Codex home is kept for its workload user"
    );
    serve(
        config,
        DaemonRuntimeState::ready(),
        Some(HostedLogins {
            codex_home,
            check_period: crate::config::CODEX_LOGIN_CHECK_PERIOD,
        }),
        None,
        None,
        incoming,
        shutdown,
    )
    .await
}

/// Codex's home on a hosted daemon, and how often the delivered agent logins
/// are checked: the production period unless the Kind test deployment set
/// [`crate::config::CODEX_LOGIN_CHECK_PERIOD_ENV`], already validated at
/// startup. Claude Code's login lives in the configured home root.
#[cfg(target_os = "linux")]
struct HostedLogins {
    codex_home: crate::codex_home::CodexHome,
    check_period: std::time::Duration,
}

#[cfg(target_os = "linux")]
impl HostedLogins {
    fn from_env(codex_home: crate::codex_home::CodexHome) -> Result<Self> {
        let check_period = crate::config::codex_login_check_period(
            std::env::var_os(crate::config::CODEX_LOGIN_CHECK_PERIOD_ENV).as_deref(),
        )?;
        Ok(Self {
            codex_home,
            check_period,
        })
    }
}

#[cfg(target_os = "linux")]
type AgentLogins = HostedLogins;
#[cfg(not(target_os = "linux"))]
type AgentLogins = std::convert::Infallible;

#[cfg(target_os = "linux")]
type HostControlBinding = crate::host_control::HostControlBinding;
#[cfg(not(target_os = "linux"))]
type HostControlBinding = std::convert::Infallible;

async fn serve<I, IO, IE, F>(
    config: Config,
    runtime_state: DaemonRuntimeState,
    // The hosted entry points' agent logins.
    logins: Option<AgentLogins>,
    host_control_binding: Option<HostControlBinding>,
    // A bound daemon's application ports and its own Pod UID.
    bound: Option<(crate::app_ports::AppPortsSender, &str)>,
    incoming: I,
    shutdown: F,
) -> Result<()>
where
    I: Stream<Item = std::result::Result<IO, IE>> + Send + 'static,
    IO: AsyncRead + AsyncWrite + Connected + Unpin + Send + 'static,
    IE: Into<Box<dyn Error + Send + Sync>>,
    F: Future<Output = ()> + Send + 'static,
{
    config.validate_host()?;
    let (app_ports, pod_uid) = bound.unzip();
    #[cfg(target_os = "linux")]
    let (codex_login, claude_login) = match logins {
        Some(logins) => {
            // A local VM keeps Claude Code's login for the same workload user
            // as Codex's native home; a hosted daemon keeps its own.
            let owner = logins.codex_home.owner();
            (
                crate::codex_home::login::login_writer(&config, logins.codex_home)
                    .map(|writer| (writer, logins.check_period)),
                crate::claude_home::login::login_writer(&config, owner)
                    .map(|writer| (writer, logins.check_period)),
            )
        }
        None => (None, None),
    };
    #[cfg(not(target_os = "linux"))]
    let _ = logins;
    let selected_ssh = config
        .managed_credential_clients
        .contains(codewire_access::ManagedCredentialClient::Ssh);
    if selected_ssh && (config.credential_bridge.is_none() || config.launch_projection.is_none()) {
        anyhow::bail!("selected SSH ingress has no launch authority");
    }
    #[cfg(target_os = "linux")]
    let startup_config = config.clone();
    let mut implementation = DaemonServiceImpl::with_runtime_state(config, runtime_state);
    if let Some(app_ports) = app_ports {
        implementation = implementation.with_app_ports(app_ports);
    }
    let session_owner = implementation.session_engine();
    #[cfg(target_os = "linux")]
    let platform_managed = crate::platform_managed::Service::new(
        startup_config.clone(),
        session_owner.clone(),
        pod_uid,
    );
    #[cfg(not(target_os = "linux"))]
    let _ = pod_uid;
    let _session_cancellation = session_owner.cancel_on_drop();
    #[cfg(target_os = "linux")]
    let host_control = match host_control_binding {
        Some(binding) => Some(
            crate::host_control::HostControlService::new(
                &startup_config,
                binding,
                session_owner.clone(),
            )
            .await?,
        ),
        None => None,
    };
    #[cfg(not(target_os = "linux"))]
    let _ = host_control_binding;
    #[cfg(target_os = "linux")]
    let control_owner = host_control.as_ref().map(|service| service.owner());
    #[cfg(target_os = "linux")]
    let _control_cancellation = control_owner.as_ref().map(|owner| owner.close_on_drop());
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
    // The agents' own logins, beside gRPC and the guest ingress. Each asks
    // only over an admitted epoch and stops with the daemon.
    #[cfg(target_os = "linux")]
    let _codex_login =
        codex_login
            .zip(bridge_owner.shared_bridge())
            .map(|((writer, check_period), bridge)| {
                AbortOnDropHandle::new(tokio::spawn(
                    crate::codex_home::login::run_codex_login_writer(
                        writer,
                        bridge,
                        check_period,
                        shutdown_rx.clone(),
                    ),
                ))
            });
    #[cfg(target_os = "linux")]
    let _claude_login =
        claude_login
            .zip(bridge_owner.shared_bridge())
            .map(|((writer, check_period), bridge)| {
                AbortOnDropHandle::new(tokio::spawn(
                    crate::claude_home::login::run_claude_login_writer(
                        writer,
                        bridge,
                        check_period,
                        shutdown_rx.clone(),
                    ),
                ))
            });
    let observer_tx = shutdown_tx.clone();
    #[cfg(target_os = "linux")]
    let observer_control = control_owner.clone();
    let shutdown_observer = AbortOnDropHandle::new(tokio::spawn(async move {
        shutdown.await;
        #[cfg(target_os = "linux")]
        if let Some(owner) = observer_control {
            owner.close();
        }
        let _ = observer_tx.send(true);
    }));
    let observed_shutdown = wait_for_shutdown(shutdown_rx.clone());
    let router = Server::builder().add_service(configure_grpc_service(implementation));
    #[cfg(target_os = "linux")]
    let router = router.add_optional_service(host_control.map(|service|
        codewire_daemon_proto::daemon::v1::host_control_service_server::HostControlServiceServer::new(service)
            .max_decoding_message_size(crate::host_control::HOST_CONTROL_MAX_MESSAGE_BYTES)
            .max_encoding_message_size(crate::host_control::HOST_CONTROL_MAX_MESSAGE_BYTES)));
    #[cfg(target_os="linux")]
    let router=router.add_optional_service(platform_managed.map(|service|
        codewire_daemon_proto::daemon::v1::platform_managed_service_server::PlatformManagedServiceServer::new(service)
            .max_decoding_message_size(codewire_daemon_proto::platform_managed::REQUEST_BYTES)
            .max_encoding_message_size(codewire_daemon_proto::platform_managed::FRAME_BYTES)));
    let serving = router.serve_with_incoming_shutdown(incoming, observed_shutdown);
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
            #[cfg(target_os = "linux")]
            if let Some(owner) = &control_owner { owner.close(); }
            session_owner.cancel_launches();
            let _ = shutdown_tx.send(true);
            bridge_owner.shutdown().await;
            timeout(GRPC_GRACEFUL_SHUTDOWN_TIMEOUT, &mut ingress_serving)
                .await
                .context("stop credential bridge guest ingress timed out")??;
            result.context("serve workspace daemon gRPC transport")
        }
        ingress_result = &mut ingress_serving => {
            #[cfg(target_os = "linux")]
            if let Some(owner) = &control_owner { owner.close(); }
            session_owner.cancel_launches();
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
            #[cfg(target_os = "linux")]
            if let Some(owner) = &control_owner { owner.close(); }
            session_owner.cancel_launches();
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
    #[cfg(target_os = "linux")]
    let control_cleanup = match control_owner {
        Some(owner) => owner.drain().await.map_err(anyhow::Error::from),
        None => Ok(()),
    };
    #[cfg(not(target_os = "linux"))]
    let control_cleanup = Ok::<(), anyhow::Error>(());
    let session_cleanup = session_owner.shutdown().await;
    bridge_owner.shutdown().await;
    shutdown_observer.abort();
    let _ = shutdown_observer.await;
    result
        .and(control_cleanup.context("settle host control requests during shutdown"))
        .and(session_cleanup.context("settle daemon session launches during shutdown"))
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
