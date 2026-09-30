use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context, Result};
use codewire_gateway_proto::DaemonAuthToken;
use codewire_tailnet::netstack::TcpListener as TailnetTcpListener;
use codewire_tls::TlsListener;
use std::net::{IpAddr, SocketAddr};
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio::time::{Duration, Instant, sleep, timeout};

use crate::binding::{
    BindingPollConfig, BindingPollResult, poll_binding_once, poll_binding_until_ready,
};
use crate::config::{CredentialRuntimeConfig, DockerProxyConfig, GatewayConfig};
use crate::credentials::CredentialIngress;
use crate::daemon::{DaemonClientError, DaemonSessionClient};
use crate::docker_proxy::{DockerProxySettings, serve_docker_socket_proxy};
use crate::host_key;
use crate::readiness::{
    CredentialReadiness, ReadinessState, StartupGate, router as readiness_router,
};
use crate::scp::DaemonScpRunner;
use crate::sftp::DaemonSftpRunner;
use crate::ssh::{DaemonBackedSshRunner, GatewaySshHandler, gateway_server_config};
use crate::tailnet;

/// How the gateway retries its workspace daemon. There is deliberately no
/// deadline: a slow workspace start (image pull, volume attach, guest boot)
/// must not turn into gateway exits and CrashLoopBackOff. `/readyz` stays
/// unavailable until the daemon connects, and orchestration's tier ready
/// timeout, which the gateway startup probe matches, bounds a daemon that
/// never comes up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DaemonConnectBackoff {
    initial_delay: Duration,
    max_delay: Duration,
    attempt_timeout: Duration,
}

impl DaemonConnectBackoff {
    /// Doubles from `initial_delay` after each consecutive failure and holds
    /// at `max_delay`.
    fn delay_after(&self, failures: u32) -> Duration {
        let doublings = failures.saturating_sub(1).min(16);
        self.initial_delay
            .saturating_mul(1 << doublings)
            .min(self.max_delay)
    }
}

/// The cap equals the 2-second startup probe period orchestration renders, so
/// retrying delays readiness by at most one probe. One attempt is an in-cluster
/// TCP and HTTP/2 handshake; its timeout only bounds a dropped connection.
const DAEMON_CONNECT_BACKOFF: DaemonConnectBackoff = DaemonConnectBackoff {
    initial_delay: Duration::from_millis(250),
    max_delay: Duration::from_secs(2),
    attempt_timeout: Duration::from_secs(5),
};
/// Failed attempts are logged at debug; this interval bounds the warnings.
const DAEMON_WAIT_WARN_INTERVAL: Duration = Duration::from_secs(30);

pub async fn run_gateway(config: GatewayConfig) -> Result<()> {
    run_gateway_until_shutdown(config, shutdown_signal()).await
}

pub async fn run_gateway_until_shutdown<F>(config: GatewayConfig, shutdown: F) -> Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    let ssh_listener = TcpListener::bind(&config.ssh_listen_addr)
        .await
        .with_context(|| format!("listen SSH {}", config.ssh_listen_addr))?;
    let readyz_listener = TcpListener::bind(&config.readyz_listen_addr)
        .await
        .with_context(|| format!("listen readyz {}", config.readyz_listen_addr))?;
    run_gateway_with_listeners(config, ssh_listener, readyz_listener, shutdown).await
}

async fn run_gateway_with_listeners<F>(
    config: GatewayConfig,
    ssh_listener: TcpListener,
    readyz_listener: TcpListener,
    shutdown: F,
) -> Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut tasks = JoinSet::new();
    let mut ingress = None;
    let mut hosted_relay = None;
    tokio::pin!(shutdown);
    let result = {
        let serve = run_gateway_services(
            config,
            ssh_listener,
            readyz_listener,
            shutdown_rx,
            &mut tasks,
            &mut ingress,
            &mut hosted_relay,
        );
        tokio::pin!(serve);
        tokio::select! {
            biased;
            _ = &mut shutdown => Ok(()),
            result = &mut serve => result,
        }
    };

    // Every return, including failed startup/listener/task, follows this owner
    // path. Cancel credential workers BEFORE waiting for graceful HTTP bodies;
    // otherwise an active streaming response can deadlock shutdown.
    let _ = shutdown_tx.send(true);
    let cleanup = drain_gateway_workers(ingress, &mut hosted_relay, &mut tasks).await;
    cleanup?;
    result
}

async fn drain_gateway_workers(
    ingress: Option<CredentialIngress>,
    hosted_relay: &mut Option<tokio::task::JoinHandle<Result<()>>>,
    tasks: &mut JoinSet<Result<()>>,
) -> Result<()> {
    if let Some(ingress) = ingress {
        ingress.shutdown().await;
    }
    // This owner is deliberately outside the abortable listener set. Its
    // completion includes BOTH outgoing tonic producers and its request pump.
    let relay_result = match hosted_relay.take() {
        Some(relay) => relay
            .await
            .context("hosted credential relay owner failed")
            .and_then(|result| result),
        None => Ok(()),
    };
    // Give listeners their normal graceful exit after credential calls drain.
    // Unresponsive non-credential clients cannot retain the runtime forever.
    if timeout(Duration::from_secs(5), async {
        while tasks.join_next().await.is_some() {}
    })
    .await
    .is_err()
    {
        tasks.shutdown().await;
    }
    relay_result
}

async fn run_gateway_services(
    config: GatewayConfig,
    ssh_listener: TcpListener,
    readyz_listener: TcpListener,
    shutdown_rx: watch::Receiver<bool>,
    tasks: &mut JoinSet<Result<()>>,
    ingress_owner: &mut Option<CredentialIngress>,
    hosted_relay: &mut Option<tokio::task::JoinHandle<Result<()>>>,
) -> Result<()> {
    let credential_readiness = if let Some(credentials) = config.credentials.as_ref() {
        let (ingress, listener) = prepare_credentials(credentials).await?;
        let live = Arc::new(AtomicBool::new(false));
        *ingress_owner = Some(ingress.clone());
        tasks.spawn(serve_credentials_listener(
            listener,
            ingress,
            live.clone(),
            shutdown_rx.clone(),
        ));
        Some(CredentialReadiness::new(
            live,
            credentials.server_tls()?,
            credentials.broker_endpoint()?,
        ))
    } else {
        None
    };

    let ssh_addr = ssh_listener
        .local_addr()
        .context("read SSH listener addr")?;
    let readyz_addr = readyz_listener
        .local_addr()
        .context("read readyz listener addr")?;
    // Serve /readyz before the daemon wait so probes see an explicit 503.
    // The gate opens where the listener used to start, so a ready response
    // still means the daemon connected and startup reached the SSH path.
    let startup = StartupGate::default();
    tasks.spawn(serve_readiness_listener(
        readyz_listener,
        ssh_addr.to_string(),
        startup.clone(),
        credential_readiness,
        shutdown_rx.clone(),
    ));

    tracing::info!(
        shim_addr = %config.shim_addr,
        "rust gateway waiting for workspace daemon; readyz reports not ready until connected"
    );
    let daemon_client = wait_for_daemon(&config, tasks).await?;
    let host_key = host_key::load_or_create(&config.host_key_path)
        .with_context(|| format!("load host key {}", config.host_key_path))?;

    if let Some(credentials) = config.credentials.as_ref()
        && let Some(bridge) = credentials.hosted_bridge()?
    {
        *hosted_relay = Some(tokio::spawn(crate::hosted_bridge::run(
            bridge,
            daemon_client.credential_client(),
            shutdown_rx.clone(),
        )));
    }

    let runner = Arc::new(DaemonBackedSshRunner::new(daemon_client.clone()));
    let sftp = Arc::new(DaemonSftpRunner::new(daemon_client.clone()));
    let scp = Arc::new(DaemonScpRunner::new(daemon_client));
    let mut ssh_config = gateway_server_config();
    ssh_config.keys.push(host_key.key);
    let ssh_config = Arc::new(ssh_config);

    startup.open();
    if let Some(docker_proxy) = config.docker_proxy.clone() {
        tasks.spawn(serve_docker_proxy(docker_proxy, shutdown_rx.clone()));
    }
    if let Some(binding_config) = BindingPollConfig::from_gateway_config(&config) {
        tracing::info!(
            "rust gateway binding mode: will poll with projected identity for tailnet credentials and runtime transport"
        );
        tasks.spawn(serve_tailnet_after_binding(
            config.clone(),
            binding_config,
            ssh_config.clone(),
            runner.clone(),
            sftp.clone(),
            scp.clone(),
            shutdown_rx.clone(),
        ));
    } else if let Some(tailnet_config) = config.tailnet.clone() {
        let stun_server_count = if config.stun_servers.is_empty() {
            usize::from(config.stun.is_some())
        } else {
            config.stun_servers.len()
        };
        if stun_server_count > 0 {
            tracing::info!(
                environment_id = %tailnet_config.environment_id,
                stun_server_count,
                "rust gateway tailnet direct path config present; DERP relay remains fallback path"
            );
        }
        let tailnet_runtime = tailnet::connect_tailnet(&config, &tailnet_config)
            .await
            .context("start gateway tailnet connection")?;
        let tailnet_conn = tailnet_runtime.conn();
        let tailnet_listener = tailnet_conn
            .listen("tcp", ":22")
            .await
            .context("listen on gateway tailnet :22")?;
        tasks.spawn(tailnet::run_coordinator_loop(
            tailnet_runtime,
            tailnet_config.clone(),
            shutdown_rx.clone(),
        ));
        tasks.spawn(serve_tailnet_ssh_listener(
            tailnet_listener,
            ssh_config.clone(),
            runner.clone(),
            sftp.clone(),
            scp.clone(),
            shutdown_rx.clone(),
        ));
    }

    tracing::info!(
        ssh_addr = %ssh_addr,
        readyz_addr = %readyz_addr,
        shim_addr = %config.shim_addr,
        docker_proxy = config.docker_proxy.is_some(),
        tailnet = config.tailnet.is_some(),
        "rust gateway starting"
    );

    let mut accept_shutdown_rx = shutdown_rx.clone();
    loop {
        tokio::select! {
            result = async {
                match hosted_relay.as_mut() {
                    Some(relay) => relay.await,
                    None => std::future::pending().await,
                }
            } => {
                *hosted_relay = None;
                result.context("hosted credential relay owner failed")??;
                if *shutdown_rx.borrow() { return Ok(()); }
                anyhow::bail!("hosted credential relay stopped unexpectedly");
            }
            changed = accept_shutdown_rx.changed() => {
                let _ = changed;
                return Ok(());
            }
            joined = tasks.join_next(), if !tasks.is_empty() => {
                match joined {
                    Some(Ok(Ok(()))) => {}
                    Some(Ok(Err(err))) => return Err(err),
                    Some(Err(err)) => return Err(err).context("gateway task join"),
                    None => {}
                }
            }
            accepted = ssh_listener.accept() => {
                let (stream, peer_addr) = accepted.context("accept SSH connection")?;
                let config = ssh_config.clone();
                let runner = runner.clone();
                let sftp = sftp.clone();
                let scp = scp.clone();
                tokio::spawn(async move {
                    let handler =
                        GatewaySshHandler::with_file_protocols(runner, Some(sftp), Some(scp));
                    match russh::server::run_stream(config, stream, handler).await {
                        Ok(session) => {
                            let _ = session.await;
                        }
                        Err(err) => {
                            tracing::warn!(%peer_addr, error = %err, "rust gateway SSH handshake failed");
                        }
                    }
                });
            }
        }
    }
}

async fn prepare_credentials(
    config: &CredentialRuntimeConfig,
) -> Result<(CredentialIngress, TlsListener)> {
    let files = config.server_tls()?;
    let broker = config.broker_endpoint()?;
    timeout(Duration::from_secs(5), async {
        files
            .validate()
            .await
            .map_err(|_| anyhow::anyhow!("credential server TLS unavailable"))?;
        broker
            .validate()
            .await
            .map_err(|_| anyhow::anyhow!("credential broker trust unavailable"))?;
        Ok::<_, anyhow::Error>(())
    })
    .await
    .map_err(|_| anyhow::anyhow!("credential TLS startup timed out"))??;
    let listener = TcpListener::bind(config.listen_addr)
        .await
        .map_err(|_| anyhow::anyhow!("credential HTTPS listener unavailable"))?;
    let listener = TlsListener::new(listener, files)
        .map_err(|_| anyhow::anyhow!("credential HTTPS configuration invalid"))?;
    Ok((CredentialIngress::new(config.ingress()?), listener))
}

struct CredentialListenerReadiness(Arc<AtomicBool>);

impl Drop for CredentialListenerReadiness {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

async fn serve_credentials_listener(
    listener: TlsListener,
    ingress: CredentialIngress,
    live: Arc<AtomicBool>,
    shutdown_rx: watch::Receiver<bool>,
) -> Result<()> {
    let _readiness = CredentialListenerReadiness(live.clone());
    live.store(true, Ordering::Release);
    let app =
        axum::Router::new().fallback(move |request: axum::http::Request<axum::body::Body>| {
            let ingress = ingress.clone();
            async move { ingress.respond(request).await }
        });
    axum::serve(listener, app)
        .with_graceful_shutdown(wait_for_shutdown(shutdown_rx.clone()))
        .await
        .map_err(|_| anyhow::anyhow!("credential HTTPS listener failed"))?;
    if !*shutdown_rx.borrow() {
        anyhow::bail!("credential HTTPS listener stopped");
    }
    Ok(())
}

async fn serve_tailnet_after_binding(
    config: GatewayConfig,
    binding_config: BindingPollConfig,
    ssh_config: Arc<russh::server::Config>,
    runner: Arc<DaemonBackedSshRunner<DaemonSessionClient>>,
    sftp: Arc<DaemonSftpRunner<DaemonSessionClient>>,
    scp: Arc<DaemonScpRunner<DaemonSessionClient>>,
    shutdown_rx: watch::Receiver<bool>,
) -> Result<()> {
    let binding = match poll_binding_until_ready(binding_config.clone(), shutdown_rx.clone()).await
    {
        Ok(Some(binding)) => binding,
        Ok(None) => return Ok(()),
        Err(err) => {
            if !*shutdown_rx.borrow() {
                tracing::error!(error = %err, "rust gateway binding poll failed");
            }
            return Ok(());
        }
    };
    let tailnet_config = binding.tailnet.clone();
    let mut config = config;
    if let Some(runtime_transport) = binding.runtime_transport.as_ref() {
        runtime_transport.apply_to_gateway_config(&mut config);
        tracing::info!(
            environment_id = %tailnet_config.environment_id,
            runtime_region = %runtime_transport.runtime_region,
            transport_zone = %runtime_transport.transport_zone,
            peer_relay_endpoints = ?runtime_transport.peer_relay.as_ref().map(|relay| &relay.public_endpoints),
            "rust gateway applied runtime transport binding"
        );
    }
    tracing::info!(
        environment_id = %tailnet_config.environment_id,
        "rust gateway binding received"
    );

    let tailnet_runtime = match tailnet::connect_tailnet(&config, &tailnet_config).await {
        Ok(runtime) => runtime,
        Err(err) => {
            if !*shutdown_rx.borrow() {
                let error_chain = format!("{err:#}");
                tracing::error!(error = %error_chain, "rust gateway bound tailnet failed");
            }
            return Ok(());
        }
    };
    let tailnet_conn = tailnet_runtime.conn();
    let tailnet_listener = match tailnet_conn.listen("tcp", ":22").await {
        Ok(listener) => listener,
        Err(err) => {
            if !*shutdown_rx.borrow() {
                tracing::error!(error = %err, "rust gateway bound tailnet listen failed");
            }
            return Ok(());
        }
    };
    tokio::spawn(serve_tailnet_app_port_forward_manager(
        tailnet_conn.clone(),
        binding_config,
        binding.clone(),
        shutdown_rx.clone(),
    ));
    tokio::spawn(tailnet::run_coordinator_loop(
        tailnet_runtime,
        tailnet_config,
        shutdown_rx.clone(),
    ));
    if let Err(err) =
        serve_tailnet_ssh_listener(tailnet_listener, ssh_config, runner, sftp, scp, shutdown_rx)
            .await
    {
        tracing::error!(error = %err, "rust gateway bound tailnet SSH failed");
    }
    Ok(())
}

async fn serve_tailnet_app_port_forward_manager(
    conn: Arc<codewire_tailnet::conn::Conn>,
    binding_config: BindingPollConfig,
    initial: BindingPollResult,
    shutdown_rx: watch::Receiver<bool>,
) -> Result<()> {
    let client = binding_config
        .client()
        .context("build binding Connect client")?;
    let mut shutdown_rx = shutdown_rx;
    let mut bound_ports = HashSet::new();
    let mut next = Some(initial);

    loop {
        if let Some(binding) = next.take()
            && let Err(err) = bind_new_tailnet_app_port_forwards(
                &conn,
                &binding,
                &mut bound_ports,
                shutdown_rx.clone(),
            )
            .await
        {
            tracing::warn!(error = %err, "rust gateway tailnet app-port binding update failed");
        }

        tokio::select! {
            changed = shutdown_rx.changed() => {
                let _ = changed;
                return Ok(());
            }
            _ = sleep(Duration::from_secs(2)) => {}
        }

        match poll_binding_once(&client, &binding_config).await {
            Ok(Some(binding)) => next = Some(binding),
            Ok(None) => {}
            Err(err) => {
                tracing::debug!(error = %err, "rust gateway app-port binding poll failed");
            }
        }
    }
}

async fn bind_new_tailnet_app_port_forwards(
    conn: &Arc<codewire_tailnet::conn::Conn>,
    binding: &BindingPollResult,
    bound_ports: &mut HashSet<u16>,
    shutdown_rx: watch::Receiver<bool>,
) -> Result<()> {
    let Some(workspace_pod_ip) = binding.workspace_pod_ip.as_deref() else {
        return Ok(());
    };
    let workspace_ip = workspace_pod_ip
        .parse::<IpAddr>()
        .with_context(|| format!("parse workspace pod IP {workspace_pod_ip:?}"))?;
    let mut unique_ports = binding.app_ports.clone();
    unique_ports.sort_unstable();
    unique_ports.dedup();
    unique_ports.retain(|port| *port != 0 && *port != 22);

    for port in unique_ports {
        if bound_ports.contains(&port) {
            continue;
        }
        let listener = conn
            .listen("tcp", &format!(":{port}"))
            .await
            .with_context(|| format!("listen on gateway tailnet :{port}"))?;
        let target = SocketAddr::new(workspace_ip, port);
        tracing::info!(
            port,
            workspace_pod_ip = %workspace_ip,
            "rust gateway tailnet app-port forward enabled"
        );
        tokio::spawn(serve_tailnet_tcp_proxy_listener(
            listener,
            target,
            shutdown_rx.clone(),
        ));
        bound_ports.insert(port);
    }
    Ok(())
}

async fn serve_tailnet_tcp_proxy_listener(
    mut listener: TailnetTcpListener,
    target: SocketAddr,
    shutdown_rx: watch::Receiver<bool>,
) -> Result<()> {
    let mut shutdown_rx = shutdown_rx;
    loop {
        tokio::select! {
            changed = shutdown_rx.changed() => {
                let _ = changed;
                return Ok(());
            }
            accepted = listener.accept() => {
                let Some(mut inbound) = accepted else {
                    return Ok(());
                };
                tokio::spawn(async move {
                    match TcpStream::connect(target).await {
                        Ok(mut outbound) => {
                            if let Err(err) = copy_bidirectional(&mut inbound, &mut outbound).await {
                                tracing::debug!(port = target.port(), error = %err, "tailnet app-port proxy closed with error");
                            }
                        }
                        Err(err) => {
                            tracing::debug!(port = target.port(), error = %err, "tailnet app-port target connect failed");
                        }
                    }
                });
            }
        }
    }
}

/// Wait for the daemon while still failing on any listener started before it
/// (credential HTTPS, `/readyz`). The owner cancels this future on shutdown.
async fn wait_for_daemon(
    config: &GatewayConfig,
    tasks: &mut JoinSet<Result<()>>,
) -> Result<DaemonSessionClient> {
    let connect = connect_daemon_with_retry(
        &config.shim_addr,
        config.daemon_auth_token.clone(),
        DAEMON_CONNECT_BACKOFF,
    );
    tokio::pin!(connect);
    loop {
        tokio::select! {
            client = &mut connect => return client,
            joined = tasks.join_next(), if !tasks.is_empty() => match joined {
                Some(Ok(Ok(()))) | None => {}
                Some(Ok(Err(err))) => return Err(err),
                Some(Err(err)) => return Err(err).context("gateway task join"),
            },
        }
    }
}

/// Retry until connected. Only a connection failure or an attempt timeout is
/// retried; an invalid endpoint or client configuration cannot recover.
async fn connect_daemon_with_retry(
    shim_addr: &str,
    auth_token: DaemonAuthToken,
    backoff: DaemonConnectBackoff,
) -> Result<DaemonSessionClient> {
    let started = Instant::now();
    let mut last_warning: Option<Instant> = None;
    let mut attempts = 0u32;

    loop {
        attempts = attempts.saturating_add(1);
        let error = match timeout(
            backoff.attempt_timeout,
            DaemonSessionClient::connect_shim(shim_addr, auth_token.clone()),
        )
        .await
        {
            Ok(Ok(client)) => {
                if attempts > 1 {
                    tracing::info!(
                        shim_addr,
                        attempts,
                        waited_ms = elapsed_ms(started),
                        "connected to workspace daemon after retry"
                    );
                }
                return Ok(client);
            }
            Ok(Err(err @ DaemonClientError::Connect { .. })) => {
                format!("{:#}", anyhow::Error::new(err))
            }
            Ok(Err(err @ DaemonClientError::InvalidEndpoint { .. })) => {
                return Err(err)
                    .with_context(|| format!("connect daemon shim {shim_addr}: invalid endpoint"));
            }
            Ok(Err(err)) => {
                return Err(err).with_context(|| format!("connect daemon shim {shim_addr}"));
            }
            Err(_) => format!(
                "connect attempt exceeded {} ms",
                backoff.attempt_timeout.as_millis()
            ),
        };
        let next_retry = backoff.delay_after(attempts);
        let now = Instant::now();
        if last_warning.is_none_or(|warned| now.duration_since(warned) >= DAEMON_WAIT_WARN_INTERVAL)
        {
            last_warning = Some(now);
            tracing::warn!(
                shim_addr,
                attempts,
                waited_ms = elapsed_ms(started),
                next_retry_ms = next_retry.as_millis() as u64,
                error = %error,
                "workspace daemon unavailable; gateway stays not ready and keeps retrying"
            );
        } else {
            tracing::debug!(
                shim_addr,
                attempts,
                waited_ms = elapsed_ms(started),
                next_retry_ms = next_retry.as_millis() as u64,
                error = %error,
                "workspace daemon unavailable; retrying"
            );
        }
        sleep(next_retry).await;
    }
}

fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

async fn serve_tailnet_ssh_listener(
    mut listener: TailnetTcpListener,
    ssh_config: Arc<russh::server::Config>,
    runner: Arc<DaemonBackedSshRunner<DaemonSessionClient>>,
    sftp: Arc<DaemonSftpRunner<DaemonSessionClient>>,
    scp: Arc<DaemonScpRunner<DaemonSessionClient>>,
    shutdown_rx: watch::Receiver<bool>,
) -> Result<()> {
    let mut shutdown_rx = shutdown_rx;
    loop {
        tokio::select! {
            changed = shutdown_rx.changed() => {
                let _ = changed;
                return Ok(());
            }
            accepted = listener.accept() => {
                let Some(stream) = accepted else {
                    return Ok(());
                };
                let config = ssh_config.clone();
                let runner = runner.clone();
                let sftp = sftp.clone();
                let scp = scp.clone();
                tokio::spawn(async move {
                    let handler =
                        GatewaySshHandler::with_file_protocols(runner, Some(sftp), Some(scp));
                    match russh::server::run_stream(config, stream, handler).await {
                        Ok(session) => {
                            let _ = session.await;
                        }
                        Err(err) => {
                            tracing::warn!(error = %err, "rust gateway tailnet SSH handshake failed");
                        }
                    }
                });
            }
        }
    }
}

async fn serve_readiness_listener(
    listener: TcpListener,
    ssh_listen_addr: String,
    startup: StartupGate,
    credentials: Option<CredentialReadiness>,
    shutdown_rx: watch::Receiver<bool>,
) -> Result<()> {
    let app = readiness_router(
        ReadinessState::new(ssh_listen_addr)
            .with_startup_gate(startup)
            .with_credentials(credentials),
    );
    axum::serve(listener, app)
        .with_graceful_shutdown(wait_for_shutdown(shutdown_rx))
        .await
        .context("serve readyz")?;
    Ok(())
}

async fn serve_docker_proxy(
    config: DockerProxyConfig,
    shutdown_rx: watch::Receiver<bool>,
) -> Result<()> {
    let settings = DockerProxySettings::new(config.listen_sock, config.upstream_sock)
        .context("configure Docker proxy")?;
    let _stats = serve_docker_socket_proxy(settings, wait_for_shutdown(shutdown_rx))
        .await
        .context("serve Docker proxy")?;
    Ok(())
}

async fn wait_for_shutdown(mut shutdown_rx: watch::Receiver<bool>) {
    loop {
        if *shutdown_rx.borrow() {
            return;
        }
        if shutdown_rx.changed().await.is_err() {
            return;
        }
    }
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
}

#[cfg(test)]
mod tests {
    use super::*;
    mod credentials;
    use codewire_gateway_proto::codewire::bridge::v1 as bridge_v1;
    use codewire_gateway_proto::daemon::v1::daemon_service_server::{
        DaemonService, DaemonServiceServer,
    };
    use codewire_gateway_proto::{DaemonAuthToken, daemon::v1};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;
    use tokio::time::{sleep, timeout};
    use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};
    use tonic::transport::Server;
    use tonic::{Request, Response, Status};
    use uuid::Uuid;

    #[tokio::test]
    async fn shutdown_awaits_dedicated_relay_owner_and_preserves_drain_failure() {
        let (release, released) = oneshot::channel();
        let relay = tokio::spawn(async move {
            released.await.unwrap();
            Err(anyhow::anyhow!(
                "hosted credential bridge transport did not drain"
            ))
        });
        let cleanup = tokio::spawn(async move {
            let mut relay = Some(relay);
            let mut listeners = JoinSet::new();
            let result = drain_gateway_workers(None, &mut relay, &mut listeners).await;
            assert!(relay.is_none());
            result
        });
        tokio::task::yield_now().await;
        assert!(!cleanup.is_finished());
        release.send(()).unwrap();
        let result = timeout(Duration::from_secs(1), cleanup)
            .await
            .unwrap()
            .unwrap();
        assert!(result.unwrap_err().to_string().contains("did not drain"));
    }

    #[tokio::test]
    async fn shutdown_does_not_convert_relay_join_failure_to_success() {
        let mut relay = Some(tokio::spawn(async {
            panic!("synthetic relay owner failure");
            #[allow(unreachable_code)]
            Ok(())
        }));
        assert!(
            drain_gateway_workers(None, &mut relay, &mut JoinSet::new())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn gateway_runtime_serves_ssh_and_readyz_until_shutdown() {
        let daemon_addr = spawn_minimal_daemon().await;
        let ssh_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ssh_addr = ssh_listener.local_addr().unwrap().to_string();
        let readyz_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let readyz_addr = readyz_listener.local_addr().unwrap().to_string();
        let host_key_path = std::env::temp_dir()
            .join(format!("codewire-gateway-runtime-{}", Uuid::new_v4()))
            .join("host_ed25519");
        let config = GatewayConfig {
            shim_addr: daemon_addr.to_string(),
            ssh_listen_addr: ssh_addr.clone(),
            readyz_listen_addr: readyz_addr.clone(),
            host_key_path: host_key_path.display().to_string(),
            listener_self_check_interval: None,
            api_url: None,
            binding_url: None,
            coordinator_url: None,
            daemon_auth_token: DaemonAuthToken::new("gateway-runtime-test-token").unwrap(),
            derp_url: None,
            stun: None,
            stun_servers: Vec::new(),
            tailnet_udp_listen_addr: None,
            tailnet_direct_udp_advertise_endpoints: Vec::new(),
            udp_relay_allocator_url: None,
            udp_relay_allocator_token: None,
            udp_relay_bind_addrs: Vec::new(),
            tailnet: None,
            docker_proxy: None,
            debug_tailnet: false,
            credentials: None,
        };
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let task = tokio::spawn(run_gateway_with_listeners(
            config,
            ssh_listener,
            readyz_listener,
            async move {
                let _ = shutdown_rx.await;
            },
        ));

        wait_for_tcp(&ssh_addr).await;
        wait_for_readyz_ok(&readyz_addr).await;

        let _ = shutdown_tx.send(());
        timeout(Duration::from_secs(3), task)
            .await
            .expect("gateway runtime shutdown")
            .expect("gateway runtime task")
            .expect("gateway runtime result");
    }

    #[tokio::test]
    async fn gateway_stays_unready_without_exiting_until_the_daemon_listens() {
        let daemon_addr = reserve_local_addr().await;

        let ssh_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ssh_addr = ssh_listener.local_addr().unwrap().to_string();
        let readyz_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let readyz_addr = readyz_listener.local_addr().unwrap().to_string();
        let host_key_path = std::env::temp_dir()
            .join(format!(
                "codewire-gateway-runtime-delayed-{}",
                Uuid::new_v4()
            ))
            .join("host_ed25519");
        let config = GatewayConfig {
            shim_addr: daemon_addr.clone(),
            ssh_listen_addr: ssh_addr.clone(),
            readyz_listen_addr: readyz_addr.clone(),
            host_key_path: host_key_path.display().to_string(),
            listener_self_check_interval: None,
            api_url: None,
            binding_url: None,
            coordinator_url: None,
            daemon_auth_token: DaemonAuthToken::new("gateway-runtime-test-token").unwrap(),
            derp_url: None,
            stun: None,
            stun_servers: Vec::new(),
            tailnet_udp_listen_addr: None,
            tailnet_direct_udp_advertise_endpoints: Vec::new(),
            udp_relay_allocator_url: None,
            udp_relay_allocator_token: None,
            udp_relay_bind_addrs: Vec::new(),
            tailnet: None,
            docker_proxy: None,
            debug_tailnet: false,
            credentials: None,
        };
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let task = tokio::spawn(run_gateway_with_listeners(
            config,
            ssh_listener,
            readyz_listener,
            async move {
                let _ = shutdown_rx.await;
            },
        ));

        // The SSH listener accepts TCP from the start, yet /readyz answers an
        // explicit 503 while the daemon is unavailable and the gateway keeps
        // running instead of exiting.
        wait_for_tcp(&ssh_addr).await;
        let unavailable_until = Instant::now() + Duration::from_millis(1_500);
        while Instant::now() < unavailable_until {
            assert_eq!(readyz_status(&readyz_addr).await, 503);
            assert!(!task.is_finished(), "gateway exited while waiting");
            sleep(Duration::from_millis(100)).await;
        }

        spawn_minimal_daemon_at(&daemon_addr).await;
        wait_for_readyz_ok(&readyz_addr).await;

        let _ = shutdown_tx.send(());
        timeout(Duration::from_secs(3), task)
            .await
            .expect("gateway runtime shutdown")
            .expect("gateway runtime task")
            .expect("gateway runtime result");
    }

    #[test]
    fn daemon_connect_backoff_doubles_to_its_cap() {
        let delays: Vec<_> = (1..=6)
            .map(|failures| DAEMON_CONNECT_BACKOFF.delay_after(failures))
            .collect();
        assert_eq!(
            delays,
            [250, 500, 1_000, 2_000, 2_000, 2_000].map(Duration::from_millis)
        );
        assert_eq!(
            DAEMON_CONNECT_BACKOFF.delay_after(u32::MAX),
            Duration::from_secs(2)
        );
    }

    #[tokio::test]
    async fn daemon_connect_retries_past_the_retired_deadline_until_connected() {
        // The retired default deadline failed this wait after 60 seconds, and
        // its old test after 1. Keep a scaled-down backoff failing well past
        // that, then let the daemon listen.
        let daemon_addr = reserve_local_addr().await;
        let delayed_daemon_addr = daemon_addr.clone();
        tokio::spawn(async move {
            sleep(Duration::from_millis(1_200)).await;
            spawn_minimal_daemon_at(&delayed_daemon_addr).await;
        });
        let backoff = DaemonConnectBackoff {
            initial_delay: Duration::from_millis(5),
            max_delay: Duration::from_millis(20),
            attempt_timeout: Duration::from_secs(1),
        };
        timeout(
            Duration::from_secs(5),
            connect_daemon_with_retry(
                &daemon_addr,
                DaemonAuthToken::new("gateway-runtime-retry-test-token").unwrap(),
                backoff,
            ),
        )
        .await
        .expect("daemon connection did not follow the listening daemon")
        .expect("daemon retry gave up");
    }

    #[tokio::test]
    async fn invalid_daemon_endpoint_fails_without_retrying() {
        let result = timeout(
            Duration::from_secs(3),
            connect_daemon_with_retry(
                "http://[",
                DaemonAuthToken::new("gateway-runtime-invalid-endpoint-test-token").unwrap(),
                DAEMON_CONNECT_BACKOFF,
            ),
        )
        .await
        .expect("invalid daemon endpoint entered the retry loop");
        let err = match result {
            Ok(_) => panic!("invalid daemon endpoint unexpectedly connected"),
            Err(err) => err,
        };
        assert!(
            err.to_string().contains("invalid endpoint"),
            "unexpected invalid-endpoint error: {err:#}"
        );
    }

    async fn wait_for_tcp(addr: &str) {
        timeout(Duration::from_secs(3), async {
            loop {
                if tokio::net::TcpStream::connect(addr).await.is_ok() {
                    return;
                }
                sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("TCP listener ready");
    }

    async fn readyz_response(addr: &str) -> String {
        let mut stream = timeout(Duration::from_secs(3), tokio::net::TcpStream::connect(addr))
            .await
            .expect("readyz connect")
            .expect("readyz TCP");
        stream
            .write_all(b"GET /readyz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        timeout(Duration::from_secs(3), stream.read_to_end(&mut response))
            .await
            .expect("readyz answered")
            .unwrap();
        String::from_utf8_lossy(&response).into_owned()
    }

    async fn readyz_status(addr: &str) -> u16 {
        let response = readyz_response(addr).await;
        response
            .strip_prefix("HTTP/1.1 ")
            .and_then(|rest| rest.get(..3))
            .and_then(|status| status.parse().ok())
            .unwrap_or_else(|| panic!("unexpected readyz response: {response}"))
    }

    /// Readiness is served before the daemon connects, so wait for it.
    async fn wait_for_readyz_ok(addr: &str) {
        let response = timeout(Duration::from_secs(5), async {
            loop {
                let response = readyz_response(addr).await;
                if response.starts_with("HTTP/1.1 200 OK") {
                    return response;
                }
                sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("readyz became ready");
        assert!(response.ends_with("ok\n"));
    }

    async fn spawn_minimal_daemon() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        spawn_minimal_daemon_on(listener);
        addr.to_string()
    }

    async fn reserve_local_addr() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        drop(listener);
        addr
    }

    async fn spawn_minimal_daemon_at(addr: &str) {
        let listener = TcpListener::bind(addr).await.unwrap();
        spawn_minimal_daemon_on(listener);
    }

    fn spawn_minimal_daemon_on(listener: TcpListener) {
        let incoming = TcpListenerStream::new(listener);
        tokio::spawn(async move {
            Server::builder()
                .add_service(DaemonServiceServer::new(MinimalDaemon))
                .serve_with_incoming(incoming)
                .await
                .unwrap();
        });
    }

    #[derive(Clone)]
    struct MinimalDaemon;

    #[tonic::async_trait]
    impl DaemonService for MinimalDaemon {
        async fn poweroff_guest(
            &self,
            _request: Request<v1::PoweroffGuestRequest>,
        ) -> Result<Response<v1::PoweroffGuestResponse>, Status> {
            Err(Status::unimplemented("fixture unused lifecycle RPC"))
        }

        type ExecSessionStream = ReceiverStream<Result<v1::ExecMessage, Status>>;
        type PtySessionStream = ReceiverStream<Result<v1::PtyMessage, Status>>;
        type AttachSessionStream = ReceiverStream<Result<v1::SessionAttachMessage, Status>>;
        type CredentialBridgeStream =
            ReceiverStream<Result<bridge_v1::CredentialBridgeGuestMessage, Status>>;

        async fn get_capabilities(
            &self,
            _request: Request<v1::GetCapabilitiesRequest>,
        ) -> Result<Response<v1::GetCapabilitiesResponse>, Status> {
            Err(Status::unimplemented("get capabilities"))
        }

        async fn get_health(
            &self,
            _request: Request<v1::GetHealthRequest>,
        ) -> Result<Response<v1::GetHealthResponse>, Status> {
            Err(Status::unimplemented("get health"))
        }

        async fn credential_bridge(
            &self,
            _request: Request<tonic::Streaming<bridge_v1::CredentialBridgeHostMessage>>,
        ) -> Result<Response<Self::CredentialBridgeStream>, Status> {
            Err(Status::unimplemented("credential bridge"))
        }

        async fn launch_session(
            &self,
            _request: Request<v1::LaunchSessionRequest>,
        ) -> Result<Response<v1::LaunchSessionResponse>, Status> {
            Err(Status::unimplemented("launch session"))
        }

        async fn list_sessions(
            &self,
            _request: Request<v1::ListSessionsRequest>,
        ) -> Result<Response<v1::ListSessionsResponse>, Status> {
            Err(Status::unimplemented("list sessions"))
        }

        async fn get_session(
            &self,
            _request: Request<v1::GetSessionRequest>,
        ) -> Result<Response<v1::GetSessionResponse>, Status> {
            Err(Status::unimplemented("get session"))
        }

        async fn stop_session(
            &self,
            _request: Request<v1::StopSessionRequest>,
        ) -> Result<Response<v1::StopSessionResponse>, Status> {
            Err(Status::unimplemented("stop session"))
        }

        async fn restart_session(
            &self,
            _request: Request<v1::RestartSessionRequest>,
        ) -> Result<Response<v1::RestartSessionResponse>, Status> {
            Err(Status::unimplemented("restart session"))
        }

        async fn send_session_input(
            &self,
            _request: Request<v1::SendSessionInputRequest>,
        ) -> Result<Response<v1::SendSessionInputResponse>, Status> {
            Err(Status::unimplemented(
                "fixture unused acknowledged input RPC",
            ))
        }

        async fn read_session_output(
            &self,
            _request: Request<v1::ReadSessionOutputRequest>,
        ) -> Result<Response<v1::ReadSessionOutputResponse>, Status> {
            Err(Status::unimplemented("read session output"))
        }

        async fn attach_session(
            &self,
            _request: Request<tonic::Streaming<v1::SessionAttachMessage>>,
        ) -> Result<Response<Self::AttachSessionStream>, Status> {
            Err(Status::unimplemented("attach session"))
        }

        async fn exec_session(
            &self,
            _request: Request<tonic::Streaming<v1::ExecMessage>>,
        ) -> Result<Response<Self::ExecSessionStream>, Status> {
            Err(Status::unimplemented("exec session"))
        }

        async fn pty_session(
            &self,
            _request: Request<tonic::Streaming<v1::PtyMessage>>,
        ) -> Result<Response<Self::PtySessionStream>, Status> {
            Err(Status::unimplemented("pty session"))
        }

        async fn list(
            &self,
            _request: Request<v1::ListRequest>,
        ) -> Result<Response<v1::ListResponse>, Status> {
            Err(Status::unimplemented("list"))
        }

        async fn stat(
            &self,
            _request: Request<v1::StatRequest>,
        ) -> Result<Response<v1::StatResponse>, Status> {
            Err(Status::unimplemented("stat"))
        }

        async fn open_file(
            &self,
            _request: Request<v1::OpenFileRequest>,
        ) -> Result<Response<v1::OperationStatus>, Status> {
            Err(Status::unimplemented("open file"))
        }

        async fn read(
            &self,
            _request: Request<v1::ReadRequest>,
        ) -> Result<Response<v1::ReadResponse>, Status> {
            Err(Status::unimplemented("read"))
        }

        async fn write(
            &self,
            _request: Request<v1::WriteRequest>,
        ) -> Result<Response<v1::WriteResponse>, Status> {
            Err(Status::unimplemented("write"))
        }

        async fn mkdir(
            &self,
            _request: Request<v1::MkdirRequest>,
        ) -> Result<Response<v1::OperationStatus>, Status> {
            Err(Status::unimplemented("mkdir"))
        }

        async fn remove(
            &self,
            _request: Request<v1::RemoveRequest>,
        ) -> Result<Response<v1::OperationStatus>, Status> {
            Err(Status::unimplemented("remove"))
        }

        async fn rename(
            &self,
            _request: Request<v1::RenameRequest>,
        ) -> Result<Response<v1::OperationStatus>, Status> {
            Err(Status::unimplemented("rename"))
        }

        async fn set_stat(
            &self,
            _request: Request<v1::SetStatRequest>,
        ) -> Result<Response<v1::OperationStatus>, Status> {
            Err(Status::unimplemented("set stat"))
        }

        async fn readlink(
            &self,
            _request: Request<v1::ReadlinkRequest>,
        ) -> Result<Response<v1::ReadlinkResponse>, Status> {
            Err(Status::unimplemented("readlink"))
        }
    }
}
