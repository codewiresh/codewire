use std::collections::HashSet;
use std::sync::Arc;

use anyhow::{Context, Result};
use codewire_tailnet::netstack::TcpListener as TailnetTcpListener;
use std::net::{IpAddr, SocketAddr};
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio::time::{Duration, Instant, sleep};

use crate::binding::{
    BindingPollConfig, BindingPollResult, poll_binding_once, poll_binding_until_ready,
};
use crate::config::{DockerProxyConfig, GatewayConfig};
use crate::daemon::DaemonSessionClient;
use crate::docker_proxy::{DockerProxySettings, serve_docker_socket_proxy};
use crate::host_key;
use crate::readiness::{ReadinessState, router as readiness_router};
use crate::scp::DaemonScpRunner;
use crate::sftp::DaemonSftpRunner;
use crate::ssh::{DaemonBackedSshRunner, GatewaySshHandler, gateway_server_config};
use crate::tailnet;

const DAEMON_CONNECT_TIMEOUT: Duration = Duration::from_secs(60);
const DAEMON_CONNECT_RETRY_INTERVAL: Duration = Duration::from_millis(250);

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
    tokio::spawn(async move {
        shutdown.await;
        let _ = shutdown_tx.send(true);
    });

    let daemon_client =
        connect_daemon_with_retry(&config.shim_addr, config.daemon_auth_token.clone()).await?;
    let host_key = host_key::load_or_create(&config.host_key_path)
        .with_context(|| format!("load host key {}", config.host_key_path))?;

    let ssh_addr = ssh_listener
        .local_addr()
        .context("read SSH listener addr")?;
    let readyz_addr = readyz_listener
        .local_addr()
        .context("read readyz listener addr")?;

    let runner = Arc::new(DaemonBackedSshRunner::new(daemon_client.clone()));
    let sftp = Arc::new(DaemonSftpRunner::new(daemon_client.clone()));
    let scp = Arc::new(DaemonScpRunner::new(daemon_client));
    let mut ssh_config = gateway_server_config();
    ssh_config.keys.push(host_key.key);
    let ssh_config = Arc::new(ssh_config);

    let mut tasks = JoinSet::new();
    tasks.spawn(serve_readiness_listener(
        readyz_listener,
        ssh_addr.to_string(),
        shutdown_rx.clone(),
    ));
    if let Some(docker_proxy) = config.docker_proxy.clone() {
        tasks.spawn(serve_docker_proxy(docker_proxy, shutdown_rx.clone()));
    }
    if let Some(binding_config) = BindingPollConfig::from_gateway_config(&config) {
        tracing::info!(
            pod = %binding_config.pod_name,
            namespace = %binding_config.pod_namespace,
            "rust gateway binding mode: will poll for tailnet credentials and runtime transport"
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

async fn connect_daemon_with_retry(
    shim_addr: &str,
    auth_token: Option<String>,
) -> Result<DaemonSessionClient> {
    let deadline = Instant::now() + DAEMON_CONNECT_TIMEOUT;
    let mut attempts = 0u32;

    loop {
        match DaemonSessionClient::connect_shim_with_auth(shim_addr, auth_token.clone()).await {
            Ok(client) => {
                if attempts > 0 {
                    tracing::info!(shim_addr, attempts, "connected to daemon shim after retry");
                }
                return Ok(client);
            }
            Err(err) => {
                attempts += 1;
                if Instant::now() >= deadline {
                    return Err(err).with_context(|| {
                        format!("connect daemon shim {shim_addr} after {attempts} attempts")
                    });
                }
                if attempts == 1 || attempts.is_multiple_of(20) {
                    tracing::warn!(
                        shim_addr,
                        attempts,
                        error = %err,
                        "daemon shim unavailable; retrying"
                    );
                }
                sleep(DAEMON_CONNECT_RETRY_INTERVAL).await;
            }
        }
    }
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
    shutdown_rx: watch::Receiver<bool>,
) -> Result<()> {
    let app = readiness_router(ReadinessState::new(ssh_listen_addr));
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
    use codewire_gateway_proto::daemon::v1;
    use codewire_gateway_proto::daemon::v1::daemon_service_server::{
        DaemonService, DaemonServiceServer,
    };
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
    async fn gateway_runtime_serves_ssh_and_readyz_until_shutdown() {
        let daemon_addr = spawn_minimal_daemon().await;
        let ssh_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ssh_addr = ssh_listener.local_addr().unwrap().to_string();
        let readyz_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let readyz_addr = readyz_listener.local_addr().unwrap().to_string();
        let host_key_path = std::env::temp_dir()
            .join(format!("codewire-gateway-runtime-{}", Uuid::new_v4()))
            .join("sidecar_host_ed25519");
        let config = GatewayConfig {
            shim_addr: daemon_addr.to_string(),
            ssh_listen_addr: ssh_addr.clone(),
            readyz_listen_addr: readyz_addr.clone(),
            host_key_path: host_key_path.display().to_string(),
            listener_self_check_interval: None,
            api_url: None,
            binding_url: None,
            coordinator_url: None,
            daemon_auth_token: None,
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
        assert_readyz_ok(&readyz_addr).await;

        let _ = shutdown_tx.send(());
        timeout(Duration::from_secs(3), task)
            .await
            .expect("gateway runtime shutdown")
            .expect("gateway runtime task")
            .expect("gateway runtime result");
    }

    #[tokio::test]
    async fn gateway_runtime_waits_for_delayed_daemon_shim() {
        let daemon_addr = reserve_local_addr().await;
        let delayed_daemon_addr = daemon_addr.clone();
        tokio::spawn(async move {
            sleep(Duration::from_millis(200)).await;
            spawn_minimal_daemon_at(&delayed_daemon_addr).await;
        });

        let ssh_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ssh_addr = ssh_listener.local_addr().unwrap().to_string();
        let readyz_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let readyz_addr = readyz_listener.local_addr().unwrap().to_string();
        let host_key_path = std::env::temp_dir()
            .join(format!(
                "codewire-gateway-runtime-delayed-{}",
                Uuid::new_v4()
            ))
            .join("sidecar_host_ed25519");
        let config = GatewayConfig {
            shim_addr: daemon_addr,
            ssh_listen_addr: ssh_addr.clone(),
            readyz_listen_addr: readyz_addr.clone(),
            host_key_path: host_key_path.display().to_string(),
            listener_self_check_interval: None,
            api_url: None,
            binding_url: None,
            coordinator_url: None,
            daemon_auth_token: None,
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
        assert_readyz_ok(&readyz_addr).await;

        let _ = shutdown_tx.send(());
        timeout(Duration::from_secs(3), task)
            .await
            .expect("gateway runtime shutdown")
            .expect("gateway runtime task")
            .expect("gateway runtime result");
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

    async fn assert_readyz_ok(addr: &str) {
        let mut stream = timeout(Duration::from_secs(3), tokio::net::TcpStream::connect(addr))
            .await
            .expect("readyz connect")
            .expect("readyz TCP");
        stream
            .write_all(b"GET /readyz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        let response = String::from_utf8_lossy(&response);
        assert!(
            response.starts_with("HTTP/1.1 200 OK"),
            "unexpected readyz response: {response}"
        );
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
        type ExecSessionStream = ReceiverStream<Result<v1::ExecMessage, Status>>;
        type PtySessionStream = ReceiverStream<Result<v1::PtyMessage, Status>>;
        type AttachSessionStream = ReceiverStream<Result<v1::SessionAttachMessage, Status>>;

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
