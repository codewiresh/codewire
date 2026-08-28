use std::path::{Path, PathBuf};

use codewire_daemon::service::DaemonRuntimeState;
use codewire_daemon::{Config, server};
use codewire_gateway_proto::DAEMON_AUTH_TOKEN_HEADER;
use codewire_gateway_proto::daemon::v1;
use codewire_gateway_proto::daemon::v1::daemon_service_client::DaemonServiceClient;
use tempfile::TempDir;
use tokio::net::TcpListener;
#[cfg(unix)]
use tokio::net::UnixListener;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
#[cfg(not(unix))]
use tokio_stream::wrappers::TcpListenerStream;
#[cfg(unix)]
use tokio_stream::wrappers::UnixListenerStream;
use tonic::metadata::{Ascii, MetadataValue};
use tonic::service::Interceptor;
use tonic::service::interceptor::InterceptedService;
use tonic::transport::{Channel, Endpoint};
use tonic::{Request, Status};

const DEFAULT_TEST_AUTH_TOKEN: &str = "daemon-conformance-token";

#[derive(Clone)]
pub struct HarnessAuthInterceptor {
    auth_token: MetadataValue<Ascii>,
}

impl Interceptor for HarnessAuthInterceptor {
    fn call(&mut self, mut request: Request<()>) -> Result<Request<()>, Status> {
        request
            .metadata_mut()
            .insert(DAEMON_AUTH_TOKEN_HEADER, self.auth_token.clone());
        Ok(request)
    }
}

pub type HarnessClient = DaemonServiceClient<InterceptedService<Channel, HarnessAuthInterceptor>>;

#[derive(Clone, Copy)]
enum HarnessTransport {
    Injected,
    LegacyTcp,
}

pub struct DaemonHarness {
    _temp: Option<TempDir>,
    _transport_temp: Option<TempDir>,
    workspace_root: PathBuf,
    home_root: PathBuf,
    endpoint: String,
    unix_socket: Option<PathBuf>,
    auth_token: MetadataValue<Ascii>,
    shutdown: Option<oneshot::Sender<()>>,
    server: Option<JoinHandle<()>>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct PersistedOutputFrame {
    pub offset: u64,
    pub stream: v1::SessionOutputStream,
    pub data: Vec<u8>,
}

impl DaemonHarness {
    pub async fn spawn() -> Self {
        Self::spawn_owned(
            DaemonRuntimeState::ready(),
            DEFAULT_TEST_AUTH_TOKEN.into(),
            HarnessTransport::Injected,
        )
        .await
    }

    pub async fn spawn_tcp() -> Self {
        Self::spawn_owned(
            DaemonRuntimeState::ready(),
            DEFAULT_TEST_AUTH_TOKEN.into(),
            HarnessTransport::LegacyTcp,
        )
        .await
    }

    pub async fn spawn_with_runtime_state(runtime_state: DaemonRuntimeState) -> Self {
        Self::spawn_owned(
            runtime_state,
            DEFAULT_TEST_AUTH_TOKEN.into(),
            HarnessTransport::LegacyTcp,
        )
        .await
    }

    async fn spawn_owned(
        runtime_state: DaemonRuntimeState,
        auth_token: String,
        transport: HarnessTransport,
    ) -> Self {
        let temp = tempfile::tempdir().expect("daemon harness tempdir");
        let workspace_root = temp.path().join("workspace");
        let home_root = temp.path().join("home");
        Self::spawn_inner(
            Some(temp),
            workspace_root,
            home_root,
            runtime_state,
            auth_token,
            transport,
        )
        .await
    }

    pub async fn spawn_with_auth_token(auth_token: impl Into<String>) -> Self {
        let temp = tempfile::tempdir().expect("daemon harness tempdir");
        let workspace_root = temp.path().join("workspace");
        let home_root = temp.path().join("home");
        Self::spawn_inner(
            Some(temp),
            workspace_root,
            home_root,
            DaemonRuntimeState::ready(),
            auth_token.into(),
            HarnessTransport::Injected,
        )
        .await
    }

    pub async fn spawn_at(workspace_root: PathBuf, home_root: PathBuf) -> Self {
        Self::spawn_inner(
            None,
            workspace_root,
            home_root,
            DaemonRuntimeState::ready(),
            DEFAULT_TEST_AUTH_TOKEN.into(),
            HarnessTransport::Injected,
        )
        .await
    }

    async fn spawn_inner(
        temp: Option<TempDir>,
        workspace_root: PathBuf,
        home_root: PathBuf,
        runtime_state: DaemonRuntimeState,
        auth_token: String,
        transport: HarnessTransport,
    ) -> Self {
        std::fs::create_dir_all(&workspace_root).expect("create workspace");
        std::fs::create_dir_all(&home_root).expect("create home");

        #[cfg(unix)]
        let (transport_temp, endpoint, unix_socket, shutdown_tx, server) = match transport {
            HarnessTransport::Injected => {
                assert_eq!(runtime_state, DaemonRuntimeState::ready());
                let transport_temp = tempfile::tempdir().expect("daemon transport tempdir");
                let socket_path = transport_temp.path().join("daemon.sock");
                let listener = UnixListener::bind(&socket_path).expect("bind daemon Unix listener");
                let endpoint = format!("unix:{}", socket_path.display());
                let config = Config {
                    listen_addr: endpoint.clone(),
                    workspace_root: workspace_root.clone(),
                    home_root: home_root.clone(),
                    auth_token: Some(auth_token.clone()),
                };
                let (shutdown_tx, shutdown_rx) = oneshot::channel();
                let server = tokio::spawn(async move {
                    server::serve_grpc_with_incoming(
                        config,
                        UnixListenerStream::new(listener),
                        async {
                            let _ = shutdown_rx.await;
                        },
                    )
                    .await
                    .expect("serve daemon injected transport harness");
                });
                (
                    Some(transport_temp),
                    endpoint,
                    Some(socket_path),
                    shutdown_tx,
                    server,
                )
            }
            HarnessTransport::LegacyTcp => {
                let listener = TcpListener::bind("127.0.0.1:0")
                    .await
                    .expect("bind daemon TCP harness");
                let addr = listener.local_addr().expect("daemon harness address");
                let endpoint = format!("http://{addr}");
                let config = Config {
                    listen_addr: addr.to_string(),
                    workspace_root: workspace_root.clone(),
                    home_root: home_root.clone(),
                    auth_token: Some(auth_token.clone()),
                };
                let (shutdown_tx, shutdown_rx) = oneshot::channel();
                let server = tokio::spawn(async move {
                    axum::serve(
                        listener,
                        server::router_with_runtime_state(config, runtime_state),
                    )
                    .with_graceful_shutdown(async {
                        let _ = shutdown_rx.await;
                    })
                    .await
                    .expect("serve daemon TCP harness");
                });
                (None, endpoint, None, shutdown_tx, server)
            }
        };

        #[cfg(not(unix))]
        let (transport_temp, endpoint, unix_socket, shutdown_tx, server) = {
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind daemon harness");
            let addr = listener.local_addr().expect("daemon harness address");
            let endpoint = format!("http://{addr}");
            let config = Config {
                listen_addr: addr.to_string(),
                workspace_root: workspace_root.clone(),
                home_root: home_root.clone(),
                auth_token: Some(auth_token.clone()),
            };
            let (shutdown_tx, shutdown_rx) = oneshot::channel();
            let server = match transport {
                HarnessTransport::Injected => tokio::spawn(async move {
                    server::serve_grpc_with_incoming(
                        config,
                        TcpListenerStream::new(listener),
                        async {
                            let _ = shutdown_rx.await;
                        },
                    )
                    .await
                    .expect("serve daemon injected transport harness");
                }),
                HarnessTransport::LegacyTcp => tokio::spawn(async move {
                    axum::serve(
                        listener,
                        server::router_with_runtime_state(config, runtime_state),
                    )
                    .with_graceful_shutdown(async {
                        let _ = shutdown_rx.await;
                    })
                    .await
                    .expect("serve daemon TCP harness");
                }),
            };
            (None, endpoint, None, shutdown_tx, server)
        };

        let mut auth_metadata = MetadataValue::try_from(auth_token).expect("valid test auth token");
        auth_metadata.set_sensitive(true);

        Self {
            _temp: temp,
            _transport_temp: transport_temp,
            workspace_root,
            home_root,
            endpoint,
            unix_socket,
            auth_token: auth_metadata,
            shutdown: Some(shutdown_tx),
            server: Some(server),
        }
    }

    pub async fn client(&self) -> HarnessClient {
        DaemonServiceClient::with_interceptor(
            self.channel().await,
            HarnessAuthInterceptor {
                auth_token: self.auth_token.clone(),
            },
        )
    }

    pub async fn unauthenticated_client(&self) -> DaemonServiceClient<Channel> {
        DaemonServiceClient::new(self.channel().await)
    }

    pub async fn channel(&self) -> Channel {
        Endpoint::from_shared(self.endpoint.clone())
            .expect("valid daemon harness endpoint")
            .connect()
            .await
            .expect("connect daemon harness")
    }

    pub fn endpoint(&self) -> String {
        self.endpoint.clone()
    }

    pub fn workspace_root(&self) -> &Path {
        &self.workspace_root
    }

    pub fn unix_socket(&self) -> Option<&Path> {
        self.unix_socket.as_deref()
    }

    pub async fn shutdown(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(server) = self.server.take() {
            server.await.expect("join daemon harness");
        }
    }

    pub async fn persisted_output(&self, session_id: &str) -> Vec<PersistedOutputFrame> {
        read_persisted_output(&self.home_root, session_id).await
    }
}

impl Drop for DaemonHarness {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(server) = self.server.take() {
            server.abort();
        }
    }
}

async fn read_persisted_output(home_root: &Path, session_id: &str) -> Vec<PersistedOutputFrame> {
    let path = home_root
        .join(".codewire/daemon/sessions")
        .join(session_id)
        .join("output.bin");
    let bytes = tokio::fs::read(&path)
        .await
        .unwrap_or_else(|error| panic!("read persisted output {}: {error}", path.display()));
    let mut cursor = 0;
    let mut frames = Vec::new();
    while cursor < bytes.len() {
        assert!(
            bytes.len() - cursor >= 17,
            "truncated output frame header in {}",
            path.display()
        );
        let offset =
            u64::from_le_bytes(bytes[cursor..cursor + 8].try_into().expect("output offset"));
        let stream = v1::SessionOutputStream::try_from(i32::from(bytes[cursor + 8]))
            .expect("known output stream");
        let length = u64::from_le_bytes(
            bytes[cursor + 9..cursor + 17]
                .try_into()
                .expect("output length"),
        );
        cursor += 17;
        let length = usize::try_from(length).expect("output length fits usize");
        assert!(
            bytes.len() - cursor >= length,
            "truncated output frame data in {}",
            path.display()
        );
        let data = bytes[cursor..cursor + length].to_vec();
        cursor += length;
        frames.push(PersistedOutputFrame {
            offset,
            stream,
            data,
        });
    }
    frames
}
