use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use codewire_daemon::service::DaemonRuntimeState;
use codewire_daemon::{Config, server};
use codewire_gateway_proto::daemon::v1;
use codewire_gateway_proto::daemon::v1::daemon_service_client::DaemonServiceClient;
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tonic::transport::Channel;

pub struct DaemonHarness {
    _temp: Option<TempDir>,
    home_root: PathBuf,
    addr: SocketAddr,
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
        Self::spawn_with_runtime_state(DaemonRuntimeState::ready()).await
    }

    pub async fn spawn_with_runtime_state(runtime_state: DaemonRuntimeState) -> Self {
        let temp = tempfile::tempdir().expect("daemon harness tempdir");
        let workspace_root = temp.path().join("workspace");
        let home_root = temp.path().join("home");
        Self::spawn_inner(Some(temp), workspace_root, home_root, runtime_state, None).await
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
            Some(auth_token.into()),
        )
        .await
    }

    pub async fn spawn_at(workspace_root: PathBuf, home_root: PathBuf) -> Self {
        Self::spawn_inner(
            None,
            workspace_root,
            home_root,
            DaemonRuntimeState::ready(),
            None,
        )
        .await
    }

    async fn spawn_inner(
        temp: Option<TempDir>,
        workspace_root: PathBuf,
        home_root: PathBuf,
        runtime_state: DaemonRuntimeState,
        auth_token: Option<String>,
    ) -> Self {
        std::fs::create_dir_all(&workspace_root).expect("create workspace");
        std::fs::create_dir_all(&home_root).expect("create home");

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind daemon harness");
        let addr = listener.local_addr().expect("daemon harness address");
        let config = Config {
            listen_addr: addr.to_string(),
            workspace_root,
            home_root: home_root.clone(),
            auth_token,
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
            .expect("serve daemon harness");
        });

        Self {
            _temp: temp,
            home_root,
            addr,
            shutdown: Some(shutdown_tx),
            server: Some(server),
        }
    }

    pub async fn client(&self) -> DaemonServiceClient<Channel> {
        DaemonServiceClient::connect(format!("http://{}", self.addr))
            .await
            .expect("connect daemon harness")
    }

    pub fn endpoint(&self) -> String {
        format!("http://{}", self.addr)
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
