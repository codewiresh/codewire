use std::path::{Path, PathBuf};

use codewire_daemon::execution::ProcessExecution;
use codewire_daemon::{Config, serve_grpc_with_incoming};
use prost::Message as _;
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio_stream::wrappers::TcpListenerStream;

use crate::client::DaemonClient;

pub(crate) const TEST_DAEMON_TOKEN: &str = "daemon-bridge-test-token";

pub(crate) fn public_service_methods(service_name: &str) -> std::collections::BTreeSet<String> {
    prost_types::FileDescriptorSet::decode(
        include_bytes!("../../codewire-proto/codewire_descriptor.bin").as_slice(),
    )
    .expect("decode public descriptor")
    .file
    .iter()
    .filter(|file| file.package.as_deref() == Some("codewire.v1"))
    .flat_map(|file| &file.service)
    .find(|service| service.name.as_deref() == Some(service_name))
    .unwrap_or_else(|| panic!("missing public service {service_name}"))
    .method
    .iter()
    .map(|method| method.name.as_deref().expect("method name").to_owned())
    .collect()
}

pub(crate) struct DaemonHarness {
    _temp: TempDir,
    workspace_root: PathBuf,
    endpoint: String,
    shutdown: Option<oneshot::Sender<()>>,
    server: Option<JoinHandle<()>>,
}

impl DaemonHarness {
    pub(crate) async fn spawn() -> Self {
        let temp = tempfile::tempdir().expect("daemon bridge tempdir");
        let workspace_root = temp.path().join("workspace");
        let home_root = temp.path().join("home");
        std::fs::create_dir_all(&workspace_root).expect("create test workspace");
        std::fs::create_dir_all(&home_root).expect("create test home");

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind daemon bridge listener");
        let endpoint = format!(
            "http://{}",
            listener.local_addr().expect("listener address")
        );
        let config = Config {
            listen_addr: endpoint.clone(),
            workspace_root: workspace_root.clone(),
            home_root,
            auth_token: Some(TEST_DAEMON_TOKEN.to_owned()),
            process_execution: ProcessExecution::Native,
            credential_bridge: None,
        };
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let server = tokio::spawn(async move {
            serve_grpc_with_incoming(config, TcpListenerStream::new(listener), async {
                let _ = shutdown_rx.await;
            })
            .await
            .expect("serve daemon bridge test transport");
        });

        Self {
            _temp: temp,
            workspace_root,
            endpoint,
            shutdown: Some(shutdown_tx),
            server: Some(server),
        }
    }

    pub(crate) async fn client(&self) -> DaemonClient {
        DaemonClient::connect(&self.endpoint, TEST_DAEMON_TOKEN)
            .await
            .expect("connect daemon bridge client")
    }

    pub(crate) fn workspace_root(&self) -> &Path {
        &self.workspace_root
    }

    pub(crate) async fn shutdown(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(server) = self.server.take() {
            server.await.expect("join daemon bridge server");
        }
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
