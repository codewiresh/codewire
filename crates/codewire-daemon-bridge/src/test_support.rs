use std::collections::VecDeque;
use std::convert::Infallible;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use codewire_daemon::execution::ProcessExecution;
use codewire_daemon::service::DaemonServiceImpl;
use codewire_daemon::{Config, DaemonAuthToken, serve_grpc_with_incoming};
use codewire_daemon_proto::daemon::v1::daemon_service_server::DaemonServiceServer;
use connectrpc::http_body::{Body as HttpBody, Frame};
use prost::Message as _;
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio::sync::{Notify, oneshot};
use tokio::task::JoinHandle;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::body::Body;
use tonic::codegen::{Service, http};
use tonic::server::NamedService;

use crate::client::DaemonClient;

pub(crate) const TEST_DAEMON_TOKEN: &str = "daemon-bridge-test-token";
pub(crate) const FILE_GATE_TIMEOUT: Duration = Duration::from_secs(5);

/// Only actual unary filesystem methods can be gated. Authorization, protobuf
/// dispatch and confined filesystem operations still belong to the real daemon.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FileRpc {
    OpenFile,
    Write,
    SetStat,
    Rename,
    Remove,
}

impl FileRpc {
    fn from_path(path: &str) -> Option<Self> {
        let prefix = format!(
            "/{}/",
            <DaemonServiceServer<DaemonServiceImpl> as NamedService>::NAME
        );
        match path.strip_prefix(&prefix)? {
            "OpenFile" => Some(Self::OpenFile),
            "Write" => Some(Self::Write),
            "SetStat" => Some(Self::SetStat),
            "Rename" => Some(Self::Rename),
            "Remove" => Some(Self::Remove),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FileRpcGatePoint {
    BeforeExecution,
    AfterExecution,
}

/// A one-shot barrier around a real daemon unary request. Releasing it never
/// fabricates a successful response or replaces confinement with a mock.
pub(crate) struct FileRpcGate {
    method: FileRpc,
    point: FileRpcGatePoint,
    armed: AtomicBool,
    entered: Notify,
    release: Notify,
    removals: AtomicUsize,
    removed: Notify,
    early_removal: AtomicBool,
    completed: AtomicBool,
    completion: Notify,
    tasks: Mutex<Vec<JoinHandle<()>>>,
}

impl FileRpcGate {
    pub(crate) fn new(method: FileRpc, point: FileRpcGatePoint) -> Arc<Self> {
        Arc::new(Self {
            method,
            point,
            armed: AtomicBool::new(true),
            entered: Notify::new(),
            release: Notify::new(),
            removals: AtomicUsize::new(0),
            removed: Notify::new(),
            early_removal: AtomicBool::new(false),
            completed: AtomicBool::new(false),
            completion: Notify::new(),
            tasks: Mutex::new(Vec::new()),
        })
    }

    async fn pause(&self, method: FileRpc, point: FileRpcGatePoint) {
        if self.method == method && self.point == point && self.armed.swap(false, Ordering::SeqCst)
        {
            self.entered.notify_one();
            self.release.notified().await;
        }
    }

    pub(crate) async fn wait(&self) {
        tokio::time::timeout(FILE_GATE_TIMEOUT, self.entered.notified())
            .await
            .expect("exact daemon filesystem RPC did not reach its barrier");
    }

    pub(crate) fn release(&self) {
        self.release.notify_one();
    }

    pub(crate) async fn wait_for_removal(&self) {
        tokio::time::timeout(FILE_GATE_TIMEOUT, async {
            loop {
                let notified = self.removed.notified();
                if self.removals.load(Ordering::SeqCst) > 0 {
                    return;
                }
                notified.await;
            }
        })
        .await
        .expect("cancellation did not finish a staging removal RPC");
    }

    pub(crate) fn removal_count(&self) -> usize {
        self.removals.load(Ordering::SeqCst)
    }

    pub(crate) fn removed_before_pending_operation_finished(&self) -> bool {
        self.early_removal.load(Ordering::SeqCst)
    }

    pub(crate) async fn wait_for_completion(&self) {
        tokio::time::timeout(FILE_GATE_TIMEOUT, async {
            loop {
                let notified = self.completion.notified();
                if self.completed.load(Ordering::SeqCst) {
                    return;
                }
                notified.await;
            }
        })
        .await
        .expect("gated daemon operation did not complete");
    }

    async fn drain(&self) {
        let tasks = std::mem::take(&mut *self.tasks.lock().expect("gated daemon task registry"));
        for mut task in tasks {
            match tokio::time::timeout(FILE_GATE_TIMEOUT, &mut task).await {
                Ok(result) => result.expect("gated daemon operation failed"),
                Err(_) => {
                    task.abort();
                    let _ = task.await;
                    panic!("gated daemon operation did not drain");
                }
            }
        }
    }

    fn abort_tasks(&self) {
        self.release();
        for task in self
            .tasks
            .lock()
            .expect("gated daemon task registry")
            .iter()
        {
            task.abort();
        }
    }
}

#[derive(Clone)]
struct GatedDaemonService {
    inner: DaemonServiceServer<DaemonServiceImpl>,
    gate: Arc<FileRpcGate>,
}

struct BufferedUnaryBody {
    frames: VecDeque<Result<Frame<bytes::Bytes>, tonic::Status>>,
}

impl HttpBody for BufferedUnaryBody {
    type Data = bytes::Bytes;
    type Error = tonic::Status;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        Poll::Ready(self.frames.pop_front())
    }

    fn is_end_stream(&self) -> bool {
        self.frames.is_empty()
    }
}

impl NamedService for GatedDaemonService {
    const NAME: &'static str = <DaemonServiceServer<DaemonServiceImpl> as NamedService>::NAME;
}

impl Service<http::Request<Body>> for GatedDaemonService {
    type Response = http::Response<Body>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Service::<http::Request<Body>>::poll_ready(&mut self.inner, cx)
    }

    fn call(&mut self, request: http::Request<Body>) -> Self::Future {
        let Some(method) = FileRpc::from_path(request.uri().path()) else {
            return Box::pin(self.inner.call(request));
        };
        let mut inner = self.inner.clone();
        let gate = Arc::clone(&self.gate);
        let (response_tx, response_rx) = oneshot::channel();
        // Accepted unary work can finish after a caller loses its response.
        // Retain that exact operation so BEFORE-create tests also catch an
        // incorrect remove-before-create cleanup, rather than canceling the
        // daemon effect alongside the public upload future.
        let task = tokio::spawn(async move {
            // Receive the complete tiny unary message before the BEFORE gate.
            // A later HTTP reset must not cancel reading its request body and
            // accidentally suppress the daemon effect being exercised.
            let (parts, mut body) = request.into_parts();
            let mut frames = VecDeque::new();
            let mut size = 0_usize;
            while let Some(frame) =
                futures::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await
            {
                if let Ok(frame) = &frame {
                    size += frame.data_ref().map_or(0, bytes::Bytes::len);
                    assert!(
                        size <= codewire_daemon_proto::CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES + 5,
                        "gated unary fixture exceeded the daemon message limit"
                    );
                }
                let failed = frame.is_err();
                frames.push_back(frame);
                if failed {
                    break;
                }
            }
            let request = http::Request::from_parts(parts, Body::new(BufferedUnaryBody { frames }));
            gate.pause(method, FileRpcGatePoint::BeforeExecution).await;
            if method == FileRpc::Remove
                && gate.method != FileRpc::Remove
                && !gate.armed.load(Ordering::SeqCst)
                && !gate.completed.load(Ordering::SeqCst)
            {
                gate.early_removal.store(true, Ordering::SeqCst);
            }
            let response = inner.call(request).await;
            gate.pause(method, FileRpcGatePoint::AfterExecution).await;
            if method == gate.method {
                gate.completed.store(true, Ordering::SeqCst);
                gate.completion.notify_one();
            }
            if method == FileRpc::Remove {
                gate.removals.fetch_add(1, Ordering::SeqCst);
                gate.removed.notify_one();
            }
            let _ = response_tx.send(response);
        });
        self.gate
            .tasks
            .lock()
            .expect("gated daemon task registry")
            .push(task);
        Box::pin(async move {
            response_rx
                .await
                .expect("gated daemon response owner disappeared")
        })
    }
}

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
    file_gate: Option<Arc<FileRpcGate>>,
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
            auth_token: DaemonAuthToken::new(TEST_DAEMON_TOKEN).unwrap(),
            process_execution: ProcessExecution::Native,
            credential_bridge: None,
            launch_projection: None,
            managed_credential_clients: Default::default(),
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
            file_gate: None,
        }
    }

    /// Opt-in cancellation fixture; ordinary harness startup is unchanged.
    /// This listener serves the actual daemon implementation, including its
    /// mandatory token validation and confined filesystem implementation.
    pub(crate) async fn spawn_with_file_gate(gate: Arc<FileRpcGate>) -> Self {
        let temp = tempfile::tempdir().expect("gated daemon bridge tempdir");
        let workspace_root = temp.path().join("workspace");
        let home_root = temp.path().join("home");
        std::fs::create_dir_all(&workspace_root).expect("create gated workspace");
        std::fs::create_dir_all(&home_root).expect("create gated home");
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind gated daemon");
        let endpoint = format!(
            "http://{}",
            listener.local_addr().expect("gated listener address")
        );
        let config = Config {
            listen_addr: endpoint.clone(),
            workspace_root: workspace_root.clone(),
            home_root,
            auth_token: DaemonAuthToken::new(TEST_DAEMON_TOKEN).unwrap(),
            process_execution: ProcessExecution::Native,
            credential_bridge: None,
            launch_projection: None,
            managed_credential_clients: Default::default(),
        };
        let service = GatedDaemonService {
            inner: DaemonServiceServer::new(DaemonServiceImpl::new(config))
                .max_decoding_message_size(
                    codewire_daemon_proto::CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES,
                )
                .max_encoding_message_size(
                    codewire_daemon_proto::CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES,
                ),
            gate: Arc::clone(&gate),
        };
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let server = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(service)
                .serve_with_incoming_shutdown(TcpListenerStream::new(listener), async {
                    let _ = shutdown_rx.await;
                })
                .await
                .expect("serve gated daemon bridge transport");
        });
        Self {
            _temp: temp,
            workspace_root,
            endpoint,
            shutdown: Some(shutdown_tx),
            server: Some(server),
            file_gate: Some(gate),
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
        if let Some(gate) = &self.file_gate {
            gate.release();
            gate.drain().await;
        }
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(mut server) = self.server.take() {
            if self.file_gate.is_some() {
                match tokio::time::timeout(FILE_GATE_TIMEOUT, &mut server).await {
                    Ok(result) => result.expect("join gated daemon bridge server"),
                    Err(_) => {
                        server.abort();
                        let _ = server.await;
                        panic!("gated daemon server did not stop");
                    }
                }
            } else {
                server.await.expect("join daemon bridge server");
            }
        }
    }
}

impl Drop for DaemonHarness {
    fn drop(&mut self) {
        if let Some(gate) = &self.file_gate {
            gate.abort_tasks();
        }
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(server) = self.server.take() {
            server.abort();
        }
    }
}
