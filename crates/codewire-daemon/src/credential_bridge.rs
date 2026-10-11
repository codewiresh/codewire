use std::future::{Future, IntoFuture as _};
use std::io;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, Response};
use codewire_credential_bridge::{
    CredentialBridge as SharedCredentialBridge, CredentialBridgeOutput, EpochReplacement,
};
use codewire_daemon_proto::codewire::bridge::v1;
use codewire_daemon_proto::{CREDENTIAL_BRIDGE_LOOPBACK_PORT, CREDENTIAL_BRIDGE_PROTOCOL_VERSION};
use tokio::net::{TcpListener, TcpSocket, TcpStream, UnixListener, UnixStream, unix::SocketAddr};
use tokio::sync::{Mutex, Semaphore};
use tokio_stream::{Stream, StreamExt};
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tonic::{Status, Streaming};

use crate::server::{ShutdownIo, TransportShutdown};
use crate::{CredentialBridgeConfig, CredentialBridgeTransport};

mod hosted;
pub(crate) use hosted::WORKSPACE_AUTHORIZATION;
mod ssh_ingress;
use ssh_ingress::SshIngress;

const HOST_OPEN_TIMEOUT: Duration = Duration::from_secs(5);
const HOSTED_OPEN_TIMEOUT: Duration = Duration::from_secs(15);
const HOSTED_EPOCH_MAX_LIFETIME: Duration = Duration::from_secs(600);
const HOSTED_INGRESS_DRAIN_TIMEOUT: Duration = Duration::from_secs(1);

/// Local transport/configuration adapter. All request/response phases and
/// connection cancellation belong to the shared material-free bridge.
#[derive(Clone)]
pub(crate) struct CredentialBridge {
    config: Option<CredentialBridgeConfig>,
    inner: Result<Option<SharedCredentialBridge>, Status>,
    owner: Arc<BridgeOwner>,
}

struct BridgeOwner {
    accepting: Mutex<bool>,
    // One active epoch, the hosted epoch draining behind it and one prepared
    // replacement; no unbounded Open waiters.
    permits: Arc<Semaphore>,
    tasks: TaskTracker,
    shutdown: CancellationToken,
}

pub(crate) struct CredentialBridgeConnection {
    pub output: CredentialBridgeOutput,
    pub workspace_authorization: Option<hosted::WorkspaceAuthorization>,
}

pub(crate) struct CredentialIngress {
    listener: CredentialIngressListener,
    loopback: Option<TcpListener>,
    ssh: Option<SshIngress>,
    bridge: SharedCredentialBridge,
    owner: CredentialBridge,
    socket: SocketGuard,
}

struct CredentialIngressListener {
    inner: UnixListener,
    uid: u32,
    failed: Option<CancellationToken>,
}

/// Hosted TCP is an environment/Pod-network-namespace boundary, not a UID
/// boundary. Only the Unix listener authenticates an individual socket UID.
struct LoopbackIngressListener {
    inner: TcpListener,
    failed: CancellationToken,
}

struct ShutdownIngressListener<L> {
    inner: L,
    shutdown: Arc<TransportShutdown>,
}

struct HostedIngressDrain {
    stop: CancellationToken,
    transports: Arc<TransportShutdown>,
    owner: CredentialBridge,
}

pub(crate) struct BridgeCancellationGuard(CredentialBridge);

impl Drop for BridgeCancellationGuard {
    fn drop(&mut self) {
        // A dropped future cannot acknowledge asynchronous drain. It must
        // still stop every registered epoch/stream and prevent new admission.
        self.0.owner.shutdown.cancel();
    }
}

impl Drop for HostedIngressDrain {
    fn drop(&mut self) {
        // Also fail closed if the containing server cancels its serve future.
        // The containing daemon still owns/awaits the bridge task tracker.
        self.stop.cancel();
        self.owner.owner.shutdown.cancel();
        self.transports.trigger();
    }
}

struct SocketGuard {
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl CredentialBridge {
    pub(crate) fn cancel_on_drop(&self) -> BridgeCancellationGuard {
        BridgeCancellationGuard(self.clone())
    }

    pub(crate) fn new(config: Option<CredentialBridgeConfig>) -> Self {
        let inner = config
            .as_ref()
            .map(|config| {
                SharedCredentialBridge::new(config.environment_id, config.environment_generation)
            })
            .transpose();
        Self {
            config,
            inner,
            owner: Arc::new(BridgeOwner {
                accepting: Mutex::new(true),
                permits: Arc::new(Semaphore::new(3)),
                tasks: TaskTracker::new(),
                shutdown: CancellationToken::new(),
            }),
        }
    }

    pub(crate) fn is_enabled(&self) -> bool {
        self.config.is_some()
    }

    fn shared(&self) -> Result<&SharedCredentialBridge, Status> {
        self.inner
            .as_ref()
            .map_err(Clone::clone)?
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("credential bridge is unavailable"))
    }

    /// The shared bridge itself, for the hosted Codex login writer.
    #[cfg(target_os = "linux")]
    pub(crate) fn shared_bridge(&self) -> Option<SharedCredentialBridge> {
        self.shared().ok().cloned()
    }

    pub(crate) async fn project_environment_for_recipient(
        &self,
        context: codewire_workload_secrets::ProjectionContext,
        recipient: [u8; 32],
    ) -> Result<codewire_credential_bridge::RelayedEnvironmentProjection, Status> {
        self.shared()?
            .project_environment_for_recipient(context, recipient)
            .await
    }

    pub(crate) async fn wait_for_initial_host(
        &self,
        context: &codewire_workload_secrets::ProjectionContext,
    ) -> Result<(), Status> {
        self.shared()?.wait_for_initial_host(context).await
    }

    pub(crate) async fn connect(
        &self,
        input: Streaming<v1::CredentialBridgeHostMessage>,
    ) -> Result<CredentialBridgeConnection, Status> {
        self.connect_with_token_file(input, Path::new(codewire_access::CODEX_PLATFORM_TOKEN_FILE))
            .await
    }

    async fn connect_with_token_file<S>(
        &self,
        mut input: S,
        token_file: &Path,
    ) -> Result<CredentialBridgeConnection, Status>
    where
        S: Stream<Item = Result<v1::CredentialBridgeHostMessage, Status>> + Send + Unpin + 'static,
    {
        let config = self
            .config
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("credential bridge is unavailable"))?;
        let permit = self
            .owner
            .permits
            .clone()
            .try_acquire_owned()
            .map_err(|_| Status::resource_exhausted("credential bridge admission is busy"))?;
        let hosted = config.transport == CredentialBridgeTransport::Hosted;
        let deadline = tokio::time::Instant::now()
            + if hosted {
                HOSTED_OPEN_TIMEOUT
            } else {
                HOST_OPEN_TIMEOUT
            };
        let workspace_authorization = if hosted {
            Some(tokio::select! {
                biased;
                _ = self.owner.shutdown.cancelled() => return Err(hosted::unavailable()),
                result = tokio::time::timeout_at(deadline, hosted::read_workspace_authorization(token_file)) => result.map_err(|_| hosted::unavailable())??,
            })
        } else {
            None
        };
        // A local host's Open is read eagerly, before preparing; a hosted
        // Open arrives only after the broker admitted the prepared Ready.
        let local_capabilities = if hosted {
            None
        } else {
            Some(tokio::select! {
                biased;
                _ = self.owner.shutdown.cancelled() => return Err(hosted::unavailable()),
                result = read_open(&mut input, config, deadline) => result?,
            })
        };
        let (prepared, output) = self.shared()?.prepare_connection()?;
        let config = config.clone();
        let owner = self.owner.clone();
        let accepting = self.owner.accepting.lock().await;
        if !*accepting || self.owner.shutdown.is_cancelled() {
            return Err(hosted::unavailable());
        }
        if let Some(capabilities) = local_capabilities {
            // Keep the local eager-Open contract: RPC headers are sent only
            // after this already-authenticated host has actually activated.
            let connection = prepared
                .activate_with_capabilities(input, &capabilities)
                .await?;
            drop(self.owner.tasks.spawn(async move {
                let _permit = permit;
                connection.run_until(owner.shutdown.cancelled()).await;
            }));
            drop(accepting);
            return Ok(CredentialBridgeConnection {
                output,
                workspace_authorization,
            });
        }
        // Register under the same admission lock closed by shutdown. Hosted
        // Ready is emitted while PREPARED: it cannot replace the live epoch.
        drop(self.owner.tasks.spawn(async move {
            let _permit = permit;
            let admitted = tokio::select! {
                biased;
                _ = owner.shutdown.cancelled() => return,
                result = read_open(&mut input, &config, deadline) => result,
            };
            let Ok(capabilities) = admitted else {
                return;
            };
            let accepting = owner.accepting.lock().await;
            if !*accepting || owner.shutdown.is_cancelled() {
                return;
            }
            // The relay admits the next epoch before the current identity
            // expires and ends the replaced one itself: that epoch finishes
            // only the requests already sent on it, for at most 90 seconds,
            // and new ones go here.
            let Ok(connection) = prepared
                .activate_with_replacement(input, &capabilities, EpochReplacement::Drain)
                .await
            else {
                return;
            };
            drop(accepting);
            connection
                .run_until(async {
                    tokio::select! {
                        _ = owner.shutdown.cancelled() => {},
                        _ = tokio::time::sleep(HOSTED_EPOCH_MAX_LIFETIME) => {},
                    }
                })
                .await;
        }));
        drop(accepting);
        Ok(CredentialBridgeConnection {
            output,
            workspace_authorization,
        })
    }

    pub(crate) async fn shutdown(&self) {
        {
            let mut accepting = self.owner.accepting.lock().await;
            *accepting = false;
            self.owner.tasks.close();
            self.owner.shutdown.cancel();
        }
        self.owner.tasks.wait().await;
    }

    pub(crate) fn prepare_ingress(
        &self,
        selected_ssh: bool,
    ) -> Result<Option<CredentialIngress>, io::Error> {
        let Some(config) = self.config.as_ref() else {
            if selected_ssh {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "selected SSH ingress has no credential bridge",
                ));
            }
            return Ok(None);
        };
        validate_config(config)?;
        let bridge = self.shared().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "credential bridge configuration is invalid",
            )
        })?;
        // Prebind before touching the Unix path. A competing Hosted owner (or
        // another occupant of the fixed port) must leave the prior UDS intact.
        // Local VMs already own their loopback forwarder and never bind here.
        let loopback = if config.transport == CredentialBridgeTransport::Hosted {
            Some(bind_hosted_loopback()?)
        } else {
            None
        };
        // Refuse an occupied SSH pathname before the existing HTTP cleanup
        // can affect another owner. SSH never removes a pre-existing object.
        let ssh = selected_ssh
            .then(|| SshIngress::prepare(config))
            .transpose()?;
        remove_stale_socket(&config.ingress_socket)?;
        let listener = UnixListener::bind(&config.ingress_socket)?;
        let metadata = std::fs::symlink_metadata(&config.ingress_socket)?;
        use std::os::unix::fs::MetadataExt as _;
        let socket = SocketGuard {
            path: config.ingress_socket.clone(),
            device: metadata.dev(),
            inode: metadata.ino(),
        };
        std::fs::set_permissions(
            &config.ingress_socket,
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        )?;
        chown_socket(
            &config.ingress_socket,
            config.ingress_uid,
            config.ingress_gid,
        )?;
        Ok(Some(CredentialIngress {
            listener: CredentialIngressListener {
                inner: listener,
                uid: config.ingress_uid,
                failed: None,
            },
            loopback,
            ssh,
            bridge: bridge.clone(),
            owner: self.clone(),
            socket,
        }))
    }
}

fn bind_hosted_loopback() -> io::Result<TcpListener> {
    let address = (Ipv4Addr::LOCALHOST, CREDENTIAL_BRIDGE_LOOPBACK_PORT).into();
    let socket = TcpSocket::new_v4()?;
    // Permit restart after this owner's connections enter TIME_WAIT. This is
    // NOT SO_REUSEPORT: a live owner remains exclusive and fails a second bind.
    socket.set_reuseaddr(true)?;
    socket.bind(address)?;
    let listener = socket.listen(128)?;
    if listener.local_addr()? != address {
        return Err(io::Error::other("credential loopback address is invalid"));
    }
    Ok(listener)
}

/// Read and check the host's Open, returning the optional operations it
/// lists for this epoch. A malformed capability list refuses the epoch.
async fn read_open<S>(
    input: &mut S,
    config: &CredentialBridgeConfig,
    deadline: tokio::time::Instant,
) -> Result<Vec<String>, Status>
where
    S: Stream<Item = Result<v1::CredentialBridgeHostMessage, Status>> + Unpin,
{
    let first = tokio::time::timeout_at(deadline, input.next())
        .await
        .map_err(|_| Status::deadline_exceeded("credential bridge open timed out"))?
        .ok_or_else(|| Status::invalid_argument("credential bridge open is missing"))??;
    let Some(v1::credential_bridge_host_message::Payload::Open(open)) = first.payload else {
        return Err(Status::invalid_argument(
            "credential bridge must begin with open",
        ));
    };
    if open.protocol_version != CREDENTIAL_BRIDGE_PROTOCOL_VERSION
        || open.environment_id != config.environment_id.to_string()
        || open.environment_generation != config.environment_generation
    {
        return Err(Status::failed_precondition(
            "credential bridge identity is invalid",
        ));
    }
    if open.capabilities.len() > codewire_daemon_proto::CREDENTIAL_BRIDGE_MAX_CAPABILITIES
        || !open
            .capabilities
            .iter()
            .all(|capability| codewire_daemon_proto::valid_credential_bridge_capability(capability))
    {
        return Err(Status::invalid_argument(
            "credential bridge capabilities are invalid",
        ));
    }
    Ok(open.capabilities)
}

impl CredentialIngress {
    pub(crate) async fn serve<F>(self, shutdown: F) -> Result<(), io::Error>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let bridge = self.bridge.clone();
        let router = Router::new()
            // Both endpoints share the same bridge epoch and request budget.
            // The bridge's closed classifier rejects unknown routes before body reads.
            .fallback(handle_provider_request)
            .with_state(bridge);
        let _socket = self.socket;
        let _ssh_socket = self.ssh.as_ref().map(|ssh| ssh.socket.clone());
        let _cancel_on_drop = self.owner.cancel_on_drop();
        if self.loopback.is_none() && self.ssh.is_none() {
            return axum::serve(self.listener, router)
                .with_graceful_shutdown(shutdown)
                .await;
        }
        let drain = HostedIngressDrain {
            stop: CancellationToken::new(),
            transports: TransportShutdown::new(),
            owner: self.owner,
        };
        let failed = CancellationToken::new();
        let unix = CredentialIngressListener {
            failed: Some(failed.clone()),
            ..self.listener
        };
        let unix = axum::serve(
            ShutdownIngressListener {
                inner: unix,
                shutdown: drain.transports.clone(),
            },
            router.clone(),
        )
        .with_graceful_shutdown(drain.stop.clone().cancelled_owned())
        .into_future();
        let tcp_stop = drain.stop.clone();
        let tcp_transports = drain.transports.clone();
        let tcp_failed = failed.clone();
        let tcp = async move {
            if let Some(loopback) = self.loopback {
                axum::serve(
                    ShutdownIngressListener {
                        inner: LoopbackIngressListener {
                            inner: loopback,
                            failed: tcp_failed,
                        },
                        shutdown: tcp_transports,
                    },
                    router,
                )
                .with_graceful_shutdown(tcp_stop.cancelled_owned())
                .await
            } else {
                tcp_stop.cancelled().await;
                Ok(())
            }
        };
        let ssh_stop = drain.stop.clone();
        let ssh_owner = drain.owner.clone();
        let ssh = async move {
            if let Some(ssh) = self.ssh {
                ssh.serve(ssh_owner, ssh_stop.cancelled_owned()).await
            } else {
                ssh_stop.cancelled().await;
                Ok(())
            }
        };
        serve_ingress_listeners(unix, tcp, ssh, shutdown, failed, drain).await
    }
}

#[cfg(test)]
async fn serve_hosted_listeners<U, T, F>(
    unix: U,
    tcp: T,
    shutdown: F,
    failed: CancellationToken,
    drain: HostedIngressDrain,
) -> io::Result<()>
where
    U: Future<Output = io::Result<()>>,
    T: Future<Output = io::Result<()>>,
    F: Future<Output = ()>,
{
    let stopped = drain.stop.clone();
    serve_ingress_listeners(
        unix,
        tcp,
        async move {
            stopped.cancelled().await;
            Ok(())
        },
        shutdown,
        failed,
        drain,
    )
    .await
}

async fn serve_ingress_listeners<U, T, S, F>(
    unix: U,
    tcp: T,
    ssh: S,
    shutdown: F,
    failed: CancellationToken,
    drain: HostedIngressDrain,
) -> io::Result<()>
where
    U: Future<Output = io::Result<()>>,
    T: Future<Output = io::Result<()>>,
    S: Future<Output = io::Result<()>>,
    F: Future<Output = ()>,
{
    tokio::pin!(unix, tcp, ssh, shutdown);
    let mut unix_done = false;
    let mut tcp_done = false;
    let mut ssh_done = false;
    let result = tokio::select! {
        biased;
        _ = failed.cancelled() => Err(io::Error::other("credential ingress listener failed")),
        _ = &mut shutdown => Ok(()),
        _ = drain.owner.owner.shutdown.cancelled() => Ok(()),
        result = &mut unix => {
            unix_done = true;
            result.and(Err(io::Error::other("credential Unix ingress stopped unexpectedly")))
        }
        result = &mut tcp => {
            tcp_done = true;
            result.and(Err(io::Error::other("credential loopback ingress stopped unexpectedly")))
        }
        result = &mut ssh => {
            ssh_done = true;
            result.and(Err(io::Error::other("SSH ingress stopped unexpectedly")))
        }
    };
    drain.stop.cancel();
    drain.owner.owner.shutdown.cancel();
    // Force-close partial uploads and idle/unread HTTP connections, then await
    // the actual Axum connection drains. Close the epoch BEFORE waiting for
    // response completion: the outer daemon finalizer otherwise cannot run.
    drain.transports.trigger();
    tokio::time::timeout(HOSTED_INGRESS_DRAIN_TIMEOUT, async {
        let owner = drain.owner.shutdown();
        let unix = async { if !unix_done { unix.await } else { Ok(()) } };
        let tcp = async { if !tcp_done { tcp.await } else { Ok(()) } };
        let ssh = async { if !ssh_done { ssh.await } else { Ok(()) } };
        let ((), unix, tcp, ssh) = tokio::join!(owner, unix, tcp, ssh);
        unix.and(tcp).and(ssh)
    })
    .await
    .map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "credential ingress drain timed out",
        )
    })??;
    // An accept failure concurrent with requested shutdown is still a failure.
    if failed.is_cancelled() {
        return Err(io::Error::other("credential ingress listener failed"));
    }
    result
}

async fn handle_provider_request(
    State(bridge): State<SharedCredentialBridge>,
    request: Request<Body>,
) -> Response<Body> {
    bridge.respond(request).await
}

impl axum::serve::Listener for CredentialIngressListener {
    type Io = UnixStream;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            match self.inner.accept().await {
                Ok((stream, address)) => match stream.peer_cred() {
                    Ok(credential) if credential.uid() == self.uid => return (stream, address),
                    Ok(_) | Err(_) => continue,
                },
                Err(error) => {
                    if let Some(failed) = self.failed.as_ref() {
                        stop_failed_listener(&error, failed).await;
                    } else {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.inner.local_addr()
    }
}

impl axum::serve::Listener for LoopbackIngressListener {
    type Io = TcpStream;
    type Addr = std::net::SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            match self.inner.accept().await {
                Ok(connection) => return connection,
                Err(error) => stop_failed_listener(&error, &self.failed).await,
            }
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.inner.local_addr()
    }
}

async fn stop_failed_listener(error: &io::Error, failed: &CancellationToken) {
    if matches!(
        error.kind(),
        io::ErrorKind::Interrupted
            | io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
    ) {
        tokio::task::yield_now().await;
        return;
    }
    failed.cancel();
    // Axum's Listener API cannot return an accept error. Wake the owner and
    // leave this accept suspended until its graceful-stop branch cancels it.
    std::future::pending::<()>().await;
}

impl<L: axum::serve::Listener> axum::serve::Listener for ShutdownIngressListener<L> {
    type Io = ShutdownIo<L::Io>;
    type Addr = L::Addr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        let (stream, address) = self.inner.accept().await;
        (ShutdownIo::new(stream, self.shutdown.clone()), address)
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.inner.local_addr()
    }
}

fn validate_config(config: &CredentialBridgeConfig) -> Result<(), io::Error> {
    if config.environment_id.is_nil()
        || config.environment_generation == 0
        || !config.ingress_socket.is_absolute()
        || config.ingress_socket.file_name().is_none()
        || config.ingress_socket.parent().is_none()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "credential bridge configuration is invalid",
        ));
    }
    Ok(())
}

fn remove_stale_socket(path: &Path) -> Result<(), io::Error> {
    use std::os::unix::fs::FileTypeExt as _;

    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => std::fs::remove_file(path),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "credential bridge ingress path contains an unexpected object",
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn chown_socket(path: &Path, uid: u32, gid: u32) -> Result<(), io::Error> {
    use std::os::unix::ffi::OsStrExt as _;

    let path = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "socket path contains NUL"))?;
    if unsafe { libc::chown(path.as_ptr(), uid, gid) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

impl Drop for SocketGuard {
    fn drop(&mut self) {
        use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};

        let Ok(metadata) = std::fs::symlink_metadata(&self.path) else {
            return;
        };
        if metadata.file_type().is_socket()
            && metadata.dev() == self.device
            && metadata.ino() == self.inode
        {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

#[cfg(test)]
#[path = "credential_bridge/ingress_tests.rs"]
mod ingress_tests;

#[cfg(test)]
mod tests {
    use std::os::unix::fs::MetadataExt as _;

    use codewire_daemon_proto::DAEMON_CAPABILITY_CREDENTIAL_BRIDGE;
    use codewire_daemon_proto::codewire::bridge::v1::credential_bridge_guest_message::Payload as GuestPayload;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::sync::oneshot;
    use tokio_stream::wrappers::TcpListenerStream;

    use super::*;
    use crate::client::{SessionClient, SessionClientError};
    use crate::execution::ProcessExecution;
    use crate::{Config, serve_grpc_with_incoming};

    const TEST_TOKEN: &str = "credential-bridge-test-generation-token";

    struct Harness {
        _temp: tempfile::TempDir,
        endpoint: String,
        socket: PathBuf,
        environment_id: uuid::Uuid,
        generation: u64,
        shutdown: Option<oneshot::Sender<()>>,
        server: tokio::task::JoinHandle<anyhow::Result<()>>,
    }

    impl Harness {
        async fn start() -> Self {
            let temp = tempfile::tempdir().expect("harness tempdir");
            let workspace_root = temp.path().join("workspace");
            let home_root = temp.path().join("home");
            let socket = temp.path().join("credential.sock");
            std::fs::create_dir_all(&workspace_root).expect("workspace root");
            std::fs::create_dir_all(&home_root).expect("home root");
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("daemon listener");
            let endpoint = format!("http://{}", listener.local_addr().expect("daemon address"));
            let environment_id = uuid::Uuid::new_v4();
            let generation = 7;
            let config = Config {
                listen_addr: "injected:credential-bridge".to_owned(),
                workspace_root,
                home_root,
                auth_token: crate::DaemonAuthToken::new(TEST_TOKEN).unwrap(),
                process_execution: ProcessExecution::Native,
                host: None,
                launch_projection: None,
                credential_bridge: Some(CredentialBridgeConfig {
                    transport: crate::CredentialBridgeTransport::Local,
                    environment_id,
                    environment_generation: generation,
                    ingress_socket: socket.clone(),
                    ingress_uid: unsafe { libc::geteuid() },
                    ingress_gid: unsafe { libc::getegid() },
                }),
                managed_credential_clients: Default::default(),
            };
            let (shutdown_tx, shutdown_rx) = oneshot::channel();
            let server = tokio::spawn(async move {
                serve_grpc_with_incoming(config, TcpListenerStream::new(listener), async {
                    let _ = shutdown_rx.await;
                })
                .await
            });
            tokio::time::timeout(Duration::from_secs(2), async {
                while !socket.exists() {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("credential ingress readiness");
            let metadata = std::fs::symlink_metadata(&socket).expect("credential socket");
            assert_eq!(metadata.mode() & 0o777, 0o600);
            Self {
                _temp: temp,
                endpoint,
                socket,
                environment_id,
                generation,
                shutdown: Some(shutdown_tx),
                server,
            }
        }

        async fn client(&self, token: &str) -> SessionClient {
            SessionClient::connect(&self.endpoint, token)
                .await
                .expect("daemon client")
        }

        async fn stop(mut self) {
            self.shutdown.take().expect("shutdown sender").send(()).ok();
            self.server
                .await
                .expect("server task")
                .expect("server stop");
            assert!(!self.socket.exists());
        }
    }

    async fn raw_request(socket: PathBuf, body: &'static [u8]) -> Vec<u8> {
        raw_provider_request(socket, "POST", "/v1/responses", "127.0.0.1", body).await
    }

    async fn raw_provider_request(
        socket: PathBuf,
        method: &'static str,
        path: &'static str,
        host: &'static str,
        body: &'static [u8],
    ) -> Vec<u8> {
        let mut stream = UnixStream::connect(socket)
            .await
            .expect("credential ingress");
        let head = format!(
            "{method} {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream
            .write_all(head.as_bytes())
            .await
            .expect("request head");
        stream.write_all(body).await.expect("request body");
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .await
            .expect("HTTP response");
        response
    }

    /// Explicit configuration proves stock-client transport, not automatic
    /// selected-profile bootstrap or provider authorization. The binary must
    /// come from the checksum-verified Codewire image toolchain.
    #[tokio::test]
    #[ignore = "requires the explicitly supplied, verified stock gh 2.97.0 binary"]
    async fn stock_gh_rest_and_graphql_use_authenticated_unix_ingress() {
        use std::process::{Output, Stdio};

        use anyhow::{Context as _, ensure};

        const LIMIT: Duration = Duration::from_secs(5);

        async fn capture(child: &mut tokio::process::Child) -> anyhow::Result<Output> {
            let stdout = child.stdout.take().context("stock gh stdout")?;
            let stderr = child.stderr.take().context("stock gh stderr")?;
            let read = |stream: Box<dyn tokio::io::AsyncRead + Unpin + Send>| async move {
                let mut bytes = Vec::new();
                stream.take(16_385).read_to_end(&mut bytes).await?;
                anyhow::ensure!(bytes.len() <= 16_384, "stock gh output exceeded the bound");
                Ok::<_, anyhow::Error>(bytes)
            };
            let (status, stdout, stderr) = tokio::try_join!(
                async { Ok::<_, anyhow::Error>(child.wait().await?) },
                read(Box::new(stdout)),
                read(Box::new(stderr)),
            )?;
            Ok(Output {
                status,
                stdout,
                stderr,
            })
        }

        fn command(binary: &Path, root: &Path) -> tokio::process::Command {
            let mut command = tokio::process::Command::new(binary);
            command
                .env_clear()
                .env("HOME", root)
                .env("XDG_CONFIG_HOME", root)
                .env("XDG_CACHE_HOME", root)
                .env("GH_CONFIG_DIR", root)
                .env("TMPDIR", root)
                .env("GH_HOST", "github.com")
                .env("GH_TOKEN", "codewire-managed")
                .env("GH_NO_UPDATE_NOTIFIER", "1")
                .env("GH_NO_EXTENSION_UPDATE_NOTIFIER", "1")
                .current_dir(root)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .kill_on_drop(true);
            command
        }

        let binary = PathBuf::from(
            std::env::var_os("CODEWIRE_TEST_GH_BIN").expect("CODEWIRE_TEST_GH_BIN is required"),
        );
        assert!(
            binary.is_absolute() && binary.is_file(),
            "verified gh must be an absolute file"
        );
        let root = tempfile::tempdir().expect("isolated stock gh config");
        let mut version = command(&binary, root.path())
            .arg("--version")
            .spawn()
            .unwrap();
        let result = tokio::time::timeout(LIMIT, capture(&mut version)).await;
        if !matches!(&result, Ok(Ok(_))) {
            version.kill().await.ok();
            version.wait().await.ok();
        }
        let version = result
            .expect("stock gh version deadline")
            .expect("stock gh version");
        assert!(version.status.success());
        assert!(
            version.stdout.starts_with(b"gh version 2.97.0 ("),
            "stock gh version mismatch"
        );

        let harness = Harness::start().await;
        // The pinned client's current public schema avoids its legacy-config
        // migration; keep the unchanged-config assertion below meaningful.
        let config = format!(
            "version: 1\nhttp_unix_socket: {}\n",
            harness.socket.display()
        );
        std::fs::write(root.path().join("config.yml"), &config).unwrap();
        let client = harness.client(TEST_TOKEN).await;
        let mut bridge = tokio::time::timeout(
            LIMIT,
            client.open_credential_bridge(harness.environment_id, harness.generation),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(matches!(
            tokio::time::timeout(LIMIT, bridge.receive())
                .await
                .unwrap()
                .unwrap()
                .unwrap()
                .payload,
            Some(GuestPayload::Ready(_))
        ));

        let proof = async {
            for (args, method, path, response, expected) in [
                (
                    vec!["api", "user", "--jq", ".login"],
                    "GET",
                    "/user",
                    br#"{"login":"transport-fixture"}"#.as_slice(),
                    b"transport-fixture\n".as_slice(),
                ),
                (
                    vec![
                        "api",
                        "graphql",
                        "-f",
                        "query=query { viewer { login } }",
                        "--jq",
                        ".data.viewer.login",
                    ],
                    "POST",
                    "/graphql",
                    br#"{"data":{"viewer":{"login":"transport-fixture"}}}"#.as_slice(),
                    b"transport-fixture\n".as_slice(),
                ),
            ] {
                let mut child = command(&binary, root.path()).args(args).spawn()?;
                let result = tokio::time::timeout(LIMIT, async {
                    let message = bridge.receive().await?.context("stock gh request frame")?;
                    let Some(GuestPayload::Request(request)) = message.payload else {
                        anyhow::bail!("stock gh did not send a provider request");
                    };
                    ensure!(request.capability_slot == "github" && request.route == "github-api");
                    ensure!(
                        request.method == method
                            && request.path == path
                            && request.query.is_empty()
                    );
                    if method == "POST" {
                        let body: serde_json::Value = serde_json::from_slice(&request.body)?;
                        ensure!(body == serde_json::json!({"query": "query { viewer { login } }"}));
                    } else {
                        ensure!(request.body.is_empty());
                    }
                    bridge
                        .send_response_start(v1::CredentialBridgeResponseStart {
                            request_id: request.request_id.clone(),
                            status_code: 200,
                            headers: vec![v1::CredentialHttpHeader {
                                name: "content-type".into(),
                                value: b"application/json".to_vec(),
                            }],
                        })
                        .await?;
                    bridge
                        .send_response_body(v1::CredentialBridgeResponseBody {
                            request_id: request.request_id.clone(),
                            data: response.to_vec(),
                        })
                        .await?;
                    bridge
                        .send_response_end(v1::CredentialBridgeResponseEnd {
                            request_id: request.request_id,
                        })
                        .await?;
                    let output = capture(&mut child).await?;
                    ensure!(output.status.success(), "stock gh returned a failure");
                    ensure!(
                        output.stdout == expected && output.stderr.is_empty(),
                        "unexpected stock gh output"
                    );
                    Ok::<_, anyhow::Error>(())
                })
                .await;
                if !matches!(&result, Ok(Ok(_))) {
                    child.kill().await.ok();
                    child.wait().await.ok();
                }
                result.context("stock gh transport deadline")??;
            }
            ensure!(std::fs::read_to_string(root.path().join("config.yml"))? == config);
            ensure!(
                !root.path().join("hosts.yml").exists(),
                "stock gh saved authentication"
            );
            Ok::<_, anyhow::Error>(())
        }
        .await;
        drop(bridge);
        harness.stop().await;
        proof.expect("explicitly configured stock gh transport proof");
    }

    #[tokio::test]
    async fn authenticated_unix_ingress_routes_stock_clients_and_rejects_unknown_destinations() {
        let harness = Harness::start().await;
        let client = harness.client(TEST_TOKEN).await;
        let mut bridge = client
            .open_credential_bridge(harness.environment_id, harness.generation)
            .await
            .unwrap();
        assert!(matches!(
            bridge.receive().await.unwrap().unwrap().payload,
            Some(GuestPayload::Ready(_))
        ));
        for (method, uri, host, slot, route, path, query) in [
            (
                "POST",
                "/v1/responses",
                "localhost",
                "codex",
                "openai-api",
                "/responses",
                "",
            ),
            (
                "POST",
                "/_codewire/openai/v1/responses",
                "localhost",
                "openai",
                "openai-api",
                "/responses",
                "",
            ),
            (
                "POST",
                "/_codewire/anthropic/v1/messages?beta=true",
                "localhost",
                "anthropic",
                "anthropic-api",
                "/v1/messages",
                "beta=true",
            ),
            (
                "GET",
                "/_codewire/github/owner/repo.git/info/refs?service=git-upload-pack",
                "localhost",
                "github",
                "github-https",
                "/owner/repo.git/info/refs",
                "service=git-upload-pack",
            ),
            (
                "GET",
                "/repos/owner/repo/issues?state=open",
                "api.github.com",
                "github",
                "github-api",
                "/repos/owner/repo/issues",
                "state=open",
            ),
        ] {
            let http = tokio::spawn(raw_provider_request(
                harness.socket.clone(),
                method,
                uri,
                host,
                b"{}",
            ));
            let request = tokio::time::timeout(Duration::from_secs(5), bridge.receive())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            let Some(GuestPayload::Request(request)) = request.payload else {
                panic!("expected provider request");
            };
            assert_eq!(
                (
                    request.capability_slot.as_str(),
                    request.route.as_str(),
                    request.method.as_str(),
                    request.path.as_str(),
                    request.query.as_str()
                ),
                (slot, route, method, path, query)
            );
            bridge
                .send_response_start(v1::CredentialBridgeResponseStart {
                    request_id: request.request_id.clone(),
                    status_code: 204,
                    headers: vec![],
                })
                .await
                .unwrap();
            bridge
                .send_response_end(v1::CredentialBridgeResponseEnd {
                    request_id: request.request_id,
                })
                .await
                .unwrap();
            assert!(
                tokio::time::timeout(Duration::from_secs(5), http)
                    .await
                    .unwrap()
                    .unwrap()
                    .starts_with(b"HTTP/1.1 204 No Content")
            );
        }
        for (uri, host) in [
            ("/v2/unknown", "localhost"),
            ("/repos/owner/repo/issues", "foreign.invalid"),
            ("http://foreign.invalid/v1/responses", "localhost"),
            ("/v1/responses", "api.github.com"),
        ] {
            let response = tokio::time::timeout(
                Duration::from_secs(5),
                raw_provider_request(harness.socket.clone(), "POST", uri, host, b"{}"),
            )
            .await
            .unwrap();
            assert!(response.starts_with(b"HTTP/1.1 403 Forbidden"));
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(20), bridge.receive())
                .await
                .is_err()
        );
        drop(bridge);
        harness.stop().await;
    }

    #[tokio::test]
    async fn authenticated_bridge_carries_only_bounded_guest_request_and_redacted_response() {
        let harness = Harness::start().await;

        let unavailable = raw_request(harness.socket.clone(), br#"{"model":"synthetic"}"#).await;
        assert!(
            unavailable.starts_with(b"HTTP/1.1 503 Service Unavailable"),
            "unexpected unavailable response: {}",
            String::from_utf8_lossy(&unavailable)
        );

        let client = harness.client(TEST_TOKEN).await;
        let capabilities = client
            .get_capabilities(&[DAEMON_CAPABILITY_CREDENTIAL_BRIDGE])
            .await
            .expect("credential bridge capability");
        assert!(
            capabilities
                .capabilities
                .iter()
                .any(|capability| capability == DAEMON_CAPABILITY_CREDENTIAL_BRIDGE)
        );
        let mut bridge = client
            .open_credential_bridge(harness.environment_id, harness.generation)
            .await
            .expect("open credential bridge");
        let ready = bridge.receive().await.expect("ready frame").expect("ready");
        let Some(GuestPayload::Ready(ready)) = ready.payload else {
            panic!("first credential bridge frame was not ready");
        };
        assert_eq!(ready.environment_id, harness.environment_id.to_string());
        assert_eq!(ready.environment_generation, harness.generation);

        let request_task = tokio::spawn(raw_request(
            harness.socket.clone(),
            br#"{"model":"synthetic"}"#,
        ));
        let request = bridge
            .receive()
            .await
            .expect("request frame")
            .expect("request");
        let Some(GuestPayload::Request(request)) = request.payload else {
            panic!("credential bridge did not carry a request");
        };
        assert_eq!(request.method, "POST");
        assert_eq!(request.path, "/responses");
        assert!(request.query.is_empty());
        assert_eq!(request.body, br#"{"model":"synthetic"}"#);
        assert!(
            request
                .headers
                .iter()
                .any(|header| header.name == "content-type" && header.value == b"application/json")
        );
        assert!(request.headers.iter().all(|header| {
            !matches!(
                header.name.as_str(),
                "content-length" | "connection" | "transfer-encoding"
            )
        }));

        bridge
            .send_response_start(v1::CredentialBridgeResponseStart {
                request_id: request.request_id.clone(),
                status_code: 200,
                headers: vec![v1::CredentialHttpHeader {
                    name: "content-type".to_owned(),
                    value: b"text/event-stream".to_vec(),
                }],
            })
            .await
            .expect("response start");
        for data in [b"data: synthetic".as_slice(), b" response\n\n".as_slice()] {
            bridge
                .send_response_body(v1::CredentialBridgeResponseBody {
                    request_id: request.request_id.clone(),
                    data: data.to_vec(),
                })
                .await
                .expect("response body");
        }
        bridge
            .send_response_end(v1::CredentialBridgeResponseEnd {
                request_id: request.request_id,
            })
            .await
            .expect("response end");

        let response = request_task.await.expect("request task");
        assert!(response.starts_with(b"HTTP/1.1 200 OK"));
        assert!(
            response
                .windows(b"content-type: text/event-stream".len())
                .any(|window| window == b"content-type: text/event-stream")
        );
        for chunk in [b"data: synthetic".as_slice(), b" response\n\n".as_slice()] {
            assert!(
                response.windows(chunk.len()).any(|window| window == chunk),
                "streamed response chunk was absent: {}",
                String::from_utf8_lossy(&response)
            );
        }

        drop(bridge);
        harness.stop().await;
    }

    #[tokio::test]
    async fn bridge_rejects_wrong_generation_identity_and_daemon_token() {
        let harness = Harness::start().await;
        let client = harness.client(TEST_TOKEN).await;
        let wrong_identity = match client
            .open_credential_bridge(uuid::Uuid::new_v4(), harness.generation)
            .await
        {
            Ok(_) => panic!("wrong environment must fail"),
            Err(error) => error,
        };
        assert!(matches!(
            wrong_identity,
            SessionClientError::Status(status)
                if status.code() == tonic::Code::FailedPrecondition
        ));

        let wrong_generation = match client
            .open_credential_bridge(harness.environment_id, harness.generation + 1)
            .await
        {
            Ok(_) => panic!("wrong generation must fail"),
            Err(error) => error,
        };
        assert!(matches!(
            wrong_generation,
            SessionClientError::Status(status)
                if status.code() == tonic::Code::FailedPrecondition
        ));

        let wrong_token = harness.client("wrong-generation-token").await;
        let error = match wrong_token
            .open_credential_bridge(harness.environment_id, harness.generation)
            .await
        {
            Ok(_) => panic!("wrong token must fail"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            SessionClientError::Status(status) if status.code() == tonic::Code::Unauthenticated
        ));
        harness.stop().await;
    }

    /// Local transport keeps fail-pending replacement; the hosted transport
    /// drains instead (`hosted_replacement_completes_the_request_pending_on_
    /// the_replaced_epoch`).
    #[tokio::test]
    async fn local_replacement_closes_stale_stream_and_fails_its_pending_request() {
        let harness = Harness::start().await;
        let client = harness.client(TEST_TOKEN).await;
        let mut first = client
            .open_credential_bridge(harness.environment_id, harness.generation)
            .await
            .expect("first bridge");
        assert!(matches!(
            first.receive().await.unwrap().unwrap().payload,
            Some(GuestPayload::Ready(_))
        ));
        let request_task = tokio::spawn(raw_request(harness.socket.clone(), b"{}"));
        assert!(matches!(
            first.receive().await.unwrap().unwrap().payload,
            Some(GuestPayload::Request(_))
        ));

        let mut second = client
            .open_credential_bridge(harness.environment_id, harness.generation)
            .await
            .expect("replacement bridge");
        assert!(matches!(
            second.receive().await.unwrap().unwrap().payload,
            Some(GuestPayload::Ready(_))
        ));
        let response = request_task.await.expect("pending request");
        assert!(response.starts_with(b"HTTP/1.1 503 Service Unavailable"));
        assert!(first.receive().await.unwrap().is_none());

        harness.stop().await;
    }

    #[tokio::test]
    async fn out_of_order_host_body_fails_closed_and_detaches_the_bridge() {
        let harness = Harness::start().await;
        let client = harness.client(TEST_TOKEN).await;
        let mut bridge = client
            .open_credential_bridge(harness.environment_id, harness.generation)
            .await
            .expect("bridge");
        assert!(matches!(
            bridge.receive().await.unwrap().unwrap().payload,
            Some(GuestPayload::Ready(_))
        ));

        let request_task = tokio::spawn(raw_request(harness.socket.clone(), b"{}"));
        let request = bridge
            .receive()
            .await
            .expect("request frame")
            .expect("request");
        let Some(GuestPayload::Request(request)) = request.payload else {
            panic!("credential bridge did not carry a request");
        };
        bridge
            .send_response_body(v1::CredentialBridgeResponseBody {
                request_id: request.request_id,
                data: b"body-before-start".to_vec(),
            })
            .await
            .expect("enqueue malformed host frame");

        assert!(matches!(
            bridge.receive().await,
            Err(SessionClientError::Status(status))
                if status.code() == tonic::Code::InvalidArgument
        ));
        let response = request_task.await.expect("pending request");
        assert!(response.starts_with(b"HTTP/1.1 503 Service Unavailable"));

        harness.stop().await;
    }
}
