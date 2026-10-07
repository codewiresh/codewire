//! One-shot HTTPS or selected-key SSH repository preparation for the local runtime.
//!
//! The public authority socket carries only normalized repository intent and
//! credential-free bundle output. A separate authority-created inherited
//! stream admits one exact profile revision to one isolated executor. GitHub
//! OAuth executors read one admitted generation from protected storage; SSH
//! executors receive only canonical public trust and typed signing responses.

use std::ffi::OsStr;
use std::io;
use std::os::unix::ffi::OsStrExt as _;
use std::panic::AssertUnwindSafe;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};

use codewire_access::{
    AccessProfileId, BrokerOperationId, BrokerRouteId, CredentialAuthKind, GrantPermission,
};
use codewire_project::{canonical_repository_known_hosts, parse_repository_ssh_host};
use codewire_protected_store::{ProtectedStore, ProtectedValue};
use futures::FutureExt as _;
use hyper_util::rt::TokioIo;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::UnixStream;
use tokio::sync::{Mutex, oneshot};
use tokio_stream::{StreamExt as _, once, pending};
use tonic::transport::server::Connected;
use tonic::transport::{Channel, Endpoint, Server};
use tonic::{Request, Response, Status};
use url::Url;
use uuid::Uuid;

mod executor;
mod platform;
mod platform_ingress;
mod ssh;
mod ssh_executor;

pub use executor::{
    LocalRepositoryGitProcessSpawner, MAX_GIT_BUNDLE_BYTES, RepositoryExecutorError,
    run_git_credential_helper, run_git_credential_helper_for_endpoint,
    run_local_repository_executor,
};
pub(crate) use executor::{
    cleanup_repository_staging, create_repository_staging, prepared_bundle_path,
    read_prepared_repository, remove_repository_staging,
};
pub(crate) use platform::{PlatformRepositoryConnection, RepositoryPlatformCheckout};
pub use platform::{RepositoryPlatformAccess, run_platform_repository_executor};
pub use ssh::RepositorySshCheckoutIntent;
pub use ssh_executor::{
    SSH_HELPER_BASENAME, SSH_HELPER_HOST_ENV, SSH_HELPER_OWNER_ENV, SSH_HELPER_PORT_ENV,
    SSH_HELPER_RUNTIME_ENV, run_local_ssh_repository_executor,
};

use crate::client::credential_from_proto;
use crate::control::v1;
use crate::control::v1::local_credential_repository_lease_service_client::LocalCredentialRepositoryLeaseServiceClient;
use crate::control::v1::local_credential_repository_lease_service_server::{
    LocalCredentialRepositoryLeaseService, LocalCredentialRepositoryLeaseServiceServer,
};
use crate::service::credential_to_proto;
use crate::{
    CredentialRecord, LocalCredentialAuthority, LocalCredentialError,
    RepositoryCredentialLeaseRequest, protected_entry_id,
};

const REPOSITORY_LEASE_REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
const MAX_REPOSITORY_LEASE_RPC_MESSAGE_BYTES: usize = 128 * 1024;
pub const REPOSITORY_LEASE_PROTOCOL_VERSION: u32 = 3;
pub const REPOSITORY_SSH_RUNTIME_PREFIX: &str = "ssh-";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalRepositoryTransport {
    GitHubOAuth,
    Ssh,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalRepositoryProcessConfig {
    pub request_id: Uuid,
    pub staging_directory: PathBuf,
    pub transport: LocalRepositoryTransport,
    pub platform_delegated: bool,
    pub ssh_runtime_directory: Option<PathBuf>,
}

impl LocalRepositoryProcessConfig {
    pub(crate) fn validate(&self) -> Result<(), LocalRepositorySpawnError> {
        let Some(name) = self.staging_directory.file_name().and_then(OsStr::to_str) else {
            return Err(LocalRepositorySpawnError::InvalidConfiguration);
        };
        let Some(id) = name.strip_prefix("repository-executor-") else {
            return Err(LocalRepositorySpawnError::InvalidConfiguration);
        };
        let valid_ssh_runtime = match (&self.transport, &self.ssh_runtime_directory) {
            (LocalRepositoryTransport::GitHubOAuth, None) => true,
            (LocalRepositoryTransport::Ssh, Some(path)) => {
                validate_repository_ssh_runtime_path(path).is_ok()
            }
            _ => false,
        };
        if self.request_id.is_nil()
            || !self.staging_directory.is_absolute()
            || Uuid::parse_str(id).is_err()
            || Uuid::parse_str(id).is_ok_and(|parsed| parsed.to_string() != id)
            || !valid_ssh_runtime
        {
            return Err(LocalRepositorySpawnError::InvalidConfiguration);
        }
        Ok(())
    }
}

pub fn validate_repository_ssh_runtime_path(path: &Path) -> Result<(), LocalRepositorySpawnError> {
    let name = path
        .file_name()
        .and_then(OsStr::to_str)
        .and_then(|name| name.strip_prefix(REPOSITORY_SSH_RUNTIME_PREFIX))
        .ok_or(LocalRepositorySpawnError::InvalidConfiguration)?;
    if !Uuid::parse_str(name).is_ok_and(|id| !id.is_nil() && id.to_string() == name) {
        return Err(LocalRepositorySpawnError::InvalidConfiguration);
    }
    let bytes = path.as_os_str().as_bytes();
    let socket_bytes = path.join("agent");
    if !path.is_absolute()
        || bytes.is_empty()
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-'))
        || socket_bytes.as_os_str().as_bytes().len() >= 108
    {
        return Err(LocalRepositorySpawnError::InvalidConfiguration);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum LocalRepositorySpawnError {
    #[error("local repository executor launch configuration is invalid")]
    InvalidConfiguration,
    #[error("spawn local repository executor failed")]
    Spawn,
}

/// Authority-owned one-shot repository executor launcher. The lease stream is
/// transferred directly into the child and never exposed at a socket path.
/// An SSH executor must be its own process-group leader and expose piped
/// stderr; the authority reserves that leader until it has killed the exact
/// group, reaped the child, and observed stderr EOF from every descendant.
pub trait LocalRepositoryProcessSpawner: Send + Sync + 'static {
    fn spawn(
        &self,
        config: &LocalRepositoryProcessConfig,
        authority_peer: std::os::unix::net::UnixStream,
    ) -> Result<tokio::process::Child, LocalRepositorySpawnError>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PreparedRepositoryMetadata {
    pub branch: String,
    pub commit: String,
    pub bundle_size: u64,
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum RepositoryLeaseChannelError {
    #[error("repository credential lease request is invalid")]
    InvalidRequest,
    #[error("repository credential lease was denied")]
    Denied,
    #[error("repository credential lease authority is unavailable")]
    Unavailable,
    #[error("repository credential lease authority returned invalid metadata")]
    InvalidResponse,
}

/// Non-cloneable credential lease held only by the one-shot repository
/// executor. Debug output never renders the protected value.
pub struct RepositoryCredentialLease {
    pub credential: CredentialRecord,
    pub profile_id: AccessProfileId,
    pub profile_revision: u64,
    pub permission: GrantPermission,
    pub source: String,
    pub branch: String,
    pub revision: String,
    material_generation: u64,
    value: ProtectedValue,
}

impl RepositoryCredentialLease {
    pub(crate) fn material(&self) -> &[u8] {
        self.value.expose_secret()
    }
}

impl std::fmt::Debug for RepositoryCredentialLease {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RepositoryCredentialLease")
            .field("credential", &self.credential)
            .field("profile_id", &self.profile_id)
            .field("profile_revision", &self.profile_revision)
            .field("permission", &self.permission)
            .field("source", &self.source)
            .field("branch", &self.branch)
            .field("revision", &self.revision)
            .field("material_generation", &self.material_generation)
            .field("value", &"[REDACTED]")
            .finish()
    }
}

/// Client for the unnameable, authority-created repository lease channel.
pub struct LocalCredentialRepositoryLeaseClient {
    inner: LocalCredentialRepositoryLeaseServiceClient<Channel>,
    request_id: Uuid,
}

impl LocalCredentialRepositoryLeaseClient {
    pub async fn connect(
        stream: UnixStream,
        request_id: Uuid,
    ) -> Result<Self, RepositoryLeaseChannelError> {
        if request_id.is_nil() {
            return Err(RepositoryLeaseChannelError::InvalidRequest);
        }
        let stream = Arc::new(Mutex::new(Some(stream)));
        let channel = Endpoint::from_static("http://codewire-local-repository-lease")
            .timeout(REPOSITORY_LEASE_REQUEST_TIMEOUT)
            .connect_with_connector(tower::service_fn(move |_| {
                let stream = Arc::clone(&stream);
                async move {
                    stream.lock().await.take().map(TokioIo::new).ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::NotConnected,
                            "repository lease channel already consumed",
                        )
                    })
                }
            }))
            .await
            .map_err(|_| RepositoryLeaseChannelError::Unavailable)?;
        Ok(Self {
            inner: LocalCredentialRepositoryLeaseServiceClient::new(channel)
                .max_decoding_message_size(MAX_REPOSITORY_LEASE_RPC_MESSAGE_BYTES)
                .max_encoding_message_size(MAX_REPOSITORY_LEASE_RPC_MESSAGE_BYTES),
            request_id,
        })
    }

    pub async fn report_ready(&mut self) -> Result<(), RepositoryLeaseChannelError> {
        self.inner
            .report_repository_executor_ready(v1::RepositoryExecutorReadyRequest {
                protocol_version: REPOSITORY_LEASE_PROTOCOL_VERSION,
            })
            .await
            .map_err(map_client_status)?;
        Ok(())
    }

    pub(crate) async fn brokered_checkout(
        &mut self,
    ) -> Result<v1::RepositoryBrokeredCheckoutResponse, Status> {
        self.inner
            .get_repository_brokered_checkout(v1::RepositoryCredentialLeaseRequest {
                request_id: self.request_id.to_string(),
            })
            .await
            .map(Response::into_inner)
    }

    pub async fn lease_github<S>(
        &mut self,
        protected_store: S,
    ) -> Result<RepositoryCredentialLease, RepositoryLeaseChannelError>
    where
        S: ProtectedStore + Clone + 'static,
    {
        let response = self
            .inner
            .lease_repository_credential(v1::RepositoryCredentialLeaseRequest {
                request_id: self.request_id.to_string(),
            })
            .await
            .map_err(map_client_status)?
            .into_inner();
        let credential = response
            .credential
            .ok_or(RepositoryLeaseChannelError::InvalidResponse)
            .and_then(|credential| {
                credential_from_proto(credential)
                    .map_err(|_| RepositoryLeaseChannelError::InvalidResponse)
            })?;
        let profile_id = AccessProfileId::parse(response.profile_id)
            .map_err(|_| RepositoryLeaseChannelError::InvalidResponse)?;
        let permission = response
            .permission
            .ok_or(RepositoryLeaseChannelError::InvalidResponse)
            .and_then(permission_from_proto)?;
        let expected_permission = github_fetch_permission();
        if response.profile_revision == 0
            || response.material_generation == 0
            || credential.persistence != protected_store.persistence()
            || credential.metadata.provider.as_str() != "github"
            || credential.metadata.authentication_kind != CredentialAuthKind::OAuth
            || permission != expected_permission
            || validate_github_https_source(&response.source).is_err()
            || (!response.branch.is_empty() && !valid_git_selector(&response.branch))
            || (!response.revision.is_empty() && !valid_git_selector(&response.revision))
            || (!response.branch.is_empty() && !response.revision.is_empty())
        {
            return Err(RepositoryLeaseChannelError::InvalidResponse);
        }
        let entry_id = protected_entry_id(&credential.metadata.id, response.material_generation)
            .map_err(|_| RepositoryLeaseChannelError::InvalidResponse)?;
        let store = protected_store;
        let value = tokio::task::spawn_blocking(move || store.get(&entry_id))
            .await
            .map_err(|_| RepositoryLeaseChannelError::Unavailable)?
            .map_err(|_| RepositoryLeaseChannelError::Unavailable)?
            .ok_or(RepositoryLeaseChannelError::Unavailable)?;
        Ok(RepositoryCredentialLease {
            credential,
            profile_id,
            profile_revision: response.profile_revision,
            permission,
            source: response.source,
            branch: response.branch,
            revision: response.revision,
            material_generation: response.material_generation,
            value,
        })
    }
}

pub(crate) async fn serve_repository_lease_channel_with_ready<S>(
    authority: Arc<LocalCredentialAuthority<S>>,
    stream: UnixStream,
    authorization: RepositoryCredentialLeaseRequest,
    ssh_runtime: Arc<crate::broker_channel::LocalSshOperationRuntime>,
    platform: Option<Arc<RepositoryPlatformCheckout>>,
    ready: oneshot::Sender<()>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<(), RepositoryLeaseChannelError>
where
    S: ProtectedStore + 'static,
{
    if validate_repository_lease_request(&authorization).is_err() {
        return Err(RepositoryLeaseChannelError::InvalidRequest);
    }
    let lifetime = Arc::new(RepositoryLeaseLifetime::new(ssh_runtime));
    let service = RepositoryLeaseRpc {
        authority,
        authorization,
        platform,
        ready: Mutex::new(Some(ready)),
        ready_reported: AtomicBool::new(false),
        leased: AtomicBool::new(false),
        ssh_intent_issued: AtomicBool::new(false),
        lifetime: Arc::clone(&lifetime),
    };
    let (closed_tx, closed_rx) = oneshot::channel();
    let incoming = once(Ok::<_, io::Error>(ObservedRepositoryStream {
        inner: stream,
        closed: Some(closed_tx),
    }))
    .chain(pending());
    let closing_lifetime = Arc::clone(&lifetime);
    let result = AssertUnwindSafe(
        Server::builder()
            .concurrency_limit_per_connection(1)
            .add_service(
                LocalCredentialRepositoryLeaseServiceServer::new(service)
                    .max_decoding_message_size(MAX_REPOSITORY_LEASE_RPC_MESSAGE_BYTES)
                    .max_encoding_message_size(MAX_REPOSITORY_LEASE_RPC_MESSAGE_BYTES),
            )
            .serve_with_incoming_shutdown(incoming, async move {
                tokio::select! {
                    _ = closed_rx => {}
                    _ = async {
                        while !*shutdown.borrow_and_update() {
                            if shutdown.changed().await.is_err() {
                                break;
                            }
                        }
                    } => {}
                }
                closing_lifetime.closed.store(true, Ordering::Release);
                closing_lifetime.ssh.cancel_all();
            }),
    )
    .catch_unwind()
    .await
    .map_err(|_| RepositoryLeaseChannelError::Unavailable)
    .and_then(|result| result.map_err(|_| RepositoryLeaseChannelError::Unavailable));
    // This owner outlives tonic's shutdown future and dropped RPC futures.
    // A metadata admission already running in spawn_blocking keeps its permit
    // until it actually returns (and latches panic before releasing capacity).
    result.and(lifetime.close_and_drain().await)
}

struct RepositoryLeaseLifetime {
    operations: Arc<tokio::sync::Semaphore>,
    closed: AtomicBool,
    failed: AtomicBool,
    ssh: ssh::RepositorySshOperations,
}

impl RepositoryLeaseLifetime {
    fn new(ssh_runtime: Arc<crate::broker_channel::LocalSshOperationRuntime>) -> Self {
        Self {
            operations: Arc::new(tokio::sync::Semaphore::new(1)),
            closed: AtomicBool::new(false),
            failed: AtomicBool::new(false),
            ssh: ssh::RepositorySshOperations::new(ssh_runtime),
        }
    }

    fn ensure_open(&self) -> Result<(), Status> {
        if self.closed.load(Ordering::Acquire) || self.failed.load(Ordering::Acquire) {
            Err(Status::unavailable(
                "repository credential channel is closed",
            ))
        } else {
            Ok(())
        }
    }

    async fn close_and_drain(&self) -> Result<(), RepositoryLeaseChannelError> {
        self.closed.store(true, Ordering::Release);
        self.ssh.cancel_all();
        let drained = Arc::clone(&self.operations)
            .acquire_owned()
            .await
            .map_err(|_| RepositoryLeaseChannelError::Unavailable)?;
        let failed = self.failed.load(Ordering::Acquire) || self.ssh.failed();
        drop(drained);
        if failed {
            Err(RepositoryLeaseChannelError::Unavailable)
        } else {
            Ok(())
        }
    }

    fn acquire(self: &Arc<Self>) -> Result<RepositoryLeaseOperation, Status> {
        self.ensure_open()?;
        let permit = Arc::clone(&self.operations)
            .try_acquire_owned()
            .map_err(|_| Status::unavailable("repository credential channel is busy"))?;
        self.ensure_open()?;
        Ok(RepositoryLeaseOperation {
            lifetime: Arc::clone(self),
            permit: Some(permit),
        })
    }
}

struct RepositoryLeaseOperation {
    lifetime: Arc<RepositoryLeaseLifetime>,
    permit: Option<tokio::sync::OwnedSemaphorePermit>,
}

impl Drop for RepositoryLeaseOperation {
    fn drop(&mut self) {
        if std::thread::panicking() {
            self.lifetime.failed.store(true, Ordering::Release);
        }
        drop(self.permit.take());
    }
}

struct RepositoryLeaseRpc<S: ProtectedStore> {
    authority: Arc<LocalCredentialAuthority<S>>,
    authorization: RepositoryCredentialLeaseRequest,
    platform: Option<Arc<RepositoryPlatformCheckout>>,
    ready: Mutex<Option<oneshot::Sender<()>>>,
    ready_reported: AtomicBool,
    leased: AtomicBool,
    ssh_intent_issued: AtomicBool,
    lifetime: Arc<RepositoryLeaseLifetime>,
}

#[tonic::async_trait]
impl<S> LocalCredentialRepositoryLeaseService for RepositoryLeaseRpc<S>
where
    S: ProtectedStore + 'static,
{
    async fn report_repository_executor_ready(
        &self,
        request: Request<v1::RepositoryExecutorReadyRequest>,
    ) -> Result<Response<v1::RepositoryExecutorReadyResponse>, Status> {
        self.lifetime.ensure_open()?;
        if request.into_inner().protocol_version != REPOSITORY_LEASE_PROTOCOL_VERSION {
            return Err(Status::failed_precondition(
                "repository executor lease protocol is incompatible",
            ));
        }
        let ready =
            self.ready.lock().await.take().ok_or_else(|| {
                Status::failed_precondition("repository executor is already ready")
            })?;
        ready
            .send(())
            .map_err(|_| Status::unavailable("repository executor launch was cancelled"))?;
        self.ready_reported.store(true, Ordering::Release);
        Ok(Response::new(v1::RepositoryExecutorReadyResponse {}))
    }

    async fn lease_repository_credential(
        &self,
        request: Request<v1::RepositoryCredentialLeaseRequest>,
    ) -> Result<Response<v1::RepositoryCredentialLeaseResponse>, Status> {
        let request_id = parse_canonical_uuid(&request.into_inner().request_id)?;
        if !self.ready_reported.load(Ordering::Acquire)
            || self.platform.is_some()
            || request_id != self.authorization.request_id
            || validate_repository_lease_request(&self.authorization)
                != Ok(LocalRepositoryTransport::GitHubOAuth)
            || self.leased.swap(true, Ordering::AcqRel)
        {
            return Err(Status::permission_denied(
                "repository credential lease was denied",
            ));
        }
        let authority = Arc::clone(&self.authority);
        let authorization = self.authorization.clone();
        let operation = self.lifetime.acquire()?;
        let admission = tokio::task::spawn_blocking(move || {
            let _operation = operation;
            authority.admit_repository_credential_operation(&authorization)
        })
        .await
        .map_err(|_| Status::unavailable("repository credential authority is unavailable"))?
        .map_err(map_server_error)?;
        let crate::RepositoryCredentialAdmission::GitHubOAuth(admission) = admission else {
            return Err(Status::permission_denied(
                "repository credential lease was denied",
            ));
        };
        self.lifetime.ensure_open()?;
        Ok(Response::new(v1::RepositoryCredentialLeaseResponse {
            credential: Some(credential_to_proto(admission.credential)),
            profile_id: admission.profile_id.to_string(),
            profile_revision: admission.profile_revision,
            permission: Some(v1::GrantPermission {
                operation: admission.permission.operation.to_string(),
                route: admission.permission.route.to_string(),
            }),
            material_generation: admission.material_generation,
            source: self.authorization.source.clone(),
            branch: self.authorization.branch.clone(),
            revision: self.authorization.revision.clone(),
        }))
    }

    async fn get_repository_ssh_checkout(
        &self,
        request: Request<v1::RepositorySshCheckoutRequest>,
    ) -> Result<Response<v1::RepositorySshCheckoutResponse>, Status> {
        self.run_ssh_checkout(request.into_inner()).await
    }

    async fn repository_ssh_operation(
        &self,
        request: Request<v1::RepositorySshOperationRequest>,
    ) -> Result<Response<codewire_daemon_proto::codewire::bridge::v1::CredentialSshResponse>, Status>
    {
        self.run_ssh_operation(request.into_inner()).await
    }

    async fn get_repository_brokered_checkout(
        &self,
        request: Request<v1::RepositoryCredentialLeaseRequest>,
    ) -> Result<Response<v1::RepositoryBrokeredCheckoutResponse>, Status> {
        self.lifetime.ensure_open()?;
        let request_id = parse_canonical_uuid(&request.into_inner().request_id)?;
        let platform = self
            .platform
            .as_ref()
            .ok_or_else(|| Status::permission_denied("repository mode mismatch"))?;
        let RepositoryPlatformCheckout::GitHub {
            endpoint,
            capability,
        } = platform.as_ref()
        else {
            return Err(Status::permission_denied("repository mode mismatch"));
        };
        if !self.ready_reported.load(Ordering::Acquire)
            || request_id != self.authorization.request_id
            || self.leased.swap(true, Ordering::AcqRel)
        {
            return Err(Status::permission_denied("repository checkout was denied"));
        }
        Ok(Response::new(v1::RepositoryBrokeredCheckoutResponse {
            source: self.authorization.source.clone(),
            branch: self.authorization.branch.clone(),
            revision: self.authorization.revision.clone(),
            endpoint: endpoint.clone(),
            capability: capability.to_vec(),
        }))
    }
}

struct ObservedRepositoryStream {
    inner: UnixStream,
    closed: Option<oneshot::Sender<()>>,
}

impl Drop for ObservedRepositoryStream {
    fn drop(&mut self) {
        if let Some(closed) = self.closed.take() {
            let _ = closed.send(());
        }
    }
}

impl AsyncRead for ObservedRepositoryStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(context, buffer)
    }
}

impl AsyncWrite for ObservedRepositoryStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(context, buffer)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

impl Connected for ObservedRepositoryStream {
    type ConnectInfo = ();

    fn connect_info(&self) -> Self::ConnectInfo {}
}

/// Run one isolated repository executor after its outer process confinement
/// has been reasserted. Only the inherited lease stream can select material.
fn valid_object_id(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn validate_repository_lease_request(
    request: &RepositoryCredentialLeaseRequest,
) -> Result<LocalRepositoryTransport, RepositoryLeaseChannelError> {
    if request.request_id.is_nil()
        || request.profile_revision == 0
        || (!request.branch.is_empty() && !valid_git_selector(&request.branch))
        || (!request.revision.is_empty() && !valid_git_selector(&request.revision))
        || (!request.branch.is_empty() && !request.revision.is_empty())
    {
        return Err(RepositoryLeaseChannelError::InvalidRequest);
    }
    if validate_github_https_source(&request.source).is_ok() {
        return if request.known_hosts.is_empty() {
            Ok(LocalRepositoryTransport::GitHubOAuth)
        } else {
            Err(RepositoryLeaseChannelError::InvalidRequest)
        };
    }
    if parse_repository_ssh_host(&request.source)
        .map_err(|_| RepositoryLeaseChannelError::InvalidRequest)?
        .is_none()
    {
        return Err(RepositoryLeaseChannelError::InvalidRequest);
    }
    let canonical = canonical_repository_known_hosts(&request.source, request.known_hosts.clone())
        .map_err(|_| RepositoryLeaseChannelError::InvalidRequest)?;
    if canonical != request.known_hosts {
        return Err(RepositoryLeaseChannelError::InvalidRequest);
    }
    Ok(LocalRepositoryTransport::Ssh)
}

pub fn validate_github_https_source(source: &str) -> Result<(), RepositoryLeaseChannelError> {
    if source.len() > 1024 || !source.starts_with("https://github.com/") {
        return Err(RepositoryLeaseChannelError::InvalidRequest);
    }
    let url = Url::parse(source).map_err(|_| RepositoryLeaseChannelError::InvalidRequest)?;
    let mut segments = url
        .path_segments()
        .ok_or(RepositoryLeaseChannelError::InvalidRequest)?;
    let owner = segments.next().unwrap_or_default();
    let repository = segments.next().unwrap_or_default();
    if url.scheme() != "https"
        || url.host_str() != Some("github.com")
        || url.port().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || owner.is_empty()
        || repository.is_empty()
        || segments.next().is_some()
        || !owner.bytes().all(valid_github_path_byte)
        || !repository.bytes().all(valid_github_path_byte)
        || repository == ".git"
    {
        return Err(RepositoryLeaseChannelError::InvalidRequest);
    }
    Ok(())
}

fn valid_github_path_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')
}

pub(crate) fn valid_git_selector(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 1024
        && !value.starts_with('-')
        && !value.ends_with('/')
        && !value.ends_with('.')
        && !value.ends_with(".lock")
        && !value.contains(char::is_whitespace)
        && !value.contains("..")
        && !value.contains("@{")
        && !value.contains("//")
        && !value.contains(['~', '^', ':', '?', '*', '[', '\\'])
}

pub(crate) fn github_fetch_permission() -> GrantPermission {
    GrantPermission {
        operation: BrokerOperationId::parse("git-fetch").expect("canonical Git fetch operation ID"),
        route: BrokerRouteId::parse("github-https").expect("canonical GitHub HTTPS route ID"),
    }
}

fn permission_from_proto(
    permission: v1::GrantPermission,
) -> Result<GrantPermission, RepositoryLeaseChannelError> {
    Ok(GrantPermission {
        operation: BrokerOperationId::parse(permission.operation)
            .map_err(|_| RepositoryLeaseChannelError::InvalidResponse)?,
        route: BrokerRouteId::parse(permission.route)
            .map_err(|_| RepositoryLeaseChannelError::InvalidResponse)?,
    })
}

fn parse_canonical_uuid(value: &str) -> Result<Uuid, Status> {
    let parsed = Uuid::parse_str(value)
        .map_err(|_| Status::invalid_argument("invalid repository lease request"))?;
    if parsed.is_nil() || parsed.to_string() != value {
        return Err(Status::invalid_argument("invalid repository lease request"));
    }
    Ok(parsed)
}

fn map_client_status(status: Status) -> RepositoryLeaseChannelError {
    match status.code() {
        tonic::Code::InvalidArgument => RepositoryLeaseChannelError::InvalidRequest,
        tonic::Code::PermissionDenied | tonic::Code::FailedPrecondition | tonic::Code::NotFound => {
            RepositoryLeaseChannelError::Denied
        }
        _ => RepositoryLeaseChannelError::Unavailable,
    }
}

fn map_server_error(error: LocalCredentialError) -> Status {
    match error {
        LocalCredentialError::CredentialOperationLeaseDenied
        | LocalCredentialError::CredentialInactive
        | LocalCredentialError::CredentialNotFound
        | LocalCredentialError::CredentialUnavailable
        | LocalCredentialError::ProfileNotFound
        | LocalCredentialError::ProfileRevisionNotFound => {
            Status::permission_denied("repository credential lease was denied")
        }
        _ => Status::unavailable("repository credential authority is unavailable"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    #[cfg(target_os = "linux")]
    use std::fs::OpenOptions;
    use std::fs::{self, DirBuilder};
    #[cfg(target_os = "linux")]
    use std::io::Read as _;
    use std::io::Write as _;
    #[cfg(target_os = "linux")]
    use std::os::unix::fs::OpenOptionsExt as _;
    use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
    #[cfg(target_os = "linux")]
    use std::process::Stdio;
    #[cfg(target_os = "linux")]
    use tokio::process::Command;

    #[cfg(target_os = "linux")]
    use super::executor::*;

    use codewire_access::{AccessProfileName, ProviderId};
    use codewire_protected_store::{ProtectedStorePersistence, ProtectedValue};
    use tempfile::TempDir;

    use crate::NewCredential;
    use crate::tests::TestProtectedStore;

    #[test]
    fn repository_transport_requires_one_exact_runtime_shape() {
        let root = PathBuf::from("/run/user/1000/codewire");
        let request_id = Uuid::new_v4();
        let staging = root.join(format!("repository-executor-{request_id}"));
        let runtime = root.join(format!("{REPOSITORY_SSH_RUNTIME_PREFIX}{request_id}"));
        let github = LocalRepositoryProcessConfig {
            request_id,
            staging_directory: staging.clone(),
            transport: LocalRepositoryTransport::GitHubOAuth,
            platform_delegated: false,
            ssh_runtime_directory: None,
        };
        github.validate().unwrap();
        let ssh = LocalRepositoryProcessConfig {
            transport: LocalRepositoryTransport::Ssh,
            ssh_runtime_directory: Some(runtime.clone()),
            ..github.clone()
        };
        ssh.validate().unwrap();

        assert!(
            LocalRepositoryProcessConfig {
                ssh_runtime_directory: None,
                ..ssh.clone()
            }
            .validate()
            .is_err()
        );
        assert!(
            LocalRepositoryProcessConfig {
                ssh_runtime_directory: Some(root.join(format!("ssh bad-{request_id}"))),
                ..ssh
            }
            .validate()
            .is_err()
        );
        assert!(validate_repository_ssh_runtime_path(&runtime).is_ok());
    }

    #[tokio::test]
    async fn channel_drain_retains_blocking_admission_after_its_waiter_is_dropped() {
        let lifetime = Arc::new(RepositoryLeaseLifetime::new(
            crate::broker_channel::LocalSshOperationRuntime::new(None),
        ));
        let operation = lifetime.acquire().unwrap();
        let (release, released) = std::sync::mpsc::channel();
        let (started, running) = oneshot::channel();
        let worker = tokio::task::spawn_blocking(move || {
            let _operation = operation;
            started.send(()).unwrap();
            released.recv().unwrap();
        });
        running.await.unwrap();
        drop(worker);
        let drain = lifetime.close_and_drain();
        tokio::pin!(drain);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(25), &mut drain)
                .await
                .is_err()
        );
        assert!(lifetime.acquire().is_err());
        release.send(()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(1), drain)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn blocking_admission_panic_latches_failure_before_channel_drain() {
        let lifetime = Arc::new(RepositoryLeaseLifetime::new(
            crate::broker_channel::LocalSshOperationRuntime::new(None),
        ));
        let operation = lifetime.acquire().unwrap();
        let worker = tokio::task::spawn_blocking(move || {
            let _operation = operation;
            panic!("synthetic metadata admission panic");
        });
        assert!(worker.await.is_err());
        assert!(lifetime.close_and_drain().await.is_err());
        assert!(lifetime.acquire().is_err());
    }

    #[cfg(target_os = "linux")]
    #[derive(Default)]
    struct SyntheticGitSpawner {
        tokens: Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
        invocations: std::sync::Mutex<Vec<String>>,
    }

    #[cfg(target_os = "linux")]
    impl SyntheticGitSpawner {
        fn take_tokens(&self) -> io::Result<Vec<Vec<u8>>> {
            Ok(self.tokens.lock().unwrap().drain(..).collect())
        }
    }

    #[cfg(target_os = "linux")]
    impl LocalRepositoryGitProcessSpawner for SyntheticGitSpawner {
        fn spawn(&self, command: &mut Command) -> io::Result<tokio::process::Child> {
            let command = command.as_std();
            let arguments = command
                .get_args()
                .map(|argument| argument.to_string_lossy().into_owned())
                .collect::<Vec<_>>();
            let credential_gate = if let Some(socket) = arguments.iter().find_map(|argument| {
                argument
                    .strip_prefix("credential.helper=")?
                    .split_once(" --credential-socket ")
                    .map(|(_, socket)| socket.trim_matches('\''))
            }) {
                let mut channel = std::os::unix::net::UnixStream::connect(socket)?;
                let (gate_reader, gate_writer) = std::os::unix::net::UnixStream::pair()?;
                let tokens = Arc::clone(&self.tokens);
                std::thread::spawn(move || {
                    let mut token = Vec::new();
                    if channel.read_to_end(&mut token).is_ok() {
                        tokens.lock().unwrap().push(token);
                    }
                    drop(gate_writer);
                });
                Some(gate_reader)
            } else {
                None
            };
            let environment = command
                .get_envs()
                .map(|(name, value)| {
                    format!(
                        "{}={}",
                        name.to_string_lossy(),
                        value
                            .map_or_else(String::new, |value| value.to_string_lossy().into_owned())
                    )
                })
                .collect::<Vec<_>>();
            self.invocations
                .lock()
                .unwrap()
                .push(format!("{arguments:?} {environment:?}"));

            if arguments.iter().any(|argument| argument == "init") {
                let bare = PathBuf::from(arguments.last().unwrap());
                fs::create_dir(&bare)?;
                fs::set_permissions(&bare, fs::Permissions::from_mode(0o700))?;
            }
            if let Some(create) = arguments.iter().position(|argument| argument == "create") {
                let bundle = PathBuf::from(&arguments[create + 1]);
                let mut file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(bundle)?;
                file.write_all(b"synthetic credential-free Git bundle")?;
            }
            let output = if arguments.iter().any(|argument| argument == "rev-parse") {
                format!("{}\n", "a".repeat(40))
            } else {
                String::new()
            };
            let mut child = if let Some(gate_reader) = credential_gate {
                let mut child = tokio::process::Command::new("/usr/bin/cat");
                child.stdin(Stdio::from(std::os::fd::OwnedFd::from(gate_reader)));
                child
            } else {
                let mut child = tokio::process::Command::new("/usr/bin/printf");
                child.arg("%s").arg(output).stdin(Stdio::null());
                child
            };
            child
                .env_clear()
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .kill_on_drop(true)
                .spawn()
        }
    }

    #[test]
    fn github_route_requires_one_canonical_https_repository() {
        for source in [
            "https://github.com/codewire/codewire",
            "https://github.com/codewire/codewire.git",
            "https://github.com/CodewireHQ/codewire.rs",
        ] {
            assert!(validate_github_https_source(source).is_ok(), "{source}");
        }
        for source in [
            "http://github.com/codewire/codewire",
            "https://GHCR.IO/codewire/codewire",
            "https://github.com:443/codewire/codewire",
            "https://token@github.com/codewire/codewire",
            "https://github.com/codewire/codewire/extra",
            "https://github.com/codewire/%63odewire",
            "https://github.com/codewire/.git",
            "https://github.com/codewire/codewire?ref=main",
            "https://github.com/codewire/codewire#main",
        ] {
            assert!(validate_github_https_source(source).is_err(), "{source}");
        }
    }

    #[test]
    fn credential_helper_releases_one_token_only_to_github_https() {
        let (temp, socket, server) = credential_socket_fixture(b"synthetic-github-token");
        let mut output = Vec::new();
        run_git_credential_helper(
            "get",
            &socket,
            &b"protocol=https\nhost=github.com\npath=owner/repository\n\n"[..],
            &mut output,
        )
        .unwrap();
        server.join().unwrap();
        drop(temp);
        assert_eq!(
            output,
            b"username=x-access-token\npassword=synthetic-github-token\n\n"
        );

        assert!(
            run_git_credential_helper(
                "get",
                Path::new("/not-used"),
                &b"protocol=https\nhost=example.com\n\n"[..],
                Vec::new(),
            )
            .is_err()
        );
        assert!(
            run_git_credential_helper(
                "get",
                Path::new("/not-used"),
                &b"protocol=https\nhost=example.com\nhost=github.com\n\n"[..],
                Vec::new(),
            )
            .is_err()
        );
    }

    #[test]
    fn credential_helper_never_releases_material_for_store_or_erase() {
        for operation in ["store", "erase"] {
            let mut output = Vec::new();
            run_git_credential_helper(
                operation,
                Path::new("/not-used"),
                &b"protocol=https\nhost=github.com\npassword=discard-me\n\n"[..],
                &mut output,
            )
            .unwrap();
            assert!(output.is_empty());
        }
    }

    #[test]
    fn credential_helper_rejects_a_non_private_socket() {
        let temp = TempDir::new().unwrap();
        let directory = temp.path().join(format!("cwgr-{}", Uuid::new_v4()));
        DirBuilder::new().mode(0o700).create(&directory).unwrap();
        let socket = directory.join("c");
        let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o660)).unwrap();
        assert!(
            run_git_credential_helper(
                "get",
                &socket,
                &b"protocol=https\nhost=github.com\n\n"[..],
                Vec::new(),
            )
            .is_err()
        );
    }

    fn credential_socket_fixture(
        token: &'static [u8],
    ) -> (TempDir, PathBuf, std::thread::JoinHandle<()>) {
        let temp = TempDir::new().unwrap();
        let staging = temp.path().join(format!("cwgr-{}", Uuid::new_v4()));
        DirBuilder::new().mode(0o700).create(&staging).unwrap();
        let socket = staging.join("c");
        let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.write_all(token).unwrap();
            stream.shutdown(std::net::Shutdown::Write).unwrap();
        });
        (temp, socket, server)
    }

    #[tokio::test]
    async fn inherited_channel_admits_one_exact_repository_lease() {
        let temp = TempDir::new().unwrap();
        let store = TestProtectedStore::new(ProtectedStorePersistence::OperatingSystem);
        let authority = Arc::new(
            LocalCredentialAuthority::open(
                &temp.path().join("authority"),
                store.clone(),
                codewire_access::builtin_provider_catalog(),
            )
            .unwrap(),
        );
        let _connection = authority
            .add_credential(
                NewCredential {
                    provider: ProviderId::parse("github").unwrap(),
                    authentication_kind: CredentialAuthKind::OAuth,
                    display_name: "github-work".to_owned(),
                    account_hint: None,
                    expires_at_unix: None,
                },
                ProtectedValue::from_slice(b"synthetic-github-token").unwrap(),
            )
            .unwrap();
        let profile = authority
            .create_profile(
                AccessProfileName::parse("github-work").unwrap(),
                BTreeMap::new(),
            )
            .unwrap();
        let authorization = RepositoryCredentialLeaseRequest {
            request_id: Uuid::new_v4(),
            profile_id: profile.profile.id.clone(),
            profile_revision: profile.profile.revision,
            source: "https://github.com/codewire/codewire.git".to_owned(),
            branch: "main".to_owned(),
            revision: String::new(),
            known_hosts: Vec::new(),
        };
        let (authority_stream, client_stream) = std::os::unix::net::UnixStream::pair().unwrap();
        authority_stream.set_nonblocking(true).unwrap();
        client_stream.set_nonblocking(true).unwrap();
        let (ready_tx, ready_rx) = oneshot::channel();
        let (_shutdown, shutdown_rx) = tokio::sync::watch::channel(false);
        let server = tokio::spawn(serve_repository_lease_channel_with_ready(
            Arc::clone(&authority),
            UnixStream::from_std(authority_stream).unwrap(),
            authorization.clone(),
            crate::broker_channel::LocalSshOperationRuntime::new(None),
            None,
            ready_tx,
            shutdown_rx,
        ));
        let mut client = LocalCredentialRepositoryLeaseClient::connect(
            UnixStream::from_std(client_stream).unwrap(),
            authorization.request_id,
        )
        .await
        .unwrap();
        client.report_ready().await.unwrap();
        ready_rx.await.unwrap();
        let lease = client.lease_github(store.clone()).await.unwrap();
        assert_eq!(lease.profile_id, profile.profile.id);
        assert_eq!(lease.profile_revision, 1);
        assert_eq!(lease.source, authorization.source);
        assert_eq!(lease.material(), b"synthetic-github-token");
        assert!(matches!(
            client.lease_github(store).await,
            Err(RepositoryLeaseChannelError::Denied)
        ));
        drop(client);
        tokio::time::timeout(std::time::Duration::from_secs(1), server)
            .await
            .expect("repository lease server stopped")
            .unwrap()
            .unwrap();
    }

    // The repository executor is the Linux consumption path; macOS stores only.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn executor_keeps_github_token_out_of_git_argv_environment_and_disk() {
        let staging = TempDir::new().unwrap();
        fs::set_permissions(staging.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let spawner = SyntheticGitSpawner::default();
        let token = b"synthetic-github-token-canary";
        execute_git_repository(
            staging.path(),
            staging.path(),
            Path::new("/synthetic/git"),
            Path::new("/synthetic/cw"),
            &spawner,
            "https://github.com/codewire/codewire.git",
            "main",
            "",
            token,
        )
        .await
        .unwrap();
        assert_eq!(
            spawner.take_tokens().unwrap().as_slice(),
            [token.as_slice()]
        );
        for invocation in spawner.invocations.lock().unwrap().iter() {
            assert!(!invocation.contains("synthetic-github-token-canary"));
        }
        assert!(fs::read_dir(staging.path()).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("cwgr-")
        }));
        let metadata = read_prepared_repository(staging.path()).unwrap();
        assert_eq!(metadata.branch, "main");
        assert_eq!(metadata.commit, "a".repeat(40));
        for path in [
            staging.path().join(BUNDLE_FILE_NAME),
            staging.path().join(RESULT_FILE_NAME),
        ] {
            let bytes = fs::read(path).unwrap();
            assert!(!bytes.windows(token.len()).any(|window| window == token));
        }
    }
}
