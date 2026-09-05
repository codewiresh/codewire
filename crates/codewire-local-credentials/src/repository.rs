//! One-shot GitHub repository preparation for the local runtime.
//!
//! The public authority socket carries only normalized repository intent and
//! credential-free bundle output. A separate authority-created inherited
//! stream admits one exact profile revision to one isolated executor. That
//! executor reads the selected generation directly from protected storage.

use std::ffi::OsStr;
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{self, Read as _, Write as _};
use std::os::unix::fs::{
    DirBuilderExt as _, FileTypeExt as _, MetadataExt as _, OpenOptionsExt as _,
    PermissionsExt as _,
};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};

use codewire_access::{
    AccessProfileId, BrokerOperationId, BrokerRouteId, CredentialAuthKind, GrantPermission,
};
use codewire_protected_store::{ProtectedStore, ProtectedValue};
use hyper_util::rt::TokioIo;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt as _, ReadBuf};
use tokio::net::{UnixListener, UnixStream};
use tokio::process::Command;
use tokio::sync::{Mutex, oneshot};
use tokio_stream::{StreamExt as _, once, pending};
use tonic::transport::server::Connected;
use tonic::transport::{Channel, Endpoint, Server};
use tonic::{Request, Response, Status};
use url::Url;
use uuid::Uuid;
use zeroize::{Zeroize as _, Zeroizing};

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
const MAX_REPOSITORY_LEASE_RPC_MESSAGE_BYTES: usize = 64 * 1024;
pub const REPOSITORY_LEASE_PROTOCOL_VERSION: u32 = 1;
pub const MAX_GITHUB_TOKEN_BYTES: usize = 4 * 1024;
pub const MAX_GIT_BUNDLE_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const MAX_GIT_CONTROL_OUTPUT: usize = 16 * 1024 * 1024;
const GIT_COMMAND_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);
const RESULT_FILE_NAME: &str = "result";
const BUNDLE_FILE_NAME: &str = "source.bundle";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalRepositoryProcessConfig {
    pub request_id: Uuid,
    pub staging_directory: PathBuf,
}

impl LocalRepositoryProcessConfig {
    pub(crate) fn validate(&self) -> Result<(), LocalRepositorySpawnError> {
        let Some(name) = self.staging_directory.file_name().and_then(OsStr::to_str) else {
            return Err(LocalRepositorySpawnError::InvalidConfiguration);
        };
        let Some(id) = name.strip_prefix("repository-executor-") else {
            return Err(LocalRepositorySpawnError::InvalidConfiguration);
        };
        if self.request_id.is_nil()
            || !self.staging_directory.is_absolute()
            || Uuid::parse_str(id).is_err()
            || Uuid::parse_str(id).is_ok_and(|parsed| parsed.to_string() != id)
        {
            return Err(LocalRepositorySpawnError::InvalidConfiguration);
        }
        Ok(())
    }
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
pub trait LocalRepositoryProcessSpawner: Send + Sync + 'static {
    fn spawn(
        &self,
        config: &LocalRepositoryProcessConfig,
        authority_peer: std::os::unix::net::UnixStream,
    ) -> Result<tokio::process::Child, LocalRepositorySpawnError>;
}

/// Executor-local Git launcher. The production implementation applies a
/// parent-death signal in the post-fork child before every Git exec, so an
/// abrupt executor death cannot orphan a credential-bearing Git process.
pub trait LocalRepositoryGitProcessSpawner: Send + Sync {
    fn spawn(&self, command: &mut Command) -> io::Result<tokio::process::Child>;
}

#[derive(Debug, Error)]
pub enum RepositoryExecutorError {
    #[error("repository executor configuration is invalid")]
    InvalidConfiguration,
    #[error("repository credential lease is unavailable")]
    LeaseUnavailable,
    #[error("repository credential material is invalid")]
    InvalidCredential,
    #[error("Git repository preparation failed")]
    GitFailed,
    #[error("Git repository preparation timed out")]
    GitTimeout,
    #[error("Git repository output exceeded its safety limit")]
    GitOutputTooLarge,
    #[error("Git executable is unavailable")]
    GitUnavailable,
    #[error("repository executor filesystem operation failed")]
    Filesystem,
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
pub struct LocalCredentialRepositoryLeaseClient<S> {
    inner: LocalCredentialRepositoryLeaseServiceClient<Channel>,
    protected_store: S,
    request_id: Uuid,
}

impl<S> LocalCredentialRepositoryLeaseClient<S>
where
    S: ProtectedStore + Clone + 'static,
{
    pub async fn connect(
        stream: UnixStream,
        protected_store: S,
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
            protected_store,
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

    pub async fn lease(
        &mut self,
    ) -> Result<RepositoryCredentialLease, RepositoryLeaseChannelError> {
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
            || credential.persistence != self.protected_store.persistence()
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
        let store = self.protected_store.clone();
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
    ready: oneshot::Sender<()>,
) -> Result<(), RepositoryLeaseChannelError>
where
    S: ProtectedStore + 'static,
{
    if validate_repository_lease_request(&authorization).is_err() {
        return Err(RepositoryLeaseChannelError::InvalidRequest);
    }
    let service = RepositoryLeaseRpc {
        authority,
        authorization,
        ready: Mutex::new(Some(ready)),
        ready_reported: AtomicBool::new(false),
        leased: AtomicBool::new(false),
    };
    let (closed_tx, closed_rx) = oneshot::channel();
    let incoming = once(Ok::<_, io::Error>(ObservedRepositoryStream {
        inner: stream,
        closed: Some(closed_tx),
    }))
    .chain(pending());
    Server::builder()
        .concurrency_limit_per_connection(1)
        .add_service(
            LocalCredentialRepositoryLeaseServiceServer::new(service)
                .max_decoding_message_size(MAX_REPOSITORY_LEASE_RPC_MESSAGE_BYTES)
                .max_encoding_message_size(MAX_REPOSITORY_LEASE_RPC_MESSAGE_BYTES),
        )
        .serve_with_incoming_shutdown(incoming, async move {
            let _ = closed_rx.await;
        })
        .await
        .map_err(|_| RepositoryLeaseChannelError::Unavailable)
}

struct RepositoryLeaseRpc<S: ProtectedStore> {
    authority: Arc<LocalCredentialAuthority<S>>,
    authorization: RepositoryCredentialLeaseRequest,
    ready: Mutex<Option<oneshot::Sender<()>>>,
    ready_reported: AtomicBool,
    leased: AtomicBool,
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
            || request_id != self.authorization.request_id
            || self.leased.swap(true, Ordering::AcqRel)
        {
            return Err(Status::permission_denied(
                "repository credential lease was denied",
            ));
        }
        let authority = Arc::clone(&self.authority);
        let authorization = self.authorization.clone();
        let admission = tokio::task::spawn_blocking(move || {
            authority.admit_repository_credential_operation(&authorization)
        })
        .await
        .map_err(|_| Status::unavailable("repository credential authority is unavailable"))?
        .map_err(map_server_error)?;
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
pub async fn run_local_repository_executor<S>(
    authority_stream: UnixStream,
    protected_store: S,
    config: LocalRepositoryProcessConfig,
    credential_runtime_directory: &Path,
    git_executable: &Path,
    credential_helper_executable: &Path,
    git_spawner: &dyn LocalRepositoryGitProcessSpawner,
) -> Result<(), RepositoryExecutorError>
where
    S: ProtectedStore + Clone + 'static,
{
    config
        .validate()
        .map_err(|_| RepositoryExecutorError::InvalidConfiguration)?;
    validate_private_staging_directory(&config.staging_directory)?;
    validate_credential_runtime_directory(credential_runtime_directory)?;
    if !git_executable.is_absolute() || !credential_helper_executable.is_absolute() {
        return Err(RepositoryExecutorError::InvalidConfiguration);
    }
    let mut leases = LocalCredentialRepositoryLeaseClient::connect(
        authority_stream,
        protected_store,
        config.request_id,
    )
    .await
    .map_err(|_| RepositoryExecutorError::LeaseUnavailable)?;
    leases
        .report_ready()
        .await
        .map_err(|_| RepositoryExecutorError::LeaseUnavailable)?;
    let lease = leases
        .lease()
        .await
        .map_err(|_| RepositoryExecutorError::LeaseUnavailable)?;
    let token = lease.material();
    if token.is_empty()
        || token.len() > MAX_GITHUB_TOKEN_BYTES
        || !token.iter().all(u8::is_ascii_graphic)
    {
        return Err(RepositoryExecutorError::InvalidCredential);
    }
    execute_git_repository(
        &config.staging_directory,
        credential_runtime_directory,
        git_executable,
        credential_helper_executable,
        git_spawner,
        &lease.source,
        &lease.branch,
        &lease.revision,
        token,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn execute_git_repository(
    staging: &Path,
    credential_runtime_directory: &Path,
    git_executable: &Path,
    helper_executable: &Path,
    git_spawner: &dyn LocalRepositoryGitProcessSpawner,
    source: &str,
    requested_branch: &str,
    revision: &str,
    token: &[u8],
) -> Result<(), RepositoryExecutorError> {
    validate_github_https_source(source)
        .map_err(|_| RepositoryExecutorError::InvalidConfiguration)?;
    if (!requested_branch.is_empty() && !valid_git_selector(requested_branch))
        || (!revision.is_empty() && !valid_git_selector(revision))
        || (!requested_branch.is_empty() && !revision.is_empty())
    {
        return Err(RepositoryExecutorError::InvalidConfiguration);
    }
    let git = GitExecution {
        executable: git_executable,
        helper_executable,
        credential_runtime_directory,
        spawner: git_spawner,
    };
    let bare = staging.join("source.git");
    git_status(
        &git,
        staging,
        [
            OsStr::new("init"),
            OsStr::new("--bare"),
            OsStr::new("--quiet"),
            bare.as_os_str(),
        ],
        None,
    )
    .await?;

    let branch = if !requested_branch.is_empty() {
        requested_branch.to_owned()
    } else if revision.is_empty() {
        resolve_default_branch(&git, staging, source, token).await?
    } else {
        String::new()
    };
    let selector = if revision.is_empty() {
        format!("refs/heads/{branch}")
    } else {
        revision.to_owned()
    };
    let refspec = format!("{selector}:refs/codewire/source");
    git_status(
        &git,
        &bare,
        [
            OsStr::new("fetch"),
            OsStr::new("--quiet"),
            OsStr::new("--no-tags"),
            OsStr::new("--force"),
            OsStr::new("--no-recurse-submodules"),
            OsStr::new("--"),
            OsStr::new(source),
            OsStr::new(&refspec),
        ],
        Some(token),
    )
    .await?;
    let commit = git_text(
        &git,
        &bare,
        [
            OsStr::new("rev-parse"),
            OsStr::new("--verify"),
            OsStr::new("refs/codewire/source^{commit}"),
        ],
        256,
        None,
    )
    .await?
    .trim()
    .to_owned();
    if !valid_object_id(&commit) {
        return Err(RepositoryExecutorError::GitFailed);
    }
    reject_submodules(&git, &bare, &commit).await?;

    let bundle = staging.join(BUNDLE_FILE_NAME);
    git_status(
        &git,
        &bare,
        [
            OsStr::new("bundle"),
            OsStr::new("create"),
            bundle.as_os_str(),
            OsStr::new("refs/codewire/source"),
        ],
        None,
    )
    .await?;
    git_status(
        &git,
        &bare,
        [
            OsStr::new("bundle"),
            OsStr::new("verify"),
            bundle.as_os_str(),
        ],
        None,
    )
    .await?;
    let bundle_size = regular_file_size(&bundle)?;
    if bundle_size == 0 || bundle_size > MAX_GIT_BUNDLE_BYTES {
        return Err(RepositoryExecutorError::GitOutputTooLarge);
    }
    write_result(
        staging,
        &PreparedRepositoryMetadata {
            branch,
            commit,
            bundle_size,
        },
    )
}

async fn resolve_default_branch(
    git: &GitExecution<'_>,
    staging: &Path,
    source: &str,
    token: &[u8],
) -> Result<String, RepositoryExecutorError> {
    let output = git_text(
        git,
        staging,
        [
            OsStr::new("ls-remote"),
            OsStr::new("--symref"),
            OsStr::new("--exit-code"),
            OsStr::new("--"),
            OsStr::new(source),
            OsStr::new("HEAD"),
        ],
        4096,
        Some(token),
    )
    .await?;
    output
        .lines()
        .find_map(|line| {
            line.strip_prefix("ref: refs/heads/")?
                .strip_suffix("\tHEAD")
        })
        .filter(|branch| valid_git_selector(branch))
        .map(str::to_owned)
        .ok_or(RepositoryExecutorError::GitFailed)
}

async fn reject_submodules(
    git: &GitExecution<'_>,
    bare: &Path,
    commit: &str,
) -> Result<(), RepositoryExecutorError> {
    let output = git_output(
        git,
        bare,
        [
            OsStr::new("ls-tree"),
            OsStr::new("-r"),
            OsStr::new("-z"),
            OsStr::new("--full-tree"),
            OsStr::new(commit),
        ],
        MAX_GIT_CONTROL_OUTPUT,
        None,
    )
    .await?;
    for record in output.split(|byte| *byte == 0) {
        let Some(tab) = record.iter().position(|byte| *byte == b'\t') else {
            if record.is_empty() {
                continue;
            }
            return Err(RepositoryExecutorError::GitFailed);
        };
        if record[..tab].starts_with(b"160000 commit ") {
            return Err(RepositoryExecutorError::GitFailed);
        }
    }
    Ok(())
}

struct GitExecution<'a> {
    executable: &'a Path,
    helper_executable: &'a Path,
    credential_runtime_directory: &'a Path,
    spawner: &'a dyn LocalRepositoryGitProcessSpawner,
}

async fn git_status<'a>(
    git: &GitExecution<'_>,
    working_directory: &Path,
    arguments: impl IntoIterator<Item = &'a OsStr>,
    token: Option<&[u8]>,
) -> Result<(), RepositoryExecutorError> {
    let mut command = git_command(
        git.executable,
        git.helper_executable,
        working_directory,
        git.credential_runtime_directory,
        token,
    )?;
    command
        .command
        .args(arguments)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let (mut child, mut credential_server) = command.spawn(git.spawner)?;
    let status = tokio::time::timeout(
        GIT_COMMAND_TIMEOUT,
        wait_for_git_child(&mut child, credential_server.as_mut()),
    )
    .await
    .map_err(|_| RepositoryExecutorError::GitTimeout)??;
    if !status.success() {
        return Err(RepositoryExecutorError::GitFailed);
    }
    Ok(())
}

async fn git_text<'a>(
    git: &GitExecution<'_>,
    working_directory: &Path,
    arguments: impl IntoIterator<Item = &'a OsStr>,
    maximum_output: usize,
    token: Option<&[u8]>,
) -> Result<String, RepositoryExecutorError> {
    let output = git_output(git, working_directory, arguments, maximum_output, token).await?;
    String::from_utf8(output).map_err(|_| RepositoryExecutorError::GitFailed)
}

async fn git_output<'a>(
    git: &GitExecution<'_>,
    working_directory: &Path,
    arguments: impl IntoIterator<Item = &'a OsStr>,
    maximum_output: usize,
    token: Option<&[u8]>,
) -> Result<Vec<u8>, RepositoryExecutorError> {
    use tokio::io::AsyncReadExt as _;

    let maximum_output_plus_one = maximum_output
        .checked_add(1)
        .and_then(|value| u64::try_from(value).ok())
        .ok_or(RepositoryExecutorError::GitOutputTooLarge)?;
    let mut command = git_command(
        git.executable,
        git.helper_executable,
        working_directory,
        git.credential_runtime_directory,
        token,
    )?;
    command
        .command
        .args(arguments)
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let (mut child, mut credential_server) = command.spawn(git.spawner)?;
    let stdout = child
        .stdout
        .take()
        .ok_or(RepositoryExecutorError::GitUnavailable)?;
    let result = tokio::time::timeout(GIT_COMMAND_TIMEOUT, async {
        let read_output = async {
            let mut output = Vec::with_capacity(maximum_output.min(64 * 1024));
            stdout
                .take(maximum_output_plus_one)
                .read_to_end(&mut output)
                .await
                .map_err(|_| RepositoryExecutorError::GitUnavailable)?;
            if output.len() > maximum_output {
                return Err(RepositoryExecutorError::GitOutputTooLarge);
            }
            Ok(output)
        };
        let (output, status) = tokio::try_join!(
            read_output,
            wait_for_git_child(&mut child, credential_server.as_mut())
        )?;
        if !status.success() {
            return Err(RepositoryExecutorError::GitFailed);
        }
        Ok(output)
    })
    .await
    .unwrap_or(Err(RepositoryExecutorError::GitTimeout));
    if result.is_err() {
        let _ = child.kill().await;
        let _ = child.wait().await;
    }
    result
}

struct GitCommand {
    command: Command,
    credential_server: Option<CredentialSocketServer>,
}

impl GitCommand {
    fn spawn(
        mut self,
        spawner: &dyn LocalRepositoryGitProcessSpawner,
    ) -> Result<(tokio::process::Child, Option<CredentialSocketServer>), RepositoryExecutorError>
    {
        let child = spawner
            .spawn(&mut self.command)
            .map_err(|_| RepositoryExecutorError::GitUnavailable)?;
        Ok((child, self.credential_server.take()))
    }
}

struct CredentialSocketServer {
    listener: UnixListener,
    directory: PathBuf,
    path: PathBuf,
    token: Zeroizing<Vec<u8>>,
}

impl CredentialSocketServer {
    fn bind(runtime_directory: &Path, token: &[u8]) -> Result<Self, RepositoryExecutorError> {
        validate_credential_runtime_directory(runtime_directory)?;
        let directory = runtime_directory.join(format!("cwgr-{}", Uuid::new_v4()));
        DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .map_err(|_| RepositoryExecutorError::Filesystem)?;
        let path = directory.join("c");
        let listener = match UnixListener::bind(&path) {
            Ok(listener) => listener,
            Err(_) => {
                let _ = fs::remove_dir(&directory);
                return Err(RepositoryExecutorError::Filesystem);
            }
        };
        let server = Self {
            listener,
            directory,
            path,
            token: Zeroizing::new(token.to_vec()),
        };
        fs::set_permissions(&server.path, fs::Permissions::from_mode(0o600))
            .map_err(|_| RepositoryExecutorError::Filesystem)?;
        validate_credential_socket_path(&server.path)?;
        Ok(server)
    }

    async fn serve(&mut self) -> Result<(), RepositoryExecutorError> {
        let (mut stream, _) = self
            .listener
            .accept()
            .await
            .map_err(|_| RepositoryExecutorError::InvalidCredential)?;
        let peer = stream
            .peer_cred()
            .map_err(|_| RepositoryExecutorError::InvalidCredential)?;
        if peer.uid() != rustix::process::getuid().as_raw() {
            return Err(RepositoryExecutorError::InvalidCredential);
        }
        self.unlink()?;
        stream
            .write_all(&self.token)
            .await
            .map_err(|_| RepositoryExecutorError::InvalidCredential)?;
        stream
            .shutdown()
            .await
            .map_err(|_| RepositoryExecutorError::InvalidCredential)?;
        self.token.zeroize();
        Ok(())
    }

    fn unlink(&self) -> Result<(), RepositoryExecutorError> {
        match fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(RepositoryExecutorError::Filesystem),
        }
    }
}

impl Drop for CredentialSocketServer {
    fn drop(&mut self) {
        let _ = self.unlink();
        let _ = fs::remove_dir(&self.directory);
    }
}

async fn wait_for_git_child(
    child: &mut tokio::process::Child,
    credential_server: Option<&mut CredentialSocketServer>,
) -> Result<std::process::ExitStatus, RepositoryExecutorError> {
    let Some(credential_server) = credential_server else {
        return child
            .wait()
            .await
            .map_err(|_| RepositoryExecutorError::GitUnavailable);
    };
    tokio::select! {
        biased;
        result = credential_server.serve() => {
            result?;
            child
                .wait()
                .await
                .map_err(|_| RepositoryExecutorError::GitUnavailable)
        }
        status = child.wait() => {
            status.map_err(|_| RepositoryExecutorError::GitUnavailable)
        }
    }
}

fn git_command(
    git_executable: &Path,
    helper_executable: &Path,
    working_directory: &Path,
    credential_socket_directory: &Path,
    token: Option<&[u8]>,
) -> Result<GitCommand, RepositoryExecutorError> {
    let mut command = Command::new(git_executable);
    command
        .args([
            "-c",
            "credential.helper=",
            "-c",
            "credential.useHttpPath=false",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "filter.lfs.required=false",
            "-c",
            "filter.lfs.smudge=",
            "-c",
            "protocol.file.allow=never",
            "-c",
            "protocol.ext.allow=never",
            "-c",
            "http.followRedirects=initial",
        ])
        .env_clear()
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_ASKPASS", "/bin/false")
        .env("GIT_NO_LAZY_FETCH", "1")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("LC_ALL", "C")
        .current_dir(working_directory)
        .stdin(Stdio::null())
        .kill_on_drop(true);
    let credential_server = if let Some(token) = token {
        let server = CredentialSocketServer::bind(credential_socket_directory, token)?;
        let helper = format!(
            "!exec {} __local-git-credential-helper --credential-socket {}",
            quote_shell_word(helper_executable)?,
            quote_shell_word(&server.path)?,
        );
        command.args(["-c", &format!("credential.helper={helper}")]);
        Some(server)
    } else {
        None
    };
    Ok(GitCommand {
        command,
        credential_server,
    })
}

fn quote_shell_word(path: &Path) -> Result<String, RepositoryExecutorError> {
    let value = path
        .to_str()
        .ok_or(RepositoryExecutorError::InvalidConfiguration)?;
    Ok(format!("'{}'", value.replace('\'', "'\\''")))
}

fn validate_private_staging_directory(path: &Path) -> Result<(), RepositoryExecutorError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| RepositoryExecutorError::Filesystem)?;
    if !metadata.is_dir()
        || metadata.uid() != rustix::process::getuid().as_raw()
        || metadata.permissions().mode() & 0o7777 != 0o700
    {
        return Err(RepositoryExecutorError::InvalidConfiguration);
    }
    Ok(())
}

fn validate_credential_runtime_directory(path: &Path) -> Result<(), RepositoryExecutorError> {
    validate_private_staging_directory(path)?;
    if !path.is_absolute()
        || fs::canonicalize(path).map_err(|_| RepositoryExecutorError::Filesystem)? != path
    {
        return Err(RepositoryExecutorError::InvalidConfiguration);
    }
    Ok(())
}

fn regular_file_size(path: &Path) -> Result<u64, RepositoryExecutorError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| RepositoryExecutorError::Filesystem)?;
    if !metadata.is_file()
        || metadata.uid() != rustix::process::getuid().as_raw()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(RepositoryExecutorError::Filesystem);
    }
    Ok(metadata.len())
}

fn write_result(
    staging: &Path,
    metadata: &PreparedRepositoryMetadata,
) -> Result<(), RepositoryExecutorError> {
    if !valid_object_id(&metadata.commit)
        || (!metadata.branch.is_empty() && !valid_git_selector(&metadata.branch))
        || metadata.bundle_size == 0
        || metadata.bundle_size > MAX_GIT_BUNDLE_BYTES
    {
        return Err(RepositoryExecutorError::GitFailed);
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(staging.join(RESULT_FILE_NAME))
        .map_err(|_| RepositoryExecutorError::Filesystem)?;
    writeln!(
        file,
        "{}\n{}\n{}",
        metadata.branch, metadata.commit, metadata.bundle_size
    )
    .map_err(|_| RepositoryExecutorError::Filesystem)?;
    file.sync_all()
        .map_err(|_| RepositoryExecutorError::Filesystem)
}

pub(crate) fn read_prepared_repository(
    staging: &Path,
) -> Result<PreparedRepositoryMetadata, RepositoryExecutorError> {
    validate_private_staging_directory(staging)?;
    let result_path = staging.join(RESULT_FILE_NAME);
    if regular_file_size(&result_path)? > 4096 {
        return Err(RepositoryExecutorError::Filesystem);
    }
    let text = fs::read_to_string(result_path).map_err(|_| RepositoryExecutorError::Filesystem)?;
    let mut lines = text.lines();
    let branch = lines.next().ok_or(RepositoryExecutorError::Filesystem)?;
    let commit = lines.next().ok_or(RepositoryExecutorError::Filesystem)?;
    let bundle_size = lines
        .next()
        .ok_or(RepositoryExecutorError::Filesystem)?
        .parse::<u64>()
        .map_err(|_| RepositoryExecutorError::Filesystem)?;
    if lines.next().is_some()
        || (!branch.is_empty() && !valid_git_selector(branch))
        || !valid_object_id(commit)
        || bundle_size == 0
        || bundle_size > MAX_GIT_BUNDLE_BYTES
        || regular_file_size(&staging.join(BUNDLE_FILE_NAME))? != bundle_size
    {
        return Err(RepositoryExecutorError::Filesystem);
    }
    Ok(PreparedRepositoryMetadata {
        branch: branch.to_owned(),
        commit: commit.to_owned(),
        bundle_size,
    })
}

pub(crate) fn prepared_bundle_path(staging: &Path) -> PathBuf {
    staging.join(BUNDLE_FILE_NAME)
}

pub(crate) fn create_repository_staging(
    authority_root: &Path,
) -> Result<PathBuf, RepositoryExecutorError> {
    let staging = authority_root.join(format!("repository-executor-{}", Uuid::new_v4()));
    DirBuilder::new()
        .mode(0o700)
        .create(&staging)
        .map_err(|_| RepositoryExecutorError::Filesystem)?;
    validate_private_staging_directory(&staging)?;
    Ok(staging)
}

pub(crate) fn remove_repository_staging(path: &Path) -> Result<(), RepositoryExecutorError> {
    validate_private_staging_directory(path)?;
    let name = path
        .file_name()
        .and_then(OsStr::to_str)
        .and_then(|name| name.strip_prefix("repository-executor-"))
        .ok_or(RepositoryExecutorError::InvalidConfiguration)?;
    let id = Uuid::parse_str(name).map_err(|_| RepositoryExecutorError::InvalidConfiguration)?;
    if id.to_string() != name {
        return Err(RepositoryExecutorError::InvalidConfiguration);
    }
    fs::remove_dir_all(path).map_err(|_| RepositoryExecutorError::Filesystem)
}

pub(crate) fn cleanup_repository_staging(
    authority_root: &Path,
) -> Result<(), RepositoryExecutorError> {
    for entry in fs::read_dir(authority_root).map_err(|_| RepositoryExecutorError::Filesystem)? {
        let entry = entry.map_err(|_| RepositoryExecutorError::Filesystem)?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let Some(id) = name.strip_prefix("repository-executor-") else {
            continue;
        };
        if Uuid::parse_str(id).is_ok_and(|parsed| parsed.to_string() == id) {
            remove_repository_staging(&entry.path())?;
        }
    }
    Ok(())
}

fn validate_credential_socket_path(path: &Path) -> Result<(), RepositoryExecutorError> {
    if !path.is_absolute() {
        return Err(RepositoryExecutorError::InvalidConfiguration);
    }
    let parent = path
        .parent()
        .ok_or(RepositoryExecutorError::InvalidConfiguration)?;
    validate_private_staging_directory(parent)?;
    if fs::canonicalize(parent).map_err(|_| RepositoryExecutorError::Filesystem)? != parent {
        return Err(RepositoryExecutorError::InvalidConfiguration);
    }
    let parent_id = parent
        .file_name()
        .and_then(OsStr::to_str)
        .and_then(|name| name.strip_prefix("cwgr-"))
        .and_then(|value| Uuid::parse_str(value).ok())
        .filter(|id| parent.ends_with(format!("cwgr-{id}")))
        .ok_or(RepositoryExecutorError::InvalidConfiguration)?;
    if parent_id.is_nil() {
        return Err(RepositoryExecutorError::InvalidConfiguration);
    }
    if path.file_name() != Some(OsStr::new("c")) {
        return Err(RepositoryExecutorError::InvalidConfiguration);
    }
    let metadata = fs::symlink_metadata(path).map_err(|_| RepositoryExecutorError::Filesystem)?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != rustix::process::getuid().as_raw()
        || metadata.permissions().mode() & 0o7777 != 0o600
    {
        return Err(RepositoryExecutorError::InvalidConfiguration);
    }
    Ok(())
}

/// Implement Git's credential-helper protocol without consulting ambient
/// configuration. `get` consumes one private one-use socket; `store` and
/// `erase` only drain and zeroize the bounded request Git supplies.
pub fn run_git_credential_helper(
    operation: &str,
    credential_socket: &Path,
    input: impl io::Read,
    mut output: impl io::Write,
) -> Result<(), RepositoryExecutorError> {
    let mut request = Zeroizing::new(Vec::with_capacity(1024));
    input
        .take(16 * 1024 + 1)
        .read_to_end(&mut request)
        .map_err(|_| RepositoryExecutorError::InvalidConfiguration)?;
    if request.len() > 16 * 1024 {
        return Err(RepositoryExecutorError::InvalidConfiguration);
    }
    if operation != "get" {
        return if matches!(operation, "store" | "erase") {
            Ok(())
        } else {
            Err(RepositoryExecutorError::InvalidConfiguration)
        };
    }
    let request =
        std::str::from_utf8(&request).map_err(|_| RepositoryExecutorError::InvalidConfiguration)?;
    let mut protocol = None;
    let mut host = None;
    for line in request.lines() {
        if let Some(value) = line.strip_prefix("protocol=") {
            if protocol.is_some() {
                return Err(RepositoryExecutorError::InvalidConfiguration);
            }
            protocol = Some(value);
        } else if let Some(value) = line.strip_prefix("host=") {
            if host.is_some() {
                return Err(RepositoryExecutorError::InvalidConfiguration);
            }
            host = Some(value);
        }
    }
    if protocol != Some("https") || host != Some("github.com") {
        return Err(RepositoryExecutorError::InvalidConfiguration);
    }
    validate_credential_socket_path(credential_socket)?;
    let stream = std::os::unix::net::UnixStream::connect(credential_socket)
        .map_err(|_| RepositoryExecutorError::InvalidCredential)?;
    stream
        .set_read_timeout(Some(REPOSITORY_LEASE_REQUEST_TIMEOUT))
        .map_err(|_| RepositoryExecutorError::InvalidCredential)?;
    let mut token = Zeroizing::new(Vec::with_capacity(MAX_GITHUB_TOKEN_BYTES));
    stream
        .take(u64::try_from(MAX_GITHUB_TOKEN_BYTES + 1).expect("token bound fits u64"))
        .read_to_end(&mut token)
        .map_err(|_| RepositoryExecutorError::InvalidCredential)?;
    if token.is_empty()
        || token.len() > MAX_GITHUB_TOKEN_BYTES
        || !token.iter().all(u8::is_ascii_graphic)
    {
        return Err(RepositoryExecutorError::InvalidCredential);
    }
    output
        .write_all(b"username=x-access-token\npassword=")
        .and_then(|()| output.write_all(&token))
        .and_then(|()| output.write_all(b"\n\n"))
        .and_then(|()| output.flush())
        .map_err(|_| RepositoryExecutorError::InvalidCredential)
}

fn valid_object_id(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn validate_repository_lease_request(
    request: &RepositoryCredentialLeaseRequest,
) -> Result<(), RepositoryLeaseChannelError> {
    if request.request_id.is_nil()
        || request.profile_revision == 0
        || validate_github_https_source(&request.source).is_err()
        || (!request.branch.is_empty() && !valid_git_selector(&request.branch))
        || (!request.revision.is_empty() && !valid_git_selector(&request.revision))
        || (!request.branch.is_empty() && !request.revision.is_empty())
    {
        return Err(RepositoryLeaseChannelError::InvalidRequest);
    }
    Ok(())
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

    use codewire_access::{AccessProfileName, CapabilitySlot, ProviderId};
    use codewire_protected_store::{ProtectedStorePersistence, ProtectedValue};
    use tempfile::TempDir;

    use crate::NewCredential;
    use crate::tests::TestProtectedStore;

    #[derive(Default)]
    struct SyntheticGitSpawner {
        tokens: Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
        invocations: std::sync::Mutex<Vec<String>>,
    }

    impl SyntheticGitSpawner {
        fn take_tokens(&self) -> io::Result<Vec<Vec<u8>>> {
            Ok(self.tokens.lock().unwrap().drain(..).collect())
        }
    }

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
        let credential = authority
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
                BTreeMap::from([(CapabilitySlot::github(), credential.metadata.id.clone())]),
            )
            .unwrap();
        let authorization = RepositoryCredentialLeaseRequest {
            request_id: Uuid::new_v4(),
            profile_id: profile.profile.id.clone(),
            profile_revision: profile.profile.revision,
            source: "https://github.com/codewire/codewire.git".to_owned(),
            branch: "main".to_owned(),
            revision: String::new(),
        };
        let (authority_stream, client_stream) = std::os::unix::net::UnixStream::pair().unwrap();
        authority_stream.set_nonblocking(true).unwrap();
        client_stream.set_nonblocking(true).unwrap();
        let (ready_tx, ready_rx) = oneshot::channel();
        let server = tokio::spawn(serve_repository_lease_channel_with_ready(
            Arc::clone(&authority),
            UnixStream::from_std(authority_stream).unwrap(),
            authorization.clone(),
            ready_tx,
        ));
        let mut client = LocalCredentialRepositoryLeaseClient::connect(
            UnixStream::from_std(client_stream).unwrap(),
            store,
            authorization.request_id,
        )
        .await
        .unwrap();
        client.report_ready().await.unwrap();
        ready_rx.await.unwrap();
        let lease = client.lease().await.unwrap();
        assert_eq!(lease.profile_id, profile.profile.id);
        assert_eq!(lease.profile_revision, 1);
        assert_eq!(lease.source, authorization.source);
        assert_eq!(lease.material(), b"synthetic-github-token");
        assert!(matches!(
            client.lease().await,
            Err(RepositoryLeaseChannelError::Denied)
        ));
        drop(client);
        tokio::time::timeout(std::time::Duration::from_secs(1), server)
            .await
            .expect("repository lease server stopped")
            .unwrap()
            .unwrap();
    }

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
