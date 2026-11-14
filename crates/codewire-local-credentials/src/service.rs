use std::collections::{BTreeMap, BTreeSet, HashMap};
#[cfg(target_os = "linux")]
use std::ffi::OsStr;
use std::future::Future;
use std::mem;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use codewire_access::{
    AccessError, AccessProfileId, AccessProfileName, AccessProfileReference, CapabilitySlot,
    CredentialAuthKind, CredentialId, CredentialStatus, DerivedGrant, EnvironmentAccessBinding,
    EnvironmentId, ProviderCatalog, ProviderId, builtin_provider_catalog,
};
use codewire_protected_store::{
    MAX_PROTECTED_VALUE_BYTES, ProtectedStore, ProtectedStoreError, ProtectedStorePersistence,
    ProtectedValue,
    ssh_material::{SshMaterialError, generate_ed25519, import_openssh},
};
use futures::FutureExt as _;
use tokio::net::UnixStream;
use tokio::sync::{Mutex, watch};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};
use uuid::Uuid;
use zeroize::Zeroizing;

#[cfg(target_os = "linux")]
use crate::AUTHORITY_ALLOWED_ENVIRONMENT_VARIABLES;
use crate::broker_channel::{
    BrokerChannelRefreshLifetime, BrokerLeaseAuditLog, BrokerLeaseChannelControl,
    LocalSshOperationRuntime, LocalSshSigner, MAX_BROKER_LEASE_AUDIT_LIST_LIMIT,
    serve_broker_lease_channel_with_ready,
};
use crate::broker_log::{BrokerLog, StderrTail, exit_status};
use crate::control::v1::local_credential_authority_service_server::{
    LocalCredentialAuthorityService, LocalCredentialAuthorityServiceServer,
};
use crate::control::v1::{self, CredentialAuthenticationKind};
use crate::repository::{LocalRepositoryProcessSpawner, cleanup_repository_staging};
use crate::transport::{
    AUTHORITY_PROTOCOL_VERSION, AuthorityRuntimeConfig, AuthorityRuntimeError, bind_owner_only,
    remove_bound_socket,
};
use crate::{
    AccessProfileRecord, AccessProfileRevisionRecord, AuthorityProtectedStore, CredentialRecord,
    EnvironmentAccessBindingRecord, EnvironmentBrokerRuntime, LocalBrokerProcessConfig,
    LocalBrokerProcessSpawner, LocalCredentialAuthority, LocalCredentialError, LocalSecretProject,
    NewCredential, RepositoryCredentialLeaseRequest, ResolvedWorkloadSecretMetadata,
    WorkloadSecretMetadata, WorkloadSecretSelection, WorkloadSecretSource,
};

const MAX_RPC_MESSAGE_BYTES: usize = MAX_PROTECTED_VALUE_BYTES + 64 * 1024;
const BROKER_LOCAL_START_TIMEOUT: Duration = Duration::from_secs(10);
// One total attempt, including the existing seven-second daemon phase and
// the connector's original fifteen-second OAuth/admission phase. This does
// not extend operation deadlines or the existing shutdown bound.
const BROKER_PLATFORM_START_TIMEOUT: Duration = Duration::from_secs(30);
const BROKER_DRAIN_TIMEOUT: Duration = Duration::from_secs(10);
// The connector's OAuth and metadata read for a start-time GitHub answer. It
// is the same bound as a delegation's OAuth/admission phase.
const PLATFORM_GITHUB_STATE_DEADLINE: Duration = Duration::from_secs(15);
const BROKER_READY_STABILITY: std::time::Duration = std::time::Duration::from_millis(25);
const BROKER_RESTART_MIN_DELAY: std::time::Duration = std::time::Duration::from_millis(100);
const BROKER_RESTART_MAX_DELAY: std::time::Duration = std::time::Duration::from_secs(30);
const BROKER_STABLE_RUNTIME: std::time::Duration = std::time::Duration::from_secs(30);
/// How long one broker child takes new work, from its spawn. A child resolves
/// provider addresses and opens its authority channel once, at its start, so
/// this bounds their age. It also ends no later than an owner-local platform
/// delegation, which the platform admits for at most 600 seconds.
const BROKER_EPOCH_LIFETIME: Duration = Duration::from_secs(600);
/// Its successor is spawned this long before that lifetime ends. Once the
/// successor runs, the daemon sends it all new work, and the predecessor only
/// finishes the requests already sent to it until its lifetime ends.
const BROKER_SUCCESSOR_LEAD: Duration = Duration::from_secs(90);
/// Between successor attempts while the predecessor still serves: 3 seconds,
/// doubling to at most 15.
const BROKER_SUCCESSOR_RETRY_FIRST: Duration = Duration::from_secs(3);
const BROKER_SUCCESSOR_RETRY_MAX: Duration = Duration::from_secs(15);
const REPOSITORY_STREAM_CHUNK_BYTES: usize = 48 * 1024;
const MAX_SSH_ENROLLMENT_WORKERS: u32 = 8;
const SSH_ENROLLMENT_DEADLINE: Duration = Duration::from_secs(30);

mod repository;
pub(crate) use repository::REPOSITORY_PREPARATION_TIMEOUT;
use repository::{PreparedRepository, RepositoryProcessManager, cleanup_repository_ssh_runtimes};

struct AuthorityRpc<S: ProtectedStore> {
    authority: Arc<LocalCredentialAuthority<S>>,
    brokers: Arc<BrokerProcessManager<S>>,
    repositories: Arc<RepositoryProcessManager<S>>,
    broker_audit: Arc<BrokerLeaseAuditLog>,
    shutdown: watch::Sender<bool>,
    ssh_enrollment_workers: SshEnrollmentWorkers,
}

impl<S: ProtectedStore> Clone for AuthorityRpc<S> {
    fn clone(&self) -> Self {
        Self {
            authority: Arc::clone(&self.authority),
            brokers: Arc::clone(&self.brokers),
            repositories: Arc::clone(&self.repositories),
            broker_audit: Arc::clone(&self.broker_audit),
            shutdown: self.shutdown.clone(),
            ssh_enrollment_workers: self.ssh_enrollment_workers.clone(),
        }
    }
}

#[derive(Clone)]
struct SshEnrollmentWorkers {
    permits: Arc<tokio::sync::Semaphore>,
    shutdown: watch::Sender<bool>,
}

struct SshEnrollmentCancellation {
    shutdown: watch::Receiver<bool>,
    request: watch::Receiver<bool>,
}

impl SshEnrollmentCancellation {
    fn is_cancelled(&self) -> bool {
        *self.shutdown.borrow() || *self.request.borrow()
    }
}

struct SshEnrollmentRequestGuard {
    cancelled: watch::Sender<bool>,
}

impl Drop for SshEnrollmentRequestGuard {
    fn drop(&mut self) {
        self.cancelled.send_replace(true);
    }
}

impl SshEnrollmentWorkers {
    fn new() -> Self {
        let (shutdown, _) = watch::channel(false);
        Self {
            permits: Arc::new(tokio::sync::Semaphore::new(
                MAX_SSH_ENROLLMENT_WORKERS as usize,
            )),
            shutdown,
        }
    }

    async fn run<T>(
        &self,
        operation: impl FnOnce(SshEnrollmentCancellation) -> Result<T, Status> + Send + 'static,
    ) -> Result<T, Status>
    where
        T: Send + 'static,
    {
        let shutdown = self.shutdown.subscribe();
        if *shutdown.borrow() {
            return Err(Status::unavailable(
                "local SSH credential enrollment is stopping",
            ));
        }
        let permit = Arc::clone(&self.permits)
            .try_acquire_owned()
            .map_err(|_| Status::resource_exhausted("local SSH enrollment workers are busy"))?;
        if *shutdown.borrow() {
            return Err(Status::unavailable(
                "local SSH credential enrollment is stopping",
            ));
        }
        let (request_cancelled, request) = watch::channel(false);
        let request_guard = SshEnrollmentRequestGuard {
            cancelled: request_cancelled,
        };
        let result = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            operation(SshEnrollmentCancellation { shutdown, request })
        })
        .await
        .map_err(|_| Status::internal("local SSH enrollment worker failed"))?;
        drop(request_guard);
        result
    }

    async fn shutdown(&self) {
        self.shutdown.send_replace(true);
        if let Ok(permits) = Arc::clone(&self.permits)
            .acquire_many_owned(MAX_SSH_ENROLLMENT_WORKERS)
            .await
        {
            drop(permits);
        }
    }
}

pub async fn serve_local_credential_authority<S: ProtectedStore + 'static>(
    config: AuthorityRuntimeConfig,
    protected_store: S,
    catalog: ProviderCatalog,
) -> Result<(), AuthorityRuntimeError> {
    serve_until(config, protected_store, catalog, std::future::pending()).await
}

/// Run the production authority with both authority-owned credential-bearing
/// child launchers. Neither launcher is exposed through the owner RPC API.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub async fn serve_os_local_credential_authority_with_process_spawners(
    config: AuthorityRuntimeConfig,
    store: AuthorityProtectedStore,
    broker_spawner: Arc<dyn LocalBrokerProcessSpawner>,
    repository_spawner: Arc<dyn LocalRepositoryProcessSpawner>,
    ssh_signer: Arc<dyn LocalSshSigner>,
    platform_connector: Arc<dyn crate::PlatformCredentialConnector>,
) -> Result<(), AuthorityRuntimeError> {
    verify_production_process_confinement()?;
    serve_selected(
        config,
        store,
        AuthorityRuntimeAdapters {
            broker_spawner: Some(broker_spawner),
            repository_spawner: Some(repository_spawner),
            ssh_signer: Some(ssh_signer),
            platform_connector: Some(platform_connector),
            #[cfg(test)]
            listening: None,
        },
    )
    .await
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn serve_selected(
    config: AuthorityRuntimeConfig,
    store: AuthorityProtectedStore,
    adapters: AuthorityRuntimeAdapters,
) -> Result<(), AuthorityRuntimeError> {
    config.prepare_root()?;
    let authority =
        LocalCredentialAuthority::open_selected(&config.root, &store, builtin_provider_catalog())?;
    serve_authority(config, authority, std::future::pending(), adapters).await
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
async fn serve_selected(
    _config: AuthorityRuntimeConfig,
    _store: AuthorityProtectedStore,
    _adapters: AuthorityRuntimeAdapters,
) -> Result<(), AuthorityRuntimeError> {
    Err(AuthorityRuntimeError::UnsupportedPlatform)
}

#[cfg(target_os = "linux")]
fn verify_production_process_confinement() -> Result<(), AuthorityRuntimeError> {
    if !rustix::thread::no_new_privs().map_err(|_| AuthorityRuntimeError::ProcessNotConfined)? {
        return Err(AuthorityRuntimeError::ProcessNotConfined);
    }

    let capabilities = rustix::thread::capabilities(None)
        .map_err(|_| AuthorityRuntimeError::ProcessNotConfined)?;
    if !capabilities.effective.is_empty()
        || !capabilities.permitted.is_empty()
        || !capabilities.inheritable.is_empty()
    {
        return Err(AuthorityRuntimeError::ProcessNotConfined);
    }

    let pid = rustix::process::getpid();
    if rustix::process::getsid(None).map_err(|_| AuthorityRuntimeError::ProcessNotConfined)? != pid
    {
        return Err(AuthorityRuntimeError::ProcessNotConfined);
    }

    for (name, _) in std::env::vars_os() {
        if !AUTHORITY_ALLOWED_ENVIRONMENT_VARIABLES
            .iter()
            .any(|allowed| name == OsStr::new(allowed))
        {
            return Err(AuthorityRuntimeError::ProcessNotConfined);
        }
    }
    Ok(())
}

/// macOS has no capabilities or no-new-privileges bit. The launcher
/// supplies a new session, an empty environment and only standard
/// descriptors (`posix_spawn` with `POSIX_SPAWN_CLOEXEC_DEFAULT`); the
/// authority never runs as root. CoreFoundation, which cw links, sets
/// `__CF_USER_TEXT_ENCODING` itself while the process loads, from the user
/// ID rather than from the parent, so that one name is not ambient input.
#[cfg(target_os = "macos")]
fn verify_production_process_confinement() -> Result<(), AuthorityRuntimeError> {
    if rustix::process::geteuid().is_root()
        || rustix::process::getsid(None).map_err(|_| AuthorityRuntimeError::ProcessNotConfined)?
            != rustix::process::getpid()
        || std::env::vars_os().any(|(name, _)| name != "__CF_USER_TEXT_ENCODING")
    {
        return Err(AuthorityRuntimeError::ProcessNotConfined);
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn verify_production_process_confinement() -> Result<(), AuthorityRuntimeError> {
    Err(AuthorityRuntimeError::UnsupportedPlatform)
}

pub(crate) async fn serve_until<S, F>(
    config: AuthorityRuntimeConfig,
    protected_store: S,
    catalog: ProviderCatalog,
    shutdown: F,
) -> Result<(), AuthorityRuntimeError>
where
    S: ProtectedStore + 'static,
    F: Future<Output = ()> + Send + 'static,
{
    serve_until_with_spawner(config, protected_store, catalog, shutdown, None).await
}

pub(crate) async fn serve_until_with_spawner<S, F>(
    config: AuthorityRuntimeConfig,
    protected_store: S,
    catalog: ProviderCatalog,
    shutdown: F,
    spawner: Option<Arc<dyn LocalBrokerProcessSpawner>>,
) -> Result<(), AuthorityRuntimeError>
where
    S: ProtectedStore + 'static,
    F: Future<Output = ()> + Send + 'static,
{
    serve_until_with_process_spawners(
        config,
        protected_store,
        catalog,
        shutdown,
        AuthorityRuntimeAdapters {
            broker_spawner: spawner,
            ..Default::default()
        },
    )
    .await
}

#[derive(Default)]
pub(crate) struct AuthorityRuntimeAdapters {
    pub broker_spawner: Option<Arc<dyn LocalBrokerProcessSpawner>>,
    pub repository_spawner: Option<Arc<dyn LocalRepositoryProcessSpawner>>,
    pub ssh_signer: Option<Arc<dyn LocalSshSigner>>,
    pub platform_connector: Option<Arc<dyn crate::PlatformCredentialConnector>>,
    /// Tests learn here that the authority's socket is bound and listening,
    /// instead of guessing with a wall clock.
    #[cfg(test)]
    pub listening: Option<tokio::sync::oneshot::Sender<()>>,
}

pub(crate) async fn serve_until_with_process_spawners<S, F>(
    config: AuthorityRuntimeConfig,
    protected_store: S,
    catalog: ProviderCatalog,
    shutdown: F,
    adapters: AuthorityRuntimeAdapters,
) -> Result<(), AuthorityRuntimeError>
where
    S: ProtectedStore + 'static,
    F: Future<Output = ()> + Send + 'static,
{
    config.prepare_root()?;
    let authority = LocalCredentialAuthority::open(&config.root, protected_store, catalog)?;
    serve_authority(config, authority, shutdown, adapters).await
}

async fn serve_authority<S, F>(
    config: AuthorityRuntimeConfig,
    authority: LocalCredentialAuthority<S>,
    shutdown: F,
    adapters: AuthorityRuntimeAdapters,
) -> Result<(), AuthorityRuntimeError>
where
    S: ProtectedStore + 'static,
    F: Future<Output = ()> + Send + 'static,
{
    let AuthorityRuntimeAdapters {
        broker_spawner,
        repository_spawner,
        ssh_signer,
        platform_connector,
        #[cfg(test)]
        listening,
    } = adapters;
    let authority_root = config.root.clone();
    let socket_dir = config.socket_dir.clone();
    let authority = Arc::new(authority);
    crate::transport::validate_socket_dir(&socket_dir)?;
    cleanup_repository_staging(&authority_root)
        .map_err(|_| AuthorityRuntimeError::InvalidPrivatePath)?;
    // Runtimes live in the socket directory; a cw before #2745 left them in
    // the credential root.
    for directory in [&socket_dir, &authority_root] {
        #[cfg(target_os = "macos")]
        crate::repository::cleanup_repository_credential_sockets(directory)
            .map_err(|_| AuthorityRuntimeError::InvalidPrivatePath)?;
        cleanup_repository_ssh_runtimes(directory)?;
    }
    // The persistence singleton lock is held before a stale endpoint is ever
    // removed, so a losing process cannot unlink the live authority socket.
    let (incoming, socket_identity) = bind_owner_only(&config)?;
    #[cfg(test)]
    if let Some(listening) = listening {
        let _ = listening.send(());
    }
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    let broker_audit = Arc::new(BrokerLeaseAuditLog::default());
    let ssh_runtime = LocalSshOperationRuntime::new(ssh_signer);
    let brokers = Arc::new(BrokerProcessManager::new(
        Arc::clone(&authority),
        broker_spawner,
        Arc::clone(&broker_audit),
        Arc::clone(&ssh_runtime),
        platform_connector.clone(),
        Arc::new(BrokerLog::in_root(&authority_root)),
    ));
    let repositories = Arc::new(RepositoryProcessManager::new(
        Arc::clone(&authority),
        repository_spawner,
        authority_root,
        socket_dir,
        ssh_runtime,
        platform_connector,
    ));
    let _repository_shutdown = repositories.shutdown_on_drop();
    let ssh_enrollment_workers = SshEnrollmentWorkers::new();
    let service = AuthorityRpc {
        authority,
        brokers: Arc::clone(&brokers),
        repositories: Arc::clone(&repositories),
        broker_audit,
        shutdown: shutdown_tx,
        ssh_enrollment_workers: ssh_enrollment_workers.clone(),
    };
    let observed_ssh_enrollment_workers = ssh_enrollment_workers.clone();
    let observed_repositories = Arc::clone(&repositories);
    let observed_shutdown = async move {
        tokio::select! {
            () = shutdown => {}
            _ = async {
                while shutdown_rx.changed().await.is_ok() {
                    if *shutdown_rx.borrow() {
                        break;
                    }
                }
            } => {}
        }
        // Close repository admission immediately, before waiting for other
        // owners; a caller's RPC future is not its process cleanup owner.
        observed_repositories.cancel_all();
        observed_ssh_enrollment_workers.shutdown().await;
    };
    let result = tonic::transport::Server::builder()
        .add_service(
            LocalCredentialAuthorityServiceServer::new(service)
                .max_decoding_message_size(MAX_RPC_MESSAGE_BYTES)
                .max_encoding_message_size(MAX_RPC_MESSAGE_BYTES),
        )
        .serve_with_incoming_shutdown(incoming, observed_shutdown)
        .await
        .map_err(|_| AuthorityRuntimeError::Serve);
    // Tonic may return because its incoming stream ended or service setup
    // failed without completing the supplied shutdown future. Retain this
    // owner outside that future so every server return closes admission and
    // drains detached enrollment workers before authority state is released.
    repositories.cancel_all();
    ssh_enrollment_workers.shutdown().await;
    let repository_cleanup = repositories.shutdown_all().await;
    let broker_cleanup = brokers.shutdown_all().await;
    let cleanup = remove_bound_socket(&config, &socket_identity);
    result
        .and(repository_cleanup)
        .and(broker_cleanup)
        .and(cleanup)
}

struct BrokerProcessEntry {
    generation: u64,
    config: LocalBrokerProcessConfig,
    projection: Option<crate::LocalEnvironmentProjectionBinding>,
    platform: Option<crate::PlatformCredentialBinding>,
    local_profile: Option<EnvironmentAccessBinding>,
    shutdown: watch::Sender<bool>,
    state: watch::Receiver<BrokerProcessState>,
    task: tokio::task::JoinHandle<()>,
    drain_failed: bool,
}

struct BrokerEnsureRequest {
    environment_id: EnvironmentId,
    environment_generation: u64,
    environment_name: String,
    runner_socket: PathBuf,
    projection: Option<crate::LocalEnvironmentProjectionBinding>,
    platform: Option<crate::PlatformCredentialBinding>,
    local_profile: Option<EnvironmentAccessBinding>,
}

type PlatformBrokerBinding = (
    crate::PlatformCredentialBinding,
    Arc<dyn crate::PlatformCredentialConnector>,
);

#[cfg(test)]
mod platform_tests;
#[cfg(test)]
mod renewal_tests;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BrokerProcessState {
    Starting,
    Running,
}

/// When a broker child is replaced: [`BROKER_EPOCH_LIFETIME`] and
/// [`BROKER_SUCCESSOR_LEAD`], shortened only by tests.
#[derive(Clone, Copy, Debug)]
struct BrokerRenewal {
    lifetime: Duration,
    lead: Duration,
}

impl BrokerRenewal {
    const PRODUCTION: Self = Self {
        lifetime: BROKER_EPOCH_LIFETIME,
        lead: BROKER_SUCCESSOR_LEAD,
    };
}

struct BrokerProcessManager<S: ProtectedStore> {
    authority: Arc<LocalCredentialAuthority<S>>,
    spawner: Option<Arc<dyn LocalBrokerProcessSpawner>>,
    audit: Arc<BrokerLeaseAuditLog>,
    entries: Mutex<HashMap<EnvironmentId, BrokerProcessEntry>>,
    ssh_runtime: Arc<LocalSshOperationRuntime>,
    platform_connector: Option<Arc<dyn crate::PlatformCredentialConnector>>,
    log: Arc<BrokerLog>,
}

impl<S: ProtectedStore + 'static> BrokerProcessManager<S> {
    fn new(
        authority: Arc<LocalCredentialAuthority<S>>,
        spawner: Option<Arc<dyn LocalBrokerProcessSpawner>>,
        audit: Arc<BrokerLeaseAuditLog>,
        ssh_runtime: Arc<LocalSshOperationRuntime>,
        platform_connector: Option<Arc<dyn crate::PlatformCredentialConnector>>,
        log: Arc<BrokerLog>,
    ) -> Self {
        Self {
            authority,
            spawner,
            audit,
            entries: Mutex::new(HashMap::new()),
            ssh_runtime,
            platform_connector,
            log,
        }
    }

    /// A platform selection has no local binding to evaluate. Its one
    /// start-time question is GitHub: the platform authorizes it only while
    /// the creator's connection is active, so the guest is configured for it
    /// exactly then. The connector asks as the pinned creator, material-free.
    ///
    /// The environment must be one a platform broker start would admit: it
    /// has no local profile binding, the same check `ensure` makes for a
    /// platform selection (the binding names no environment of its own). The
    /// whole question, whatever the connector does, ends by the deadline.
    async fn platform_github_connected(
        &self,
        environment_id: &EnvironmentId,
        environment_generation: u64,
        platform: v1::PlatformCredentialBinding,
    ) -> Result<bool, Status> {
        self.platform_github_connected_within(
            environment_id,
            environment_generation,
            platform,
            PLATFORM_GITHUB_STATE_DEADLINE,
        )
        .await
    }

    async fn platform_github_connected_within(
        &self,
        environment_id: &EnvironmentId,
        environment_generation: u64,
        platform: v1::PlatformCredentialBinding,
        bound: Duration,
    ) -> Result<bool, Status> {
        // One deadline covers the whole question: the local binding check as
        // well as the connector's OAuth read, `userinfo` and listing.
        let deadline = tokio::time::Instant::now() + bound;
        let binding = crate::PlatformCredentialBinding::from_proto(platform)?;
        binding.validate()?;
        let authority = Arc::clone(&self.authority);
        let id = environment_id.clone();
        let connector = self.platform_connector.clone();
        tokio::time::timeout_at(deadline, async move {
            run_blocking(move || {
                authority.evaluate_selected_environment_grants(&id, environment_generation, None)
            })
            .await?;
            let connector = connector.ok_or_else(|| {
                Status::unavailable("native platform credential connector is unavailable")
            })?;
            connector.github_connected(binding, deadline).await
        })
        .await
        .map_err(|_| Status::deadline_exceeded("platform GitHub connection state timed out"))?
    }

    async fn ensure(
        &self,
        mut request: BrokerEnsureRequest,
    ) -> Result<EnvironmentBrokerRuntime, Status> {
        // Serialize grant evaluation with entry insertion/removal. Binding
        // mutation commits before calling `stop`, so either this evaluation
        // observes the new binding or that stop observes the inserted entry.
        let mut entries = self.entries.lock().await;
        let authority = Arc::clone(&self.authority);
        let ssh_runtime = Arc::clone(&self.ssh_runtime);
        let audit = Arc::clone(&self.audit);
        let environment_id = request.environment_id.clone();
        let generation = request.environment_generation;
        if let Some(binding) = &request.platform {
            binding.validate()?;
        }
        let has_platform = request.platform.is_some();
        let expected_local_profile = request.local_profile.clone();
        let platform_profile = request
            .platform
            .as_ref()
            .is_some_and(|binding| binding.selection.profile.is_some());
        let (http_providers, has_grants, selected_slots, platform_delegated) =
            run_blocking(move || {
                let grants = authority.evaluate_selected_environment_grants(
                    &environment_id,
                    generation,
                    expected_local_profile.as_ref(),
                )?;
                let local_profile = expected_local_profile.is_some();
                // Provider profiles select exactly one authority. Application
                // source placement is independent of that provider selection.
                if platform_profile && local_profile {
                    return Err(LocalCredentialError::StaleEnvironmentBinding);
                }
                if has_platform && !local_profile {
                    return Ok((BTreeSet::new(), false, BTreeSet::new(), true));
                }
                let has_grants = !grants.is_empty();
                let mut providers = BTreeSet::new();
                let mut selected_slots = BTreeSet::new();
                for grant in grants {
                    selected_slots.insert(grant.capability_slot.to_string());
                    let credential = authority.get_credential(&grant.credential_id)?;
                    if let Some(provider) = codewire_access::HttpProvider::for_credential(
                        &grant.capability_slot,
                        &credential.metadata,
                    ) {
                        providers.insert(provider);
                    }
                }
                Ok((providers, has_grants, selected_slots, false))
            })
            .await?;
        let clients = codewire_access::ManagedCredentialClients::from_profile_slots(
            selected_slots.iter().map(String::as_str),
        )
        .map_err(|_| Status::failed_precondition("invalid managed client selection"))?;
        let mut reserved_keys: BTreeSet<String> = clients
            .reserved_environment_keys()
            .into_iter()
            .map(str::to_owned)
            .collect();
        if selected_slots.contains("github") {
            reserved_keys.extend(
                codewire_access::HttpProvider::GitHubOAuth
                    .reserved_environment_keys()
                    .iter()
                    .map(|key| (*key).to_owned()),
            );
        }
        if let Some(platform) = &request.platform {
            reserved_keys.extend(platform.selection.reserved_keys.iter().cloned());
        }
        if let Some(projection) = &request.projection {
            reserved_keys.extend(projection.selection.reserved_keys.iter().cloned());
        }
        if let Some(projection) = request.projection.as_mut() {
            projection.selection.reserved_keys = reserved_keys.clone();
            projection.validate().map_err(status_for_error)?;
        }
        let platform = request
            .platform
            .as_mut()
            .map(|binding| {
                binding.selection.reserved_keys = reserved_keys;
                binding.validate()?;
                if let Some(local) = &request.projection {
                    binding.validate_local_projection(local)?;
                }
                let connector = self.platform_connector.as_ref().cloned().ok_or_else(|| {
                    Status::unavailable("native platform credential connector is unavailable")
                })?;
                Ok::<_, Status>((binding.clone(), connector))
            })
            .transpose()?;
        if !has_grants && request.projection.is_none() && platform.is_none() {
            if let Some(existing) = entries.get_mut(&request.environment_id) {
                stop_broker_entry(existing, &self.ssh_runtime).await?;
            }
            entries.remove(&request.environment_id);
            return Ok(EnvironmentBrokerRuntime {
                environment_id: request.environment_id,
                environment_generation: request.environment_generation,
                running: false,
            });
        }
        let config = LocalBrokerProcessConfig {
            environment_id: request.environment_id,
            environment_generation: request.environment_generation,
            environment_name: request.environment_name,
            runner_socket: request.runner_socket,
            http_providers,
            platform_delegated,
        };
        config
            .validate()
            .map_err(|_| Status::invalid_argument("invalid local credential broker request"))?;
        let spawner = self.spawner.as_ref().cloned().ok_or_else(|| {
            Status::unavailable("local credential broker launcher is unavailable")
        })?;

        if let Some(existing) = entries.get_mut(&config.environment_id) {
            if existing.generation == config.environment_generation && !existing.task.is_finished()
            {
                if *existing.shutdown.borrow() {
                    return Err(Status::unavailable("local credential broker is draining"));
                }
                if existing.config != config
                    || existing.projection != request.projection
                    || existing.platform != request.platform
                    || existing.local_profile != request.local_profile
                {
                    return Err(Status::failed_precondition(
                        "broker selection changed within an active environment generation",
                    ));
                }
                let running = *existing.state.borrow() == BrokerProcessState::Running;
                return Ok(broker_runtime(config, running));
            }
            stop_broker_entry(existing, &self.ssh_runtime).await?;
        }
        entries.remove(&config.environment_id);

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (state_tx, mut state_rx) = watch::channel(BrokerProcessState::Starting);
        let task = tokio::spawn(run_broker_lifecycle(
            Arc::new(BrokerLaunch {
                authority: Arc::clone(&self.authority),
                ssh_runtime,
                spawner,
                config: config.clone(),
                audit,
                projection: request.projection.clone(),
                platform,
                local_profile: request.local_profile.clone(),
                renewal: BrokerRenewal::PRODUCTION,
                log: Arc::clone(&self.log),
            }),
            shutdown_rx,
            state_tx,
        ));
        entries.insert(
            config.environment_id.clone(),
            BrokerProcessEntry {
                generation: config.environment_generation,
                config: config.clone(),
                projection: request.projection,
                platform: request.platform,
                local_profile: request.local_profile,
                shutdown: shutdown_tx,
                state: state_rx.clone(),
                task,
                drain_failed: false,
            },
        );
        // Once admitted, the lifecycle remains authority-owned even when its
        // provider is temporarily offline. Daemon/session access must not be
        // coupled to provider DNS; callers receive an honest readiness
        // snapshot while the bounded restart loop continues in the background.
        drop(entries);
        let running = wait_for_broker_running(&mut state_rx).await.is_ok();
        Ok(broker_runtime(config, running))
    }

    async fn stop(
        &self,
        environment_id: &EnvironmentId,
        generation: Option<u64>,
    ) -> Result<(), Status> {
        let mut entries = self.entries.lock().await;
        let Some(entry) = entries.get_mut(environment_id) else {
            return Ok(());
        };
        if generation.is_some_and(|generation| generation != entry.generation) {
            return Err(Status::failed_precondition(
                "local credential broker generation does not match",
            ));
        }
        stop_broker_entry(entry, &self.ssh_runtime).await?;
        entries.remove(environment_id);
        Ok(())
    }

    async fn shutdown_all(&self) -> Result<(), AuthorityRuntimeError> {
        let entries = {
            let mut entries = self.entries.lock().await;
            entries.drain().map(|(_, entry)| entry).collect::<Vec<_>>()
        };
        for mut entry in entries {
            let _ = entry.shutdown.send(true);
            if !entry.drain_failed {
                let _ = (&mut entry.task).await;
            }
        }
        if self.ssh_runtime.is_unhealthy() {
            Err(AuthorityRuntimeError::Serve)
        } else {
            Ok(())
        }
    }
}

fn broker_runtime(config: LocalBrokerProcessConfig, running: bool) -> EnvironmentBrokerRuntime {
    EnvironmentBrokerRuntime {
        environment_id: config.environment_id,
        environment_generation: config.environment_generation,
        running,
    }
}

async fn wait_for_broker_running(
    state: &mut watch::Receiver<BrokerProcessState>,
) -> Result<(), ()> {
    // This is an honest status snapshot, not the child attempt's lifetime.
    // A delegated child may still become ready in its separately bounded owner.
    tokio::time::timeout(BROKER_LOCAL_START_TIMEOUT, async {
        loop {
            if *state.borrow() == BrokerProcessState::Running {
                return Ok(());
            }
            state.changed().await.map_err(|_| ())?;
        }
    })
    .await
    .map_err(|_| ())?
}

/// What every broker child of one environment generation is started with.
struct BrokerLaunch<S: ProtectedStore> {
    authority: Arc<LocalCredentialAuthority<S>>,
    ssh_runtime: Arc<LocalSshOperationRuntime>,
    spawner: Arc<dyn LocalBrokerProcessSpawner>,
    config: LocalBrokerProcessConfig,
    audit: Arc<BrokerLeaseAuditLog>,
    projection: Option<crate::LocalEnvironmentProjectionBinding>,
    platform: Option<PlatformBrokerBinding>,
    local_profile: Option<EnvironmentAccessBinding>,
    renewal: BrokerRenewal,
    log: Arc<BrokerLog>,
}

type StartingBroker<S> =
    std::pin::Pin<Box<dyn Future<Output = Result<BrokerChild<S>, BrokerAttempt>> + Send>>;

/// Run one environment generation's broker children until `shutdown`.
///
/// A child takes new work until its lifetime ends. Its successor is spawned
/// earlier; once the successor runs, the daemon sends it all new work and
/// keeps the predecessor's epoch draining, so the predecessor only finishes
/// the requests already sent to it, and stops when its lifetime ends. A
/// successor that cannot start is retried while the predecessor serves; a
/// predecessor whose lifetime ends first stops anyway, and a fresh child
/// starts. A child that ends by itself restarts after the bounded backoff.
async fn run_broker_lifecycle<S: ProtectedStore + 'static>(
    launch: Arc<BrokerLaunch<S>>,
    mut shutdown: watch::Receiver<bool>,
    state: watch::Sender<BrokerProcessState>,
) {
    let mut restart_delay = BROKER_RESTART_MIN_DELAY;
    // The child taking new work, the predecessor it replaced while that one
    // finishes, and one child starting: a successor, or a fresh child when
    // none is current.
    let mut current: Option<BrokerChild<S>> = None;
    let mut retiring: Option<BrokerChild<S>> = None;
    let mut starting: Option<StartingBroker<S>> = None;
    let mut fresh_at = tokio::time::Instant::now();
    let mut successor_at = None;
    let mut successor_failures = 0_u32;
    // Since a child last ran with none before it: successors keep it.
    let mut serving_since = None;
    loop {
        let next_start = match (&current, &starting) {
            (_, Some(_)) => None,
            (None, None) => Some(fresh_at),
            (Some(current), None) => {
                successor_at.filter(|at| retiring.is_none() && *at < current.ends_at)
            }
        };
        tokio::select! {
            biased;
            _ = shutdown.changed() => break,
            started = run_starting(&mut starting) => {
                starting = None;
                let now = tokio::time::Instant::now();
                match started {
                    Ok(child) => {
                        if state.send(BrokerProcessState::Running).is_err() {
                            child.stop().await;
                            break;
                        }
                        successor_at = Some(
                            child.ends_at.checked_sub(launch.renewal.lead).unwrap_or(now),
                        );
                        successor_failures = 0;
                        serving_since.get_or_insert(now);
                        // Its Ready means the daemon already sends all new
                        // work to it; the predecessor drains.
                        if let Some(predecessor) = current.replace(child)
                            && let Some(older) = retiring.replace(predecessor)
                        {
                            older.stop().await;
                        }
                    }
                    Err(BrokerAttempt::Stopped) => break,
                    Err(BrokerAttempt::Failed) if current.is_some() => {
                        successor_at = Some(now + successor_backoff(successor_failures));
                        successor_failures = successor_failures.saturating_add(1);
                    }
                    Err(BrokerAttempt::Failed) => {
                        restart_delay = restart_delay
                            .saturating_mul(2)
                            .min(BROKER_RESTART_MAX_DELAY);
                        fresh_at = now + restart_delay;
                        launch.log.record(
                            "broker_restart_scheduled",
                            &[
                                ("environment", &launch.config.environment_id),
                                ("generation", &launch.config.environment_generation),
                                ("in_ms", &restart_delay.as_millis()),
                            ],
                        );
                    }
                }
            }
            event = child_event(&mut current) => {
                let Some(mut child) = current.take() else {
                    continue;
                };
                let running_for = serving_since
                    .take()
                    .map_or(Duration::ZERO, |since: tokio::time::Instant| since.elapsed());
                let (reason, delay) = match event {
                    // No successor ran in time: fail closed and start a fresh
                    // child at once, unless a successor is still starting.
                    ChildEvent::LifetimeEnded => ("lifetime_ended", BROKER_RESTART_MIN_DELAY),
                    ChildEvent::Ended => ("ended", next_restart_delay(restart_delay, running_for)),
                };
                record_broker_end(
                    &launch.log,
                    "broker_ended",
                    reason,
                    &mut child,
                    &launch.config.environment_id,
                    launch.config.environment_generation,
                    running_for,
                    Some(match event {
                        ChildEvent::LifetimeEnded => Duration::ZERO,
                        ChildEvent::Ended => delay,
                    }),
                )
                .await;
                child.stop().await;
                let _ = state.send(BrokerProcessState::Starting);
                successor_at = None;
                successor_failures = 0;
                restart_delay = delay;
                fresh_at = tokio::time::Instant::now()
                    + match event {
                        ChildEvent::LifetimeEnded => Duration::ZERO,
                        ChildEvent::Ended => delay,
                    };
            }
            _ = child_event(&mut retiring) => {
                if let Some(predecessor) = retiring.take() {
                    predecessor.stop().await;
                }
            }
            () = sleep_until_some(next_start) => {
                starting = Some(Box::pin(start_broker(Arc::clone(&launch), shutdown.clone())));
            }
        }
    }
    // A starting child observes the same shutdown and stops itself.
    let starting = async {
        if let Some(starting) = starting
            && let Ok(child) = starting.await
        {
            child.stop().await;
        }
    };
    tokio::join!(stop_some(current), stop_some(retiring), starting);
}

enum BrokerAttempt {
    Stopped,
    Failed,
}

enum ChildEvent {
    /// The child or its lease channel ended by itself.
    Ended,
    LifetimeEnded,
}

/// One admitted broker child and its lease channel. Its owner ends it with
/// [`Self::stop`].
struct BrokerChild<S: ProtectedStore> {
    child: tokio::process::Child,
    lease_shutdown: watch::Sender<bool>,
    lease_task: tokio::task::JoinHandle<Result<(), crate::BrokerLeaseChannelError>>,
    /// The lease task already returned and must not be polled again.
    channel_ended: bool,
    /// How the lease task ended, once it has (for the broker log).
    lease_outcome: Option<&'static str>,
    pid: Option<u32>,
    stderr: Option<StderrTail>,
    lifetime: Arc<BrokerChannelRefreshLifetime<S>>,
    /// Its spawn plus the renewal lifetime.
    ends_at: tokio::time::Instant,
}

impl<S: ProtectedStore> BrokerChild<S> {
    /// Resolves when the child exits or its lease channel ends. Cancel-safe.
    async fn ended(&mut self) {
        tokio::select! {
            _ = self.child.wait() => {}
            result = &mut self.lease_task, if !self.channel_ended => {
                self.channel_ended = true;
                self.lease_outcome = Some(lease_outcome(&result));
            }
        }
    }

    /// Why the broker ended before it was ready: the child exited, or else
    /// its lease channel closed. A child's exit closes its lease too, so both
    /// can be seen at once; the reason comes from the child's state, never
    /// from which event was noticed first (#3069).
    fn not_ready_reason(&mut self) -> &'static str {
        if matches!(self.child.try_wait(), Ok(Some(_))) {
            "ended_before_ready"
        } else {
            "lease_closed_before_ready"
        }
    }

    /// The child's exit status and the lease channel's outcome so far, for
    /// the broker log. Call before [`Self::stop`], which kills the child.
    fn outcome(&mut self) -> (String, &'static str) {
        let status = exit_status(self.child.try_wait().ok().flatten());
        let lease = if self.channel_ended {
            self.lease_outcome.unwrap_or("ended")
        } else if self.lease_task.is_finished() {
            "finished"
        } else {
            "open"
        };
        (status, lease)
    }

    async fn stop(mut self) {
        let _ = self.child.kill().await;
        let _ = self.lease_shutdown.send(true);
        if !self.channel_ended {
            let _ = (&mut self.lease_task).await;
        }
        // A panicked lease task drops its close guard but cannot await workers.
        // Its manager holds this independent observer until the same drain ends.
        self.lifetime.close_and_wait().await;
    }
}

/// The lease task's typed outcome; no request or credential data.
fn lease_outcome(
    result: &Result<Result<(), crate::BrokerLeaseChannelError>, tokio::task::JoinError>,
) -> &'static str {
    use crate::BrokerLeaseChannelError as E;
    match result {
        Ok(Ok(())) => "closed",
        Ok(Err(E::InvalidRequest)) => "invalid_request",
        Ok(Err(E::Denied)) => "denied",
        Ok(Err(E::Unavailable)) => "unavailable",
        Ok(Err(E::InvalidResponse)) => "invalid_response",
        Ok(Err(E::RefreshInProgress)) => "refresh_in_progress",
        Ok(Err(E::StaleRefresh)) => "stale_refresh",
        Err(error) if error.is_panic() => "panicked",
        Err(_) => "cancelled",
    }
}

async fn child_event<S: ProtectedStore>(child: &mut Option<BrokerChild<S>>) -> ChildEvent {
    let Some(child) = child else {
        return std::future::pending().await;
    };
    let ends_at = child.ends_at;
    tokio::select! {
        () = child.ended() => ChildEvent::Ended,
        () = tokio::time::sleep_until(ends_at) => ChildEvent::LifetimeEnded,
    }
}

async fn run_starting<S: ProtectedStore>(
    starting: &mut Option<StartingBroker<S>>,
) -> Result<BrokerChild<S>, BrokerAttempt> {
    match starting {
        Some(starting) => starting.as_mut().await,
        None => std::future::pending().await,
    }
}

async fn sleep_until_some(at: Option<tokio::time::Instant>) {
    match at {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
    }
}

async fn stop_some<S: ProtectedStore>(child: Option<BrokerChild<S>>) {
    if let Some(child) = child {
        child.stop().await;
    }
}

/// The delay before restarting a child that ended by itself after serving for
/// `running_for`: it doubles from the previous delay up to the maximum while
/// children keep failing young, and starts over once one has served for the
/// stable runtime, so a bad period does not leave a healthy environment on
/// the maximum delay.
fn next_restart_delay(previous: Duration, running_for: Duration) -> Duration {
    if running_for >= BROKER_STABLE_RUNTIME {
        BROKER_RESTART_MIN_DELAY
    } else {
        previous.saturating_mul(2).min(BROKER_RESTART_MAX_DELAY)
    }
}

/// After `failures` earlier failed successors of the current child.
fn successor_backoff(failures: u32) -> Duration {
    BROKER_SUCCESSOR_RETRY_FIRST
        .checked_mul(2_u32.saturating_pow(failures.min(8)))
        .map_or(BROKER_SUCCESSOR_RETRY_MAX, |delay| {
            delay.min(BROKER_SUCCESSOR_RETRY_MAX)
        })
}

/// Spawn one child and admit it within one start deadline: its lease channel
/// reports it ready and it stays up for the stability interval.
async fn start_broker<S: ProtectedStore + 'static>(
    launch: Arc<BrokerLaunch<S>>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<BrokerChild<S>, BrokerAttempt> {
    if *shutdown.borrow() {
        return Err(BrokerAttempt::Stopped);
    }
    // Capture before spawning the child. Neither handshake phase nor retry
    // within this attempt can reset this total deadline. The child's
    // lifetime also counts from here.
    let spawned_at = tokio::time::Instant::now();
    let start_deadline = spawned_at
        + if launch.platform.is_some() {
            BROKER_PLATFORM_START_TIMEOUT
        } else {
            BROKER_LOCAL_START_TIMEOUT
        };
    let Ok((authority_stream, broker_stream)) = std::os::unix::net::UnixStream::pair() else {
        return Err(BrokerAttempt::Failed);
    };
    if authority_stream.set_nonblocking(true).is_err() {
        return Err(BrokerAttempt::Failed);
    }
    let Ok(authority_stream) = UnixStream::from_std(authority_stream) else {
        return Err(BrokerAttempt::Failed);
    };
    let log = &launch.log;
    let environment = &launch.config.environment_id;
    let generation = launch.config.environment_generation;
    let Ok(child) = launch.spawner.spawn(&launch.config, broker_stream) else {
        log.record(
            "broker_spawn_failed",
            &[("environment", environment), ("generation", &generation)],
        );
        return Err(BrokerAttempt::Failed);
    };
    let mut child = child;
    let pid = child.id();
    let stderr = child.stderr.take().map(StderrTail::spawn);
    log.record(
        "broker_spawned",
        &[
            ("environment", environment),
            ("generation", &generation),
            (
                "pid",
                &pid.map_or_else(|| "none".to_owned(), |pid| pid.to_string()),
            ),
        ],
    );
    let (ready_tx, mut ready_rx) = tokio::sync::oneshot::channel();
    let (lease_shutdown, lease_stopped) = watch::channel(false);
    let lifetime = BrokerChannelRefreshLifetime::new_with_ssh_runtime(
        Arc::clone(&launch.authority),
        Arc::clone(&launch.ssh_runtime),
    );
    let lease_task = tokio::spawn(serve_broker_lease_channel_with_ready(
        Arc::clone(&lifetime),
        authority_stream,
        launch.config.environment_id.clone(),
        launch.config.environment_generation,
        Arc::clone(&launch.audit),
        launch.projection.clone(),
        BrokerLeaseChannelControl {
            ready: Some(ready_tx),
            shutdown: Some(lease_stopped),
            platform: launch.platform.clone(),
            platform_delegated: launch.config.platform_delegated,
            local_profile: launch.local_profile.clone(),
        },
    ));
    let mut broker = BrokerChild {
        child,
        lease_shutdown,
        lease_task,
        channel_ended: false,
        lease_outcome: None,
        pid,
        stderr,
        lifetime,
        ends_at: spawned_at + launch.renewal.lifetime,
    };
    let mut start_timeout = Box::pin(tokio::time::sleep_until(start_deadline));
    let not_ready = tokio::select! {
        ready = &mut ready_rx => ready.is_err().then(|| broker.not_ready_reason()),
        () = broker.ended() => Some(broker.not_ready_reason()),
        _ = shutdown.changed() => {
            broker.stop().await;
            return Err(BrokerAttempt::Stopped);
        }
        _ = &mut start_timeout => Some("start_timeout"),
    };
    if let Some(reason) = not_ready {
        record_broker_end(
            log,
            "broker_not_ready",
            reason,
            &mut broker,
            environment,
            generation,
            spawned_at.elapsed(),
            None,
        )
        .await;
        broker.stop().await;
        return Err(BrokerAttempt::Failed);
    }
    log.record(
        "broker_ready",
        &[
            ("environment", environment),
            ("generation", &generation),
            (
                "pid",
                &pid.map_or_else(|| "none".to_owned(), |pid| pid.to_string()),
            ),
            ("elapsed_ms", &spawned_at.elapsed().as_millis()),
        ],
    );

    let stability = tokio::time::sleep(BROKER_READY_STABILITY);
    let unstable = tokio::select! {
        _ = stability => (tokio::time::Instant::now() >= start_deadline).then_some("start_timeout"),
        _ = &mut start_timeout => Some("start_timeout"),
        () = broker.ended() => Some("ended_while_settling"),
        _ = shutdown.changed() => {
            broker.stop().await;
            return Err(BrokerAttempt::Stopped);
        }
    };
    if let Some(reason) = unstable {
        record_broker_end(
            log,
            "broker_not_ready",
            reason,
            &mut broker,
            environment,
            generation,
            spawned_at.elapsed(),
            None,
        )
        .await;
        broker.stop().await;
        return Err(BrokerAttempt::Failed);
    }
    Ok(broker)
}

/// One line for a child that ended or never became ready: its exit status and
/// lease outcome are read before the authority stops it.
#[allow(clippy::too_many_arguments)]
async fn record_broker_end<S: ProtectedStore>(
    log: &BrokerLog,
    event: &str,
    reason: &str,
    broker: &mut BrokerChild<S>,
    environment: &EnvironmentId,
    generation: u64,
    ran: Duration,
    restart_in: Option<Duration>,
) {
    let (status, lease) = broker.outcome();
    let exited = status != "running";
    let error = match &mut broker.stderr {
        Some(tail) => tail.exit_line(exited).await,
        None => String::new(),
    };
    let error = if error.is_empty() {
        "-".to_owned()
    } else {
        error
    };
    let pid = broker
        .pid
        .map_or_else(|| "none".to_owned(), |pid| pid.to_string());
    let restart = restart_in.map_or_else(|| "-".to_owned(), |delay| delay.as_millis().to_string());
    log.record(
        event,
        &[
            ("environment", environment),
            ("generation", &generation),
            ("pid", &pid),
            ("reason", &reason),
            ("status", &status),
            ("lease", &lease),
            ("ran_ms", &ran.as_millis()),
            ("restart_in_ms", &restart),
            ("error", &error),
        ],
    );
}

async fn stop_broker_entry(
    entry: &mut BrokerProcessEntry,
    ssh_runtime: &LocalSshOperationRuntime,
) -> Result<(), Status> {
    if entry.drain_failed {
        return Err(Status::unavailable("local credential broker drain failed"));
    }
    let _ = entry.shutdown.send(true);
    // Cancellation or a timeout must retain the entry and its lifecycle owner:
    // a retry cannot acknowledge a still-running protected-store worker.
    let result = tokio::time::timeout(BROKER_DRAIN_TIMEOUT, &mut entry.task)
        .await
        .map_err(|_| Status::deadline_exceeded("local credential broker is still draining"))?;
    if result.is_err() || ssh_runtime.is_unhealthy() {
        entry.drain_failed = true;
        return Err(Status::unavailable("local credential broker drain failed"));
    }
    Ok(())
}

#[tonic::async_trait]
impl<S: ProtectedStore + 'static> LocalCredentialAuthorityService for AuthorityRpc<S> {
    async fn get_authority_info(
        &self,
        _request: Request<v1::GetAuthorityInfoRequest>,
    ) -> Result<Response<v1::AuthorityInfo>, Status> {
        Ok(Response::new(v1::AuthorityInfo {
            protocol_version: AUTHORITY_PROTOCOL_VERSION,
            protected_store_persistence: persistence_to_proto(
                self.authority.protected_store_persistence(),
            ) as i32,
            protected_store_backend: self
                .authority
                .protected_store_identity()
                .map(AuthorityProtectedStore::to_record)
                .unwrap_or_default(),
        }))
    }

    async fn shutdown_authority(
        &self,
        _request: Request<v1::ShutdownAuthorityRequest>,
    ) -> Result<Response<v1::ShutdownAuthorityResponse>, Status> {
        self.shutdown
            .send(true)
            .map_err(|_| Status::unavailable("local credential authority is stopping"))?;
        Ok(Response::new(v1::ShutdownAuthorityResponse {}))
    }

    async fn add_credential(
        &self,
        request: Request<v1::AddCredentialRequest>,
    ) -> Result<Response<v1::Credential>, Status> {
        let mut request = request.into_inner();
        let input = NewCredential {
            provider: ProviderId::parse(mem::take(&mut request.provider))
                .map_err(status_for_access_error)?,
            authentication_kind: auth_kind_from_proto(request.authentication_kind)?,
            display_name: mem::take(&mut request.display_name),
            account_hint: mem::take(&mut request.account_hint),
            expires_at_unix: request.expires_at_unix,
        };
        let material = ProtectedValue::new(mem::take(&mut request.material))
            .map_err(|_| Status::invalid_argument("the value is not a valid credential"))?;
        let authority = Arc::clone(&self.authority);
        let record = run_blocking(move || authority.add_credential(input, material)).await?;
        Ok(Response::new(credential_to_proto(record)))
    }

    async fn generate_ssh_credential(
        &self,
        request: Request<v1::GenerateSshCredentialRequest>,
    ) -> Result<Response<v1::Credential>, Status> {
        let deadline = Instant::now() + SSH_ENROLLMENT_DEADLINE;
        let request = request.into_inner();
        let authority = Arc::clone(&self.authority);
        authority
            .validate_ssh_enrollment_name(&request.name)
            .map_err(status_for_access_error)?;
        validate_ssh_expiry(request.expires_at_unix)?;
        let record = self
            .ssh_enrollment_workers
            .run(move |cancelled| {
                ssh_enrollment_check(deadline, &cancelled).map_err(status_for_error)?;
                let prepared = generate_ed25519().map_err(status_for_ssh_material_error)?;
                authority
                    .add_ssh_credential(request.name, request.expires_at_unix, prepared, || {
                        ssh_enrollment_check(deadline, &cancelled)
                    })
                    .map_err(status_for_error)
            })
            .await?;
        Ok(Response::new(credential_to_proto(record)))
    }

    async fn add_ssh_credential(
        &self,
        request: Request<v1::AddSshCredentialRequest>,
    ) -> Result<Response<v1::Credential>, Status> {
        let deadline = Instant::now() + SSH_ENROLLMENT_DEADLINE;
        let mut request = request.into_inner();
        let private_key = Zeroizing::new(mem::take(&mut request.private_key));
        let passphrase = request.passphrase.take().map(Zeroizing::new);
        let name = mem::take(&mut request.name);
        let expires_at_unix = request.expires_at_unix;
        let authority = Arc::clone(&self.authority);
        authority
            .validate_ssh_enrollment_name(&name)
            .map_err(status_for_access_error)?;
        validate_ssh_expiry(expires_at_unix)?;
        let record = self
            .ssh_enrollment_workers
            .run(move |cancelled| {
                ssh_enrollment_check(deadline, &cancelled).map_err(status_for_error)?;
                let prepared = import_openssh(private_key, passphrase)
                    .map_err(status_for_ssh_material_error)?;
                authority
                    .add_ssh_credential(name, expires_at_unix, prepared, || {
                        ssh_enrollment_check(deadline, &cancelled)
                    })
                    .map_err(status_for_error)
            })
            .await?;
        Ok(Response::new(credential_to_proto(record)))
    }

    async fn list_credentials(
        &self,
        _request: Request<v1::ListCredentialsRequest>,
    ) -> Result<Response<v1::ListCredentialsResponse>, Status> {
        let authority = Arc::clone(&self.authority);
        let credentials = run_blocking(move || authority.list_credentials()).await?;
        Ok(Response::new(v1::ListCredentialsResponse {
            credentials: credentials.into_iter().map(credential_to_proto).collect(),
        }))
    }

    async fn get_credential(
        &self,
        request: Request<v1::CredentialSelector>,
    ) -> Result<Response<v1::Credential>, Status> {
        let id = credential_id(request.into_inner().credential_id)?;
        let authority = Arc::clone(&self.authority);
        let record = run_blocking(move || authority.get_credential(&id)).await?;
        Ok(Response::new(credential_to_proto(record)))
    }

    async fn rename_credential(
        &self,
        request: Request<v1::RenameCredentialRequest>,
    ) -> Result<Response<v1::Credential>, Status> {
        let request = request.into_inner();
        let id = credential_id(request.credential_id)?;
        let authority = Arc::clone(&self.authority);
        let record =
            run_blocking(move || authority.rename_credential(&id, request.display_name)).await?;
        Ok(Response::new(credential_to_proto(record)))
    }

    async fn rotate_credential_material(
        &self,
        request: Request<v1::RotateCredentialMaterialRequest>,
    ) -> Result<Response<v1::Credential>, Status> {
        let mut request = request.into_inner();
        let id = credential_id(mem::take(&mut request.credential_id))?;
        let expected_revocation_generation = request.expected_revocation_generation;
        if expected_revocation_generation == 0 {
            return Err(Status::invalid_argument(
                "expected credential revision must be positive",
            ));
        }
        let material = ProtectedValue::new(mem::take(&mut request.material))
            .map_err(|_| Status::invalid_argument("the value is not a valid credential"))?;
        let expires_at_unix = request.expires_at_unix;
        let account_hint = request.account_hint.take();
        let authority = Arc::clone(&self.authority);
        let record = run_blocking(move || {
            authority.rotate_credential_material(
                &id,
                expected_revocation_generation,
                material,
                expires_at_unix,
                account_hint,
            )
        })
        .await?;
        Ok(Response::new(credential_to_proto(record)))
    }

    async fn revoke_credential(
        &self,
        request: Request<v1::CredentialSelector>,
    ) -> Result<Response<v1::Credential>, Status> {
        let id = credential_id(request.into_inner().credential_id)?;
        let authority = Arc::clone(&self.authority);
        let record = run_blocking(move || authority.revoke_credential(&id)).await?;
        Ok(Response::new(credential_to_proto(record)))
    }

    async fn delete_credential(
        &self,
        request: Request<v1::CredentialSelector>,
    ) -> Result<Response<v1::DeleteCredentialResponse>, Status> {
        let id = credential_id(request.into_inner().credential_id)?;
        let authority = Arc::clone(&self.authority);
        run_blocking(move || authority.delete_credential(&id)).await?;
        Ok(Response::new(v1::DeleteCredentialResponse {}))
    }

    async fn create_secret_project(
        &self,
        request: Request<v1::CreateLocalSecretProjectRequest>,
    ) -> Result<Response<v1::LocalSecretProject>, Status> {
        let name = request.into_inner().name;
        let authority = Arc::clone(&self.authority);
        let project = run_blocking(move || authority.create_secret_project(&name)).await?;
        Ok(Response::new(secret_project_to_proto(project)))
    }

    async fn list_secret_projects(
        &self,
        _request: Request<v1::ListLocalSecretProjectsRequest>,
    ) -> Result<Response<v1::ListLocalSecretProjectsResponse>, Status> {
        let authority = Arc::clone(&self.authority);
        let projects = run_blocking(move || authority.list_secret_projects()).await?;
        Ok(Response::new(v1::ListLocalSecretProjectsResponse {
            projects: projects.into_iter().map(secret_project_to_proto).collect(),
        }))
    }

    async fn delete_secret_project(
        &self,
        request: Request<v1::LocalSecretProjectSelector>,
    ) -> Result<Response<v1::DeleteLocalSecretProjectResponse>, Status> {
        let project_id = local_secret_project_id(&request.into_inner().project_id)?;
        let authority = Arc::clone(&self.authority);
        run_blocking(move || authority.delete_secret_project(project_id)).await?;
        Ok(Response::new(v1::DeleteLocalSecretProjectResponse {}))
    }

    async fn list_user_workload_secrets(
        &self,
        _request: Request<v1::ListUserWorkloadSecretsRequest>,
    ) -> Result<Response<v1::ListWorkloadSecretsResponse>, Status> {
        let authority = Arc::clone(&self.authority);
        let secrets = run_blocking(move || authority.list_user_workload_secrets()).await?;
        Ok(Response::new(v1::ListWorkloadSecretsResponse {
            secrets: secrets.into_iter().map(workload_secret_to_proto).collect(),
        }))
    }

    async fn set_user_workload_secret(
        &self,
        request: Request<v1::SetUserWorkloadSecretRequest>,
    ) -> Result<Response<v1::WorkloadSecretMetadata>, Status> {
        let mut request = request.into_inner();
        let key = mem::take(&mut request.key);
        let value = ProtectedValue::new(mem::take(&mut request.value))
            .map_err(|_| Status::invalid_argument("invalid workload-secret value"))?;
        let authority = Arc::clone(&self.authority);
        let secret = run_blocking(move || authority.set_user_workload_secret(&key, value)).await?;
        Ok(Response::new(workload_secret_to_proto(secret)))
    }

    async fn delete_user_workload_secret(
        &self,
        request: Request<v1::DeleteUserWorkloadSecretRequest>,
    ) -> Result<Response<v1::DeleteWorkloadSecretResponse>, Status> {
        let key = request.into_inner().key;
        let authority = Arc::clone(&self.authority);
        run_blocking(move || authority.delete_user_workload_secret(&key)).await?;
        Ok(Response::new(v1::DeleteWorkloadSecretResponse {}))
    }

    async fn rename_user_workload_secret(
        &self,
        request: Request<v1::RenameUserWorkloadSecretRequest>,
    ) -> Result<Response<v1::WorkloadSecretMetadata>, Status> {
        let request = request.into_inner();
        let authority = Arc::clone(&self.authority);
        let secret = run_blocking(move || {
            authority.rename_user_workload_secret(&request.key, &request.new_key)
        })
        .await?;
        Ok(Response::new(workload_secret_to_proto(secret)))
    }

    async fn list_project_workload_secrets(
        &self,
        request: Request<v1::ListProjectWorkloadSecretsRequest>,
    ) -> Result<Response<v1::ListWorkloadSecretsResponse>, Status> {
        let project_id = local_secret_project_id(&request.into_inner().project_id)?;
        let authority = Arc::clone(&self.authority);
        let secrets =
            run_blocking(move || authority.list_project_workload_secrets(project_id)).await?;
        Ok(Response::new(v1::ListWorkloadSecretsResponse {
            secrets: secrets.into_iter().map(workload_secret_to_proto).collect(),
        }))
    }

    async fn set_project_workload_secret(
        &self,
        request: Request<v1::SetProjectWorkloadSecretRequest>,
    ) -> Result<Response<v1::WorkloadSecretMetadata>, Status> {
        let mut request = request.into_inner();
        let project_id = local_secret_project_id(&request.project_id)?;
        let key = mem::take(&mut request.key);
        let value = ProtectedValue::new(mem::take(&mut request.value))
            .map_err(|_| Status::invalid_argument("invalid workload-secret value"))?;
        let authority = Arc::clone(&self.authority);
        let secret =
            run_blocking(move || authority.set_project_workload_secret(project_id, &key, value))
                .await?;
        Ok(Response::new(workload_secret_to_proto(secret)))
    }

    async fn delete_project_workload_secret(
        &self,
        request: Request<v1::DeleteProjectWorkloadSecretRequest>,
    ) -> Result<Response<v1::DeleteWorkloadSecretResponse>, Status> {
        let request = request.into_inner();
        let project_id = local_secret_project_id(&request.project_id)?;
        let authority = Arc::clone(&self.authority);
        run_blocking(move || authority.delete_project_workload_secret(project_id, &request.key))
            .await?;
        Ok(Response::new(v1::DeleteWorkloadSecretResponse {}))
    }

    async fn rename_project_workload_secret(
        &self,
        request: Request<v1::RenameProjectWorkloadSecretRequest>,
    ) -> Result<Response<v1::WorkloadSecretMetadata>, Status> {
        let request = request.into_inner();
        let project_id = local_secret_project_id(&request.project_id)?;
        let authority = Arc::clone(&self.authority);
        let secret = run_blocking(move || {
            authority.rename_project_workload_secret(project_id, &request.key, &request.new_key)
        })
        .await?;
        Ok(Response::new(workload_secret_to_proto(secret)))
    }

    async fn resolve_workload_secret_metadata(
        &self,
        request: Request<v1::ResolveWorkloadSecretMetadataRequest>,
    ) -> Result<Response<v1::ResolveWorkloadSecretMetadataResponse>, Status> {
        let selection =
            workload_secret_selection_from_proto(request.into_inner().selection.ok_or_else(
                || Status::invalid_argument("workload-secret selection is required"),
            )?)?;
        let authority = Arc::clone(&self.authority);
        let secrets =
            run_blocking(move || authority.resolve_workload_secret_metadata(&selection)).await?;
        Ok(Response::new(v1::ResolveWorkloadSecretMetadataResponse {
            secrets: secrets.into_iter().map(resolved_secret_to_proto).collect(),
        }))
    }

    async fn create_access_profile(
        &self,
        request: Request<v1::CreateAccessProfileRequest>,
    ) -> Result<Response<v1::AccessProfileRevision>, Status> {
        let request = request.into_inner();
        let name = AccessProfileName::parse(request.name).map_err(status_for_access_error)?;
        let entries = profile_entries(request.entries)?;
        let authority = Arc::clone(&self.authority);
        let profile = run_blocking(move || authority.create_profile(name, entries)).await?;
        Ok(Response::new(profile_record_to_proto(profile)))
    }

    async fn update_access_profile(
        &self,
        request: Request<v1::UpdateAccessProfileRequest>,
    ) -> Result<Response<v1::AccessProfileRevision>, Status> {
        let request = request.into_inner();
        let id = profile_id(request.profile_id)?;
        let entries = profile_entries(request.entries)?;
        let authority = Arc::clone(&self.authority);
        let profile =
            run_blocking(move || authority.update_profile(&id, request.expected_revision, entries))
                .await?;
        Ok(Response::new(profile_record_to_proto(profile)))
    }

    async fn list_access_profiles(
        &self,
        _request: Request<v1::ListAccessProfilesRequest>,
    ) -> Result<Response<v1::ListAccessProfilesResponse>, Status> {
        let authority = Arc::clone(&self.authority);
        let profiles = run_blocking(move || authority.list_profiles()).await?;
        Ok(Response::new(v1::ListAccessProfilesResponse {
            profiles: profiles.into_iter().map(profile_record_to_proto).collect(),
        }))
    }

    async fn get_access_profile(
        &self,
        request: Request<v1::AccessProfileSelector>,
    ) -> Result<Response<v1::AccessProfileRevision>, Status> {
        let id = profile_id(request.into_inner().profile_id)?;
        let authority = Arc::clone(&self.authority);
        let profile = run_blocking(move || authority.get_profile(&id)).await?;
        Ok(Response::new(profile_record_to_proto(profile)))
    }

    async fn get_access_profile_revision(
        &self,
        request: Request<v1::GetAccessProfileRevisionRequest>,
    ) -> Result<Response<v1::AccessProfileRevision>, Status> {
        let request = request.into_inner();
        let id = profile_id(request.profile_id)?;
        let authority = Arc::clone(&self.authority);
        let revision =
            run_blocking(move || authority.get_profile_revision(&id, request.revision)).await?;
        Ok(Response::new(profile_revision_to_proto(revision)))
    }

    async fn list_access_profile_revisions(
        &self,
        request: Request<v1::ListAccessProfileRevisionsRequest>,
    ) -> Result<Response<v1::ListAccessProfileRevisionsResponse>, Status> {
        let id = profile_id(request.into_inner().profile_id)?;
        let authority = Arc::clone(&self.authority);
        let revisions = run_blocking(move || authority.list_profile_revisions(&id)).await?;
        Ok(Response::new(v1::ListAccessProfileRevisionsResponse {
            revisions: revisions
                .into_iter()
                .map(profile_revision_to_proto)
                .collect(),
        }))
    }

    async fn resolve_access_profile(
        &self,
        request: Request<v1::ResolveAccessProfileRequest>,
    ) -> Result<Response<v1::AccessProfileRevision>, Status> {
        let reference = request
            .into_inner()
            .reference
            .parse::<AccessProfileReference>()
            .map_err(status_for_access_error)?;
        let authority = Arc::clone(&self.authority);
        let profile = run_blocking(move || authority.resolve_profile(&reference)).await?;
        Ok(Response::new(profile_record_to_proto(profile)))
    }

    async fn delete_access_profile(
        &self,
        request: Request<v1::AccessProfileSelector>,
    ) -> Result<Response<v1::DeleteAccessProfileResponse>, Status> {
        let id = profile_id(request.into_inner().profile_id)?;
        let authority = Arc::clone(&self.authority);
        run_blocking(move || authority.delete_profile(&id)).await?;
        Ok(Response::new(v1::DeleteAccessProfileResponse {}))
    }

    async fn create_environment_access_binding(
        &self,
        request: Request<v1::CreateEnvironmentAccessBindingRequest>,
    ) -> Result<Response<v1::EnvironmentAccessBinding>, Status> {
        let request = request.into_inner();
        let binding = EnvironmentAccessBinding {
            environment_id: environment_id(request.environment_id)?,
            profile_id: profile_id(request.profile_id)?,
            profile_revision: request.profile_revision,
        };
        binding.validate().map_err(status_for_access_error)?;
        let authority = Arc::clone(&self.authority);
        let binding =
            run_blocking(move || authority.create_environment_access_binding(binding)).await?;
        Ok(Response::new(environment_binding_to_proto(binding)))
    }

    async fn replace_environment_access_binding(
        &self,
        request: Request<v1::ReplaceEnvironmentAccessBindingRequest>,
    ) -> Result<Response<v1::EnvironmentAccessBinding>, Status> {
        let request = request.into_inner();
        let environment_id = environment_id(request.environment_id)?;
        let expected_profile_id = profile_id(request.expected_profile_id)?;
        let profile_id = profile_id(request.profile_id)?;
        if request.expected_profile_revision == 0 || request.profile_revision == 0 {
            return Err(Status::invalid_argument(
                "invalid environment access binding revision",
            ));
        }
        let broker_environment_id = environment_id.clone();
        let authority = Arc::clone(&self.authority);
        let binding = run_blocking(move || {
            authority.replace_environment_access_binding(
                &environment_id,
                &expected_profile_id,
                request.expected_profile_revision,
                profile_id,
                request.profile_revision,
            )
        })
        .await?;
        self.brokers.stop(&broker_environment_id, None).await?;
        Ok(Response::new(environment_binding_to_proto(binding)))
    }

    async fn get_environment_access_binding(
        &self,
        request: Request<v1::EnvironmentAccessBindingSelector>,
    ) -> Result<Response<v1::EnvironmentAccessBinding>, Status> {
        let environment_id = environment_id(request.into_inner().environment_id)?;
        let authority = Arc::clone(&self.authority);
        let binding =
            run_blocking(move || authority.get_environment_access_binding(&environment_id)).await?;
        Ok(Response::new(environment_binding_to_proto(binding)))
    }

    async fn list_environment_access_bindings(
        &self,
        _request: Request<v1::ListEnvironmentAccessBindingsRequest>,
    ) -> Result<Response<v1::ListEnvironmentAccessBindingsResponse>, Status> {
        let authority = Arc::clone(&self.authority);
        let bindings = run_blocking(move || authority.list_environment_access_bindings()).await?;
        Ok(Response::new(v1::ListEnvironmentAccessBindingsResponse {
            bindings: bindings
                .into_iter()
                .map(environment_binding_to_proto)
                .collect(),
        }))
    }

    async fn delete_environment_access_binding(
        &self,
        request: Request<v1::DeleteEnvironmentAccessBindingRequest>,
    ) -> Result<Response<v1::DeleteEnvironmentAccessBindingResponse>, Status> {
        let request = request.into_inner();
        let environment_id = environment_id(request.environment_id)?;
        let expected_profile_id = profile_id(request.expected_profile_id)?;
        if request.expected_profile_revision == 0 {
            return Err(Status::invalid_argument(
                "invalid environment access binding revision",
            ));
        }
        let broker_environment_id = environment_id.clone();
        let authority = Arc::clone(&self.authority);
        run_blocking(move || {
            authority.delete_environment_access_binding(
                &environment_id,
                &expected_profile_id,
                request.expected_profile_revision,
            )
        })
        .await?;
        self.brokers.stop(&broker_environment_id, None).await?;
        Ok(Response::new(v1::DeleteEnvironmentAccessBindingResponse {}))
    }

    async fn evaluate_environment_grants(
        &self,
        request: Request<v1::EvaluateEnvironmentGrantsRequest>,
    ) -> Result<Response<v1::EvaluateEnvironmentGrantsResponse>, Status> {
        let request = request.into_inner();
        let environment_id = environment_id(request.environment_id)?;
        if request.environment_generation == 0 {
            return Err(Status::invalid_argument("invalid environment generation"));
        }
        if let Some(platform) = request.platform {
            let connected = self
                .brokers
                .platform_github_connected(
                    &environment_id,
                    request.environment_generation,
                    platform,
                )
                .await?;
            return Ok(Response::new(v1::EvaluateEnvironmentGrantsResponse {
                grants: Vec::new(),
                platform_github_connected: connected,
            }));
        }
        let authority = Arc::clone(&self.authority);
        let grants = run_blocking(move || {
            authority.evaluate_environment_grants(&environment_id, request.environment_generation)
        })
        .await?;
        Ok(Response::new(v1::EvaluateEnvironmentGrantsResponse {
            grants: grants.into_iter().map(derived_grant_to_proto).collect(),
            platform_github_connected: false,
        }))
    }

    async fn ensure_environment_broker(
        &self,
        request: Request<v1::EnsureEnvironmentBrokerRequest>,
    ) -> Result<Response<v1::EnvironmentBrokerRuntime>, Status> {
        let request = request.into_inner();
        let selected_environment = environment_id(request.environment_id)?;
        let local_profile = request
            .local_profile
            .map(|profile| {
                if profile.profile_revision == 0 {
                    return Err(Status::invalid_argument("invalid local profile revision"));
                }
                Ok::<_, Status>(EnvironmentAccessBinding {
                    environment_id: selected_environment.clone(),
                    profile_id: profile_id(profile.profile_id)?,
                    profile_revision: profile.profile_revision,
                })
            })
            .transpose()?;
        let runtime = self
            .brokers
            .ensure(BrokerEnsureRequest {
                environment_id: selected_environment,
                local_profile,
                environment_generation: request.environment_generation,
                environment_name: request.environment_name,
                runner_socket: PathBuf::from(request.runner_socket),
                projection: request
                    .projection
                    .map(crate::LocalEnvironmentProjectionBinding::from_proto)
                    .transpose()?,
                platform: request
                    .platform
                    .map(crate::PlatformCredentialBinding::from_proto)
                    .transpose()?,
            })
            .await?;
        Ok(Response::new(environment_broker_runtime_to_proto(runtime)))
    }

    async fn stop_environment_broker(
        &self,
        request: Request<v1::StopEnvironmentBrokerRequest>,
    ) -> Result<Response<v1::StopEnvironmentBrokerResponse>, Status> {
        let request = request.into_inner();
        let environment_id = environment_id(request.environment_id)?;
        if request.environment_generation == Some(0) {
            return Err(Status::invalid_argument("invalid environment generation"));
        }
        self.brokers
            .stop(&environment_id, request.environment_generation)
            .await?;
        Ok(Response::new(v1::StopEnvironmentBrokerResponse {}))
    }

    async fn list_recent_broker_lease_audit_events(
        &self,
        request: Request<v1::ListRecentBrokerLeaseAuditEventsRequest>,
    ) -> Result<Response<v1::ListRecentBrokerLeaseAuditEventsResponse>, Status> {
        let limit = usize::try_from(request.into_inner().limit)
            .ok()
            .filter(|limit| (1..=MAX_BROKER_LEASE_AUDIT_LIST_LIMIT).contains(limit))
            .ok_or_else(|| Status::invalid_argument("invalid broker audit list limit"))?;
        let events = self
            .broker_audit
            .recent(limit)
            .await
            .into_iter()
            .map(broker_lease_audit_event_to_proto)
            .collect();
        Ok(Response::new(
            v1::ListRecentBrokerLeaseAuditEventsResponse { events },
        ))
    }

    type PrepareGitRepositoryStream =
        ReceiverStream<Result<v1::PreparedGitRepositoryChunk, Status>>;

    async fn prepare_git_repository(
        &self,
        request: Request<v1::PrepareGitRepositoryRequest>,
    ) -> Result<Response<Self::PrepareGitRepositoryStream>, Status> {
        let request = request.into_inner();
        let request_id = Uuid::parse_str(&request.request_id)
            .ok()
            .filter(|request_id| {
                !request_id.is_nil() && request_id.to_string() == request.request_id
            })
            .ok_or_else(|| Status::invalid_argument("invalid repository preparation request"))?;
        let authorization = RepositoryCredentialLeaseRequest {
            request_id,
            profile_id: profile_id(request.profile_id)?,
            profile_revision: request.profile_revision,
            source: request.source,
            branch: request.branch,
            revision: request.revision,
            known_hosts: request.known_hosts,
        };
        let platform = request
            .platform
            .map(crate::RepositoryPlatformAccess::from_proto)
            .transpose()?;
        let git = request
            .git
            .map(crate::LocalRepositoryGit::from_proto)
            .transpose()
            .map_err(|()| Status::invalid_argument("invalid repository preparation request"))?;
        let prepared = self
            .repositories
            .prepare(authorization, platform, git)
            .await?;
        let (sender, receiver) = tokio::sync::mpsc::channel(8);
        tokio::spawn(stream_prepared_repository(prepared, sender));
        Ok(Response::new(ReceiverStream::new(receiver)))
    }
}

async fn stream_prepared_repository(
    mut prepared: PreparedRepository,
    sender: tokio::sync::mpsc::Sender<Result<v1::PreparedGitRepositoryChunk, Status>>,
) {
    let mut shutdown = prepared.shutdown.clone();
    let deadline = prepared.deadline;
    let result = std::panic::AssertUnwindSafe(async {
        tokio::select! {
            biased;
            () = repository::wait_for_shutdown(&mut shutdown) => {}
            () = tokio::time::sleep_until(deadline) => {}
            () = sender.closed() => {}
            () = write_prepared_repository(&mut prepared, &sender) => {}
        }
    })
    .catch_unwind()
    .await;
    if result.is_err() {
        prepared.latch_failure();
    }
    prepared.drain_bundle().await;
}

async fn write_prepared_repository(
    prepared: &mut PreparedRepository,
    sender: &tokio::sync::mpsc::Sender<Result<v1::PreparedGitRepositoryChunk, Status>>,
) {
    use tokio::io::AsyncReadExt as _;

    let Some(bundle) = prepared.bundle.as_mut() else {
        return;
    };

    let metadata = v1::PreparedGitRepositoryChunk {
        value: Some(v1::prepared_git_repository_chunk::Value::Metadata(
            v1::PreparedGitRepositoryMetadata {
                branch: prepared.metadata.branch.clone(),
                commit: prepared.metadata.commit.clone(),
                bundle_size: prepared.metadata.bundle_size,
            },
        )),
    };
    if sender.send(Ok(metadata)).await.is_err() {
        return;
    }
    let mut remaining = prepared.metadata.bundle_size;
    let mut buffer = vec![0_u8; REPOSITORY_STREAM_CHUNK_BYTES];
    while remaining > 0 {
        let limit = usize::try_from(remaining.min(buffer.len() as u64))
            .expect("repository stream chunk bound fits usize");
        let length = match bundle.read(&mut buffer[..limit]).await {
            Ok(0) | Err(_) => {
                let _ = sender
                    .send(Err(Status::data_loss(
                        "local repository bundle ended unexpectedly",
                    )))
                    .await;
                return;
            }
            Ok(length) => length,
        };
        remaining -= u64::try_from(length).expect("repository read length fits u64");
        if sender
            .send(Ok(v1::PreparedGitRepositoryChunk {
                value: Some(v1::prepared_git_repository_chunk::Value::Bundle(
                    buffer[..length].to_vec(),
                )),
            }))
            .await
            .is_err()
        {
            return;
        }
    }
    match bundle.read(&mut buffer[..1]).await {
        Ok(0) => {}
        _ => {
            let _ = sender
                .send(Err(Status::data_loss(
                    "local repository bundle size changed",
                )))
                .await;
        }
    }
}

async fn run_blocking<T, F>(operation: F) -> Result<T, Status>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, LocalCredentialError> + Send + 'static,
{
    tokio::task::spawn_blocking(operation)
        .await
        .map_err(|_| Status::internal("local credential authority worker failed"))?
        .map_err(status_for_error)
}

fn ssh_enrollment_check(
    deadline: Instant,
    cancelled: &SshEnrollmentCancellation,
) -> Result<(), LocalCredentialError> {
    if cancelled.is_cancelled() {
        Err(LocalCredentialError::SshEnrollmentClosed)
    } else if Instant::now() >= deadline {
        Err(LocalCredentialError::SshEnrollmentDeadlineElapsed)
    } else {
        Ok(())
    }
}

fn validate_ssh_expiry(expires_at_unix: Option<u64>) -> Result<(), Status> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Status::internal("local credential authority time is invalid"))?
        .as_secs();
    validate_ssh_expiry_at(expires_at_unix, now)
}

fn validate_ssh_expiry_at(expires_at_unix: Option<u64>, now: u64) -> Result<(), Status> {
    if expires_at_unix.is_some_and(|value| value <= now || i64::try_from(value).is_err()) {
        Err(Status::invalid_argument(
            "SSH credential expiry must be a future Unix timestamp",
        ))
    } else {
        Ok(())
    }
}

fn status_for_ssh_material_error(error: SshMaterialError) -> Status {
    match error {
        SshMaterialError::EntropyUnavailable => {
            Status::unavailable("SSH key generation entropy is unavailable")
        }
        _ => Status::invalid_argument(error.to_string()),
    }
}

fn credential_id(value: String) -> Result<CredentialId, Status> {
    CredentialId::parse(value).map_err(status_for_access_error)
}

fn profile_id(value: String) -> Result<AccessProfileId, Status> {
    AccessProfileId::parse(value).map_err(status_for_access_error)
}

fn environment_id(value: String) -> Result<EnvironmentId, Status> {
    EnvironmentId::parse(value).map_err(status_for_access_error)
}

fn local_secret_project_id(value: &str) -> Result<Uuid, Status> {
    let id = Uuid::parse_str(value)
        .map_err(|_| Status::invalid_argument("invalid local secret-project identity"))?;
    if id.is_nil() || id.to_string() != value {
        return Err(Status::invalid_argument(
            "invalid local secret-project identity",
        ));
    }
    Ok(id)
}

fn secret_project_to_proto(project: LocalSecretProject) -> v1::LocalSecretProject {
    v1::LocalSecretProject {
        id: project.id.to_string(),
        name: project.name,
        secret_count: project.secret_count,
        created_at_unix_ms: project.created_at_unix_ms,
        updated_at_unix_ms: project.updated_at_unix_ms,
    }
}

fn workload_secret_to_proto(secret: WorkloadSecretMetadata) -> v1::WorkloadSecretMetadata {
    v1::WorkloadSecretMetadata {
        key: secret.key,
        created_at_unix_ms: secret.created_at_unix_ms,
        updated_at_unix_ms: secret.updated_at_unix_ms,
        protected_store_cleanup_pending: secret.protected_store_cleanup_pending,
    }
}

fn workload_secret_source_to_proto(source: WorkloadSecretSource) -> v1::WorkloadSecretSource {
    match source {
        WorkloadSecretSource::Organization => v1::WorkloadSecretSource::Organization,
        WorkloadSecretSource::Project => v1::WorkloadSecretSource::Project,
        WorkloadSecretSource::User => v1::WorkloadSecretSource::User,
        WorkloadSecretSource::ExplicitEnvironment => v1::WorkloadSecretSource::ExplicitEnvironment,
    }
}

fn resolved_secret_to_proto(
    secret: ResolvedWorkloadSecretMetadata,
) -> v1::ResolvedWorkloadSecretMetadata {
    v1::ResolvedWorkloadSecretMetadata {
        key: secret.key,
        source: workload_secret_source_to_proto(secret.source) as i32,
        overridden_sources: secret
            .overridden_sources
            .into_iter()
            .map(|source| workload_secret_source_to_proto(source) as i32)
            .collect(),
    }
}

fn workload_secret_selection_from_proto(
    selection: v1::WorkloadSecretSelection,
) -> Result<WorkloadSecretSelection, Status> {
    let explicit_environment_keys = selection
        .explicit_environment_keys
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if explicit_environment_keys.len() != selection.explicit_environment_keys.len() {
        return Err(Status::invalid_argument(
            "duplicate explicit environment key",
        ));
    }
    Ok(WorkloadSecretSelection {
        organization: selection.organization,
        project: selection.project,
        user: selection.user,
        explicit_environment_keys,
    })
}

fn environment_broker_runtime_to_proto(
    runtime: EnvironmentBrokerRuntime,
) -> v1::EnvironmentBrokerRuntime {
    v1::EnvironmentBrokerRuntime {
        environment_id: runtime.environment_id.to_string(),
        environment_generation: runtime.environment_generation,
        running: runtime.running,
    }
}

fn broker_lease_audit_event_to_proto(
    event: crate::BrokerLeaseAuditEvent,
) -> v1::BrokerLeaseAuditEvent {
    let decision = match event.decision {
        crate::BrokerLeaseAuditDecision::Admitted => v1::BrokerLeaseAuditDecision::Admitted,
        crate::BrokerLeaseAuditDecision::Denied => v1::BrokerLeaseAuditDecision::Denied,
        crate::BrokerLeaseAuditDecision::Unavailable => v1::BrokerLeaseAuditDecision::Unavailable,
    };
    v1::BrokerLeaseAuditEvent {
        sequence: event.sequence,
        observed_at_unix_ms: event.observed_at_unix_ms,
        environment_id: event.environment_id.to_string(),
        environment_generation: event.environment_generation,
        request_id: event.request_id.to_string(),
        capability_slot: event.capability_slot.to_string(),
        operation: event.operation.to_string(),
        route: event.route.to_string(),
        decision: decision as i32,
        credential_id: event.credential_id.map(|id| id.to_string()),
        profile_id: event.profile_id.map(|id| id.to_string()),
        profile_revision: event.profile_revision,
        credential_revocation_generation: event.credential_revocation_generation,
    }
}

/// Parse entries. Every profile includes the store's one GitHub connection, so
/// a legacy client's `github` entry is accepted and its credential ID discarded.
fn profile_entries(
    entries: Vec<v1::AccessProfileEntry>,
) -> Result<BTreeMap<CapabilitySlot, CredentialId>, Status> {
    let mut parsed = BTreeMap::new();
    let mut github = false;
    for entry in entries {
        let slot = CapabilitySlot::parse(entry.capability_slot).map_err(status_for_access_error)?;
        let credential =
            CredentialId::parse(entry.credential_id).map_err(status_for_access_error)?;
        if slot == CapabilitySlot::github() {
            if std::mem::replace(&mut github, true) {
                return Err(Status::invalid_argument(
                    "duplicate access profile capability slot",
                ));
            }
            continue;
        }
        if parsed.insert(slot, credential).is_some() {
            return Err(Status::invalid_argument(
                "duplicate access profile capability slot",
            ));
        }
    }
    Ok(parsed)
}

fn auth_kind_from_proto(value: i32) -> Result<CredentialAuthKind, Status> {
    match CredentialAuthenticationKind::try_from(value) {
        Ok(CredentialAuthenticationKind::Oauth) => Ok(CredentialAuthKind::OAuth),
        Ok(CredentialAuthenticationKind::ApiKey) => Ok(CredentialAuthKind::ApiKey),
        Ok(CredentialAuthenticationKind::AccessToken) => Ok(CredentialAuthKind::AccessToken),
        Ok(CredentialAuthenticationKind::GithubApp) => Ok(CredentialAuthKind::GitHubApp),
        Ok(CredentialAuthenticationKind::SshKey) => Ok(CredentialAuthKind::SshKey),
        Ok(CredentialAuthenticationKind::ClaudeSignIn) => Ok(CredentialAuthKind::ClaudeSignIn),
        Ok(CredentialAuthenticationKind::Unspecified) | Err(_) => Err(Status::invalid_argument(
            "invalid credential authentication kind",
        )),
    }
}

pub(crate) fn auth_kind_to_proto(value: CredentialAuthKind) -> CredentialAuthenticationKind {
    match value {
        CredentialAuthKind::OAuth => CredentialAuthenticationKind::Oauth,
        CredentialAuthKind::ApiKey => CredentialAuthenticationKind::ApiKey,
        CredentialAuthKind::AccessToken => CredentialAuthenticationKind::AccessToken,
        CredentialAuthKind::GitHubApp => CredentialAuthenticationKind::GithubApp,
        CredentialAuthKind::SshKey => CredentialAuthenticationKind::SshKey,
        CredentialAuthKind::ClaudeSignIn => CredentialAuthenticationKind::ClaudeSignIn,
    }
}

pub(crate) fn status_to_proto(value: CredentialStatus) -> v1::CredentialStatus {
    match value {
        CredentialStatus::Active => v1::CredentialStatus::Active,
        CredentialStatus::Expired => v1::CredentialStatus::Expired,
        CredentialStatus::RefreshFailed => v1::CredentialStatus::RefreshFailed,
        CredentialStatus::Revoked => v1::CredentialStatus::Revoked,
    }
}

pub(crate) fn persistence_to_proto(
    value: ProtectedStorePersistence,
) -> v1::ProtectedStorePersistence {
    match value {
        ProtectedStorePersistence::OperatingSystem => {
            v1::ProtectedStorePersistence::OperatingSystem
        }
        ProtectedStorePersistence::ProcessLifetime => {
            v1::ProtectedStorePersistence::ProcessLifetime
        }
    }
}

pub(crate) fn credential_to_proto(record: CredentialRecord) -> v1::Credential {
    v1::Credential {
        id: record.metadata.id.to_string(),
        provider: record.metadata.provider.to_string(),
        authentication_kind: auth_kind_to_proto(record.metadata.authentication_kind) as i32,
        display_name: record.metadata.display_name,
        account_hint: record.metadata.account_hint,
        status: status_to_proto(record.metadata.status) as i32,
        expires_at_unix: record.metadata.expires_at_unix,
        revocation_generation: record.metadata.revocation_generation,
        protected_store_persistence: persistence_to_proto(record.persistence) as i32,
        protected_store_cleanup_pending: record.protected_store_cleanup_pending,
        created_at_unix_ms: record.created_at_unix_ms,
        updated_at_unix_ms: record.updated_at_unix_ms,
        ssh_public_key: record.metadata.ssh_public_key.map(|key| v1::SshPublicKey {
            openssh: key.openssh,
            fingerprint: key.fingerprint,
        }),
    }
}

fn profile_record_to_proto(record: AccessProfileRecord) -> v1::AccessProfileRevision {
    profile_to_proto(
        record.profile,
        record.created_at_unix_ms,
        record.updated_at_unix_ms,
    )
}

fn profile_revision_to_proto(record: AccessProfileRevisionRecord) -> v1::AccessProfileRevision {
    profile_to_proto(
        record.profile,
        record.profile_created_at_unix_ms,
        record.revision_created_at_unix_ms,
    )
}

fn profile_to_proto(
    profile: codewire_access::AccessProfile,
    profile_created_at_unix_ms: u64,
    revision_created_at_unix_ms: u64,
) -> v1::AccessProfileRevision {
    v1::AccessProfileRevision {
        id: profile.id.to_string(),
        name: profile.name.to_string(),
        revision: profile.revision,
        entries: profile
            .entries
            .into_iter()
            .map(|(slot, credential)| v1::AccessProfileEntry {
                capability_slot: slot.to_string(),
                credential_id: credential.to_string(),
            })
            .collect(),
        profile_created_at_unix_ms,
        revision_created_at_unix_ms,
    }
}

fn environment_binding_to_proto(
    record: EnvironmentAccessBindingRecord,
) -> v1::EnvironmentAccessBinding {
    v1::EnvironmentAccessBinding {
        environment_id: record.binding.environment_id.to_string(),
        profile_id: record.binding.profile_id.to_string(),
        profile_revision: record.binding.profile_revision,
        created_at_unix_ms: record.created_at_unix_ms,
        updated_at_unix_ms: record.updated_at_unix_ms,
    }
}

pub(crate) fn derived_grant_to_proto(grant: DerivedGrant) -> v1::DerivedGrant {
    v1::DerivedGrant {
        environment_id: grant.environment_id.to_string(),
        environment_generation: grant.environment_generation,
        // Local grants always name their profile; a missing one encodes as
        // revision 0, which every decoder rejects.
        profile_id: grant
            .profile
            .as_ref()
            .map(|profile| profile.id.to_string())
            .unwrap_or_default(),
        profile_revision: grant.profile.as_ref().map_or(0, |profile| profile.revision),
        capability_slot: grant.capability_slot.to_string(),
        credential_id: grant.credential_id.to_string(),
        credential_revocation_generation: grant.credential_revocation_generation,
        expires_at_unix: grant.expires_at_unix,
        permissions: grant
            .permissions
            .into_iter()
            .map(|permission| v1::GrantPermission {
                operation: permission.operation.to_string(),
                route: permission.route.to_string(),
            })
            .collect(),
    }
}

fn status_for_access_error(_error: AccessError) -> Status {
    Status::invalid_argument("invalid local credential request")
}

fn status_for_error(error: LocalCredentialError) -> Status {
    match error {
        LocalCredentialError::StaleCredentialRevision => Status::failed_precondition(
            "local credential revision changed; inspect before retrying",
        ),
        LocalCredentialError::AlreadyExists => {
            Status::already_exists("local credential record already exists")
        }
        LocalCredentialError::EnvironmentBindingAlreadyExists => {
            Status::already_exists("local environment access binding already exists")
        }
        LocalCredentialError::GitHubAlreadyConnected => Status::already_exists(
            "a local GitHub connection already exists; reconnect or delete it",
        ),
        LocalCredentialError::AmbiguousGitHubConnections => Status::failed_precondition(
            "local credential metadata has more than one active GitHub connection",
        ),
        LocalCredentialError::CredentialNotFound
        | LocalCredentialError::ProfileNotFound
        | LocalCredentialError::ProfileRevisionNotFound
        | LocalCredentialError::SecretProjectNotFound
        | LocalCredentialError::WorkloadSecretNotFound => {
            Status::not_found("local credential record was not found")
        }
        LocalCredentialError::EnvironmentBindingNotFound => {
            Status::not_found("local environment access binding was not found")
        }
        LocalCredentialError::CredentialUnavailable
        | LocalCredentialError::CredentialInactive
        | LocalCredentialError::CredentialMaterialMissing
        | LocalCredentialError::WorkloadSecretMaterialMissing
        | LocalCredentialError::CredentialOperationLeaseDenied
        | LocalCredentialError::CredentialRefreshInProgress
        | LocalCredentialError::StaleCredentialRefresh
        | LocalCredentialError::StaleProfileRevision
        | LocalCredentialError::StaleEnvironmentBinding
        | LocalCredentialError::ProtectedEntryCollision
        | LocalCredentialError::OwnerMismatch
        | LocalCredentialError::ProtectedStoreMismatch
        | LocalCredentialError::UnsupportedSchema
        | LocalCredentialError::InvalidDatabase
        | LocalCredentialError::CorruptMetadata => {
            Status::failed_precondition("local credential operation cannot be applied")
        }
        // Both are the user's to resolve, so say what holds the record.
        LocalCredentialError::CredentialInUse => Status::failed_precondition(
            "local credential is selected by an access profile or environment; unset it from the profile (cw credentials --local --profile NAME unset PROVIDER) or remove the environment first",
        ),
        LocalCredentialError::ProfileInUse => Status::failed_precondition(
            "local access profile is selected by an environment; remove the environment first",
        ),
        LocalCredentialError::SshCredentialRequiresEnrollment => Status::failed_precondition(
            "SSH credentials require the dedicated enrollment operation",
        ),
        LocalCredentialError::SshEnrollmentClosed => {
            Status::unavailable("local SSH credential enrollment is stopping")
        }
        LocalCredentialError::SshEnrollmentDeadlineElapsed => {
            Status::deadline_exceeded("local SSH credential enrollment timed out")
        }
        // AccessError is deliberately material-free and carries the stable
        // provider/profile diagnostic needed to repair a rejected selection.
        LocalCredentialError::Access(error) => Status::failed_precondition(error.to_string()),
        LocalCredentialError::ProtectedStore(ProtectedStoreError::AccessDenied) => {
            Status::unavailable(
                "local protected storage is locked or inaccessible; unlock it and retry",
            )
        }
        LocalCredentialError::ProtectedStore(ProtectedStoreError::TimedOut) => {
            Status::unavailable("local protected storage did not respond in time")
        }
        LocalCredentialError::DatabaseUnavailable
        | LocalCredentialError::ProtectedStore(_)
        | LocalCredentialError::ProtectedStoreSwitch(_) => {
            Status::unavailable("local credential authority storage is unavailable")
        }
        LocalCredentialError::AlreadyRunning => {
            Status::already_exists("local credential authority is already running")
        }
        LocalCredentialError::UnsupportedPlatform => {
            Status::unimplemented("local credential authority is unsupported")
        }
        LocalCredentialError::OrganizationSecretsUnsupported => {
            Status::unimplemented("organization workload secrets are unsupported locally")
        }
        LocalCredentialError::InvalidWorkloadSecret => {
            Status::invalid_argument("invalid local workload-secret request")
        }
        LocalCredentialError::InvalidDatabasePath | LocalCredentialError::InvalidTime => {
            Status::internal("local credential authority state is invalid")
        }
    }
}

#[cfg(test)]
mod status_tests {
    use super::*;

    #[test]
    fn a_record_in_use_says_what_holds_it() {
        let credential = status_for_error(LocalCredentialError::CredentialInUse);
        assert_eq!(credential.code(), tonic::Code::FailedPrecondition);
        assert!(
            credential
                .message()
                .contains("selected by an access profile or environment")
        );
        assert!(
            credential
                .message()
                .contains("--profile NAME unset PROVIDER")
        );
        let profile = status_for_error(LocalCredentialError::ProfileInUse);
        assert_eq!(profile.code(), tonic::Code::FailedPrecondition);
        assert!(profile.message().contains("selected by an environment"));
        // Internal states stay undisclosed.
        let corrupt = status_for_error(LocalCredentialError::CorruptMetadata);
        assert_eq!(
            corrupt.message(),
            "local credential operation cannot be applied"
        );
    }
}

#[cfg(test)]
mod restart_delay_tests {
    use super::*;

    /// Children that fail young back off up to the maximum; one that served
    /// for the stable runtime starts the next restart from the minimum.
    #[test]
    fn restart_delay_doubles_to_the_maximum_and_resets_after_a_healthy_run() {
        let young = Duration::from_millis(500);
        let mut delay = BROKER_RESTART_MIN_DELAY;
        let mut seen = Vec::new();
        for _ in 0..12 {
            delay = next_restart_delay(delay, young);
            seen.push(delay);
        }
        assert_eq!(seen[0], BROKER_RESTART_MIN_DELAY * 2);
        assert!(seen.windows(2).all(|pair| pair[1] >= pair[0]));
        assert_eq!(*seen.last().unwrap(), BROKER_RESTART_MAX_DELAY);
        assert_eq!(
            next_restart_delay(BROKER_RESTART_MAX_DELAY, BROKER_STABLE_RUNTIME),
            BROKER_RESTART_MIN_DELAY
        );
        assert_eq!(
            next_restart_delay(BROKER_RESTART_MAX_DELAY, BROKER_STABLE_RUNTIME - young),
            BROKER_RESTART_MAX_DELAY
        );
    }
}

#[cfg(test)]
mod drain_tests {
    use super::*;
    use codewire_access::builtin_provider_catalog;
    use codewire_protected_store::EphemeralProtectedStore;
    use std::sync::atomic::{AtomicBool, Ordering};

    async fn fixture(
        task: tokio::task::JoinHandle<()>,
    ) -> (
        tempfile::TempDir,
        BrokerProcessManager<EphemeralProtectedStore>,
        EnvironmentId,
    ) {
        let directory = tempfile::tempdir().unwrap();
        let authority = Arc::new(
            LocalCredentialAuthority::open(
                &directory.path().join("authority"),
                EphemeralProtectedStore::default(),
                builtin_provider_catalog(),
            )
            .unwrap(),
        );
        let manager = BrokerProcessManager::new(
            authority,
            None,
            Arc::new(BrokerLeaseAuditLog::default()),
            LocalSshOperationRuntime::new(None),
            None,
            Arc::new(BrokerLog::disabled()),
        );
        let environment_id = EnvironmentId::parse(Uuid::new_v4().to_string()).unwrap();
        let config = LocalBrokerProcessConfig {
            environment_id: environment_id.clone(),
            environment_generation: 7,
            environment_name: "synthetic".into(),
            runner_socket: directory.path().join("runner.sock"),
            http_providers: BTreeSet::new(),
            platform_delegated: false,
        };
        manager.entries.lock().await.insert(
            environment_id.clone(),
            BrokerProcessEntry {
                generation: 7,
                config,
                projection: None,
                platform: None,
                local_profile: None,
                shutdown: watch::channel(false).0,
                state: watch::channel(BrokerProcessState::Running).1,
                task,
                drain_failed: false,
            },
        );
        (directory, manager, environment_id)
    }

    #[tokio::test]
    async fn cancelled_stop_retains_drain_until_exact_lifecycle_finishes() {
        let (release, pending) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(async move {
            let _ = pending.await;
        });
        let (_directory, manager, id) = fixture(task).await;
        for _ in 0..2 {
            assert!(
                tokio::time::timeout(
                    std::time::Duration::from_millis(20),
                    manager.stop(&id, Some(7))
                )
                .await
                .is_err()
            );
            assert!(manager.entries.lock().await.contains_key(&id));
        }
        release.send(()).unwrap();
        manager.stop(&id, Some(7)).await.unwrap();
        assert!(!manager.entries.lock().await.contains_key(&id));
        manager.stop(&id, Some(7)).await.unwrap();
    }

    #[tokio::test]
    async fn failed_lifecycle_drain_is_latched_and_never_acknowledged() {
        let task = tokio::spawn(async {
            panic!("synthetic lifecycle failure");
        });
        let (_directory, manager, id) = fixture(task).await;
        for _ in 0..2 {
            assert_eq!(
                manager.stop(&id, Some(7)).await.unwrap_err().code(),
                tonic::Code::Unavailable
            );
            assert!(manager.entries.lock().await.contains_key(&id));
        }
    }

    #[tokio::test]
    async fn poisoned_ssh_runtime_prevents_successful_broker_stop_acknowledgement() {
        let task = tokio::spawn(async {});
        let (_directory, manager, id) = fixture(task).await;
        manager.ssh_runtime.latch_cleanup_failure();

        assert_eq!(
            manager.stop(&id, Some(7)).await.unwrap_err().code(),
            tonic::Code::Unavailable
        );
        let entries = manager.entries.lock().await;
        assert!(entries.get(&id).unwrap().drain_failed);
    }

    #[tokio::test]
    async fn ssh_enrollment_shutdown_with_no_workers_durably_closes_admission() {
        let workers = SshEnrollmentWorkers::new();
        workers.shutdown().await;
        let ran = Arc::new(AtomicBool::new(false));
        let worker_ran = Arc::clone(&ran);
        let error = workers
            .run(move |_| {
                worker_ran.store(true, Ordering::SeqCst);
                Ok(())
            })
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::Unavailable);
        assert!(!ran.load(Ordering::SeqCst));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn outer_ssh_drain_survives_unpolled_shutdown_future_and_is_idempotent() {
        let workers = SshEnrollmentWorkers::new();
        let abandoned_workers = workers.clone();
        let unpolled_server_shutdown = async move {
            std::future::pending::<()>().await;
            abandoned_workers.shutdown().await;
        };
        drop(unpolled_server_shutdown);

        let (entered, entered_rx) = tokio::sync::oneshot::channel();
        let worker = workers.clone();
        let operation = tokio::spawn(async move {
            worker
                .run(move |cancelled| {
                    let _ = entered.send(());
                    while !cancelled.is_cancelled() {
                        std::thread::yield_now();
                    }
                    Err::<(), _>(Status::unavailable("synthetic cancellation"))
                })
                .await
        });
        entered_rx.await.unwrap();
        workers.shutdown().await;
        assert_eq!(
            operation.await.unwrap().unwrap_err().code(),
            tonic::Code::Unavailable
        );
        workers.shutdown().await;
        assert_eq!(
            workers.permits.available_permits(),
            MAX_SSH_ENROLLMENT_WORKERS as usize
        );
    }

    #[test]
    fn ssh_enrollment_expiry_requires_a_representable_future_timestamp() {
        let now = 2_000_000_000;
        assert!(validate_ssh_expiry_at(None, now).is_ok());
        assert!(validate_ssh_expiry_at(Some(now + 1), now).is_ok());
        for invalid in [0, now - 1, now, u64::MAX] {
            let error = validate_ssh_expiry_at(Some(invalid), now).unwrap_err();
            assert_eq!(error.code(), tonic::Code::InvalidArgument);
            assert_eq!(
                error.message(),
                "SSH credential expiry must be a future Unix timestamp"
            );
        }
    }
}
