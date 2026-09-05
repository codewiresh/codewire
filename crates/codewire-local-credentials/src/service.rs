use std::collections::{BTreeMap, BTreeSet, HashMap};
#[cfg(target_os = "linux")]
use std::ffi::OsStr;
use std::future::Future;
use std::mem;
use std::path::PathBuf;
use std::sync::Arc;

use codewire_access::{
    AccessError, AccessProfileId, AccessProfileName, AccessProfileReference, CapabilitySlot,
    CredentialAuthKind, CredentialId, CredentialStatus, DerivedGrant, EnvironmentAccessBinding,
    EnvironmentId, ProviderCatalog, ProviderId, builtin_provider_catalog,
};
use codewire_protected_store::{
    MAX_PROTECTED_VALUE_BYTES, OsProtectedStore, ProtectedStore, ProtectedStorePersistence,
    ProtectedValue,
};
use tokio::net::UnixStream;
use tokio::sync::{Mutex, watch};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};
use uuid::Uuid;

use crate::broker_channel::{
    BrokerLeaseAuditLog, MAX_BROKER_LEASE_AUDIT_LIST_LIMIT, serve_broker_lease_channel_with_ready,
};
use crate::control::v1::local_credential_authority_service_server::{
    LocalCredentialAuthorityService, LocalCredentialAuthorityServiceServer,
};
use crate::control::v1::{self, CredentialAuthenticationKind};
use crate::repository::{
    LocalRepositoryProcessConfig, LocalRepositoryProcessSpawner, PreparedRepositoryMetadata,
    RepositoryExecutorError, cleanup_repository_staging, create_repository_staging,
    prepared_bundle_path, read_prepared_repository, remove_repository_staging,
    serve_repository_lease_channel_with_ready, validate_repository_lease_request,
};
use crate::transport::{
    AUTHORITY_PROTOCOL_VERSION, AuthorityRuntimeConfig, AuthorityRuntimeError, bind_owner_only,
    remove_bound_socket,
};
use crate::{
    AUTHORITY_ALLOWED_ENVIRONMENT_VARIABLES, AccessProfileRecord, AccessProfileRevisionRecord,
    CredentialRecord, EnvironmentAccessBindingRecord, EnvironmentBrokerRuntime,
    LocalBrokerProcessConfig, LocalBrokerProcessSpawner, LocalCredentialAuthority,
    LocalCredentialError, LocalSecretProject, NewCredential, RepositoryCredentialLeaseRequest,
    ResolvedWorkloadSecretMetadata, WorkloadSecretMetadata, WorkloadSecretSelection,
    WorkloadSecretSource,
};

const MAX_RPC_MESSAGE_BYTES: usize = MAX_PROTECTED_VALUE_BYTES + 64 * 1024;
const BROKER_START_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
const BROKER_READY_STABILITY: std::time::Duration = std::time::Duration::from_millis(25);
const BROKER_RESTART_MIN_DELAY: std::time::Duration = std::time::Duration::from_millis(100);
const BROKER_RESTART_MAX_DELAY: std::time::Duration = std::time::Duration::from_secs(30);
const BROKER_STABLE_RUNTIME: std::time::Duration = std::time::Duration::from_secs(30);
const REPOSITORY_START_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
const REPOSITORY_EXECUTION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(310);
const REPOSITORY_CHANNEL_CLOSE_GRACE: std::time::Duration = std::time::Duration::from_secs(1);
const REPOSITORY_STREAM_CHUNK_BYTES: usize = 48 * 1024;

struct AuthorityRpc<S: ProtectedStore> {
    authority: Arc<LocalCredentialAuthority<S>>,
    brokers: Arc<BrokerProcessManager<S>>,
    repositories: Arc<RepositoryProcessManager<S>>,
    broker_audit: Arc<BrokerLeaseAuditLog>,
    shutdown: watch::Sender<bool>,
}

impl<S: ProtectedStore> Clone for AuthorityRpc<S> {
    fn clone(&self) -> Self {
        Self {
            authority: Arc::clone(&self.authority),
            brokers: Arc::clone(&self.brokers),
            repositories: Arc::clone(&self.repositories),
            broker_audit: Arc::clone(&self.broker_audit),
            shutdown: self.shutdown.clone(),
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

/// Run the production local authority against the operating-system protected
/// store and the exact capability catalog compiled into this binary.
pub async fn serve_os_local_credential_authority(
    config: AuthorityRuntimeConfig,
) -> Result<(), AuthorityRuntimeError> {
    verify_production_process_confinement()?;
    serve_local_credential_authority(config, OsProtectedStore, builtin_provider_catalog()).await
}

/// Run the production authority with an authority-owned isolated broker
/// launcher. No control client receives the inherited lease-channel peer.
pub async fn serve_os_local_credential_authority_with_broker_spawner(
    config: AuthorityRuntimeConfig,
    spawner: Arc<dyn LocalBrokerProcessSpawner>,
) -> Result<(), AuthorityRuntimeError> {
    verify_production_process_confinement()?;
    serve_until_with_spawner(
        config,
        OsProtectedStore,
        builtin_provider_catalog(),
        std::future::pending(),
        Some(spawner),
    )
    .await
}

/// Run the production authority with both authority-owned credential-bearing
/// child launchers. Neither launcher is exposed through the owner RPC API.
pub async fn serve_os_local_credential_authority_with_process_spawners(
    config: AuthorityRuntimeConfig,
    broker_spawner: Arc<dyn LocalBrokerProcessSpawner>,
    repository_spawner: Arc<dyn LocalRepositoryProcessSpawner>,
) -> Result<(), AuthorityRuntimeError> {
    verify_production_process_confinement()?;
    serve_until_with_process_spawners(
        config,
        OsProtectedStore,
        builtin_provider_catalog(),
        std::future::pending(),
        Some(broker_spawner),
        Some(repository_spawner),
    )
    .await
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

#[cfg(not(target_os = "linux"))]
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
    serve_until_with_process_spawners(config, protected_store, catalog, shutdown, spawner, None)
        .await
}

pub(crate) async fn serve_until_with_process_spawners<S, F>(
    config: AuthorityRuntimeConfig,
    protected_store: S,
    catalog: ProviderCatalog,
    shutdown: F,
    broker_spawner: Option<Arc<dyn LocalBrokerProcessSpawner>>,
    repository_spawner: Option<Arc<dyn LocalRepositoryProcessSpawner>>,
) -> Result<(), AuthorityRuntimeError>
where
    S: ProtectedStore + 'static,
    F: Future<Output = ()> + Send + 'static,
{
    config.prepare_root()?;
    let authority_root = config.root.clone();
    let authority = Arc::new(LocalCredentialAuthority::open(
        &config.root,
        protected_store,
        catalog,
    )?);
    cleanup_repository_staging(&authority_root)
        .map_err(|_| AuthorityRuntimeError::InvalidPrivatePath)?;
    // The persistence singleton lock is held before a stale endpoint is ever
    // removed, so a losing process cannot unlink the live authority socket.
    let (incoming, socket_identity) = bind_owner_only(&config)?;
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    let broker_audit = Arc::new(BrokerLeaseAuditLog::default());
    let brokers = Arc::new(BrokerProcessManager::new(
        Arc::clone(&authority),
        broker_spawner,
        Arc::clone(&broker_audit),
    ));
    let repositories = Arc::new(RepositoryProcessManager::new(
        Arc::clone(&authority),
        repository_spawner,
        authority_root,
    ));
    let service = AuthorityRpc {
        authority,
        brokers: Arc::clone(&brokers),
        repositories,
        broker_audit,
        shutdown: shutdown_tx,
    };
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
    brokers.shutdown_all().await;
    let cleanup = remove_bound_socket(&config, &socket_identity);
    result.and(cleanup)
}

struct RepositoryProcessManager<S: ProtectedStore> {
    authority: Arc<LocalCredentialAuthority<S>>,
    spawner: Option<Arc<dyn LocalRepositoryProcessSpawner>>,
    authority_root: PathBuf,
}

impl<S: ProtectedStore + 'static> RepositoryProcessManager<S> {
    fn new(
        authority: Arc<LocalCredentialAuthority<S>>,
        spawner: Option<Arc<dyn LocalRepositoryProcessSpawner>>,
        authority_root: PathBuf,
    ) -> Self {
        Self {
            authority,
            spawner,
            authority_root,
        }
    }

    async fn prepare(
        &self,
        authorization: RepositoryCredentialLeaseRequest,
    ) -> Result<PreparedRepository, Status> {
        validate_repository_lease_request(&authorization)
            .map_err(|_| Status::invalid_argument("invalid repository preparation request"))?;
        let authority = Arc::clone(&self.authority);
        let preflight = authorization.clone();
        run_blocking(move || authority.admit_repository_credential_operation(&preflight)).await?;
        let spawner = self.spawner.as_ref().cloned().ok_or_else(|| {
            Status::unavailable("local repository executor launcher is unavailable")
        })?;
        let staging =
            create_repository_staging(&self.authority_root).map_err(repository_executor_status)?;
        let cleanup = RepositoryStagingGuard {
            path: Some(staging.clone()),
        };
        let config = LocalRepositoryProcessConfig {
            request_id: authorization.request_id,
            staging_directory: staging.clone(),
        };
        config
            .validate()
            .map_err(|_| Status::invalid_argument("invalid repository preparation request"))?;
        let (authority_stream, executor_stream) = std::os::unix::net::UnixStream::pair()
            .map_err(|_| Status::unavailable("local repository executor is unavailable"))?;
        authority_stream
            .set_nonblocking(true)
            .map_err(|_| Status::unavailable("local repository executor is unavailable"))?;
        let authority_stream = UnixStream::from_std(authority_stream)
            .map_err(|_| Status::unavailable("local repository executor is unavailable"))?;
        let mut child = spawner
            .spawn(&config, executor_stream)
            .map_err(|_| Status::unavailable("local repository executor is unavailable"))?;
        let (ready_tx, mut ready_rx) = tokio::sync::oneshot::channel();
        let mut lease_task = tokio::spawn(serve_repository_lease_channel_with_ready(
            Arc::clone(&self.authority),
            authority_stream,
            authorization,
            ready_tx,
        ));
        let mut start_timeout = Box::pin(tokio::time::sleep(REPOSITORY_START_TIMEOUT));
        let ready = tokio::select! {
            ready = &mut ready_rx => ready.is_ok(),
            _ = child.wait() => false,
            _ = &mut lease_task => false,
            _ = &mut start_timeout => false,
        };
        if !ready {
            stop_repository_child(&mut child, &mut lease_task).await;
            return Err(Status::unavailable(
                "local repository executor failed to start",
            ));
        }
        let mut execution_timeout = Box::pin(tokio::time::sleep(REPOSITORY_EXECUTION_TIMEOUT));
        let status = tokio::select! {
            status = child.wait() => {
                match status {
                    Ok(status) => status,
                    Err(_) => {
                        stop_repository_child(&mut child, &mut lease_task).await;
                        return Err(Status::unavailable(
                            "local repository executor is unavailable",
                        ));
                    }
                }
            }
            _ = &mut execution_timeout => {
                stop_repository_child(&mut child, &mut lease_task).await;
                return Err(Status::deadline_exceeded(
                    "local repository preparation timed out",
                ));
            }
            _ = &mut lease_task => {
                match tokio::time::timeout(REPOSITORY_CHANNEL_CLOSE_GRACE, child.wait()).await {
                    Ok(Ok(status)) => status,
                    _ => {
                        stop_repository_child(&mut child, &mut lease_task).await;
                        return Err(Status::unavailable(
                            "local repository credential lease is unavailable",
                        ));
                    }
                }
            }
        };
        lease_task.abort();
        if !status.success() {
            return Err(Status::unavailable("local repository preparation failed"));
        }
        let metadata = read_prepared_repository(&staging).map_err(repository_executor_status)?;
        let bundle = tokio::fs::File::open(prepared_bundle_path(&staging))
            .await
            .map_err(|_| Status::unavailable("local repository output is unavailable"))?;
        Ok(PreparedRepository {
            metadata,
            bundle,
            _cleanup: cleanup,
        })
    }
}

struct PreparedRepository {
    metadata: PreparedRepositoryMetadata,
    bundle: tokio::fs::File,
    _cleanup: RepositoryStagingGuard,
}

struct RepositoryStagingGuard {
    path: Option<PathBuf>,
}

impl Drop for RepositoryStagingGuard {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            let _ = remove_repository_staging(&path);
        }
    }
}

async fn stop_repository_child(
    child: &mut tokio::process::Child,
    lease_task: &mut tokio::task::JoinHandle<Result<(), crate::RepositoryLeaseChannelError>>,
) {
    let _ = child.kill().await;
    let _ = child.wait().await;
    lease_task.abort();
}

fn repository_executor_status(_: RepositoryExecutorError) -> Status {
    Status::unavailable("local repository preparation failed")
}

struct BrokerProcessEntry {
    generation: u64,
    shutdown: watch::Sender<bool>,
    state: watch::Receiver<BrokerProcessState>,
    task: tokio::task::JoinHandle<()>,
}

struct BrokerEnsureRequest {
    environment_id: EnvironmentId,
    environment_generation: u64,
    environment_name: String,
    supervisor_socket: PathBuf,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BrokerProcessState {
    Starting,
    Running,
}

struct BrokerProcessManager<S: ProtectedStore> {
    authority: Arc<LocalCredentialAuthority<S>>,
    spawner: Option<Arc<dyn LocalBrokerProcessSpawner>>,
    audit: Arc<BrokerLeaseAuditLog>,
    entries: Mutex<HashMap<EnvironmentId, BrokerProcessEntry>>,
}

impl<S: ProtectedStore + 'static> BrokerProcessManager<S> {
    fn new(
        authority: Arc<LocalCredentialAuthority<S>>,
        spawner: Option<Arc<dyn LocalBrokerProcessSpawner>>,
        audit: Arc<BrokerLeaseAuditLog>,
    ) -> Self {
        Self {
            authority,
            spawner,
            audit,
            entries: Mutex::new(HashMap::new()),
        }
    }

    async fn ensure(
        &self,
        request: BrokerEnsureRequest,
    ) -> Result<EnvironmentBrokerRuntime, Status> {
        // Serialize grant evaluation with entry insertion/removal. Binding
        // mutation commits before calling `stop`, so either this evaluation
        // observes the new binding or that stop observes the inserted entry.
        let mut entries = self.entries.lock().await;
        let authority = Arc::clone(&self.authority);
        let audit = Arc::clone(&self.audit);
        let environment_id = request.environment_id.clone();
        let generation = request.environment_generation;
        let authentication_kind = run_blocking(move || {
            let grant = authority
                .evaluate_environment_grants(&environment_id, generation)?
                .into_iter()
                .find(|grant| {
                    grant.capability_slot == CapabilitySlot::codex()
                        && grant.permissions.iter().any(|permission| {
                            permission.operation.as_str() == "responses"
                                && permission.route.as_str() == "openai-api"
                        })
                });
            let Some(grant) = grant else {
                return Ok(None);
            };
            let credential = authority.get_credential(&grant.credential_id)?;
            if credential.metadata.provider.as_str() != "openai"
                || !matches!(
                    credential.metadata.authentication_kind,
                    CredentialAuthKind::ApiKey | CredentialAuthKind::OAuth
                )
            {
                return Ok(None);
            }
            Ok(Some(credential.metadata.authentication_kind))
        })
        .await?;
        let Some(authentication_kind) = authentication_kind else {
            if let Some(existing) = entries.remove(&request.environment_id) {
                stop_broker_entry(existing).await;
            }
            return Ok(EnvironmentBrokerRuntime {
                environment_id: request.environment_id,
                environment_generation: request.environment_generation,
                running: false,
            });
        };
        let config = LocalBrokerProcessConfig {
            environment_id: request.environment_id,
            environment_generation: request.environment_generation,
            environment_name: request.environment_name,
            supervisor_socket: request.supervisor_socket,
            credential_authentication_kind: authentication_kind,
        };
        config
            .validate()
            .map_err(|_| Status::invalid_argument("invalid local credential broker request"))?;
        let spawner = self.spawner.as_ref().cloned().ok_or_else(|| {
            Status::unavailable("local credential broker launcher is unavailable")
        })?;

        if let Some(existing) = entries.remove(&config.environment_id) {
            if existing.generation == config.environment_generation && !existing.task.is_finished()
            {
                let running = *existing.state.borrow() == BrokerProcessState::Running;
                entries.insert(config.environment_id.clone(), existing);
                return Ok(broker_runtime(config, running));
            }
            stop_broker_entry(existing).await;
        }

        let authority = Arc::clone(&self.authority);
        let lifecycle_config = config.clone();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (state_tx, mut state_rx) = watch::channel(BrokerProcessState::Starting);
        let task = tokio::spawn(run_broker_lifecycle(
            authority,
            spawner,
            lifecycle_config,
            audit,
            shutdown_rx,
            state_tx,
        ));
        entries.insert(
            config.environment_id.clone(),
            BrokerProcessEntry {
                generation: config.environment_generation,
                shutdown: shutdown_tx,
                state: state_rx.clone(),
                task,
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
        let Some(entry) = entries.remove(environment_id) else {
            return Ok(());
        };
        if generation.is_some_and(|generation| generation != entry.generation) {
            entries.insert(environment_id.clone(), entry);
            return Err(Status::failed_precondition(
                "local credential broker generation does not match",
            ));
        }
        stop_broker_entry(entry).await;
        Ok(())
    }

    async fn shutdown_all(&self) {
        let entries = {
            let mut entries = self.entries.lock().await;
            entries.drain().map(|(_, entry)| entry).collect::<Vec<_>>()
        };
        for entry in entries {
            stop_broker_entry(entry).await;
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
    tokio::time::timeout(BROKER_START_TIMEOUT, async {
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

async fn run_broker_lifecycle<S: ProtectedStore + 'static>(
    authority: Arc<LocalCredentialAuthority<S>>,
    spawner: Arc<dyn LocalBrokerProcessSpawner>,
    config: LocalBrokerProcessConfig,
    audit: Arc<BrokerLeaseAuditLog>,
    mut shutdown: watch::Receiver<bool>,
    state: watch::Sender<BrokerProcessState>,
) {
    let mut restart_delay = BROKER_RESTART_MIN_DELAY;
    loop {
        if *shutdown.borrow() {
            return;
        }
        let _ = state.send(BrokerProcessState::Starting);
        match run_one_broker(
            Arc::clone(&authority),
            Arc::clone(&spawner),
            &config,
            Arc::clone(&audit),
            &mut shutdown,
            &state,
        )
        .await
        {
            BrokerAttempt::Stopped => return,
            BrokerAttempt::Exited { running_for } => {
                if running_for >= BROKER_STABLE_RUNTIME {
                    restart_delay = BROKER_RESTART_MIN_DELAY;
                } else {
                    restart_delay = restart_delay
                        .saturating_mul(2)
                        .min(BROKER_RESTART_MAX_DELAY);
                }
            }
            BrokerAttempt::Failed => {
                restart_delay = restart_delay
                    .saturating_mul(2)
                    .min(BROKER_RESTART_MAX_DELAY);
            }
        }
        tokio::select! {
            _ = tokio::time::sleep(restart_delay) => {}
            _ = shutdown.changed() => return,
        }
    }
}

enum BrokerAttempt {
    Stopped,
    Failed,
    Exited { running_for: std::time::Duration },
}

async fn run_one_broker<S: ProtectedStore + 'static>(
    authority: Arc<LocalCredentialAuthority<S>>,
    spawner: Arc<dyn LocalBrokerProcessSpawner>,
    config: &LocalBrokerProcessConfig,
    audit: Arc<BrokerLeaseAuditLog>,
    shutdown: &mut watch::Receiver<bool>,
    state: &watch::Sender<BrokerProcessState>,
) -> BrokerAttempt {
    let Ok((authority_stream, broker_stream)) = std::os::unix::net::UnixStream::pair() else {
        return BrokerAttempt::Failed;
    };
    if authority_stream.set_nonblocking(true).is_err() {
        return BrokerAttempt::Failed;
    }
    let Ok(authority_stream) = UnixStream::from_std(authority_stream) else {
        return BrokerAttempt::Failed;
    };
    let Ok(mut child) = spawner.spawn(config, broker_stream) else {
        return BrokerAttempt::Failed;
    };
    let (ready_tx, mut ready_rx) = tokio::sync::oneshot::channel();
    let mut lease_task = tokio::spawn(serve_broker_lease_channel_with_ready(
        authority,
        authority_stream,
        config.environment_id.clone(),
        config.environment_generation,
        audit,
        Some(ready_tx),
    ));
    let mut start_timeout = Box::pin(tokio::time::sleep(BROKER_START_TIMEOUT));
    let ready = tokio::select! {
        ready = &mut ready_rx => ready.is_ok(),
        _ = child.wait() => {
            lease_task.abort();
            return BrokerAttempt::Failed;
        }
        _ = &mut lease_task => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            return BrokerAttempt::Failed;
        }
        _ = shutdown.changed() => {
            stop_child_and_channel(&mut child, &mut lease_task).await;
            return BrokerAttempt::Stopped;
        }
        _ = &mut start_timeout => false,
    };
    if !ready {
        stop_child_and_channel(&mut child, &mut lease_task).await;
        return BrokerAttempt::Failed;
    }

    let mut stability = Box::pin(tokio::time::sleep(BROKER_READY_STABILITY));
    tokio::select! {
        _ = &mut stability => {}
        _ = child.wait() => {
            lease_task.abort();
            return BrokerAttempt::Failed;
        }
        _ = &mut lease_task => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            return BrokerAttempt::Failed;
        }
        _ = shutdown.changed() => {
            stop_child_and_channel(&mut child, &mut lease_task).await;
            return BrokerAttempt::Stopped;
        }
    }
    if state.send(BrokerProcessState::Running).is_err() {
        stop_child_and_channel(&mut child, &mut lease_task).await;
        return BrokerAttempt::Stopped;
    }
    let started = tokio::time::Instant::now();
    tokio::select! {
        _ = child.wait() => {
            lease_task.abort();
        }
        _ = &mut lease_task => {
            let _ = child.kill().await;
            let _ = child.wait().await;
        }
        _ = shutdown.changed() => {
            stop_child_and_channel(&mut child, &mut lease_task).await;
            return BrokerAttempt::Stopped;
        }
    }
    let _ = state.send(BrokerProcessState::Starting);
    BrokerAttempt::Exited {
        running_for: started.elapsed(),
    }
}

async fn stop_child_and_channel(
    child: &mut tokio::process::Child,
    lease_task: &mut tokio::task::JoinHandle<Result<(), crate::BrokerLeaseChannelError>>,
) {
    let _ = child.kill().await;
    let _ = child.wait().await;
    lease_task.abort();
}

async fn stop_broker_entry(entry: BrokerProcessEntry) {
    let _ = entry.shutdown.send(true);
    let _ = entry.task.await;
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
            .map_err(|_| Status::invalid_argument("invalid credential material"))?;
        let authority = Arc::clone(&self.authority);
        let record = run_blocking(move || authority.add_credential(input, material)).await?;
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
        let material = ProtectedValue::new(mem::take(&mut request.material))
            .map_err(|_| Status::invalid_argument("invalid credential material"))?;
        let expires_at_unix = request.expires_at_unix;
        let authority = Arc::clone(&self.authority);
        let record = run_blocking(move || {
            authority.rotate_credential_material(&id, material, expires_at_unix)
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
        let authority = Arc::clone(&self.authority);
        let grants = run_blocking(move || {
            authority.evaluate_environment_grants(&environment_id, request.environment_generation)
        })
        .await?;
        Ok(Response::new(v1::EvaluateEnvironmentGrantsResponse {
            grants: grants.into_iter().map(derived_grant_to_proto).collect(),
        }))
    }

    async fn ensure_environment_broker(
        &self,
        request: Request<v1::EnsureEnvironmentBrokerRequest>,
    ) -> Result<Response<v1::EnvironmentBrokerRuntime>, Status> {
        let request = request.into_inner();
        let runtime = self
            .brokers
            .ensure(BrokerEnsureRequest {
                environment_id: environment_id(request.environment_id)?,
                environment_generation: request.environment_generation,
                environment_name: request.environment_name,
                supervisor_socket: PathBuf::from(request.supervisor_socket),
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
        };
        let prepared = self.repositories.prepare(authorization).await?;
        let (sender, receiver) = tokio::sync::mpsc::channel(8);
        tokio::spawn(stream_prepared_repository(prepared, sender));
        Ok(Response::new(ReceiverStream::new(receiver)))
    }
}

async fn stream_prepared_repository(
    mut prepared: PreparedRepository,
    sender: tokio::sync::mpsc::Sender<Result<v1::PreparedGitRepositoryChunk, Status>>,
) {
    use tokio::io::AsyncReadExt as _;

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
        let length = match prepared.bundle.read(&mut buffer[..limit]).await {
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
    match prepared.bundle.read(&mut buffer[..1]).await {
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

fn profile_entries(
    entries: Vec<v1::AccessProfileEntry>,
) -> Result<BTreeMap<CapabilitySlot, CredentialId>, Status> {
    let mut parsed = BTreeMap::new();
    for entry in entries {
        let slot = CapabilitySlot::parse(entry.capability_slot).map_err(status_for_access_error)?;
        let credential =
            CredentialId::parse(entry.credential_id).map_err(status_for_access_error)?;
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
        Ok(CredentialAuthenticationKind::SshPrivateKey) => Ok(CredentialAuthKind::SshPrivateKey),
        Ok(CredentialAuthenticationKind::SshAgent) => Ok(CredentialAuthKind::SshAgent),
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
        CredentialAuthKind::SshPrivateKey => CredentialAuthenticationKind::SshPrivateKey,
        CredentialAuthKind::SshAgent => CredentialAuthenticationKind::SshAgent,
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
        profile_id: grant.profile_id.to_string(),
        profile_revision: grant.profile_revision,
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
        LocalCredentialError::AlreadyExists => {
            Status::already_exists("local credential record already exists")
        }
        LocalCredentialError::EnvironmentBindingAlreadyExists => {
            Status::already_exists("local environment access binding already exists")
        }
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
        | LocalCredentialError::CredentialInUse
        | LocalCredentialError::StaleProfileRevision
        | LocalCredentialError::ProfileInUse
        | LocalCredentialError::StaleEnvironmentBinding
        | LocalCredentialError::ProtectedEntryCollision
        | LocalCredentialError::OwnerMismatch
        | LocalCredentialError::ProtectedStoreMismatch
        | LocalCredentialError::UnsupportedSchema
        | LocalCredentialError::InvalidDatabase
        | LocalCredentialError::CorruptMetadata => {
            Status::failed_precondition("local credential operation cannot be applied")
        }
        // AccessError is deliberately material-free and carries the stable
        // provider/profile diagnostic needed to repair a rejected selection.
        LocalCredentialError::Access(error) => Status::failed_precondition(error.to_string()),
        LocalCredentialError::DatabaseUnavailable | LocalCredentialError::ProtectedStore(_) => {
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
