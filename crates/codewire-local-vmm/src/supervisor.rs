//! Per-user native local-environment supervisor.
//!
//! SQLite WAL and its operation journal own durable lifecycle state. Process
//! and socket identities are persisted, but daemon capabilities and workload
//! credentials never are.

mod bootstrap;
mod sources;
pub(crate) use sources::PlatformSourceAuthority;

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::io;
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::process::CommandExt as _;
use std::path::{Component, Path, PathBuf};
use std::pin::Pin;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use codewire_access::{
    AccessProfileId, AccessProfileReference, AccessProfileScope, EnvironmentAccessBinding,
    EnvironmentId,
};
use codewire_local_credentials::{
    AuthorityRuntimeConfig, EnvironmentBrokerRuntime as AuthorityBrokerRuntime,
    LocalCredentialControlClient,
};
use futures::Stream;
use rustix::fs::{FlockOperation, flock};
use rustix::process::Signal;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tokio::sync::{Mutex, broadcast, mpsc, watch};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};
use uuid::Uuid;

use crate::RunnerError;
use crate::artifact_store::RuntimeArtifactStore;
use crate::control::v1;
use crate::control::v1::local_supervisor_service_client::LocalSupervisorServiceClient;
use crate::control::v1::local_supervisor_service_server::{
    LocalSupervisorService, LocalSupervisorServiceServer,
};
use crate::generation::{GenerationError, ensure_root_generation, valid_root_disk_bytes};
use crate::host_port::{
    HostPortBinding, canonical_host_port_bindings, validate_canonical_host_port_bindings,
};
use crate::lifecycle::{EffectDurability, LifecycleEffect, next_effect};
use crate::linux::path::{PathError, PrivateRoot, SocketIdentity};
use crate::linux::process::signal_unreaped_child;
use crate::linux::state::{
    DeletionTreeLocation, StateError, cleanup_trashed_vm, cleanup_unreferenced_root_generations,
    deletion_tree_location, move_stopped_vm_to_trash,
};
use crate::linux::{LiveProcess, ProcessIdentity, RecoveryError, VmPaths};
use crate::mesh_ingress::{
    MeshAttachment, MeshEnrollmentAuthSource, canonical_mesh_ingress_ports,
    validate_canonical_mesh_ingress_ports,
};
use crate::oci::{
    ContentStore, ContentStoreError, RegistryReference, RegistryReferenceError, RegistryResolver,
    RegistryResolverError, ResolvedDescriptor, ResolvedImage, Sha256Digest,
};
use crate::runner_service::{RunnerClient, RunnerServiceError};
use crate::setup_pack::{SetupPackError, SetupPackRequest, ensure_setup_pack};
use crate::skill_snapshot::{
    SkillSnapshotPreparationError, SkillSnapshotRequest, cleanup_interrupted_skill_snapshot,
    prepare_skill_snapshot,
};
#[cfg(test)]
use crate::supervisor_config::NATIVE_SUPERVISOR_PROTOCOL_VERSION;
pub use crate::supervisor_config::NativeRuntimeConfig;
use crate::supervisor_config::{SupervisorConfigError, supervisor_info};
use crate::supervisor_store::{
    OperationKind, OperationPhase, OperationRecord, SupervisorOperationReader, SupervisorStore,
    SupervisorStoreError,
};
use crate::uds::{UdsError, bind_owner_only_listener, connect_owner_only, remove_bound_socket};
use crate::workspace::{
    WorkspaceError, WorkspaceSelection, WorkspaceSourceMode,
    cleanup_interrupted_workspace_provisioning, ensure_docker_data_disk, ensure_workspace_plan,
    inspect_workspace, workspace_content_limit,
};
use crate::workspace_generation::{WorkspaceGenerationError, WorkspaceGenerationRecord};
use crate::workspace_plan::{
    RepositoryCredentialAccess, WorkspaceInput, WorkspacePlan, WorkspacePlanError,
    prepare_direct_input, prepare_repository_plan, validate_local_mount_destination,
};

pub(crate) const SUPERVISOR_STATE_SCHEMA: u32 = 3;
const SUPERVISOR_INFO_TIMEOUT: Duration = Duration::from_secs(3);
const RUNNER_START_TIMEOUT: Duration = Duration::from_secs(15);
const RUNNER_EXIT_TIMEOUT: Duration = Duration::from_secs(5);
const _: () = assert!(
    RUNNER_EXIT_TIMEOUT.as_nanos() > crate::runner_service::RUNNER_SERVER_DRAIN_TIMEOUT.as_nanos()
);
const OPERATION_WATCH_BUFFER: usize = 8;
const OPERATION_PROGRESS_CAPACITY: usize = 256;
const RUNNER_EVENT_DRAIN_TIMEOUT: Duration = Duration::from_secs(1);
const MAXIMUM_RUNNER_EVENTS: usize = 128;
const DAEMON_VSOCK_PORT: u32 = 7777;
const DEFAULT_OCI_ROOT_DISK_BYTES: u64 = 32 * 1024 * 1024 * 1024;

async fn request_runner_shutdown_and_observe(
    client: &mut RunnerClient,
    environment_id: Uuid,
    generation: u64,
    live: &LiveProcess,
) -> Result<bool, crate::RecoveryError> {
    // A missing response does not prove the request had no effect. Always
    // observe exact process exit for the full natural-exit window. This borrows
    // only the birth-pinned descriptor; the caller retains its unreaped Child
    // until the subsequent Linux pidfd fallback and reap, if needed.
    let _ = client.shutdown(environment_id, generation).await;
    live.wait_exited(RUNNER_EXIT_TIMEOUT).await
}
const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

mod public_api;

#[derive(Debug, Clone, PartialEq, Eq)]
struct PreparedWorkspaceBoot {
    root_generation: String,
    root_disk_bytes: u64,
    setup_root_generation: String,
    setup_total_bytes: u64,
    setup_header_sha256: String,
    skill_snapshot_sha256: String,
}

#[derive(Clone)]
struct CredentialBrokerEnsureRequest {
    authority: AuthorityRuntimeConfig,
    environment_id: EnvironmentId,
    environment_generation: u64,
    environment_name: String,
    runner_socket: PathBuf,
    projection: Option<codewire_local_credentials::LocalEnvironmentProjectionBinding>,
    platform: Option<codewire_local_credentials::PlatformCredentialBinding>,
    local_profile: Option<EnvironmentAccessBinding>,
    enabled: bool,
}

#[derive(Clone)]
struct OperationProgress {
    operation_id: Uuid,
    event: v1::RunnerEvent,
}

#[repr(C)]
struct LinuxCapabilityHeader {
    version: u32,
    pid: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct LinuxCapabilityData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

impl NativeRuntimeConfig {
    fn engine_root(&self) -> PathBuf {
        self.root.join("engine")
    }

    fn runner_socket(&self, environment_id: Uuid) -> PathBuf {
        self.root
            .join("runners")
            .join(format!("{environment_id}.sock"))
    }

    fn credential_authority_config(&self) -> AuthorityRuntimeConfig {
        AuthorityRuntimeConfig {
            root: self.credential_authority_root.clone(),
            executable: self.executable.clone(),
        }
    }

    fn direct_share_forbidden_roots(&self) -> Result<Vec<PathBuf>, SupervisorError> {
        [
            &self.root,
            &self.artifact_root,
            &self.credential_authority_root,
            &self.mesh_data_dir,
            &self.platform_config_dir,
        ]
        .into_iter()
        .map(|path| resolve_forbidden_root(path))
        .collect()
    }
}

fn resolve_forbidden_root(path: &Path) -> Result<PathBuf, SupervisorError> {
    let mut components = path.components();
    if components.next() != Some(Component::RootDir)
        || components.any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(SupervisorError::InvalidConfiguration);
    }

    let mut existing_prefix = path.to_owned();
    let mut missing_suffix = Vec::<OsString>::new();
    loop {
        match fs::canonicalize(&existing_prefix) {
            Ok(mut resolved) => {
                for component in missing_suffix.iter().rev() {
                    resolved.push(component);
                }
                return Ok(resolved);
            }
            Err(source) if source.kind() == io::ErrorKind::NotFound => {
                // A dangling symlink cannot be mapped to its eventual target.
                // Treat it as invalid instead of reconstructing it as a normal
                // missing path component and weakening the exclusion boundary.
                match fs::symlink_metadata(&existing_prefix) {
                    Ok(metadata) if metadata.file_type().is_symlink() => {
                        return Err(SupervisorError::InvalidConfiguration);
                    }
                    Ok(_) => {
                        return Err(SupervisorError::Io {
                            path: existing_prefix,
                            source,
                        });
                    }
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(source) => {
                        return Err(SupervisorError::Io {
                            path: existing_prefix,
                            source,
                        });
                    }
                }
                let component = existing_prefix
                    .file_name()
                    .ok_or(SupervisorError::InvalidConfiguration)?
                    .to_os_string();
                missing_suffix.push(component);
                if !existing_prefix.pop() {
                    return Err(SupervisorError::InvalidConfiguration);
                }
            }
            Err(source) => {
                return Err(SupervisorError::Io {
                    path: existing_prefix,
                    source,
                });
            }
        }
    }
}

#[derive(Clone)]
pub struct NativeSupervisorClient {
    inner: LocalSupervisorServiceClient<tonic::transport::Channel>,
    restart_config: Option<NativeRuntimeConfig>,
}

impl NativeSupervisorClient {
    pub async fn connect_or_start(config: &NativeRuntimeConfig) -> Result<Self, SupervisorError> {
        config.validate()?;
        prepare_runtime_root(&config.root)?;
        let socket = config.supervisor_socket();
        if fs::symlink_metadata(&socket).is_ok() {
            // A killed supervisor leaves a mode-0600 socket name behind. A
            // replacement singleton owns the lock and performs the exact
            // nofollow removal; the CLI never unlinks a control endpoint.
            match Self::connect_for_config(&socket, config).await {
                Ok(client) => return Ok(client.with_restart_config(config)),
                Err(error) if error.incompatible_supervisor() => return Err(error),
                Err(_) => {}
            }
        }
        let mut child = spawn_supervisor(config)?;
        let deadline = tokio::time::Instant::now() + RUNNER_START_TIMEOUT;
        loop {
            if fs::symlink_metadata(&socket).is_ok() {
                match Self::connect_for_config(&socket, config).await {
                    Ok(client) => return Ok(client.with_restart_config(config)),
                    Err(error) if error.incompatible_supervisor() => {
                        terminate_unadmitted_child(&mut child);
                        return Err(error);
                    }
                    Err(error) if tokio::time::Instant::now() < deadline => {
                        let _ = error;
                    }
                    Err(error) => {
                        terminate_unadmitted_child(&mut child);
                        return Err(error);
                    }
                }
            }
            if child
                .try_wait()
                .map_err(|_| SupervisorError::SpawnSupervisor)?
                .is_some()
                && fs::symlink_metadata(&socket).is_err()
            {
                return Err(SupervisorError::SpawnSupervisor);
            }
            if tokio::time::Instant::now() >= deadline {
                terminate_unadmitted_child(&mut child);
                return Err(SupervisorError::SupervisorStartTimeout);
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    pub async fn connect(socket: &Path) -> Result<Self, SupervisorError> {
        Self::connect_admitted(socket, None).await
    }

    async fn connect_for_config(
        socket: &Path,
        config: &NativeRuntimeConfig,
    ) -> Result<Self, SupervisorError> {
        Self::connect_admitted(socket, Some(config.configuration_digest())).await
    }

    async fn connect_admitted(
        socket: &Path,
        expected_configuration_digest: Option<[u8; 32]>,
    ) -> Result<Self, SupervisorError> {
        let channel = connect_owner_only(socket).await?;
        let mut client = Self {
            inner: LocalSupervisorServiceClient::new(channel),
            restart_config: None,
        };
        let info = tokio::time::timeout(
            SUPERVISOR_INFO_TIMEOUT,
            client
                .inner
                .get_supervisor_info(v1::GetSupervisorInfoRequest {}),
        )
        .await
        .map_err(|_| SupervisorError::SupervisorInfoUnavailable)?
        .map_err(supervisor_info_rpc_error)?
        .into_inner();
        admit_supervisor_info(&info, expected_configuration_digest.as_ref())?;
        Ok(client)
    }

    fn with_restart_config(mut self, config: &NativeRuntimeConfig) -> Self {
        self.restart_config = Some(config.clone());
        self
    }

    pub async fn create(
        &mut self,
        request: v1::CreateEnvironmentRequest,
    ) -> Result<v1::Environment, Status> {
        let name = request.name.clone();
        let operation = self.inner.create_environment(request).await?.into_inner();
        self.follow_environment_operation(operation, &name).await
    }

    pub async fn list(&mut self) -> Result<Vec<v1::Environment>, Status> {
        Ok(self
            .inner
            .list_environments(v1::ListEnvironmentsRequest {})
            .await?
            .into_inner()
            .environments)
    }

    pub async fn get(&mut self, name: &str) -> Result<v1::Environment, Status> {
        Ok(self
            .inner
            .get_environment(read_selector(name))
            .await?
            .into_inner())
    }

    pub async fn select(
        &mut self,
        name: &str,
        environment_id: &str,
    ) -> Result<v1::Environment, Status> {
        Ok(self
            .inner
            .select_environment(v1::EnvironmentSelector {
                name: name.to_owned(),
                request_id: Uuid::new_v4().to_string(),
                environment_id: environment_id.to_owned(),
            })
            .await?
            .into_inner())
    }

    pub async fn list_orphans(&mut self) -> Result<v1::ListOrphansResponse, Status> {
        Ok(self
            .inner
            .list_orphans(v1::ListOrphansRequest {})
            .await?
            .into_inner())
    }

    pub async fn start(&mut self, name: &str) -> Result<v1::Environment, Status> {
        let operation = self
            .inner
            .start_environment(mutation_selector(name))
            .await?
            .into_inner();
        self.follow_environment_operation(operation, name).await
    }

    pub async fn stop(&mut self, name: &str) -> Result<v1::Environment, Status> {
        let operation = self
            .inner
            .stop_environment(mutation_selector(name))
            .await?
            .into_inner();
        self.follow_environment_operation(operation, name).await
    }

    pub async fn restart(
        &mut self,
        name: &str,
        environment_id: &str,
    ) -> Result<v1::Environment, Status> {
        let operation = self
            .inner
            .restart_environment(v1::EnvironmentSelector {
                name: name.to_owned(),
                request_id: Uuid::new_v4().to_string(),
                environment_id: environment_id.to_owned(),
            })
            .await?
            .into_inner();
        self.follow_environment_operation(operation, name).await
    }

    pub async fn refresh_skills(&mut self, name: &str) -> Result<v1::Environment, Status> {
        let operation = self
            .inner
            .refresh_environment_skills(mutation_selector(name))
            .await?
            .into_inner();
        self.follow_environment_operation(operation, name).await
    }

    pub async fn resize(
        &mut self,
        name: &str,
        vcpus: u32,
        memory_mib: u32,
        disk_bytes: u64,
    ) -> Result<v1::Environment, Status> {
        let operation = self
            .inner
            .resize_environment(v1::ResizeEnvironmentRequest {
                name: name.to_owned(),
                vcpus,
                memory_mib,
                disk_bytes,
                request_id: Uuid::new_v4().to_string(),
                environment_id: String::new(),
                public_request_id: String::new(),
                public_disruption_policy: String::new(),
            })
            .await?
            .into_inner();
        self.follow_environment_operation(operation, name).await
    }

    /// Update only the source selections, waiting on the existing durable operation stream.
    pub async fn update_environment_sources(
        &mut self,
        request: v1::UpdateEnvironmentSourcesRequest,
    ) -> Result<v1::Operation, Status> {
        let operation = self
            .inner
            .update_environment_sources(request)
            .await?
            .into_inner();
        self.follow_operation(operation).await
    }

    pub async fn delete(&mut self, name: &str) -> Result<v1::DeleteEnvironmentResponse, Status> {
        let operation = self
            .inner
            .delete_environment(mutation_selector(name))
            .await?
            .into_inner();
        let operation = self.follow_operation(operation).await?;
        match operation.result.and_then(|result| result.value) {
            Some(v1::operation_result::Value::Deletion(deletion)) => Ok(deletion),
            _ => Err(Status::internal(
                "local delete operation returned an invalid result",
            )),
        }
    }

    pub async fn daemon_access(&mut self, name: &str) -> Result<v1::DaemonAccess, Status> {
        Ok(self
            .inner
            .get_daemon_access(read_selector(name))
            .await?
            .into_inner())
    }

    pub async fn ensure_credential_broker(
        &mut self,
        name: &str,
    ) -> Result<v1::CredentialBrokerRuntime, Status> {
        Ok(self
            .inner
            .ensure_credential_broker(read_selector(name))
            .await?
            .into_inner())
    }

    async fn follow_environment_operation(
        &mut self,
        operation: v1::Operation,
        name: &str,
    ) -> Result<v1::Environment, Status> {
        self.follow_operation(operation).await?;
        self.get(name).await
    }

    async fn follow_operation(
        &mut self,
        operation: v1::Operation,
    ) -> Result<v1::Operation, Status> {
        let operation_id = operation.operation_id.clone();
        if operation_terminal(&operation)
            .map_err(|failure| operation_watch_failure(&operation_id, failure))?
        {
            return operation_outcome(operation);
        }
        let mut reconnects = 0_u8;
        loop {
            let stream = self
                .inner
                .watch_operation(v1::WatchOperationRequest {
                    operation_id: operation_id.clone(),
                })
                .await;
            let failure = match stream {
                Ok(response) => {
                    let mut updates = response.into_inner();
                    loop {
                        match updates.message().await {
                            Ok(Some(operation))
                                if operation_terminal(&operation).map_err(|failure| {
                                    operation_watch_failure(&operation_id, failure)
                                })? =>
                            {
                                return operation_outcome(operation);
                            }
                            Ok(Some(_)) => {}
                            Ok(None) => {
                                break Status::unavailable(
                                    "local lifecycle operation stream ended before a terminal result",
                                );
                            }
                            Err(error) => break error,
                        }
                    }
                }
                Err(error) => error,
            };
            if !watch_failure_is_reconnectable(&failure) || reconnects >= 3 {
                return Err(operation_watch_failure(&operation_id, failure));
            }
            reconnects += 1;
            let config = self.restart_config.clone().ok_or_else(|| {
                operation_watch_failure(
                    &operation_id,
                    Status::unavailable("local supervisor reconnect is unavailable"),
                )
            })?;
            tokio::time::sleep(Duration::from_millis(100)).await;
            let replacement = Self::connect_or_start(&config).await.map_err(|_| {
                operation_watch_failure(
                    &operation_id,
                    Status::unavailable("reconnect to local supervisor failed"),
                )
            })?;
            self.inner = replacement.inner;
            self.restart_config = replacement.restart_config;
        }
    }
}

fn supervisor_info_rpc_error(status: Status) -> SupervisorError {
    if status.code() == tonic::Code::Unimplemented {
        SupervisorError::SupervisorProtocolUnavailable
    } else {
        SupervisorError::SupervisorInfoUnavailable
    }
}

fn admit_supervisor_info(
    info: &v1::SupervisorInfo,
    expected_configuration_digest: Option<&[u8; 32]>,
) -> Result<(), SupervisorError> {
    crate::supervisor_config::admit_supervisor_info(info, expected_configuration_digest)
        .map_err(Into::into)
}

fn operation_watch_failure(operation_id: &str, failure: Status) -> Status {
    Status::new(
        failure.code(),
        format!("local lifecycle operation {operation_id} watch failed before a terminal result"),
    )
}

fn watch_failure_is_reconnectable(status: &Status) -> bool {
    matches!(
        status.code(),
        tonic::Code::Unavailable | tonic::Code::Unknown | tonic::Code::Cancelled
    )
}

fn operation_terminal(operation: &v1::Operation) -> Result<bool, Status> {
    match v1::OperationPhase::try_from(operation.phase) {
        Ok(v1::OperationPhase::Intent | v1::OperationPhase::EffectApplied) => Ok(false),
        Ok(
            v1::OperationPhase::Completed
            | v1::OperationPhase::Failed
            | v1::OperationPhase::Interrupted,
        ) => Ok(true),
        _ => Err(Status::internal(
            "local lifecycle operation returned an invalid phase",
        )),
    }
}

fn operation_outcome(operation: v1::Operation) -> Result<v1::Operation, Status> {
    match v1::OperationPhase::try_from(operation.phase) {
        Ok(v1::OperationPhase::Completed) => Ok(operation),
        Ok(v1::OperationPhase::Failed | v1::OperationPhase::Interrupted) => {
            let error_code = if operation.error_code.is_empty() {
                "unknown"
            } else {
                operation.error_code.as_str()
            };
            Err(Status::failed_precondition(format!(
                "local lifecycle operation {} failed: {error_code}",
                operation.operation_id
            )))
        }
        _ => Err(Status::internal(
            "local lifecycle operation is not terminal",
        )),
    }
}

fn read_selector(name: &str) -> v1::EnvironmentSelector {
    v1::EnvironmentSelector {
        name: name.to_owned(),
        request_id: String::new(),
        environment_id: String::new(),
    }
}

fn mutation_selector(name: &str) -> v1::EnvironmentSelector {
    v1::EnvironmentSelector {
        name: name.to_owned(),
        request_id: Uuid::new_v4().to_string(),
        environment_id: String::new(),
    }
}

pub async fn serve_supervisor(config: NativeRuntimeConfig) -> Result<(), SupervisorError> {
    config.validate()?;
    let root = prepare_runtime_root(&config.root)?;
    let lock = SupervisorLock::acquire(&root)?;
    let (store, state) = SupervisorStore::open(&root)?;
    let operation_events = store.operation_events();
    let operation_reader = SupervisorOperationReader::open(&root)?;
    let operation_progress = broadcast::channel(OPERATION_PROGRESS_CAPACITY).0;
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    let mut core = SupervisorCore {
        config: config.clone(),
        root,
        store,
        state,
        children: HashMap::new(),
        live_runners: HashMap::new(),
        operation_progress: operation_progress.clone(),
        _lock: lock,
    };
    #[cfg(feature = "synthetic-oci-input-smoke")]
    core.admit_synthetic_workspace_image_pin()?;
    core.recover_host_reboot_workspace_transitions()?;
    core.reconcile_exposing_runners_for_startup().await?;
    let service = SupervisorRpc {
        info: supervisor_info(&config),
        core: Arc::new(Mutex::new(core)),
        shutdown: shutdown_tx,
        operation_reader: Arc::new(Mutex::new(operation_reader)),
        operation_events,
        operation_progress,
        worker_running: Arc::new(AtomicBool::new(false)),
    };
    let socket = config.supervisor_socket();
    let (listener, socket_identity) = bind_owner_only_listener(&socket)?;
    service.schedule_operation_worker(true);
    let app = public_api::supervisor_router(service);
    let result = axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            while shutdown_rx.changed().await.is_ok() {
                if *shutdown_rx.borrow() {
                    break;
                }
            }
        })
        .await
        .map_err(|_| SupervisorError::Serve);
    remove_bound_socket(&socket, &socket_identity)?;
    result
}

pub fn inspect_orphans(root: &Path) -> Result<v1::ListOrphansResponse, SupervisorError> {
    let root = PrivateRoot::open(root)?;
    let (store, state) = SupervisorStore::inspect(&root)?;
    let deletion_trash_names = store
        .as_ref()
        .map(SupervisorStore::deletion_trash_names)
        .transpose()?
        .unwrap_or_default();
    orphan_inventory_response(&root, &state, &deletion_trash_names)
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum StoredEnvironmentState {
    Stopped,
    Starting,
    Running,
    Error,
    Orphaned,
}

impl StoredEnvironmentState {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Stopped => "stopped",
            Self::Starting => "starting",
            Self::Running => "running",
            Self::Error => "error",
            Self::Orphaned => "orphaned",
        }
    }

    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "stopped" => Some(Self::Stopped),
            "starting" => Some(Self::Starting),
            "running" => Some(Self::Running),
            "error" => Some(Self::Error),
            "orphaned" => Some(Self::Orphaned),
            _ => None,
        }
    }

    fn proto(self) -> v1::EnvironmentState {
        match self {
            Self::Stopped => v1::EnvironmentState::Stopped,
            Self::Starting => v1::EnvironmentState::Starting,
            Self::Running => v1::EnvironmentState::Running,
            Self::Error => v1::EnvironmentState::Error,
            Self::Orphaned => v1::EnvironmentState::Orphaned,
        }
    }

    fn from_proto(value: i32) -> Result<Self, SupervisorError> {
        match v1::EnvironmentState::try_from(value) {
            Ok(v1::EnvironmentState::Stopped) => Ok(Self::Stopped),
            Ok(v1::EnvironmentState::Starting) => Ok(Self::Starting),
            Ok(v1::EnvironmentState::Running) => Ok(Self::Running),
            Ok(v1::EnvironmentState::Error) => Ok(Self::Error),
            Ok(v1::EnvironmentState::Orphaned) => Ok(Self::Orphaned),
            _ => Err(SupervisorError::InvalidRunnerResponse),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct RunnerRecord {
    pub(crate) process: ProcessIdentity,
    pub(crate) socket: SocketIdentity,
    pub(crate) artifact_generation: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) error_code: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct EnvironmentRecord {
    pub(crate) id: Uuid,
    pub(crate) name: String,
    pub(crate) state: StoredEnvironmentState,
    pub(crate) vcpus: u8,
    pub(crate) memory_mib: u32,
    pub(crate) disk_bytes: u64,
    #[serde(default)]
    pub(crate) docker_disk_bytes: u64,
    pub(crate) generation: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) host_ports: Vec<HostPortBinding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) mesh: Option<MeshAttachment>,
    pub(crate) workspace_plan: WorkspacePlan,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) project_spec_json: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) project_spec_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) access_profile: Option<AccessProfileReference>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) access_binding: Option<EnvironmentAccessBinding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) platform_source_authority: Option<PlatformSourceAuthority>,
    pub(crate) runner: Option<RunnerRecord>,
    #[serde(default)]
    pub(crate) active_artifact_generation: Option<String>,
    #[serde(default)]
    pub(crate) staging_artifact_generation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) active_workspace_generation: Option<WorkspaceGenerationRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) staging_workspace_generation: Option<WorkspaceGenerationRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) rollback_workspace_generation: Option<WorkspaceGenerationRecord>,
}

impl EnvironmentRecord {
    fn proto(&self, selected: bool) -> v1::Environment {
        let project = self
            .project_spec_json
            .as_deref()
            .and_then(|bytes| serde_json::from_slice::<codewire_project::ProjectSpec>(bytes).ok());
        let skill_snapshot = self
            .active_workspace_generation
            .as_ref()
            .and_then(|generation| generation.skill_snapshot.as_ref());
        v1::Environment {
            id: self.id.to_string(),
            name: self.name.clone(),
            state: self.state.proto() as i32,
            vcpus: u32::from(self.vcpus),
            memory_mib: self.memory_mib,
            disk_bytes: self.disk_bytes,
            docker_disk_bytes: self.docker_disk_bytes,
            generation: self.generation,
            selected,
            project_spec_sha256: self.project_spec_sha256.clone().unwrap_or_default(),
            project_spec_json: self.project_spec_json.clone().unwrap_or_default(),
            access_profile_id: self
                .access_binding
                .as_ref()
                .map(|binding| binding.profile_id.to_string())
                .unwrap_or_default(),
            platform_source_authority: self
                .platform_source_authority
                .as_ref()
                .map(PlatformSourceAuthority::proto),
            workspace_plan_sha256: self.workspace_plan.sha256().unwrap_or_default(),
            workspace_input_count: u32::try_from(self.workspace_plan.inputs.len())
                .unwrap_or_default(),
            working_directory: project
                .as_ref()
                .map(|project| project.working_directory.clone())
                .unwrap_or_default(),
            access_profile: self
                .access_profile
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_default(),
            access_profile_revision: self
                .access_binding
                .as_ref()
                .map(|binding| binding.profile_revision)
                .unwrap_or_default(),
            skill_snapshot_sha256: skill_snapshot
                .and_then(|snapshot| snapshot.sha256().ok())
                .unwrap_or_default(),
            skill_snapshot_generation: skill_snapshot
                .map(codewire_vmm_guest_probe::SkillSnapshotPlan::plan_generation)
                .unwrap_or_default(),
            skill_snapshot_count: skill_snapshot
                .and_then(|snapshot| u32::try_from(snapshot.skills().len()).ok())
                .unwrap_or_default(),
            requires_credential_authority: self.access_profile.is_some()
                || project
                    .as_ref()
                    .is_some_and(|project| !project.secrets.is_empty()),
            host_ports: host_ports_to_proto(&self.host_ports),
            mesh: mesh_attachment_to_proto(self.mesh.as_ref()),
            error_code: self
                .runner
                .as_ref()
                .and_then(|runner| runner.error_code.clone())
                .filter(|_| self.state == StoredEnvironmentState::Error)
                .unwrap_or_default(),
        }
    }

    fn promote_staging_workspace_generation(
        &mut self,
    ) -> Result<Option<WorkspaceGenerationRecord>, SupervisorError> {
        let Some(staging) = self.staging_workspace_generation.as_ref() else {
            return Ok(None);
        };
        let current_project_json = self
            .project_spec_json
            .as_deref()
            .ok_or(SupervisorError::InvalidState)?;
        let current_project_sha256 = self
            .project_spec_sha256
            .as_deref()
            .ok_or(SupervisorError::InvalidState)?;
        let current_artifact_generation = self
            .active_artifact_generation
            .as_deref()
            .ok_or(SupervisorError::InvalidState)?;
        let next_rollback = self.active_workspace_generation.clone();
        if let Some(active) = next_rollback.as_ref() {
            active.validate_for_project_intent(current_project_json, current_project_sha256)?;
            if active.artifact_generation()? != current_artifact_generation {
                return Err(SupervisorError::InvalidState);
            }
        }
        let (next_project_json, next_project_sha256) = staging
            .project_intent_with_current_sources(current_project_json, current_project_sha256)?;
        let staging_artifact_fallback = self
            .staging_artifact_generation
            .as_deref()
            .unwrap_or(current_artifact_generation);
        let next_artifact_generation = staging.artifact_generation()?.to_owned();
        if next_artifact_generation != staging_artifact_fallback {
            return Err(SupervisorError::InvalidState);
        }
        if self
            .staging_artifact_generation
            .as_deref()
            .is_some_and(|artifact| artifact != next_artifact_generation)
        {
            return Err(SupervisorError::InvalidState);
        }

        let displaced = self.rollback_workspace_generation.take();
        self.rollback_workspace_generation = next_rollback;
        self.active_workspace_generation = self.staging_workspace_generation.take();
        self.project_spec_json = Some(next_project_json);
        self.project_spec_sha256 = Some(next_project_sha256);
        self.active_artifact_generation = Some(next_artifact_generation);
        self.staging_artifact_generation = None;
        Ok(displaced)
    }

    fn finish_staging_workspace_update_without_boot(&mut self) -> Result<(), SupervisorError> {
        let active_artifact = self
            .active_artifact_generation
            .as_deref()
            .ok_or(SupervisorError::InvalidState)?;
        let staging_artifact_fallback = self
            .staging_artifact_generation
            .as_deref()
            .unwrap_or(active_artifact);
        let active = self
            .active_workspace_generation
            .as_ref()
            .ok_or(SupervisorError::InvalidState)?;
        let staging = self
            .staging_workspace_generation
            .as_ref()
            .ok_or(SupervisorError::InvalidState)?;
        if workspace_storage_generation(active)? != workspace_storage_generation(staging)? {
            return Err(SupervisorError::InvalidState);
        }
        let current_project_json = self
            .project_spec_json
            .as_deref()
            .ok_or(SupervisorError::InvalidState)?;
        let current_project_sha256 = self
            .project_spec_sha256
            .as_deref()
            .ok_or(SupervisorError::InvalidState)?;
        active.validate_for_project_intent(current_project_json, current_project_sha256)?;
        let (next_project_json, next_project_sha256) = staging
            .project_intent_with_current_sources(current_project_json, current_project_sha256)?;
        let next_artifact_generation = staging.artifact_generation()?.to_owned();
        if next_artifact_generation != staging_artifact_fallback {
            return Err(SupervisorError::InvalidState);
        }

        self.active_workspace_generation = self.staging_workspace_generation.take();
        self.project_spec_json = Some(next_project_json);
        self.project_spec_sha256 = Some(next_project_sha256);
        self.active_artifact_generation = Some(next_artifact_generation);
        self.staging_artifact_generation = None;
        Ok(())
    }

    fn stage_rollback_workspace_generation(
        &mut self,
        expected_active_storage: &str,
        expected_rollback_storage: &str,
    ) -> Result<(), SupervisorError> {
        let active_artifact = self
            .active_artifact_generation
            .as_deref()
            .ok_or(SupervisorError::InvalidState)?;
        let active = self
            .active_workspace_generation
            .as_ref()
            .ok_or(SupervisorError::InvalidState)?;
        if workspace_storage_generation(active)? != expected_active_storage {
            return Err(SupervisorError::InvalidState);
        }
        if let Some(staging) = self.staging_workspace_generation.as_ref() {
            let staging_artifact = self
                .staging_artifact_generation
                .as_deref()
                .unwrap_or(active_artifact);
            if workspace_storage_generation(staging)? == expected_rollback_storage
                && self.rollback_workspace_generation.is_none()
            {
                if staging.artifact_generation()? != staging_artifact {
                    return Err(SupervisorError::InvalidState);
                }
                return Ok(());
            }
            return Err(SupervisorError::InvalidState);
        }
        let rollback = self
            .rollback_workspace_generation
            .as_ref()
            .ok_or(SupervisorError::InvalidState)?;
        if workspace_storage_generation(rollback)? != expected_rollback_storage {
            return Err(SupervisorError::InvalidState);
        }
        let rollback = self
            .rollback_workspace_generation
            .as_ref()
            .ok_or(SupervisorError::InvalidState)?;
        let rollback_artifact = rollback.artifact_generation()?.to_owned();
        self.staging_artifact_generation = Some(rollback_artifact);
        self.staging_workspace_generation = self.rollback_workspace_generation.take();
        Ok(())
    }

    fn restore_staged_rollback_workspace_generation(
        &mut self,
        expected_active_storage: &str,
        expected_rollback_storage: &str,
    ) -> Result<(), SupervisorError> {
        let active_artifact = self
            .active_artifact_generation
            .as_deref()
            .ok_or(SupervisorError::InvalidState)?;
        let active = self
            .active_workspace_generation
            .as_ref()
            .ok_or(SupervisorError::InvalidState)?;
        if workspace_storage_generation(active)? != expected_active_storage
            || self.rollback_workspace_generation.is_some()
        {
            return Err(SupervisorError::InvalidState);
        }
        let staging_artifact = self
            .staging_artifact_generation
            .as_deref()
            .unwrap_or(active_artifact);
        let staging = self
            .staging_workspace_generation
            .as_ref()
            .ok_or(SupervisorError::InvalidState)?;
        if staging.artifact_generation()? != staging_artifact
            || workspace_storage_generation(staging)? != expected_rollback_storage
        {
            return Err(SupervisorError::InvalidState);
        }
        self.rollback_workspace_generation = self.staging_workspace_generation.take();
        self.staging_artifact_generation = None;
        Ok(())
    }

    fn validate(&self, key: &str) -> Result<(), SupervisorError> {
        let invalid_workspace_generation = match (
            self.project_spec_json.as_deref(),
            self.project_spec_sha256.as_deref(),
        ) {
            (Some(project_json), Some(project_sha256)) => {
                self.active_workspace_generation
                    .as_ref()
                    .is_some_and(|generation| {
                        generation
                            .validate_for_project_intent(project_json, project_sha256)
                            .is_err()
                    })
                    || self
                        .staging_workspace_generation
                        .as_ref()
                        .is_some_and(|generation| {
                            if self.active_workspace_generation.is_some() {
                                generation.validate().is_err()
                            } else {
                                generation
                                    .validate_for_project_intent(project_json, project_sha256)
                                    .is_err()
                            }
                        })
                    || self
                        .rollback_workspace_generation
                        .as_ref()
                        .is_some_and(|generation| generation.validate().is_err())
            }
            (None, None) => true,
            _ => true,
        };
        let active_artifact = self.active_artifact_generation.as_deref();
        let staging_artifact = self
            .staging_artifact_generation
            .as_deref()
            .or(active_artifact);
        let active_storage = self
            .active_workspace_generation
            .as_ref()
            .map(|generation| {
                let artifact = active_artifact.ok_or(SupervisorError::InvalidState)?;
                if generation.artifact_generation()? != artifact {
                    return Err(SupervisorError::InvalidState);
                }
                workspace_storage_generation(generation)
            })
            .transpose()?;
        let staging_storage = self
            .staging_workspace_generation
            .as_ref()
            .map(|generation| {
                let artifact = staging_artifact.ok_or(SupervisorError::InvalidState)?;
                if generation.artifact_generation()? != artifact {
                    return Err(SupervisorError::InvalidState);
                }
                workspace_storage_generation(generation)
            })
            .transpose()?;
        let rollback_storage = self
            .rollback_workspace_generation
            .as_ref()
            .map(workspace_storage_generation)
            .transpose()?;
        let duplicate_workspace_generation =
            |left: Option<&String>, right: Option<&String>| left.is_some() && left == right;
        if self.id.is_nil()
            || self.name != key
            || !valid_environment_name(&self.name)
            || self.vcpus == 0
            || self.vcpus > 32
            || !(128..=65_536).contains(&self.memory_mib)
            || self.disk_bytes < crate::linux::state::MINIMUM_STATE_DISK_BYTES
            || !self.disk_bytes.is_multiple_of(1024 * 1024)
            || (self.docker_disk_bytes != 0
                && (self.docker_disk_bytes < crate::linux::state::MINIMUM_DOCKER_DISK_BYTES
                    || !self.docker_disk_bytes.is_multiple_of(1024 * 1024)))
            || self.workspace_plan.validate().is_err()
            || validate_canonical_host_port_bindings(&self.host_ports).is_err()
            || self.mesh.as_ref().is_some_and(|mesh| {
                mesh.validate().is_err()
                    || mesh.node_name != self.name
                    || self
                        .project_spec_json
                        .as_deref()
                        .and_then(|bytes| serde_json::from_slice(bytes).ok())
                        .is_none_or(|project: codewire_project::ProjectSpec| {
                            validate_mesh_for_project(mesh, &project).is_err()
                        })
            })
            || match (&self.project_spec_json, &self.project_spec_sha256) {
                (None, None) => true,
                (Some(bytes), Some(digest)) => {
                    validate_project_intent(bytes, digest, None).is_err()
                        || serde_json::from_slice::<codewire_project::ProjectSpec>(bytes)
                            .map_or(true, |project| {
                                self.workspace_plan.validate_for_project(&project).is_err()
                            })
                }
                _ => true,
            }
            || !environment_access_metadata_valid(self)
            || self
                .project_spec_json
                .as_deref()
                .and_then(|bytes| serde_json::from_slice(bytes).ok())
                .is_none_or(|project: codewire_project::ProjectSpec| {
                    validate_host_ports_for_project(&self.host_ports, &project).is_err()
                })
            || self
                .active_artifact_generation
                .as_ref()
                .is_none_or(|generation| !valid_sha256(generation))
            || self
                .staging_artifact_generation
                .as_ref()
                .is_some_and(|generation| !valid_sha256(generation))
            || self.runner.as_ref().is_some_and(|runner| {
                runner
                    .error_code
                    .as_deref()
                    .is_some_and(|error_code| !runner_event_error_code_valid(error_code))
            })
            || invalid_workspace_generation
            || (self.rollback_workspace_generation.is_some()
                && self.active_workspace_generation.is_none())
            || duplicate_workspace_generation(active_storage.as_ref(), rollback_storage.as_ref())
            || duplicate_workspace_generation(staging_storage.as_ref(), rollback_storage.as_ref())
        {
            return Err(SupervisorError::InvalidState);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct SupervisorState {
    pub(crate) schema_version: u32,
    pub(crate) current: Option<String>,
    pub(crate) environments: BTreeMap<String, EnvironmentRecord>,
}

impl Default for SupervisorState {
    fn default() -> Self {
        Self {
            schema_version: SUPERVISOR_STATE_SCHEMA,
            current: None,
            environments: BTreeMap::new(),
        }
    }
}

impl SupervisorState {
    pub(crate) fn validate(&self) -> Result<(), SupervisorError> {
        if self.schema_version != SUPERVISOR_STATE_SCHEMA
            || self
                .current
                .as_ref()
                .is_some_and(|name| !self.environments.contains_key(name))
        {
            return Err(SupervisorError::InvalidState);
        }
        for (name, environment) in &self.environments {
            environment.validate(name)?;
        }
        let value = serde_json::to_value(self).map_err(|_| SupervisorError::InvalidState)?;
        if contains_forbidden_state_key(&value) {
            return Err(SupervisorError::SecretInState);
        }
        Ok(())
    }
}

fn contains_forbidden_state_key(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Object(fields) => fields.iter().any(|(name, value)| {
            let name = name.to_ascii_lowercase();
            name.contains("capability")
                || name.contains("credential")
                || name.contains("token")
                || contains_forbidden_state_key(value)
        }),
        serde_json::Value::Array(values) => values.iter().any(contains_forbidden_state_key),
        _ => false,
    }
}

struct SupervisorLock(File);

impl SupervisorLock {
    fn acquire(root: &PrivateRoot) -> Result<Self, SupervisorError> {
        let opened = root.create_regular(Path::new("supervisor.lock"), 0o600, false)?;
        // A CLOEXEC descriptor is still inherited during the short interval
        // between fork and exec. Another thread spawning an unrelated process
        // can therefore transiently retain a just-released lock. Keep the
        // singleton non-blocking, but tolerate that bounded kernel-level
        // handoff instead of misclassifying it as a live supervisor.
        const RETRY_DELAY: Duration = Duration::from_millis(10);
        const MAX_RETRIES: usize = 25;
        let mut retries = 0;
        loop {
            match flock(opened.file(), FlockOperation::NonBlockingLockExclusive) {
                Ok(()) => return Ok(Self(opened.into_file())),
                Err(error) if error == rustix::io::Errno::INTR && retries < MAX_RETRIES => {
                    retries += 1;
                }
                Err(error) if error == rustix::io::Errno::WOULDBLOCK && retries < MAX_RETRIES => {
                    retries += 1;
                    std::thread::sleep(RETRY_DELAY);
                }
                Err(error) if error == rustix::io::Errno::WOULDBLOCK => {
                    return Err(SupervisorError::AlreadyRunning);
                }
                Err(source) => {
                    return Err(SupervisorError::Io {
                        path: root.path().join("supervisor.lock"),
                        source: source.into(),
                    });
                }
            }
        }
    }
}

impl std::fmt::Debug for SupervisorLock {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SupervisorLock")
            .field("file", &self.0)
            .finish_non_exhaustive()
    }
}

fn orphan_inventory_response(
    root: &PrivateRoot,
    state: &SupervisorState,
    deletion_trash_names: &std::collections::BTreeSet<String>,
) -> Result<v1::ListOrphansResponse, SupervisorError> {
    let environments = state
        .environments
        .values()
        .map(|environment| (environment.id, environment.disk_bytes))
        .collect();
    let runners = state
        .environments
        .values()
        .filter_map(|environment| {
            environment
                .runner
                .as_ref()
                .map(|runner| (format!("{}.sock", environment.id), runner.socket.clone()))
        })
        .collect();
    let retained_content = referenced_content_blobs(state)?;
    #[cfg(feature = "synthetic-oci-input-smoke")]
    let retained_content = {
        let mut retained_content = retained_content;
        let engine = root.open_private_directory(Path::new("engine"), 0o700)?;
        let content = ContentStore::create(&engine)?;
        if let Some(image) = crate::oci::load_synthetic_image_pin(&engine, &content)
            .map_err(|_| SupervisorError::InvalidState)?
        {
            retain_image_content(&mut retained_content, &image)?;
        }
        retained_content
    };
    let content_blobs = retained_content
        .into_iter()
        .map(|(digest, size)| (digest.hex().to_owned(), size))
        .collect();
    let artifact_generations = referenced_artifact_generations(state)?;
    let orphans = crate::orphan::inventory(
        root,
        &environments,
        &runners,
        deletion_trash_names,
        &content_blobs,
        &artifact_generations,
    );
    let reclaimable_bytes = orphans.iter().fold(0_u64, |total, orphan| {
        total.saturating_add(orphan.reclaimable_bytes)
    });
    Ok(v1::ListOrphansResponse {
        orphans: orphans
            .into_iter()
            .map(|orphan| v1::Orphan {
                kind: orphan.kind.to_owned(),
                path: orphan.path.to_string_lossy().into_owned(),
                reason: orphan.reason.to_owned(),
                reclaimable_bytes: orphan.reclaimable_bytes,
            })
            .collect(),
        reclaimable_bytes,
    })
}

struct SupervisorCore {
    config: NativeRuntimeConfig,
    root: PrivateRoot,
    store: SupervisorStore,
    state: SupervisorState,
    children: HashMap<Uuid, Child>,
    live_runners: HashMap<Uuid, LiveProcess>,
    operation_progress: broadcast::Sender<OperationProgress>,
    _lock: SupervisorLock,
}

async fn resolve_workspace_image(
    reference: &RegistryReference,
    content: &ContentStore,
    pinned: Option<ResolvedImage>,
) -> Result<ResolvedImage, SupervisorError> {
    if let Some(image) = pinned {
        if image.source_reference != reference.original() {
            return Err(SupervisorError::InvalidState);
        }
        image.verify_cached(content)?;
        return Ok(image);
    }
    Ok(RegistryResolver::new(content)?
        .resolve_anonymous(reference)
        .await?)
}

impl SupervisorCore {
    fn save(&self) -> Result<(), SupervisorError> {
        self.store.replace_state(&self.state)?;
        Ok(())
    }

    #[cfg(feature = "synthetic-oci-input-smoke")]
    fn synthetic_workspace_image_pin(&self) -> Result<Option<ResolvedImage>, SupervisorError> {
        let engine = PrivateRoot::open(&self.config.engine_root())?;
        let content = ContentStore::create(&engine)?;
        crate::oci::load_synthetic_image_pin(&engine, &content)
            .map_err(|_| SupervisorError::InvalidState)
    }

    #[cfg(feature = "synthetic-oci-input-smoke")]
    fn admit_synthetic_workspace_image_pin(&mut self) -> Result<(), SupervisorError> {
        let _ = self.synthetic_workspace_image_pin()?;
        Ok(())
    }

    fn matching_synthetic_workspace_image(
        &self,
        reference: &RegistryReference,
    ) -> Result<Option<ResolvedImage>, SupervisorError> {
        #[cfg(feature = "synthetic-oci-input-smoke")]
        {
            Ok(self
                .synthetic_workspace_image_pin()?
                .filter(|image| image.source_reference == reference.original()))
        }
        #[cfg(not(feature = "synthetic-oci-input-smoke"))]
        {
            let _ = reference;
            Ok(None)
        }
    }

    fn selected(&self, name: &str) -> bool {
        self.state.current.as_deref() == Some(name)
    }

    fn environment(&self, name: &str) -> Result<&EnvironmentRecord, SupervisorError> {
        self.state
            .environments
            .get(name)
            .ok_or_else(|| SupervisorError::NotFound(name.to_owned()))
    }

    fn environment_mut(&mut self, name: &str) -> Result<&mut EnvironmentRecord, SupervisorError> {
        self.state
            .environments
            .get_mut(name)
            .ok_or_else(|| SupervisorError::NotFound(name.to_owned()))
    }

    async fn access_control_client(
        &mut self,
    ) -> Result<LocalCredentialControlClient, SupervisorError> {
        LocalCredentialControlClient::connect(&self.config.credential_authority_config())
            .await
            .map_err(|_| SupervisorError::CredentialAuthorityUnavailable)
    }

    async fn bind_environment_access(
        &mut self,
        request: &v1::CreateEnvironmentRequest,
        environment_id: Uuid,
    ) -> Result<(), SupervisorError> {
        let Some((binding, reference)) = create_request_access_binding(request, environment_id)?
        else {
            return Ok(());
        };
        let project: codewire_project::ProjectSpec =
            serde_json::from_slice(&request.project_spec_json)
                .map_err(|_| SupervisorError::InvalidRequest)?;
        if sources::profile_placement(&project)?
            == Some(codewire_project::StoragePlacement::Platform)
        {
            // Platform pins never enter the local profile foreign key. Their
            // launch authority comes from fresh platform delegation instead.
            return Ok(());
        }
        self.access_control_client()
            .await?
            .ensure_environment_access_binding(&binding, &reference)
            .await
            .map(|_| ())
            .map_err(|status| match status.code() {
                tonic::Code::Unavailable | tonic::Code::DeadlineExceeded | tonic::Code::Unknown => {
                    SupervisorError::CredentialAuthorityUnavailable
                }
                code => SupervisorError::EnvironmentAccessBindingRejected(code),
            })
    }

    async fn require_environment_access(&mut self, name: &str) -> Result<(), SupervisorError> {
        let Some(expected) = self.environment(name)?.access_binding.clone() else {
            return Ok(());
        };
        let project: codewire_project::ProjectSpec = serde_json::from_slice(
            self.environment(name)?
                .project_spec_json
                .as_deref()
                .ok_or(SupervisorError::InvalidState)?,
        )
        .map_err(|_| SupervisorError::InvalidState)?;
        if sources::profile_placement(&project)?
            == Some(codewire_project::StoragePlacement::Platform)
        {
            // Metadata configures native clients only. Actual guest Ready is
            // required before the parent opens fresh authenticated delegation;
            // its live platform admission never consults the local profile DB.
            sources::platform::managed_clients(self.environment(name)?)?
                .ok_or(SupervisorError::EnvironmentAccessUnavailable)?;
            return Ok(());
        }
        let current = self
            .access_control_client()
            .await?
            .get_environment_access_binding(&expected.environment_id)
            .await
            .map_err(credential_control_error)?;
        if current.binding != expected {
            return Err(SupervisorError::EnvironmentAccessUnavailable);
        }
        Ok(())
    }

    /// Capture only client-slot metadata from the exact selected revision.
    /// This configures clients; each broker request still evaluates live grants.
    async fn managed_credential_clients_for_boot(
        &mut self,
        environment: &EnvironmentRecord,
    ) -> Result<codewire_access::ManagedCredentialClients, SupervisorError> {
        let project: codewire_project::ProjectSpec = serde_json::from_slice(
            environment
                .project_spec_json
                .as_deref()
                .ok_or(SupervisorError::InvalidState)?,
        )
        .map_err(|_| SupervisorError::InvalidState)?;
        // The existing native agent home owns skills/session state even when
        // no credential profile is selected. It is not provider authority.
        if project.environment.contains_key("CODEX_HOME") {
            return Err(SupervisorError::InvalidRequest);
        }
        if let Some(clients) = sources::platform::managed_clients(environment)? {
            return Ok(clients);
        }
        let Some(expected) = &environment.access_binding else {
            return Ok(codewire_access::ManagedCredentialClients::default());
        };
        if sources::profile_placement(&project)? != Some(codewire_project::StoragePlacement::Local)
        {
            return Err(SupervisorError::EnvironmentAccessUnavailable);
        }
        let mut authority = self.access_control_client().await?;
        let binding = authority
            .get_environment_access_binding(&expected.environment_id)
            .await
            .map_err(credential_control_error)?;
        if &binding.binding != expected {
            return Err(SupervisorError::EnvironmentAccessUnavailable);
        }
        let revision = authority
            .get_profile_revision(&expected.profile_id, expected.profile_revision)
            .await
            .map_err(credential_control_error)?;
        if revision.profile.id != expected.profile_id
            || revision.profile.revision != expected.profile_revision
        {
            return Err(SupervisorError::EnvironmentAccessUnavailable);
        }
        let clients = codewire_access::ManagedCredentialClients::from_profile_slots(
            revision.profile.entries.keys().map(|slot| slot.as_str()),
        )
        .map_err(|_| SupervisorError::EnvironmentAccessUnavailable)?;
        clients
            .check_collisions(project.environment.keys().map(String::as_str))
            .map_err(|_| SupervisorError::EnvironmentAccessUnavailable)?;
        Ok(clients)
    }

    async fn stop_environment_broker_if_present(
        &mut self,
        environment: &EnvironmentRecord,
    ) -> Result<(), SupervisorError> {
        if environment.generation == 0 {
            return Ok(());
        }
        let project: codewire_project::ProjectSpec = serde_json::from_slice(
            environment
                .project_spec_json
                .as_deref()
                .ok_or(SupervisorError::InvalidState)?,
        )
        .map_err(|_| SupervisorError::InvalidState)?;
        if environment.access_profile.is_none() && project.secrets.is_empty() {
            return Ok(());
        }
        let Ok(environment_id) = access_environment_id(environment.id) else {
            return Err(SupervisorError::InvalidState);
        };
        // A failed socket connection is not evidence that the authority and
        // its children died. Require the exact generation's drain acknowledgement
        // before replacing its sources or claiming managed cleanup completed.
        let mut client = self.access_control_client().await?;
        client
            .stop_environment_broker(&environment_id, Some(environment.generation))
            .await
            .map_err(credential_control_error)
    }

    async fn revoke_environment_access_best_effort(&mut self, environment_id: Uuid) -> bool {
        let Ok(environment_id) = access_environment_id(environment_id) else {
            return true;
        };
        let Ok(mut client) = self.access_control_client().await else {
            return true;
        };
        client
            .delete_environment_access_binding_if_present(&environment_id)
            .await
            .is_err()
    }

    async fn environment_access_cleanup_pending(&mut self, environment_id: Uuid) -> bool {
        let Ok(environment_id) = access_environment_id(environment_id) else {
            return true;
        };
        let Ok(mut client) = self.access_control_client().await else {
            return true;
        };
        match client.get_environment_access_binding(&environment_id).await {
            Ok(_) => true,
            Err(status) if status.code() == tonic::Code::NotFound => false,
            Err(_) => true,
        }
    }

    fn orphan_inventory(&self) -> Result<v1::ListOrphansResponse, SupervisorError> {
        let deletion_trash_names = self.store.deletion_trash_names()?;
        orphan_inventory_response(&self.root, &self.state, &deletion_trash_names)
    }

    async fn admit_current_artifact_generation(&mut self) -> Result<String, SupervisorError> {
        let engine = PrivateRoot::open(&self.config.engine_root())?;
        RuntimeArtifactStore::create(&engine)
            .map_err(|_| SupervisorError::ArtifactStore)?
            .admit_source(&self.config.artifact_lock, &self.config.artifact_root)
            .await
            .map_err(|_| SupervisorError::ArtifactStore)
    }

    async fn admit_cached_artifact_generation(
        &mut self,
        artifact_generation: &str,
    ) -> Result<(), SupervisorError> {
        let engine = PrivateRoot::open(&self.config.engine_root())?;
        let _ = RuntimeArtifactStore::create(&engine)
            .map_err(|_| SupervisorError::ArtifactStore)?
            .open_generation(artifact_generation)
            .await
            .map_err(|_| SupervisorError::ArtifactStore)?;
        Ok(())
    }

    async fn preflight(&mut self) -> Result<String, SupervisorError> {
        let artifact_generation = self.admit_current_artifact_generation().await?;
        crate::linux::preflight::preflight().map_err(RunnerError::from)?;
        Ok(artifact_generation)
    }

    async fn prepare_create_workspace_plan(
        &mut self,
        request: &v1::CreateEnvironmentRequest,
        environment_id: Uuid,
    ) -> Result<WorkspacePlan, SupervisorError> {
        let project: codewire_project::ProjectSpec =
            serde_json::from_slice(&request.project_spec_json)
                .map_err(|_| SupervisorError::InvalidRequest)?;
        if project.repositories.is_empty() && request.local_mounts.is_empty() {
            let requested_source = PathBuf::from(&request.source_path);
            let path_mode = parse_implicit_path_mode(&request.implicit_path_mode)?;
            let maximum_copy_bytes = workspace_content_limit(request.disk_bytes);
            let source = tokio::task::spawn_blocking(move || {
                inspect_workspace(
                    &requested_source,
                    workspace_selection(path_mode),
                    maximum_copy_bytes,
                )
            })
            .await
            .map_err(|_| SupervisorError::WorkspaceProvisionTask)??;
            let plan = WorkspacePlan::local(&source)?;
            validate_request_workspace_plan(request, &project, &plan)?;
            return Ok(plan);
        }
        let mut inputs = if project.repositories.is_empty() {
            Vec::new()
        } else {
            let platform = sources::platform::repository_binding(
                request,
                &project,
                environment_id,
                &self.config.platform_config_dir,
            )?;
            let credential_access = create_request_access_selection(request, &project)?.map(
                |(profile_id, profile_revision, _)| RepositoryCredentialAccess {
                    request_id: Uuid::parse_str(&request.request_id)
                        .expect("validated create request ID"),
                    profile_id,
                    profile_revision,
                    platform,
                },
            );
            prepare_repository_plan(
                &self.config.engine_root(),
                &project.repositories,
                credential_access.as_ref(),
                &self.config.credential_authority_config(),
            )
            .await?
            .inputs
        };
        if !request.local_mounts.is_empty() {
            let mounts = request.local_mounts.clone();
            let maximum_copy_bytes = workspace_content_limit(request.disk_bytes);
            let forbidden_roots = self.config.direct_share_forbidden_roots()?;
            let local_inputs = tokio::task::spawn_blocking(move || {
                mounts
                    .into_iter()
                    .map(|mount| {
                        let requested_source =
                            PathBuf::from(OsString::from_vec(mount.source_path.clone()));
                        if mount.mode == v1::LocalMountMode::Direct as i32 {
                            return prepare_direct_input(
                                &requested_source,
                                &mount.destination,
                                mount.read_only.ok_or(WorkspacePlanError::InvalidPlan)?,
                                &forbidden_roots,
                            )
                            .map_err(SupervisorError::from);
                        }
                        let source = inspect_workspace(
                            &requested_source,
                            WorkspaceSelection::Copy,
                            maximum_copy_bytes,
                        )
                        .map_err(SupervisorError::from)?;
                        if source.source_path.as_os_str().as_bytes() != mount.source_path {
                            return Err(SupervisorError::from(WorkspaceError::SourceChanged));
                        }
                        Ok(WorkspaceInput::local(&source, &mount.destination))
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .await
            .map_err(|_| SupervisorError::WorkspaceProvisionTask)??;
            inputs.extend(local_inputs);
        }
        let plan = WorkspacePlan::from_inputs(inputs)?;
        validate_request_workspace_plan(request, &project, &plan)?;
        Ok(plan)
    }

    async fn stage_workspace_generation(
        &mut self,
        name: &str,
    ) -> Result<SupervisorState, SupervisorError> {
        self.collect_unreferenced_workspace_roots(name)?;
        self.collect_unreferenced_content()?;
        self.collect_unreferenced_runtime_artifacts()?;
        let (project_json, project_sha256, artifact_generation) = {
            let environment = self.environment(name)?;
            if environment.active_workspace_generation.is_some()
                || environment.staging_workspace_generation.is_some()
            {
                return Ok(self.state.clone());
            }
            (
                environment
                    .project_spec_json
                    .clone()
                    .ok_or(SupervisorError::InvalidState)?,
                environment
                    .project_spec_sha256
                    .clone()
                    .ok_or(SupervisorError::InvalidState)?,
                environment
                    .active_artifact_generation
                    .clone()
                    .ok_or(SupervisorError::InvalidState)?,
            )
        };
        let project: codewire_project::ProjectSpec =
            serde_json::from_slice(&project_json).map_err(|_| SupervisorError::InvalidState)?;
        project
            .validate()
            .map_err(|_| SupervisorError::InvalidState)?;
        if project
            .canonical_json()
            .map_err(|_| SupervisorError::InvalidState)?
            != project_json
        {
            return Err(SupervisorError::InvalidState);
        }

        let reference = RegistryReference::parse(&project.image)?;
        let engine = PrivateRoot::open(&self.config.engine_root())?;
        let content = ContentStore::create(&engine)?;
        let pinned = self.matching_synthetic_workspace_image(&reference)?;
        let image = resolve_workspace_image(&reference, &content, pinned).await?;
        let skill_snapshot = self
            .spawn_skill_snapshot_resolution(name, &project, &project_sha256, 1, None)?
            .await
            .map_err(|_| SupervisorError::WorkspaceGenerationProvisionTask)??;
        let generation = WorkspaceGenerationRecord::new_with_skill_snapshot(
            &project_json,
            project_sha256.to_owned(),
            artifact_generation,
            image,
            DEFAULT_OCI_ROOT_DISK_BYTES,
            skill_snapshot,
        )?;

        let mut next_state = self.state.clone();
        let environment = next_state
            .environments
            .get_mut(name)
            .ok_or_else(|| SupervisorError::NotFound(name.to_owned()))?;
        if environment.active_workspace_generation.is_some()
            || environment.staging_workspace_generation.is_some()
        {
            return Err(SupervisorError::InvalidState);
        }
        environment.staging_workspace_generation = Some(generation);
        Ok(next_state)
    }

    async fn stage_workspace_update(
        &mut self,
        name: &str,
        parameters: &WorkspaceTransitionParameters,
    ) -> Result<SupervisorState, SupervisorError> {
        let WorkspaceTransitionIntent::Update {
            project_spec_json,
            project_spec_sha256,
        } = &parameters.intent
        else {
            return Err(SupervisorError::InvalidState);
        };
        self.collect_unreferenced_workspace_roots(name)?;
        self.collect_unreferenced_content()?;
        self.collect_unreferenced_runtime_artifacts()?;
        {
            let environment = self.environment(name)?;
            let active = environment
                .active_workspace_generation
                .as_ref()
                .ok_or(SupervisorError::InvalidState)?;
            if workspace_storage_generation(active)? != parameters.prior_storage_generation {
                return Err(SupervisorError::InvalidState);
            }
            if environment.staging_workspace_generation.is_some() {
                workspace_transition_requires_boot(environment, parameters)?;
                return Ok(self.state.clone());
            }
        }

        let project: codewire_project::ProjectSpec =
            serde_json::from_slice(project_spec_json).map_err(|_| SupervisorError::InvalidState)?;
        let (artifact_generation, image, root_disk_bytes) = if parameters.refresh_skills {
            let active = self
                .environment(name)?
                .active_workspace_generation
                .as_ref()
                .ok_or(SupervisorError::InvalidState)?;
            (
                active.artifact_generation.clone(),
                active.image.clone(),
                active.root_disk_bytes,
            )
        } else {
            let reference = RegistryReference::parse(&project.image)?;
            let artifact_generation = self.admit_current_artifact_generation().await?;
            let engine = PrivateRoot::open(&self.config.engine_root())?;
            let content = ContentStore::create(&engine)?;
            let pinned = self.matching_synthetic_workspace_image(&reference)?;
            let image = resolve_workspace_image(&reference, &content, pinned).await?;
            (artifact_generation, image, DEFAULT_OCI_ROOT_DISK_BYTES)
        };
        let plan_generation = match self
            .environment(name)?
            .active_workspace_generation
            .as_ref()
            .and_then(|generation| generation.skill_snapshot.as_ref())
        {
            Some(snapshot) => snapshot
                .plan_generation()
                .checked_add(1)
                .ok_or(SupervisorError::InvalidState)?,
            None => 1,
        };
        let skill_snapshot = self
            .spawn_skill_snapshot_resolution(
                name,
                &project,
                project_spec_sha256,
                plan_generation,
                None,
            )?
            .await
            .map_err(|_| SupervisorError::WorkspaceGenerationProvisionTask)??;
        let generation = WorkspaceGenerationRecord::new_with_skill_snapshot(
            project_spec_json,
            project_spec_sha256.clone(),
            artifact_generation.clone(),
            image,
            root_disk_bytes,
            skill_snapshot,
        )?;

        let mut next_state = self.state.clone();
        let environment = next_state
            .environments
            .get_mut(name)
            .ok_or_else(|| SupervisorError::NotFound(name.to_owned()))?;
        let active = environment
            .active_workspace_generation
            .as_ref()
            .ok_or(SupervisorError::InvalidState)?;
        if workspace_storage_generation(active)? != parameters.prior_storage_generation {
            return Err(SupervisorError::InvalidState);
        }
        if environment.staging_workspace_generation.is_some() {
            return Err(SupervisorError::InvalidState);
        }
        environment.staging_artifact_generation = Some(artifact_generation);
        environment.staging_workspace_generation = Some(generation);
        Ok(next_state)
    }

    fn spawn_skill_snapshot_resolution(
        &self,
        name: &str,
        project: &codewire_project::ProjectSpec,
        project_sha256: &str,
        plan_generation: u64,
        expected: Option<&codewire_vmm_guest_probe::SkillSnapshotPlan>,
    ) -> Result<
        tokio::task::JoinHandle<
            Result<
                Option<codewire_vmm_guest_probe::SkillSnapshotPlan>,
                SkillSnapshotPreparationError,
            >,
        >,
        SupervisorError,
    > {
        let environment = self.environment(name)?;
        let engine_root = self.config.engine_root();
        let vm_id = environment.id;
        let workspace_plan = environment.workspace_plan.clone();
        let project = project.clone();
        let project_sha256 = project_sha256.to_owned();
        let user_skills_root = self.config.mesh_data_dir.join("skills");
        let forbidden_direct_roots = self.config.direct_share_forbidden_roots()?;
        let expected = expected.cloned();
        Ok(tokio::task::spawn_blocking(move || {
            prepare_skill_snapshot(SkillSnapshotRequest {
                engine_state_root: &engine_root,
                vm_id,
                workspace_plan: &workspace_plan,
                project: &project,
                project_sha256: &project_sha256,
                user_skills_root: &user_skills_root,
                forbidden_direct_roots: &forbidden_direct_roots,
                plan_generation,
                expected: expected.as_ref(),
            })
            .map(|prepared| prepared.map(|prepared| prepared.plan().clone()))
        }))
    }

    fn stage_workspace_rollback(
        &self,
        name: &str,
        parameters: &WorkspaceTransitionParameters,
    ) -> Result<SupervisorState, SupervisorError> {
        let WorkspaceTransitionIntent::Rollback {
            rollback_storage_generation,
        } = &parameters.intent
        else {
            return Err(SupervisorError::InvalidState);
        };
        let mut next_state = self.state.clone();
        next_state
            .environments
            .get_mut(name)
            .ok_or_else(|| SupervisorError::NotFound(name.to_owned()))?
            .stage_rollback_workspace_generation(
                &parameters.prior_storage_generation,
                rollback_storage_generation,
            )?;
        Ok(next_state)
    }

    fn collect_unreferenced_workspace_roots(
        &self,
        name: &str,
    ) -> Result<Vec<String>, SupervisorError> {
        let environment = self.environment(name)?;
        let retained = referenced_root_storage_generations(environment)?;
        let engine = PrivateRoot::open(&self.config.engine_root())?;
        let paths = VmPaths::create(&engine, environment.id)?;
        cleanup_unreferenced_root_generations(&paths, &retained).map_err(Into::into)
    }

    fn collect_unreferenced_content(&mut self) -> Result<(), SupervisorError> {
        let mut retained = referenced_content_blobs(&self.state)?;
        #[cfg(feature = "synthetic-oci-input-smoke")]
        if let Some(image) = self.synthetic_workspace_image_pin()? {
            retain_image_content(&mut retained, &image)?;
        }
        for operation in self.store.pending_operations()? {
            if operation.kind != OperationKind::Create {
                continue;
            }
            let (_, workspace_plan) = create_request_from_operation(&operation)?;
            retain_workspace_plan_content(&mut retained, &workspace_plan)?;
        }
        let engine = PrivateRoot::open(&self.config.engine_root())?;
        let content = ContentStore::create(&engine)?;
        let _collected = content.collect_unreferenced(&retained)?;
        Ok(())
    }

    fn collect_unreferenced_runtime_artifacts(&mut self) -> Result<(), SupervisorError> {
        let retained = referenced_artifact_generations(&self.state)?;
        let engine = PrivateRoot::open(&self.config.engine_root())?;
        let artifacts =
            RuntimeArtifactStore::create(&engine).map_err(|_| SupervisorError::ArtifactStore)?;
        let _collected = artifacts
            .collect_unreferenced(&retained)
            .map_err(|_| SupervisorError::ArtifactStore)?;
        Ok(())
    }

    async fn revalidate_workspace_plan_for_boot(
        &mut self,
        plan: &WorkspacePlan,
    ) -> Result<(), SupervisorError> {
        let plan = plan.clone();
        let forbidden_roots = self.config.direct_share_forbidden_roots()?;
        tokio::task::spawn_blocking(move || {
            revalidate_direct_shares_for_boot(&plan, &forbidden_roots)
        })
        .await
        .map_err(|_| SupervisorError::WorkspaceGenerationProvisionTask)??;
        Ok(())
    }

    async fn revalidate_environment_workspace_plan_for_boot(
        &mut self,
        name: &str,
    ) -> Result<(), SupervisorError> {
        let environment = self.environment(name)?;
        let plan = environment.workspace_plan.clone();
        let exposes_direct_shares =
            environment.runner.is_some() && environment_may_expose_direct_shares(environment);
        let validation = self.revalidate_workspace_plan_for_boot(&plan).await;
        if exposes_direct_shares && validation.is_err() {
            // A replay can resume after StartVm. Reconciliation terminates an
            // exact live runner before an invalid or unresolved current
            // exclusion boundary is returned to the lifecycle worker.
            self.reconcile_runner(name, true).await?;
        }
        validation
    }

    async fn reconcile_active_environment_before_protected_effect(
        &mut self,
        name: &str,
    ) -> Result<(), SupervisorError> {
        let environment = self.environment(name)?;
        if matches!(
            environment.state,
            StoredEnvironmentState::Running | StoredEnvironmentState::Starting
        ) && environment.runner.is_none()
        {
            if environment.state == StoredEnvironmentState::Running {
                self.reconcile(name).await?;
            }
            return Err(SupervisorError::NotRunning);
        }
        if !environment_may_expose_direct_shares(environment) {
            return if environment.state == StoredEnvironmentState::Orphaned {
                Err(SupervisorError::Orphaned)
            } else {
                Ok(())
            };
        }
        self.reconcile(name).await?;
        self.revalidate_environment_workspace_plan_for_boot(name)
            .await?;
        let environment = self.environment(name)?;
        if environment.state == StoredEnvironmentState::Orphaned {
            return Err(SupervisorError::Orphaned);
        }
        if matches!(
            environment.state,
            StoredEnvironmentState::Running | StoredEnvironmentState::Starting
        ) && environment.runner.is_none()
        {
            return Err(SupervisorError::NotRunning);
        }
        Ok(())
    }

    async fn reconcile_exposing_runners_for_startup(&mut self) -> Result<(), SupervisorError> {
        let names = self
            .state
            .environments
            .iter()
            .filter(|(_, environment)| environment_may_expose_direct_shares(environment))
            .map(|(name, _)| name.clone())
            .collect::<Vec<_>>();
        if let Err(boundary_error) = self.config.direct_share_forbidden_roots() {
            let mut closure_error = None;
            // Configuration validation runs before the state store is opened,
            // but effective forbidden-root resolution is deliberately deferred
            // until now. That lets a replacement supervisor close every exact
            // live direct-share boundary before rejecting an unresolved alias.
            for name in names {
                if let Err(error) = self.reconcile_runner(name.as_str(), true).await {
                    closure_error.get_or_insert(error);
                }
            }
            return Err(closure_error.unwrap_or(boundary_error));
        }
        let mut valid_names = Vec::with_capacity(names.len());
        let mut first_error = None;
        // Quarantine every newly forbidden direct share before an unrelated
        // runner protocol failure can abort startup reconciliation.
        for name in names {
            match self
                .revalidate_environment_workspace_plan_for_boot(&name)
                .await
            {
                Ok(()) => valid_names.push(name),
                Err(SupervisorError::WorkspacePlan(WorkspacePlanError::DirectShareChanged)) => {
                    if let Err(error) = self.reconcile(&name).await {
                        first_error.get_or_insert(error);
                    }
                }
                Err(error) => {
                    first_error.get_or_insert(error);
                }
            }
        }
        // Full identity, socket, protocol, and state reconciliation remains a
        // startup gate, but all candidates are attempted before its first
        // failure is returned.
        for name in valid_names {
            if let Err(error) = self.reconcile(&name).await {
                first_error.get_or_insert(error);
            }
        }
        if let Some(error) = first_error {
            return Err(error);
        }
        Ok(())
    }

    async fn create(
        &mut self,
        request: &v1::CreateEnvironmentRequest,
        workspace_plan: &WorkspacePlan,
        operation: &OperationRecord,
    ) -> Result<(v1::Environment, OperationRecord), SupervisorError> {
        let environment_id = operation
            .environment_id
            .ok_or(SupervisorError::InvalidState)?;
        if operation.kind != OperationKind::Create
            || operation.payload != create_operation_payload(request, workspace_plan)?
        {
            return Err(SupervisorError::InvalidState);
        }
        let validation = self
            .revalidate_workspace_plan_for_boot(workspace_plan)
            .await;
        if validation.is_err()
            && self
                .state
                .environments
                .get(&request.name)
                .is_some_and(|environment| {
                    environment.id == environment_id
                        && &environment.workspace_plan == workspace_plan
                        && environment.runner.is_some()
                })
        {
            // A replayed create can already have crossed StartVm. Restrict
            // reconciliation to the exact environment recorded by this
            // operation so a colliding create cannot affect another runner.
            self.reconcile_runner(&request.name, true).await?;
        }
        validation?;
        let expected_access = create_request_access_binding(request, environment_id)?;
        let expected_access_binding = expected_access.as_ref().map(|(binding, _)| binding.clone());
        let expected_access_profile = expected_access.map(|(_, reference)| reference);
        let mut operation = operation.clone();
        while let Some(effect) = supervisor_effect(operation.kind, operation.checkpoint)? {
            match effect {
                LifecycleEffect::RecordEnvironment => {
                    let mut next_state = self.state.clone();
                    if let Some(environment) = next_state.environments.get(&request.name) {
                        if environment.id != environment_id
                            || u32::from(environment.vcpus) != request.vcpus
                            || environment.memory_mib != request.memory_mib
                            || environment.disk_bytes != request.disk_bytes
                            || environment.docker_disk_bytes != request.docker_disk_bytes
                            || environment.host_ports != host_ports_from_proto(&request.host_ports)?
                            || environment.mesh
                                != mesh_attachment_from_proto(request.mesh.as_ref())?
                            || environment.project_spec_json.as_deref()
                                != Some(request.project_spec_json.as_slice())
                            || environment.project_spec_sha256.as_deref()
                                != Some(request.project_spec_sha256.as_str())
                            || environment.access_profile != expected_access_profile
                            || environment.access_binding != expected_access_binding
                            || environment.platform_source_authority
                                != request
                                    .platform_source_authority
                                    .as_ref()
                                    .map(PlatformSourceAuthority::from_proto)
                                    .transpose()?
                            || &environment.workspace_plan != workspace_plan
                        {
                            return Err(SupervisorError::AlreadyExists(request.name.clone()));
                        }
                    } else {
                        let artifact_generation = self.preflight().await?;
                        let vcpus = u8::try_from(request.vcpus)
                            .map_err(|_| SupervisorError::InvalidRequest)?;
                        next_state.environments.insert(
                            request.name.clone(),
                            EnvironmentRecord {
                                id: environment_id,
                                name: request.name.clone(),
                                state: StoredEnvironmentState::Starting,
                                vcpus,
                                memory_mib: request.memory_mib,
                                disk_bytes: request.disk_bytes,
                                docker_disk_bytes: request.docker_disk_bytes,
                                generation: 0,
                                host_ports: host_ports_from_proto(&request.host_ports)?,
                                mesh: mesh_attachment_from_proto(request.mesh.as_ref())?,
                                workspace_plan: workspace_plan.clone(),
                                project_spec_json: Some(request.project_spec_json.clone()),
                                project_spec_sha256: Some(request.project_spec_sha256.clone()),
                                access_profile: expected_access_profile.clone(),
                                access_binding: expected_access_binding.clone(),
                                platform_source_authority: request
                                    .platform_source_authority
                                    .as_ref()
                                    .map(PlatformSourceAuthority::from_proto)
                                    .transpose()?,
                                runner: None,
                                active_artifact_generation: Some(artifact_generation),
                                staging_artifact_generation: None,
                                active_workspace_generation: None,
                                staging_workspace_generation: None,
                                rollback_workspace_generation: None,
                            },
                        );
                        next_state.current = Some(request.name.clone());
                    }
                    operation = self.checkpoint_state_operation(&operation, next_state)?;
                }
                LifecycleEffect::BindEnvironmentAccess => {
                    self.bind_environment_access(request, environment_id)
                        .await?;
                    operation = self.checkpoint_operation(&operation)?;
                }
                LifecycleEffect::ProvisionWorkspace => {
                    let environment = self.environment(&request.name)?.clone();
                    let engine_root = self.config.engine_root();
                    let expected_plan_sha256 = environment.workspace_plan.sha256()?;
                    let plan = environment.workspace_plan;
                    let disk_bytes = environment.disk_bytes;
                    let docker_disk_bytes = environment.docker_disk_bytes;
                    let snapshot = tokio::task::spawn_blocking(move || {
                        let snapshot =
                            ensure_workspace_plan(&engine_root, environment_id, &plan, disk_bytes)?;
                        if docker_disk_bytes != 0 {
                            ensure_docker_data_disk(
                                &engine_root,
                                environment_id,
                                docker_disk_bytes,
                            )?;
                        }
                        Ok::<_, WorkspaceError>(snapshot)
                    })
                    .await
                    .map_err(|_| SupervisorError::WorkspaceProvisionTask)??;
                    if snapshot.plan_sha256 != expected_plan_sha256 {
                        return Err(SupervisorError::InvalidState);
                    }
                    operation = self.checkpoint_operation(&operation)?;
                }
                LifecycleEffect::StageWorkspaceGeneration => {
                    let next_state = self.stage_workspace_generation(&request.name).await?;
                    operation = self.checkpoint_state_operation(&operation, next_state)?;
                }
                LifecycleEffect::RecordStarting => {
                    let mut next_state = self.state.clone();
                    let environment = next_state
                        .environments
                        .get_mut(&request.name)
                        .ok_or_else(|| SupervisorError::NotFound(request.name.clone()))?;
                    reserve_boot_generation(environment, 1)?;
                    operation = self.checkpoint_state_operation(&operation, next_state)?;
                }
                LifecycleEffect::EnsureRunner => {
                    let staging = self
                        .environment(&request.name)?
                        .staging_workspace_generation
                        .is_some();
                    validate_environment_workload_secret_delivery(
                        self.environment(&request.name)?,
                        staging,
                    )?;
                    let artifact_generation =
                        artifact_generation_for_boot(self.environment(&request.name)?, staging)?
                            .to_owned();
                    let _ = self
                        .runner_client_for_artifact(&request.name, &artifact_generation)
                        .await?;
                    operation = self.checkpoint_operation(&operation)?;
                }
                LifecycleEffect::StartVm => {
                    self.ensure_vm_started(&request.name, 1, operation.operation_id)
                        .await?;
                    operation = self.checkpoint_operation(&operation)?;
                }
                LifecycleEffect::RecordRunning => {
                    let mut next_state = self.state.clone();
                    let environment = next_state
                        .environments
                        .get_mut(&request.name)
                        .ok_or_else(|| SupervisorError::NotFound(request.name.clone()))?;
                    let _displaced = environment.promote_staging_workspace_generation()?;
                    environment.generation = 1;
                    environment.state = StoredEnvironmentState::Running;
                    operation = self.checkpoint_state_operation(&operation, next_state)?;
                }
                _ => return Err(SupervisorError::InvalidState),
            }
        }
        Ok((
            self.environment(&request.name)?
                .proto(self.selected(&request.name)),
            operation,
        ))
    }

    async fn run_pending_operations(&mut self, recovering: bool) -> Result<(), SupervisorError> {
        for operation in self.store.pending_operations()? {
            let Some(name) = operation
                .payload
                .get("name")
                .and_then(|value| value.as_str())
            else {
                self.interrupt_operation(&operation, "invalid_replay_payload")?;
                continue;
            };
            if operation.kind == OperationKind::Create {
                let (request, workspace_plan) = match create_request_from_operation(&operation) {
                    Ok(prepared) => prepared,
                    Err(_) => {
                        self.interrupt_operation(&operation, "invalid_replay_payload")?;
                        continue;
                    }
                };
                let (_, operation) = match self.create(&request, &workspace_plan, &operation).await
                {
                    Ok(result) => result,
                    Err(SupervisorError::CredentialAuthorityUnavailable) if recovering => {
                        // The owner-side CLI starts the authority. Preserve the
                        // latest durable checkpoint for its next worker run.
                        return Err(SupervisorError::CredentialAuthorityUnavailable);
                    }
                    Err(error) => {
                        let error_code = if recovering {
                            "create_interrupted"
                        } else {
                            create_failure_code(&error)
                        };
                        self.fail_replayed_operation(&operation, name, error_code)?;
                        // If failure happened before RecordEnvironment, the
                        // prepared repository bundles have no durable owner.
                        // If it happened later, the recorded plan retains
                        // them. Re-derive reachability in either case.
                        let _ = self.collect_unreferenced_content();
                        continue;
                    }
                };
                let result = self
                    .state
                    .environments
                    .get(name)
                    .map(environment_operation_result)
                    .ok_or(SupervisorError::InvalidState)?;
                self.complete_operation(&operation, &result)?;
                continue;
            }
            if operation.kind == OperationKind::Start {
                let (_, operation) = match self.start(name, &operation).await {
                    Ok(result) => result,
                    Err(SupervisorError::CredentialAuthorityUnavailable) if recovering => {
                        return Err(SupervisorError::CredentialAuthorityUnavailable);
                    }
                    Err(_) => {
                        let error_code = if recovering {
                            "start_interrupted"
                        } else {
                            "start_failed"
                        };
                        self.fail_replayed_operation(&operation, name, error_code)?;
                        continue;
                    }
                };
                let result = self
                    .state
                    .environments
                    .get(name)
                    .map(environment_operation_result)
                    .ok_or(SupervisorError::InvalidState)?;
                self.complete_operation(&operation, &result)?;
                continue;
            }
            if operation.kind == OperationKind::Stop {
                let (_, operation) = match self.stop(name, &operation).await {
                    Ok(result) => result,
                    Err(_) => {
                        self.fail_pending_operation(&operation, "stop_failed")?;
                        continue;
                    }
                };
                let result = self
                    .state
                    .environments
                    .get(name)
                    .map(environment_operation_result)
                    .ok_or(SupervisorError::InvalidState)?;
                self.complete_operation(&operation, &result)?;
                continue;
            }
            if operation.kind == OperationKind::Delete {
                let (operation, cleanup_pending) = self.delete(name, &operation).await?;
                let result = serde_json::json!({
                    "name": name,
                    "removed": true,
                    "cleanup_pending": cleanup_pending,
                });
                self.complete_operation(&operation, &result)?;
                continue;
            }
            if matches!(
                operation.kind,
                OperationKind::Restart | OperationKind::GrowDisk
            ) {
                let operation = match self.resize(name, &operation).await {
                    Ok(operation) => operation,
                    Err(SupervisorError::CredentialAuthorityUnavailable) if recovering => {
                        return Err(SupervisorError::CredentialAuthorityUnavailable);
                    }
                    Err(_) => {
                        let error_code = if recovering {
                            "resize_interrupted"
                        } else {
                            "resize_failed"
                        };
                        self.fail_replayed_operation(&operation, name, error_code)?;
                        continue;
                    }
                };
                let result = self
                    .state
                    .environments
                    .get(name)
                    .map(environment_operation_result)
                    .ok_or(SupervisorError::InvalidState)?;
                self.complete_operation(&operation, &result)?;
                continue;
            }
            if matches!(
                operation.kind,
                OperationKind::UpdateWorkspace | OperationKind::RollbackWorkspace
            ) {
                let operation = match self.workspace_transition(name, &operation).await {
                    Ok(operation) => operation,
                    Err(SupervisorError::CredentialAuthorityUnavailable) if recovering => {
                        return Err(SupervisorError::CredentialAuthorityUnavailable);
                    }
                    Err(_) => {
                        let error_code = match operation.kind {
                            OperationKind::UpdateWorkspace if recovering => {
                                "workspace_update_interrupted"
                            }
                            OperationKind::UpdateWorkspace => "workspace_update_failed",
                            OperationKind::RollbackWorkspace if recovering => {
                                "workspace_rollback_interrupted"
                            }
                            OperationKind::RollbackWorkspace => "workspace_rollback_failed",
                            _ => return Err(SupervisorError::InvalidState),
                        };
                        self.abort_replayed_workspace_transition(&operation, name, error_code)
                            .await?;
                        continue;
                    }
                };
                let result = self
                    .state
                    .environments
                    .get(name)
                    .map(environment_operation_result)
                    .ok_or(SupervisorError::InvalidState)?;
                self.complete_operation(&operation, &result)?;
                continue;
            }
            if operation.kind == OperationKind::UpdateEnvironmentSources {
                self.execute_source_operation(&operation).await?;
                continue;
            }
            if operation.kind == OperationKind::Reconcile {
                let operation = self.apply_reconcile_operation(&operation)?;
                let result = self
                    .state
                    .environments
                    .get(name)
                    .map(environment_operation_result)
                    .ok_or(SupervisorError::InvalidState)?;
                self.complete_operation(&operation, &result)?;
                continue;
            }
            return Err(SupervisorError::InvalidState);
        }
        self.ensure_no_unowned_workspace_staging()
    }

    async fn replay_pending_operations(&mut self) -> Result<(), SupervisorError> {
        self.run_pending_operations(true).await
    }

    async fn execute_pending_operations(&mut self) -> Result<(), SupervisorError> {
        self.run_pending_operations(false).await
    }

    fn recover_host_reboot_workspace_transitions(&mut self) -> Result<(), SupervisorError> {
        let operations = self.store.host_reboot_interrupted_workspace_transitions()?;
        let mut next_state = self.state.clone();
        let mut changed = false;
        for operation in operations {
            let Some(environment_id) = operation.environment_id else {
                return Err(SupervisorError::InvalidState);
            };
            let Some(name) = operation
                .payload
                .get("name")
                .and_then(serde_json::Value::as_str)
            else {
                return Err(SupervisorError::InvalidState);
            };
            let environment = next_state
                .environments
                .get_mut(name)
                .ok_or(SupervisorError::InvalidState)?;
            if environment.id != environment_id {
                return Err(SupervisorError::InvalidState);
            }
            cleanup_interrupted_skill_snapshot(&self.config.engine_root(), environment_id)?;
            if environment.staging_workspace_generation.is_none() {
                continue;
            }
            if environment.active_workspace_generation.is_none() {
                return Err(SupervisorError::InvalidState);
            }
            let parameters = workspace_transition_parameters(&operation, environment)?;
            let active = environment
                .active_workspace_generation
                .as_ref()
                .ok_or(SupervisorError::InvalidState)?;
            if workspace_storage_generation(active)? != parameters.prior_storage_generation {
                return Err(SupervisorError::InvalidState);
            }
            if operation.checkpoint == 0 {
                return Err(SupervisorError::InvalidState);
            }
            match &parameters.intent {
                WorkspaceTransitionIntent::Update {
                    project_spec_json,
                    project_spec_sha256,
                } => {
                    environment
                        .staging_workspace_generation
                        .as_ref()
                        .ok_or(SupervisorError::InvalidState)?
                        .validate_for_project_intent(project_spec_json, project_spec_sha256)?;
                    environment.staging_workspace_generation = None;
                    environment.staging_artifact_generation = None;
                }
                WorkspaceTransitionIntent::Rollback {
                    rollback_storage_generation,
                } => environment.restore_staged_rollback_workspace_generation(
                    &parameters.prior_storage_generation,
                    rollback_storage_generation,
                )?,
            }
            environment.state = StoredEnvironmentState::Stopped;
            changed = true;
        }
        if changed {
            self.store.replace_state(&next_state)?;
            self.state = next_state;
        }
        self.store.clear_host_reboot_workspace_transitions()?;
        Ok(())
    }

    fn ensure_no_unowned_workspace_staging(&self) -> Result<(), SupervisorError> {
        if self.state.environments.values().any(|environment| {
            environment.active_workspace_generation.is_some()
                && environment.staging_workspace_generation.is_some()
        }) {
            return Err(SupervisorError::InvalidState);
        }
        Ok(())
    }

    fn fail_replayed_operation(
        &mut self,
        replayed: &OperationRecord,
        name: &str,
        error_code: &str,
    ) -> Result<(), SupervisorError> {
        let current = self
            .store
            .operation_by_request(replayed.request_id)?
            .ok_or(SupervisorError::InvalidState)?;
        self.fail_operation_with_environment_error(&current, name, error_code)?;
        Ok(())
    }

    fn fail_pending_operation(
        &mut self,
        pending: &OperationRecord,
        error_code: &str,
    ) -> Result<(), SupervisorError> {
        let current = self
            .store
            .operation_by_request(pending.request_id)?
            .ok_or(SupervisorError::InvalidState)?;
        self.fail_operation(&current, error_code)?;
        Ok(())
    }

    async fn abort_replayed_workspace_transition(
        &mut self,
        replayed: &OperationRecord,
        name: &str,
        error_code: &str,
    ) -> Result<(), SupervisorError> {
        let current = self
            .store
            .operation_by_request(replayed.request_id)?
            .ok_or(SupervisorError::InvalidState)?;
        self.abort_workspace_transition(&current, name, error_code)
            .await?;
        Ok(())
    }

    fn complete_operation(
        &self,
        operation: &OperationRecord,
        result: &serde_json::Value,
    ) -> Result<OperationRecord, SupervisorError> {
        if operation.phase != OperationPhase::Completed
            && supervisor_effect(operation.kind, operation.checkpoint)?.is_some()
        {
            return Err(SupervisorError::InvalidState);
        }
        let applied = match operation.phase {
            OperationPhase::Intent => self.store.advance_operation(
                operation.operation_id,
                operation.checkpoint,
                OperationPhase::EffectApplied,
                None,
                None,
            )?,
            OperationPhase::EffectApplied => operation.clone(),
            OperationPhase::Completed => return Ok(operation.clone()),
            OperationPhase::Failed | OperationPhase::Interrupted => {
                return Err(SupervisorError::OperationTerminal);
            }
        };
        self.store
            .advance_operation(
                applied.operation_id,
                applied.checkpoint,
                OperationPhase::Completed,
                Some(result),
                None,
            )
            .map_err(Into::into)
    }

    fn checkpoint_operation(
        &self,
        operation: &OperationRecord,
    ) -> Result<OperationRecord, SupervisorError> {
        if supervisor_effect(operation.kind, operation.checkpoint)?.map(LifecycleEffect::durability)
            != Some(EffectDurability::ExternalIdempotent)
        {
            return Err(SupervisorError::InvalidState);
        }
        self.store
            .advance_operation(
                operation.operation_id,
                operation.checkpoint,
                OperationPhase::EffectApplied,
                None,
                None,
            )
            .map_err(Into::into)
    }

    fn checkpoint_state_operation(
        &mut self,
        operation: &OperationRecord,
        next_state: SupervisorState,
    ) -> Result<OperationRecord, SupervisorError> {
        if supervisor_effect(operation.kind, operation.checkpoint)?.map(LifecycleEffect::durability)
            != Some(EffectDurability::Transactional)
        {
            return Err(SupervisorError::InvalidState);
        }
        let updated = self.store.replace_state_and_advance_operation(
            &next_state,
            operation.operation_id,
            operation.checkpoint,
            OperationPhase::EffectApplied,
            None,
            None,
        )?;
        self.state = next_state;
        Ok(updated)
    }

    fn fail_operation(
        &self,
        operation: &OperationRecord,
        error_code: &str,
    ) -> Result<OperationRecord, SupervisorError> {
        self.store
            .advance_operation(
                operation.operation_id,
                operation.checkpoint,
                OperationPhase::Failed,
                None,
                Some(error_code),
            )
            .map_err(Into::into)
    }

    fn fail_operation_with_environment_error(
        &mut self,
        operation: &OperationRecord,
        name: &str,
        error_code: &str,
    ) -> Result<OperationRecord, SupervisorError> {
        if self
            .state
            .environments
            .get(name)
            .is_none_or(|environment| operation.environment_id != Some(environment.id))
        {
            return self.fail_operation(operation, error_code);
        }
        let mut next_state = self.state.clone();
        next_state
            .environments
            .get_mut(name)
            .ok_or_else(|| SupervisorError::NotFound(name.to_owned()))?
            .state = StoredEnvironmentState::Error;
        let updated = self.store.replace_state_and_advance_operation(
            &next_state,
            operation.operation_id,
            operation.checkpoint,
            OperationPhase::Failed,
            None,
            Some(error_code),
        )?;
        self.state = next_state;
        Ok(updated)
    }

    fn interrupt_operation(
        &self,
        operation: &OperationRecord,
        error_code: &str,
    ) -> Result<OperationRecord, SupervisorError> {
        self.store
            .advance_operation(
                operation.operation_id,
                operation.checkpoint,
                OperationPhase::Interrupted,
                None,
                Some(error_code),
            )
            .map_err(Into::into)
    }

    async fn reconcile(&mut self, name: &str) -> Result<(), SupervisorError> {
        self.reconcile_runner(name, false).await
    }

    async fn reconcile_runner(
        &mut self,
        name: &str,
        force_direct_share_quarantine: bool,
    ) -> Result<(), SupervisorError> {
        let environment = self.environment(name)?;
        let Some(record) = environment.runner.clone() else {
            if environment.state == StoredEnvironmentState::Running {
                self.mark_runner_dead(name)?;
            }
            return Ok(());
        };
        let environment_id = environment.id;
        let workspace_plan = environment.workspace_plan.clone();
        let direct_share_validation = if force_direct_share_quarantine {
            None
        } else {
            Some(
                self.revalidate_workspace_plan_for_boot(&workspace_plan)
                    .await,
            )
        };
        let expected_socket = self.config.runner_socket(environment_id);
        let exited = if let Some(live) = self.live_runners.get(&environment_id) {
            if live.identity() != &record.process {
                self.mark_orphaned(name)?;
                return Ok(());
            }
            live.is_exited()?
        } else {
            let live = match LiveProcess::recover(&record.process) {
                Ok(live) => live,
                Err(RecoveryError::ReadProcess(error))
                    if error.kind() == io::ErrorKind::NotFound =>
                {
                    self.mark_runner_dead(name)?;
                    return Ok(());
                }
                Err(RecoveryError::ProcessExited) => {
                    self.mark_runner_dead(name)?;
                    return Ok(());
                }
                Err(RecoveryError::IdentityMismatch) => {
                    self.mark_orphaned(name)?;
                    return Ok(());
                }
                Err(error) => return Err(error.into()),
            };
            let exited = live.is_exited()?;
            if !exited {
                self.live_runners.insert(environment_id, live);
            }
            exited
        };
        if exited {
            self.mark_runner_dead(name)?;
            return Ok(());
        }
        let socket_trusted = record.socket.revalidate(&expected_socket).is_ok();
        match direct_share_validation {
            Some(Ok(())) => {}
            None => {
                self.quarantine_recorded_runner(name, socket_trusted)
                    .await?;
                return Ok(());
            }
            Some(Err(SupervisorError::WorkspacePlan(WorkspacePlanError::DirectShareChanged))) => {
                // The exact recorded process can still own a live virtiofs
                // mount after the supervisor configuration changes. Terminate
                // it before any runner protocol use. A replaced socket is
                // untrusted input: leave that filesystem object untouched
                // while still killing the identity-bound process and clearing
                // its durable runner record.
                self.quarantine_recorded_runner(name, socket_trusted)
                    .await?;
                return Ok(());
            }
            Some(Err(error)) => {
                // If the current exclusion boundary cannot be resolved at all,
                // no direct share can remain safely exposed. Quarantine the
                // exact runner, then preserve the configuration/I/O failure as
                // the startup or mutation result.
                self.quarantine_recorded_runner(name, socket_trusted)
                    .await?;
                return Err(error);
            }
        }
        if !socket_trusted {
            self.mark_orphaned(name)?;
            return Ok(());
        }
        let mut client = match RunnerClient::connect(&expected_socket).await {
            Ok(client) => client,
            Err(error) if error.incompatible_protocol() => {
                // Process and socket identity were both revalidated above.
                // An incompatible runner must never survive for later reuse,
                // but transient transport failures are deliberately not a
                // license to kill it.
                self.terminate_recorded_runner(name).await?;
                self.mark_runner_dead(name)?;
                return Ok(());
            }
            Err(error) => return Err(error.into()),
        };
        let info = client
            .info()
            .await
            .map_err(|_| SupervisorError::RunnerUnavailable)?;
        if info.environment_id != environment_id.to_string() {
            self.mark_orphaned(name)?;
            return Ok(());
        }
        if !runner_artifact_identity_matches(&record.artifact_generation, &info.artifact_generation)
        {
            self.mark_orphaned(name)?;
            return Ok(());
        }
        let state = match StoredEnvironmentState::from_proto(info.state) {
            Ok(state) => state,
            Err(_) => {
                self.mark_orphaned(name)?;
                return Ok(());
            }
        };
        let runner_error_code = (!info.error_code.is_empty()).then_some(info.error_code.as_str());
        let runner_error_valid = runner_error_code.is_some_and(runner_event_error_code_valid);
        if (state == StoredEnvironmentState::Error) != runner_error_valid
            || (runner_error_code.is_some() && !runner_error_valid)
        {
            self.mark_orphaned(name)?;
            return Ok(());
        }
        let generation = self.environment(name)?.generation.max(info.generation);
        self.record_reconcile_observation(name, state, generation, false, runner_error_code)
    }

    fn apply_reconcile_operation(
        &mut self,
        operation: &OperationRecord,
    ) -> Result<OperationRecord, SupervisorError> {
        let parameters = reconcile_operation_parameters(operation)?;
        let environment_id = operation
            .environment_id
            .ok_or(SupervisorError::InvalidState)?;
        if self.environment(&parameters.name)?.id != environment_id {
            return Err(SupervisorError::InvalidState);
        }
        let mut operation = operation.clone();
        while let Some(effect) = supervisor_effect(operation.kind, operation.checkpoint)? {
            match effect {
                LifecycleEffect::RecordObservation => {
                    let mut next_state = self.state.clone();
                    let environment = next_state
                        .environments
                        .get_mut(&parameters.name)
                        .ok_or_else(|| SupervisorError::NotFound(parameters.name.clone()))?;
                    let precondition_matches = environment.state == parameters.precondition.state
                        && environment.generation == parameters.precondition.generation
                        && environment.runner == parameters.precondition.runner;
                    if precondition_matches {
                        environment.state = parameters.state;
                        environment.generation = parameters.generation;
                        if parameters.clear_runner {
                            environment.runner = None;
                        } else if let Some(runner) = environment.runner.as_mut() {
                            runner.error_code = parameters.runner_error_code.clone();
                        }
                    }
                    operation = self.checkpoint_state_operation(&operation, next_state)?;
                }
                _ => return Err(SupervisorError::InvalidState),
            }
        }
        Ok(operation)
    }

    fn record_reconcile_observation(
        &mut self,
        name: &str,
        state: StoredEnvironmentState,
        generation: u64,
        clear_runner: bool,
        runner_error_code: Option<&str>,
    ) -> Result<(), SupervisorError> {
        let environment = self.environment(name)?;
        if environment.state == state
            && environment.generation == generation
            && (!clear_runner || environment.runner.is_none())
            && (clear_runner
                || environment
                    .runner
                    .as_ref()
                    .and_then(|runner| runner.error_code.as_deref())
                    == runner_error_code)
        {
            return Ok(());
        }
        let payload = reconcile_operation_payload(
            environment,
            state,
            generation,
            clear_runner,
            runner_error_code,
        );
        let operation = self.store.begin_operation(
            Uuid::new_v4(),
            Some(environment.id),
            OperationKind::Reconcile,
            &payload,
        )?;
        let operation = self.apply_reconcile_operation(&operation)?;
        let result = self
            .state
            .environments
            .get(name)
            .map(environment_operation_result)
            .ok_or(SupervisorError::InvalidState)?;
        self.complete_operation(&operation, &result)?;
        Ok(())
    }

    fn mark_orphaned(&mut self, name: &str) -> Result<(), SupervisorError> {
        let generation = self.environment(name)?.generation;
        self.record_reconcile_observation(
            name,
            StoredEnvironmentState::Orphaned,
            generation,
            false,
            None,
        )
    }

    fn mark_runner_dead(&mut self, name: &str) -> Result<(), SupervisorError> {
        let environment_id = self.environment(name)?.id;
        self.live_runners.remove(&environment_id);
        if let Some(mut child) = self.children.remove(&environment_id) {
            let _ = child.try_wait();
        }
        let environment = self.environment(name)?;
        let state = if matches!(
            environment.state,
            StoredEnvironmentState::Running | StoredEnvironmentState::Starting
        ) {
            StoredEnvironmentState::Error
        } else {
            environment.state
        };
        let generation = environment.generation;
        self.record_reconcile_observation(name, state, generation, true, None)
    }

    async fn runner_client_for_artifact(
        &mut self,
        name: &str,
        artifact_generation: &str,
    ) -> Result<RunnerClient, SupervisorError> {
        if !valid_sha256(artifact_generation) {
            return Err(SupervisorError::InvalidState);
        }
        self.reconcile(name).await?;
        if self.environment(name)?.state == StoredEnvironmentState::Orphaned {
            return Err(SupervisorError::Orphaned);
        }
        if self.environment(name)?.runner.is_none() {
            self.admit_cached_artifact_generation(artifact_generation)
                .await?;
            return self.spawn_runner(name, artifact_generation).await;
        }
        let environment = self.environment(name)?;
        let environment_id = environment.id;
        let record = environment
            .runner
            .as_ref()
            .ok_or(SupervisorError::InvalidState)?;
        let socket = self.config.runner_socket(environment_id);
        let mut client = RunnerClient::connect(&socket).await?;
        let info = client
            .info()
            .await
            .map_err(|_| SupervisorError::RunnerUnavailable)?;
        if info.environment_id != environment_id.to_string()
            || !runner_artifact_identity_matches(
                &record.artifact_generation,
                &info.artifact_generation,
            )
        {
            return Err(SupervisorError::InvalidRunnerResponse);
        }
        let runner_state = StoredEnvironmentState::from_proto(info.state)?;
        match runner_artifact_disposition(
            &record.artifact_generation,
            artifact_generation,
            runner_state,
        ) {
            RunnerArtifactDisposition::Reuse => return Ok(client),
            RunnerArtifactDisposition::RejectLiveMismatch => {
                return Err(SupervisorError::ArtifactGenerationChanged);
            }
            RunnerArtifactDisposition::ReplaceStopped => {}
        }
        drop(client);
        self.admit_cached_artifact_generation(artifact_generation)
            .await?;
        self.retire_existing_runner(name).await?;
        self.spawn_runner(name, artifact_generation).await
    }

    async fn spawn_runner(
        &mut self,
        name: &str,
        artifact_generation: &str,
    ) -> Result<RunnerClient, SupervisorError> {
        let environment_id = self.environment(name)?.id;
        let socket = self.config.runner_socket(environment_id);
        let runners = PrivateRoot::open(&self.root.path().join("runners"))?;
        let socket_name = socket
            .file_name()
            .map(Path::new)
            .ok_or(SupervisorError::InvalidConfiguration)?;
        runners.remove_private_socket(socket_name)?;
        let expected_parent = unsafe { libc::getpid() };
        let mut command = Command::new(&self.config.executable);
        command
            .arg("__native-runner")
            .arg("--environment-id")
            .arg(environment_id.to_string())
            .arg("--socket")
            .arg(&socket)
            .arg("--engine-state-root")
            .arg(self.config.engine_root())
            .arg("--artifact-generation")
            .arg(artifact_generation)
            .arg("--mesh-data-dir")
            .arg(&self.config.mesh_data_dir)
            .arg("--platform-config-dir")
            .arg(&self.config.platform_config_dir)
            .env_clear();
        command
            .current_dir(&self.config.root)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        // SAFETY: these libc calls use only scalar arguments between fork and
        // exec. PDEATHSIG closes the spawn-to-manifest orphan window; the
        // runner clears it only after its exact identity is durable.
        unsafe {
            command.pre_exec(move || {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0
                    || libc::getppid() != expected_parent
                    || libc::setsid() < 0
                    || libc::syscall(
                        libc::SYS_close_range,
                        3_u32,
                        u32::MAX,
                        libc::CLOSE_RANGE_CLOEXEC,
                    ) != 0
                {
                    return Err(io::Error::last_os_error());
                }
                libc::umask(0o077);
                Ok(())
            });
        }
        let mut child = command.spawn().map_err(|_| SupervisorError::SpawnRunner)?;
        let pid = child.id();
        let live = match LiveProcess::capture_child(pid, &self.config.executable) {
            Ok(live) => live,
            Err(error) => {
                terminate_unadmitted_child(&mut child);
                return Err(error.into());
            }
        };
        let deadline = tokio::time::Instant::now() + RUNNER_START_TIMEOUT;
        let socket_identity = loop {
            if child
                .try_wait()
                .map_err(|_| SupervisorError::SpawnRunner)?
                .is_some()
            {
                return Err(SupervisorError::SpawnRunner);
            }
            if fs::symlink_metadata(&socket).is_ok() {
                match SocketIdentity::capture(&socket) {
                    Ok(identity) => break identity,
                    Err(error) => {
                        let _ = error;
                    }
                }
            }
            if tokio::time::Instant::now() >= deadline {
                let _ = live.signal(Signal::KILL);
                let _ = child.wait();
                return Err(SupervisorError::RunnerStartTimeout);
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        };
        let runner_record = RunnerRecord {
            process: live.identity().clone(),
            socket: socket_identity.clone(),
            artifact_generation: artifact_generation.to_owned(),
            error_code: None,
        };
        self.environment_mut(name)?.runner = Some(runner_record);
        if let Err(error) = self.save() {
            self.environment_mut(name)?.runner = None;
            let _ = live.signal(Signal::KILL);
            let _ = child.wait();
            let _ = remove_bound_socket(&socket, &socket_identity);
            return Err(error);
        }
        let mut client = match RunnerClient::connect(&socket).await {
            Ok(client) => client,
            Err(error) => {
                let _ = live.signal(Signal::KILL);
                let _ = child.wait();
                self.environment_mut(name)?.runner = None;
                self.save()?;
                let _ = remove_bound_socket(&socket, &socket_identity);
                return Err(error.into());
            }
        };
        let adopted = client.adopt(environment_id).await;
        if !adopted.is_ok_and(|info| {
            info.environment_id == environment_id.to_string()
                && info.state == v1::EnvironmentState::Stopped as i32
                && info.artifact_generation == artifact_generation
        }) {
            let _ = live.signal(Signal::KILL);
            let _ = child.wait();
            self.environment_mut(name)?.runner = None;
            self.save()?;
            let _ = remove_bound_socket(&socket, &socket_identity);
            return Err(SupervisorError::RunnerAdoption);
        }
        self.live_runners.insert(environment_id, live);
        self.children.insert(environment_id, child);
        Ok(client)
    }

    async fn ensure_vm_started(
        &mut self,
        name: &str,
        generation: u64,
        operation_id: Uuid,
    ) -> Result<(), SupervisorError> {
        self.revalidate_environment_workspace_plan_for_boot(name)
            .await?;
        let environment = self.environment(name)?.clone();
        let staging = environment.staging_workspace_generation.is_some();
        let expected_artifact_generation =
            artifact_generation_for_boot(&environment, staging)?.to_owned();
        validate_environment_workload_secret_delivery(&environment, staging)?;
        let mut client = self
            .runner_client_for_artifact(name, &expected_artifact_generation)
            .await?;
        let current = client
            .info()
            .await
            .map_err(|_| SupervisorError::RunnerUnavailable)?;
        if current.environment_id != environment.id.to_string() {
            return Err(SupervisorError::InvalidRunnerResponse);
        }
        let current_state = StoredEnvironmentState::from_proto(current.state)?;
        if current_state == StoredEnvironmentState::Running {
            return (current.generation == generation)
                .then_some(())
                .ok_or(SupervisorError::InvalidRunnerResponse);
        }
        if current.generation >= generation {
            return Err(SupervisorError::InvalidRunnerResponse);
        }
        let engine_root = self.config.engine_root();
        let user_skills_root = self.config.mesh_data_dir.join("skills");
        let forbidden_direct_roots = self.config.direct_share_forbidden_roots()?;
        let boot_environment = environment.clone();
        let workspace = tokio::task::spawn_blocking(move || {
            prepare_workspace_boot(
                &engine_root,
                &user_skills_root,
                &forbidden_direct_roots,
                &boot_environment,
            )
        })
        .await
        .map_err(|_| SupervisorError::WorkspaceGenerationProvisionTask)??;
        let projection_environment = sources::projection_environment_for_boot(&environment)?;
        let managed_credential_clients = self
            .managed_credential_clients_for_boot(&projection_environment)
            .await?;
        let broker_request =
            self.credential_broker_request_for_environment(&projection_environment, generation)?;
        let environment_projection_sha256 =
            if broker_request.projection.is_some() || broker_request.platform.is_some() {
                projection_environment
                    .project_spec_sha256
                    .clone()
                    .ok_or(SupervisorError::InvalidState)?
            } else {
                String::new()
            };
        let start_request = v1::StartVmRequest {
            environment_id: environment.id.to_string(),
            generation,
            vsock_cid: allocate_vsock_cid(environment.id),
            daemon_vsock_port: DAEMON_VSOCK_PORT,
            state_disk_bytes: environment.disk_bytes,
            docker_disk_bytes: environment.docker_disk_bytes,
            vcpus: u32::from(environment.vcpus),
            memory_mib: environment.memory_mib,
            root_generation: workspace.root_generation,
            root_disk_bytes: workspace.root_disk_bytes,
            setup_total_bytes: workspace.setup_total_bytes,
            setup_header_sha256: workspace.setup_header_sha256,
            setup_root_generation: workspace.setup_root_generation,
            host_ports: host_ports_to_proto(&environment.host_ports),
            mesh: mesh_attachment_to_proto(environment.mesh.as_ref()),
            direct_shares: direct_share_attachments_to_proto(&environment.workspace_plan)?,
            skill_snapshot_sha256: workspace.skill_snapshot_sha256,
            environment_projection_sha256,
            managed_credential_clients: managed_credential_clients.encode().to_owned(),
        };
        let runner_events = client
            .watch(environment.id)
            .await
            .map_err(|_| SupervisorError::RunnerUnavailable)?;
        let broker_events = if broker_request.enabled {
            Some(
                client
                    .watch(environment.id)
                    .await
                    .map_err(|_| SupervisorError::RunnerUnavailable)?,
            )
        } else {
            None
        };
        let progress = self.operation_progress.clone();
        let artifact_generation = expected_artifact_generation.clone();
        let mut relay = tokio::spawn(relay_runner_start_events(
            runner_events,
            RunnerStartRelayContext {
                operation_id,
                environment_id: environment.id,
                artifact_generation,
                prior_generation: current.generation,
                prior_state: current_state,
                target_generation: generation,
                progress,
            },
        ));
        // Broker startup must proceed while the runner waits for install and
        // startup. Its owner-only runner seam does not take either lifecycle
        // mutex; the immutable selection is admitted before either future.
        let (start, broker) = tokio::join!(client.start(start_request), async {
            if let Some(events) = broker_events {
                bootstrap::wait_for_broker_bootstrap(
                    events,
                    environment.id,
                    generation,
                    &expected_artifact_generation,
                )
                .await?;
            }
            ensure_credential_broker(broker_request).await
        },);
        let start = match broker {
            Ok(_) => start,
            Err(error) => {
                let _ = client.stop().await;
                Err(Status::unavailable(error.to_string()))
            }
        };
        if start.is_err() {
            let mut failed_generation = environment.clone();
            failed_generation.generation = generation;
            self.stop_environment_broker_if_present(&failed_generation)
                .await?;
        }
        let relay_result = match tokio::time::timeout(RUNNER_EVENT_DRAIN_TIMEOUT, &mut relay).await
        {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(SupervisorError::InvalidRunnerResponse),
            Err(_) => {
                relay.abort();
                let _ = relay.await;
                Err(SupervisorError::InvalidRunnerResponse)
            }
        };
        let runner_error_code = match relay_result {
            Ok(error_code) => error_code,
            Err(error) => {
                if start.is_ok() {
                    let _ = client.stop().await;
                }
                return Err(error);
            }
        };
        let info = match (start, runner_error_code) {
            (Ok(info), None) => info,
            (Err(status), Some(error_code)) => {
                self.record_runner_start_failure(name, &error_code)?;
                return Err(SupervisorError::VmStart(status.message().to_owned()));
            }
            (Ok(_), Some(_)) | (Err(_), None) => {
                let _ = client.stop().await;
                return Err(SupervisorError::InvalidRunnerResponse);
            }
        };
        if info.environment_id != environment.id.to_string()
            || info.generation != generation
            || info.state != v1::EnvironmentState::Running as i32
            || !info.error_code.is_empty()
        {
            let _ = client.stop().await;
            return Err(SupervisorError::InvalidRunnerResponse);
        }
        Ok(())
    }

    fn record_runner_start_failure(
        &mut self,
        name: &str,
        error_code: &str,
    ) -> Result<(), SupervisorError> {
        if !runner_event_error_code_valid(error_code) {
            return Err(SupervisorError::InvalidRunnerResponse);
        }
        let environment = self.environment_mut(name)?;
        let runner = environment
            .runner
            .as_mut()
            .ok_or(SupervisorError::InvalidState)?;
        runner.error_code = Some(error_code.to_owned());
        environment.state = StoredEnvironmentState::Error;
        self.save()
    }

    async fn ensure_vm_stopped(&mut self, name: &str) -> Result<(), SupervisorError> {
        self.reconcile(name).await?;
        if self.environment(name)?.state == StoredEnvironmentState::Orphaned {
            return Err(SupervisorError::Orphaned);
        }
        let environment = self.environment(name)?.clone();
        self.stop_environment_broker_if_present(&environment)
            .await?;
        if environment.runner.is_none() {
            return Ok(());
        }
        let socket = self.config.runner_socket(environment.id);
        let mut client = RunnerClient::connect(&socket).await?;
        let info = client.stop().await.map_err(|_| SupervisorError::VmStop)?;
        if info.environment_id != environment.id.to_string()
            || info.state != v1::EnvironmentState::Stopped as i32
        {
            return Err(SupervisorError::InvalidRunnerResponse);
        }
        Ok(())
    }

    async fn start(
        &mut self,
        name: &str,
        operation: &OperationRecord,
    ) -> Result<(v1::Environment, OperationRecord), SupervisorError> {
        let environment_id = operation
            .environment_id
            .ok_or(SupervisorError::InvalidState)?;
        if operation.kind != OperationKind::Start
            || operation
                .payload
                .get("name")
                .and_then(serde_json::Value::as_str)
                != Some(name)
            || self.environment(name)?.id != environment_id
        {
            return Err(SupervisorError::InvalidState);
        }
        let target_generation = start_operation_generation(operation)?;
        self.revalidate_environment_workspace_plan_for_boot(name)
            .await?;
        let mut operation = operation.clone();
        while let Some(effect) = supervisor_effect(operation.kind, operation.checkpoint)? {
            match effect {
                LifecycleEffect::RequireEnvironmentAccess => {
                    self.require_environment_access(name).await?;
                    operation = self.checkpoint_operation(&operation)?;
                }
                LifecycleEffect::RecordStarting => {
                    let mut next_state = self.state.clone();
                    let environment = next_state
                        .environments
                        .get_mut(name)
                        .ok_or_else(|| SupervisorError::NotFound(name.to_owned()))?;
                    reserve_boot_generation(environment, target_generation)?;
                    operation = self.checkpoint_state_operation(&operation, next_state)?;
                }
                LifecycleEffect::StageWorkspaceGeneration => {
                    let next_state = self.stage_workspace_generation(name).await?;
                    operation = self.checkpoint_state_operation(&operation, next_state)?;
                }
                LifecycleEffect::EnsureRunner => {
                    let staging = self
                        .environment(name)?
                        .staging_workspace_generation
                        .is_some();
                    validate_environment_workload_secret_delivery(
                        self.environment(name)?,
                        staging,
                    )?;
                    let artifact_generation =
                        artifact_generation_for_boot(self.environment(name)?, staging)?.to_owned();
                    let _ = self
                        .runner_client_for_artifact(name, &artifact_generation)
                        .await?;
                    operation = self.checkpoint_operation(&operation)?;
                }
                LifecycleEffect::StartVm => {
                    self.ensure_vm_started(name, target_generation, operation.operation_id)
                        .await?;
                    operation = self.checkpoint_operation(&operation)?;
                }
                LifecycleEffect::RecordRunning => {
                    let mut next_state = self.state.clone();
                    let environment = next_state
                        .environments
                        .get_mut(name)
                        .ok_or_else(|| SupervisorError::NotFound(name.to_owned()))?;
                    let _displaced = environment.promote_staging_workspace_generation()?;
                    environment.generation = target_generation;
                    environment.state = StoredEnvironmentState::Running;
                    operation = self.checkpoint_state_operation(&operation, next_state)?;
                }
                _ => return Err(SupervisorError::InvalidState),
            }
        }
        Ok((
            self.environment(name)?.proto(self.selected(name)),
            operation,
        ))
    }

    async fn stop(
        &mut self,
        name: &str,
        operation: &OperationRecord,
    ) -> Result<(v1::Environment, OperationRecord), SupervisorError> {
        let environment_id = operation
            .environment_id
            .ok_or(SupervisorError::InvalidState)?;
        if operation.kind != OperationKind::Stop
            || operation.payload != serde_json::json!({"name": name})
            || self.environment(name)?.id != environment_id
        {
            return Err(SupervisorError::InvalidState);
        }
        let mut operation = operation.clone();
        while let Some(effect) = supervisor_effect(operation.kind, operation.checkpoint)? {
            match effect {
                LifecycleEffect::StopVm => {
                    self.ensure_vm_stopped(name).await?;
                    operation = self.checkpoint_operation(&operation)?;
                }
                LifecycleEffect::RecordStopped => {
                    let mut next_state = self.state.clone();
                    next_state
                        .environments
                        .get_mut(name)
                        .ok_or_else(|| SupervisorError::NotFound(name.to_owned()))?
                        .state = StoredEnvironmentState::Stopped;
                    operation = self.checkpoint_state_operation(&operation, next_state)?;
                }
                _ => return Err(SupervisorError::InvalidState),
            }
        }
        Ok((
            self.environment(name)?.proto(self.selected(name)),
            operation,
        ))
    }

    async fn retire_existing_runner(&mut self, name: &str) -> Result<(), SupervisorError> {
        self.reconcile(name).await?;
        if self.environment(name)?.state == StoredEnvironmentState::Orphaned {
            return Err(SupervisorError::Orphaned);
        }
        let environment = self.environment(name)?;
        let environment_id = environment.id;
        if environment.runner.is_none() {
            return Ok(());
        }
        let socket = self.config.runner_socket(environment_id);
        let mut client = RunnerClient::connect(&socket).await?;
        client
            .prepare_retire()
            .await
            .map_err(|_| SupervisorError::RunnerRetirement)?;
        let generation = self.environment(name)?.generation;
        let live = self
            .live_runners
            .get(&environment_id)
            .ok_or(SupervisorError::InvalidState)?;
        let _ = request_runner_shutdown_and_observe(&mut client, environment_id, generation, live)
            .await?;
        drop(client);
        self.terminate_recorded_runner(name).await?;
        let environment = self.environment_mut(name)?;
        environment.runner = None;
        environment.state = StoredEnvironmentState::Stopped;
        self.save()
    }

    /// Terminate the exact process and remove the exact socket recorded for a
    /// runner without trusting the runner protocol. Every caller must first
    /// reconcile process and socket identity; identity mismatches remain
    /// orphaned and never reach this helper. Runner-owned VMM and auxiliary
    /// processes carry a parent-death signal, so killing this exact runner
    /// also closes its pre-upgrade guest boundary; a replacement runner still
    /// performs tracked-process cleanup before accepting lifecycle work.
    async fn terminate_recorded_runner(&mut self, name: &str) -> Result<(), SupervisorError> {
        let environment = self.environment(name)?;
        let environment_id = environment.id;
        let socket_identity = environment
            .runner
            .as_ref()
            .ok_or(SupervisorError::InvalidState)?
            .socket
            .clone();
        let socket = self.config.runner_socket(environment_id);
        self.terminate_recorded_runner_process(name).await?;
        match fs::symlink_metadata(&socket) {
            Ok(_) => remove_bound_socket(&socket, &socket_identity)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(SupervisorError::Io {
                    path: socket,
                    source,
                });
            }
        }
        Ok(())
    }

    async fn quarantine_recorded_runner(
        &mut self,
        name: &str,
        socket_trusted: bool,
    ) -> Result<(), SupervisorError> {
        let environment = self.environment(name)?;
        let environment_id = environment.id;
        let socket_identity = environment
            .runner
            .as_ref()
            .ok_or(SupervisorError::InvalidState)?
            .socket
            .clone();
        let socket = self.config.runner_socket(environment_id);
        self.terminate_recorded_runner_process(name).await?;
        let socket_cleanup = if socket_trusted {
            match fs::symlink_metadata(&socket) {
                Ok(_) => remove_bound_socket(&socket, &socket_identity).map_err(Into::into),
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
                Err(source) => Err(SupervisorError::Io {
                    path: socket,
                    source,
                }),
            }
        } else {
            Ok(())
        };
        // Once the exact runner has exited, clear its durable identity even if
        // cleanup of a previously trusted socket reports an I/O failure.
        self.mark_runner_dead(name)?;
        socket_cleanup
    }

    async fn terminate_recorded_runner_process(
        &mut self,
        name: &str,
    ) -> Result<(), SupervisorError> {
        let environment = self.environment(name)?;
        let environment_id = environment.id;
        let runner = environment
            .runner
            .clone()
            .ok_or(SupervisorError::InvalidState)?;
        let live = self
            .live_runners
            .get(&environment_id)
            .ok_or(SupervisorError::InvalidState)?;
        if live.identity() != &runner.process {
            return Err(SupervisorError::InvalidState);
        }
        if !live.is_exited()? {
            live.signal(Signal::KILL)?;
        }
        let mut child = self.children.remove(&environment_id);
        let exited = if let Some(mut owned_child) = child.take() {
            matches!(
                tokio::time::timeout(
                    RUNNER_EXIT_TIMEOUT,
                    tokio::task::spawn_blocking(move || owned_child.wait())
                )
                .await,
                Ok(Ok(Ok(_)))
            )
        } else {
            live.wait_exited(RUNNER_EXIT_TIMEOUT).await?
        };
        if !exited {
            return Err(SupervisorError::RunnerExitTimeout);
        }
        self.live_runners.remove(&environment_id);
        Ok(())
    }

    async fn prepare_environment_for_delete(&mut self, name: &str) -> Result<(), SupervisorError> {
        let environment = self.environment(name)?;
        let environment_id = environment.id;
        let never_started = environment.generation == 0
            && matches!(
                environment.state,
                StoredEnvironmentState::Starting | StoredEnvironmentState::Error
            )
            && environment.runner.is_none();
        if environment.generation == 0
            && matches!(
                environment.state,
                StoredEnvironmentState::Starting | StoredEnvironmentState::Error
            )
        {
            cleanup_interrupted_workspace_provisioning(&self.config.engine_root(), environment_id)?;
        }
        self.reconcile(name).await?;
        if self.environment(name)?.runner.is_none() {
            // Create durably reserves generation 1 before EnsureRunner. A
            // generation-zero failure with no recorded runner cannot require
            // a bootable image just to remove its owned provisioning tree.
            // Capture eligibility before reconcile: clearing a dead runner
            // must not turn previously exposed state into a preboot deletion.
            if never_started {
                return Ok(());
            }
            let artifact_generation =
                artifact_generation_for_boot(self.environment(name)?, false)?.to_owned();
            let _ = self
                .runner_client_for_artifact(name, &artifact_generation)
                .await?;
        }
        self.retire_existing_runner(name).await
    }

    async fn resize(
        &mut self,
        name: &str,
        operation: &OperationRecord,
    ) -> Result<OperationRecord, SupervisorError> {
        let environment_id = operation
            .environment_id
            .ok_or(SupervisorError::InvalidState)?;
        if !matches!(
            operation.kind,
            OperationKind::Restart | OperationKind::GrowDisk
        ) || self.environment(name)?.id != environment_id
        {
            return Err(SupervisorError::InvalidState);
        }
        let (vcpus, memory_mib, disk_bytes, was_running, target_generation) =
            resize_operation_parameters(operation)?;
        if operation.kind == OperationKind::GrowDisk && was_running {
            return Err(SupervisorError::InvalidState);
        }
        if was_running {
            self.revalidate_environment_workspace_plan_for_boot(name)
                .await?;
        }
        let mut operation = operation.clone();
        while let Some(effect) = supervisor_effect(operation.kind, operation.checkpoint)? {
            match effect {
                LifecycleEffect::RequireEnvironmentAccess => {
                    if was_running {
                        self.require_environment_access(name).await?;
                    }
                    operation = self.checkpoint_operation(&operation)?;
                }
                LifecycleEffect::StopVm => {
                    self.ensure_vm_stopped(name).await?;
                    operation = self.checkpoint_operation(&operation)?;
                }
                LifecycleEffect::RecordStopped => {
                    let mut next_state = self.state.clone();
                    next_state
                        .environments
                        .get_mut(name)
                        .ok_or_else(|| SupervisorError::NotFound(name.to_owned()))?
                        .state = StoredEnvironmentState::Stopped;
                    operation = self.checkpoint_state_operation(&operation, next_state)?;
                }
                LifecycleEffect::GrowDisk => {
                    let current_disk_bytes = self.environment(name)?.disk_bytes;
                    if disk_bytes < current_disk_bytes {
                        return Err(SupervisorError::InvalidRequest);
                    }
                    if disk_bytes > current_disk_bytes {
                        validate_environment_workload_secret_delivery(
                            self.environment(name)?,
                            false,
                        )?;
                        let artifact_generation =
                            artifact_generation_for_boot(self.environment(name)?, false)?
                                .to_owned();
                        let mut runner = self
                            .runner_client_for_artifact(name, &artifact_generation)
                            .await?;
                        let applied = runner
                            .grow_state_disk(environment_id, disk_bytes)
                            .await
                            .map_err(|_| SupervisorError::VmResize)?;
                        if applied != disk_bytes {
                            return Err(SupervisorError::InvalidRunnerResponse);
                        }
                    }
                    operation = self.checkpoint_operation(&operation)?;
                }
                LifecycleEffect::RecordResources => {
                    let mut next_state = self.state.clone();
                    let environment = next_state
                        .environments
                        .get_mut(name)
                        .ok_or_else(|| SupervisorError::NotFound(name.to_owned()))?;
                    environment.vcpus = vcpus;
                    environment.memory_mib = memory_mib;
                    environment.disk_bytes = disk_bytes;
                    operation = self.checkpoint_state_operation(&operation, next_state)?;
                }
                LifecycleEffect::RecordStarting => {
                    let mut next_state = self.state.clone();
                    let environment = next_state
                        .environments
                        .get_mut(name)
                        .ok_or_else(|| SupervisorError::NotFound(name.to_owned()))?;
                    if was_running {
                        reserve_boot_generation(environment, target_generation)?;
                    } else if environment.generation != target_generation {
                        return Err(SupervisorError::InvalidState);
                    }
                    operation = self.checkpoint_state_operation(&operation, next_state)?;
                }
                LifecycleEffect::RestartVm => {
                    if was_running {
                        self.ensure_vm_started(name, target_generation, operation.operation_id)
                            .await?;
                    }
                    operation = self.checkpoint_operation(&operation)?;
                }
                LifecycleEffect::RecordResizeOutcome => {
                    let mut next_state = self.state.clone();
                    let environment = next_state
                        .environments
                        .get_mut(name)
                        .ok_or_else(|| SupervisorError::NotFound(name.to_owned()))?;
                    if was_running {
                        let _displaced = environment.promote_staging_workspace_generation()?;
                        if environment.generation != target_generation {
                            return Err(SupervisorError::InvalidState);
                        }
                        environment.state = StoredEnvironmentState::Running;
                    } else {
                        if environment.generation != target_generation {
                            return Err(SupervisorError::InvalidState);
                        }
                        environment.state = StoredEnvironmentState::Stopped;
                    }
                    operation = self.checkpoint_state_operation(&operation, next_state)?;
                }
                _ => return Err(SupervisorError::InvalidState),
            }
        }
        Ok(operation)
    }

    async fn workspace_transition(
        &mut self,
        name: &str,
        operation: &OperationRecord,
    ) -> Result<OperationRecord, SupervisorError> {
        let environment_id = operation
            .environment_id
            .ok_or(SupervisorError::InvalidState)?;
        if !matches!(
            operation.kind,
            OperationKind::UpdateWorkspace | OperationKind::RollbackWorkspace
        ) || self.environment(name)?.id != environment_id
        {
            return Err(SupervisorError::InvalidState);
        }
        let parameters = workspace_transition_parameters(operation, self.environment(name)?)?;
        reject_workspace_transition_workload_secrets(self.environment(name)?, &parameters)?;
        self.revalidate_environment_workspace_plan_for_boot(name)
            .await?;
        let mut operation = operation.clone();
        while let Some(effect) = supervisor_effect(operation.kind, operation.checkpoint)? {
            match effect {
                LifecycleEffect::RequireEnvironmentAccess => {
                    if parameters.was_running {
                        self.require_environment_access(name).await?;
                    }
                    operation = self.checkpoint_operation(&operation)?;
                }
                LifecycleEffect::StageWorkspaceGeneration
                    if operation.kind == OperationKind::UpdateWorkspace =>
                {
                    validate_workspace_transition_start(self.environment(name)?, &parameters)?;
                    let next_state = self.stage_workspace_update(name, &parameters).await?;
                    operation = self.checkpoint_state_operation(&operation, next_state)?;
                }
                LifecycleEffect::StageRollbackGeneration
                    if operation.kind == OperationKind::RollbackWorkspace =>
                {
                    validate_workspace_transition_start(self.environment(name)?, &parameters)?;
                    let next_state = self.stage_workspace_rollback(name, &parameters)?;
                    operation = self.checkpoint_state_operation(&operation, next_state)?;
                }
                LifecycleEffect::StopVm => {
                    if workspace_transition_requires_boot(self.environment(name)?, &parameters)? {
                        self.ensure_vm_stopped(name).await?;
                    }
                    operation = self.checkpoint_operation(&operation)?;
                }
                LifecycleEffect::RecordStopped => {
                    let mut next_state = self.state.clone();
                    let environment = next_state
                        .environments
                        .get_mut(name)
                        .ok_or_else(|| SupervisorError::NotFound(name.to_owned()))?;
                    if workspace_transition_requires_boot(environment, &parameters)? {
                        environment.state = StoredEnvironmentState::Stopped;
                    }
                    operation = self.checkpoint_state_operation(&operation, next_state)?;
                }
                LifecycleEffect::RecordStarting => {
                    let mut next_state = self.state.clone();
                    let environment = next_state
                        .environments
                        .get_mut(name)
                        .ok_or_else(|| SupervisorError::NotFound(name.to_owned()))?;
                    if workspace_transition_requires_boot(environment, &parameters)? {
                        reserve_boot_generation(environment, parameters.target_generation)?;
                    }
                    operation = self.checkpoint_state_operation(&operation, next_state)?;
                }
                LifecycleEffect::EnsureRunner => {
                    if workspace_transition_requires_boot(self.environment(name)?, &parameters)? {
                        let staging = self
                            .environment(name)?
                            .staging_workspace_generation
                            .is_some();
                        validate_environment_workload_secret_delivery(
                            self.environment(name)?,
                            staging,
                        )?;
                        let artifact_generation =
                            artifact_generation_for_boot(self.environment(name)?, staging)?
                                .to_owned();
                        let _ = self
                            .runner_client_for_artifact(name, &artifact_generation)
                            .await?;
                    }
                    operation = self.checkpoint_operation(&operation)?;
                }
                LifecycleEffect::StartVm => {
                    if workspace_transition_requires_boot(self.environment(name)?, &parameters)? {
                        self.ensure_vm_started(
                            name,
                            parameters.target_generation,
                            operation.operation_id,
                        )
                        .await?;
                    }
                    operation = self.checkpoint_operation(&operation)?;
                }
                LifecycleEffect::RestoreDesiredPower => {
                    if !parameters.was_running
                        && workspace_transition_requires_boot(self.environment(name)?, &parameters)?
                    {
                        self.ensure_vm_stopped(name).await?;
                    }
                    operation = self.checkpoint_operation(&operation)?;
                }
                LifecycleEffect::RecordWorkspaceTransition => {
                    let mut next_state = self.state.clone();
                    let environment = next_state
                        .environments
                        .get_mut(name)
                        .ok_or_else(|| SupervisorError::NotFound(name.to_owned()))?;
                    if workspace_transition_requires_boot(environment, &parameters)? {
                        let _displaced = environment.promote_staging_workspace_generation()?;
                        environment.generation = parameters.target_generation;
                        environment.state = if parameters.was_running {
                            StoredEnvironmentState::Running
                        } else {
                            StoredEnvironmentState::Stopped
                        };
                    } else if operation.kind == OperationKind::UpdateWorkspace {
                        environment.finish_staging_workspace_update_without_boot()?;
                    } else {
                        return Err(SupervisorError::InvalidState);
                    }
                    operation = self.checkpoint_state_operation(&operation, next_state)?;
                }
                _ => return Err(SupervisorError::InvalidState),
            }
        }
        Ok(operation)
    }

    async fn abort_workspace_transition(
        &mut self,
        operation: &OperationRecord,
        name: &str,
        error_code: &str,
    ) -> Result<OperationRecord, SupervisorError> {
        if operation.phase != OperationPhase::Intent
            && operation.phase != OperationPhase::EffectApplied
        {
            return Err(SupervisorError::OperationTerminal);
        }
        let environment = self.environment(name)?;
        if operation.environment_id != Some(environment.id) {
            return Err(SupervisorError::InvalidState);
        }
        let parameters = workspace_transition_parameters(operation, environment)?;
        cleanup_interrupted_skill_snapshot(&self.config.engine_root(), environment.id)?;
        if operation.checkpoint == 0 {
            return self.fail_operation(operation, error_code);
        }

        let requires_boot = workspace_transition_requires_boot(environment, &parameters)?;
        if requires_boot {
            self.ensure_vm_stopped(name).await?;
        }
        let mut next_state = self.state.clone();
        let environment = next_state
            .environments
            .get_mut(name)
            .ok_or_else(|| SupervisorError::NotFound(name.to_owned()))?;
        match &parameters.intent {
            WorkspaceTransitionIntent::Update {
                project_spec_json,
                project_spec_sha256,
            } => {
                environment
                    .staging_workspace_generation
                    .as_ref()
                    .ok_or(SupervisorError::InvalidState)?
                    .validate_for_project_intent(project_spec_json, project_spec_sha256)?;
                environment.staging_workspace_generation = None;
                environment.staging_artifact_generation = None;
            }
            WorkspaceTransitionIntent::Rollback {
                rollback_storage_generation,
            } => environment.restore_staged_rollback_workspace_generation(
                &parameters.prior_storage_generation,
                rollback_storage_generation,
            )?,
        }
        if requires_boot {
            environment.state = StoredEnvironmentState::Stopped;
        }
        let updated = self.store.replace_state_and_advance_operation(
            &next_state,
            operation.operation_id,
            operation.checkpoint,
            OperationPhase::Failed,
            None,
            Some(error_code),
        )?;
        self.state = next_state;
        Ok(updated)
    }

    async fn delete(
        &mut self,
        name: &str,
        operation: &OperationRecord,
    ) -> Result<(OperationRecord, bool), SupervisorError> {
        let environment_id = operation
            .environment_id
            .ok_or(SupervisorError::InvalidState)?;
        let revoke_access = delete_operation_revoke_access(operation, name)?;
        if operation.kind != OperationKind::Delete {
            return Err(SupervisorError::InvalidState);
        }
        if let Some(environment) = self.state.environments.get(name)
            && environment.id != environment_id
        {
            return Err(SupervisorError::InvalidState);
        }

        let engine_root = self.config.engine_root();
        let mut operation = operation.clone();
        let mut cleanup_pending = false;
        while let Some(effect) = supervisor_effect(operation.kind, operation.checkpoint)? {
            match effect {
                LifecycleEffect::PrepareDelete => {
                    match deletion_tree_location(
                        &engine_root,
                        environment_id,
                        operation.operation_id,
                    )? {
                        DeletionTreeLocation::Active(_) => {
                            if !self.state.environments.contains_key(name) {
                                return Err(SupervisorError::InvalidState);
                            }
                            self.prepare_environment_for_delete(name).await?;
                        }
                        DeletionTreeLocation::Trash(_) | DeletionTreeLocation::Missing => {}
                    }
                    operation = self.checkpoint_operation(&operation)?;
                }
                LifecycleEffect::MoveToTrash => {
                    match deletion_tree_location(
                        &engine_root,
                        environment_id,
                        operation.operation_id,
                    )? {
                        DeletionTreeLocation::Active(_) => {
                            move_stopped_vm_to_trash(
                                &engine_root,
                                environment_id,
                                operation.operation_id,
                            )?;
                        }
                        DeletionTreeLocation::Trash(_) => {}
                        DeletionTreeLocation::Missing => {
                            if self.state.environments.contains_key(name) {
                                return Err(SupervisorError::State(
                                    StateError::MissingTrashSource(
                                        engine_root.join("vms").join(environment_id.to_string()),
                                    ),
                                ));
                            }
                        }
                    }
                    operation = self.checkpoint_operation(&operation)?;
                }
                LifecycleEffect::RevokeEnvironmentAccess => {
                    if revoke_access {
                        cleanup_pending |= self
                            .revoke_environment_access_best_effort(environment_id)
                            .await;
                    }
                    operation = self.checkpoint_operation(&operation)?;
                }
                LifecycleEffect::RemoveEnvironment => {
                    let mut next_state = self.state.clone();
                    next_state.environments.remove(name);
                    if next_state.current.as_deref() == Some(name) {
                        next_state.current = next_state.environments.keys().next().cloned();
                    }
                    operation = self.checkpoint_state_operation(&operation, next_state)?;
                }
                LifecycleEffect::CleanupTrash => {
                    let trash_pending =
                        cleanup_trashed_vm(&engine_root, environment_id, operation.operation_id)
                            .is_err();
                    let content_pending = self.collect_unreferenced_content().is_err();
                    let artifact_pending = self.collect_unreferenced_runtime_artifacts().is_err();
                    if trash_pending || content_pending || artifact_pending {
                        // Deletion is already durable. Any object that cannot
                        // pass the exact allowlist remains quarantined for
                        // orphan inventory; it is never recursively removed or
                        // silently adopted.
                        cleanup_pending = true;
                    }
                    operation = self.checkpoint_operation(&operation)?;
                }
                _ => return Err(SupervisorError::InvalidState),
            }
        }
        cleanup_pending |= matches!(
            deletion_tree_location(&engine_root, environment_id, operation.operation_id)?,
            DeletionTreeLocation::Trash(_)
        );
        // Re-derive shared-CAS cleanup state after the final checkpoint. This
        // preserves an honest cleanup_pending result if the supervisor died
        // after applying CleanupTrash but before completing the operation.
        cleanup_pending |= self.collect_unreferenced_content().is_err();
        cleanup_pending |= self.collect_unreferenced_runtime_artifacts().is_err();
        if revoke_access {
            cleanup_pending |= self
                .environment_access_cleanup_pending(environment_id)
                .await;
        }
        Ok((operation, cleanup_pending))
    }

    async fn daemon_access(&mut self, name: &str) -> Result<v1::DaemonAccess, SupervisorError> {
        self.reconcile(name).await?;
        if self.environment(name)?.state != StoredEnvironmentState::Running {
            return Err(SupervisorError::NotRunning);
        }
        let artifact_generation =
            artifact_generation_for_boot(self.environment(name)?, false)?.to_owned();
        let mut client = self
            .runner_client_for_artifact(name, &artifact_generation)
            .await?;
        client
            .daemon_access()
            .await
            .map_err(|_| SupervisorError::RunnerUnavailable)
    }

    fn credential_broker_ensure_request(
        &self,
        name: &str,
    ) -> Result<CredentialBrokerEnsureRequest, SupervisorError> {
        let environment = self.environment(name)?;
        if environment.state != StoredEnvironmentState::Running
            || environment.generation == 0
            || environment.runner.is_none()
        {
            return Err(SupervisorError::NotRunning);
        }
        self.credential_broker_request_for_environment(environment, environment.generation)
    }

    fn credential_broker_request_for_environment(
        &self,
        environment: &EnvironmentRecord,
        generation: u64,
    ) -> Result<CredentialBrokerEnsureRequest, SupervisorError> {
        if generation == 0 {
            return Err(SupervisorError::InvalidState);
        }
        let mut platform =
            sources::platform::broker_binding(environment, &self.config.platform_config_dir)?;
        if let Some(binding) = platform.as_mut() {
            sources::platform::resolve_config_directory(binding)?;
        }
        let projection = sources::local_launch_projection(environment)?;
        let local_profile = if platform
            .as_ref()
            .is_some_and(|binding| binding.selection.profile.is_some())
        {
            None
        } else {
            environment.access_binding.clone()
        };
        Ok(CredentialBrokerEnsureRequest {
            authority: self.config.credential_authority_config(),
            environment_id: access_environment_id(environment.id)?,
            environment_generation: generation,
            environment_name: environment.name.clone(),
            runner_socket: self.config.runner_socket(environment.id),
            enabled: environment.access_binding.is_some()
                || projection.is_some()
                || platform.is_some(),
            projection,
            platform,
            local_profile,
        })
    }
}

async fn ensure_credential_broker(
    request: CredentialBrokerEnsureRequest,
) -> Result<AuthorityBrokerRuntime, SupervisorError> {
    if !request.enabled {
        return Ok(AuthorityBrokerRuntime {
            environment_id: request.environment_id,
            environment_generation: request.environment_generation,
            running: false,
        });
    }
    let mut client = LocalCredentialControlClient::connect(&request.authority)
        .await
        .map_err(|_| SupervisorError::CredentialAuthorityUnavailable)?;
    client
        .ensure_environment_broker(
            &request.environment_id,
            request.environment_generation,
            &request.environment_name,
            &request.runner_socket,
            codewire_local_credentials::EnvironmentBrokerSelection {
                local_profile: request.local_profile,
                projection: request.projection,
                platform: request.platform,
            },
        )
        .await
        .map_err(credential_control_error)
}

fn credential_broker_runtime_proto(runtime: AuthorityBrokerRuntime) -> v1::CredentialBrokerRuntime {
    v1::CredentialBrokerRuntime {
        environment_id: runtime.environment_id.to_string(),
        environment_generation: runtime.environment_generation,
        running: runtime.running,
    }
}

#[derive(Clone)]
struct SupervisorRpc {
    info: v1::SupervisorInfo,
    core: Arc<Mutex<SupervisorCore>>,
    shutdown: watch::Sender<bool>,
    operation_reader: Arc<Mutex<SupervisorOperationReader>>,
    operation_events: broadcast::Sender<OperationRecord>,
    operation_progress: broadcast::Sender<OperationProgress>,
    worker_running: Arc<AtomicBool>,
}

impl SupervisorRpc {
    fn schedule_operation_worker(&self, recovering: bool) {
        if self
            .worker_running
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        let service = self.clone();
        tokio::spawn(async move {
            let mut core = service.core.lock().await;
            let result = if recovering {
                core.replay_pending_operations().await
            } else {
                core.execute_pending_operations().await
            };
            let deferred_for_authority = recovering
                && matches!(
                    &result,
                    Err(SupervisorError::CredentialAuthorityUnavailable)
                );
            service.worker_running.store(false, Ordering::Release);
            drop(core);
            if result.is_err() && !deferred_for_authority {
                let _ = service.shutdown.send(true);
            }
        });
    }

    async fn operation(&self, operation_id: Uuid) -> Result<OperationRecord, Status> {
        self.operation_reader
            .lock()
            .await
            .operation_by_id(operation_id)
            .map_err(SupervisorError::from)
            .map_err(Status::from)?
            .ok_or_else(|| Status::not_found("local lifecycle operation was not found"))
    }
}

#[tonic::async_trait]
impl LocalSupervisorService for SupervisorRpc {
    async fn get_supervisor_info(
        &self,
        _request: Request<v1::GetSupervisorInfoRequest>,
    ) -> Result<Response<v1::SupervisorInfo>, Status> {
        Ok(Response::new(self.info.clone()))
    }

    async fn create_environment(
        &self,
        request: Request<v1::CreateEnvironmentRequest>,
    ) -> Result<Response<v1::Operation>, Status> {
        let mut request = request.into_inner();
        request.host_ports =
            canonicalize_host_ports_proto(&request.host_ports).map_err(Status::from)?;
        request.mesh =
            canonicalize_mesh_attachment_proto(request.mesh.as_ref()).map_err(Status::from)?;
        let request_id = validate_create(&request).map_err(Status::from)?;
        let mut core = self.core.lock().await;
        core.replay_pending_operations()
            .await
            .map_err(Status::from)?;
        let operation = match core
            .store
            .operation_by_request(request_id)
            .map_err(SupervisorError::from)
            .map_err(Status::from)?
        {
            Some(operation) => {
                let (recorded, _) =
                    create_request_from_operation(&operation).map_err(Status::from)?;
                if recorded != request {
                    return Err(Status::aborted("local lifecycle request ID collision"));
                }
                operation
            }
            None => {
                // Allocate the eventual environment identity before repository
                // preparation. Successful preparation journals this SAME ID;
                // failure abandons it and keeps offline replay unchanged.
                let environment_id = Uuid::new_v4();
                let workspace_plan = match core
                    .prepare_create_workspace_plan(&request, environment_id)
                    .await
                {
                    Ok(workspace_plan) => workspace_plan,
                    Err(error) => {
                        // A multi-repository preparation can admit an earlier
                        // bundle before a later repository fails. The
                        // supervisor lock makes it safe to re-derive retained
                        // content here without racing another lifecycle.
                        let _ = core.collect_unreferenced_content();
                        return Err(Status::from(error));
                    }
                };
                let payload =
                    create_operation_payload(&request, &workspace_plan).map_err(Status::from)?;
                begin_create_operation(&core.store, request_id, environment_id, &payload)
                    .map_err(Status::from)?
            }
        };
        let payload_matches = create_request_from_operation(&operation)
            .is_ok_and(|(recorded, _)| recorded == request);
        if operation.kind != OperationKind::Create
            || !payload_matches
            || operation.environment_id.is_none()
        {
            return Err(Status::aborted("local lifecycle request ID collision"));
        }
        let response = operation_proto(&operation)?;
        drop(core);
        if !operation.phase.terminal() {
            self.schedule_operation_worker(false);
        }
        Ok(Response::new(response))
    }

    async fn list_environments(
        &self,
        _request: Request<v1::ListEnvironmentsRequest>,
    ) -> Result<Response<v1::ListEnvironmentsResponse>, Status> {
        let mut core = self.core.lock().await;
        core.replay_pending_operations()
            .await
            .map_err(Status::from)?;
        let names = core.state.environments.keys().cloned().collect::<Vec<_>>();
        for name in &names {
            core.reconcile(name).await.map_err(Status::from)?;
        }
        let environments = core
            .state
            .environments
            .iter()
            .map(|(name, environment)| environment.proto(core.selected(name)))
            .collect();
        Ok(Response::new(v1::ListEnvironmentsResponse { environments }))
    }

    async fn get_environment(
        &self,
        request: Request<v1::EnvironmentSelector>,
    ) -> Result<Response<v1::Environment>, Status> {
        let name = selected_name(request.into_inner())?;
        let mut core = self.core.lock().await;
        core.replay_pending_operations()
            .await
            .map_err(Status::from)?;
        core.reconcile(&name).await.map_err(Status::from)?;
        Ok(Response::new(
            core.environment(&name)
                .map_err(Status::from)?
                .proto(core.selected(&name)),
        ))
    }

    async fn select_environment(
        &self,
        request: Request<v1::EnvironmentSelector>,
    ) -> Result<Response<v1::Environment>, Status> {
        let (name, _request_id, expected_environment_id) =
            mutation_selection(request.into_inner())?;
        let mut core = self.core.lock().await;
        core.replay_pending_operations()
            .await
            .map_err(Status::from)?;
        core.reconcile(&name).await.map_err(Status::from)?;
        let environment = core.environment(&name).map_err(Status::from)?.clone();
        require_expected_environment(&environment, expected_environment_id)?;
        if core.state.current.as_deref() != Some(name.as_str()) {
            core.state.current = Some(name);
            core.save().map_err(Status::from)?;
        }
        Ok(Response::new(environment.proto(true)))
    }

    async fn list_orphans(
        &self,
        _request: Request<v1::ListOrphansRequest>,
    ) -> Result<Response<v1::ListOrphansResponse>, Status> {
        let core = self.core.lock().await;
        core.orphan_inventory()
            .map(Response::new)
            .map_err(Status::from)
    }

    async fn start_environment(
        &self,
        request: Request<v1::EnvironmentSelector>,
    ) -> Result<Response<v1::Operation>, Status> {
        let (name, request_id, expected_environment_id) = mutation_selection(request.into_inner())?;
        let mut core = self.core.lock().await;
        core.replay_pending_operations()
            .await
            .map_err(Status::from)?;
        core.reconcile(&name).await.map_err(Status::from)?;
        let environment = core.environment(&name).map_err(Status::from)?.clone();
        require_expected_environment(&environment, expected_environment_id)?;
        reject_environment_workload_secrets(&environment).map_err(Status::from)?;
        let existing = core
            .store
            .operation_by_request(request_id)
            .map_err(SupervisorError::from)
            .map_err(Status::from)?;
        let operation = if let Some(operation) = existing {
            if operation.kind != OperationKind::Start
                || operation.environment_id != Some(environment.id)
                || operation
                    .payload
                    .get("name")
                    .and_then(serde_json::Value::as_str)
                    != Some(name.as_str())
            {
                return Err(Status::aborted("local lifecycle request ID collision"));
            }
            operation
        } else {
            let generation = if environment.state == StoredEnvironmentState::Running {
                environment.generation
            } else {
                environment
                    .generation
                    .checked_add(1)
                    .ok_or_else(|| Status::internal("local generation overflow"))?
            };
            let payload = serde_json::json!({"name": name, "generation": generation});
            core.store
                .begin_operation(
                    request_id,
                    Some(environment.id),
                    OperationKind::Start,
                    &payload,
                )
                .map_err(SupervisorError::from)
                .map_err(Status::from)?
        };
        let response = operation_proto(&operation)?;
        drop(core);
        if !operation.phase.terminal() {
            self.schedule_operation_worker(false);
        }
        Ok(Response::new(response))
    }

    async fn stop_environment(
        &self,
        request: Request<v1::EnvironmentSelector>,
    ) -> Result<Response<v1::Operation>, Status> {
        let (name, request_id, expected_environment_id) = mutation_selection(request.into_inner())?;
        let mut core = self.core.lock().await;
        core.replay_pending_operations()
            .await
            .map_err(Status::from)?;
        let environment = core.environment(&name).map_err(Status::from)?;
        require_expected_environment(environment, expected_environment_id)?;
        let environment_id = environment.id;
        let payload = serde_json::json!({"name": name});
        let operation = core
            .store
            .begin_operation(
                request_id,
                Some(environment_id),
                OperationKind::Stop,
                &payload,
            )
            .map_err(SupervisorError::from)
            .map_err(Status::from)?;
        let response = operation_proto(&operation)?;
        drop(core);
        if !operation.phase.terminal() {
            self.schedule_operation_worker(false);
        }
        Ok(Response::new(response))
    }

    async fn restart_environment(
        &self,
        request: Request<v1::EnvironmentSelector>,
    ) -> Result<Response<v1::Operation>, Status> {
        let (name, request_id, expected_environment_id) = mutation_selection(request.into_inner())?;
        let mut core = self.core.lock().await;
        core.replay_pending_operations()
            .await
            .map_err(Status::from)?;
        core.reconcile(&name).await.map_err(Status::from)?;
        let environment = core.environment(&name).map_err(Status::from)?.clone();
        require_expected_environment(&environment, expected_environment_id)?;
        reject_environment_workload_secrets(&environment).map_err(Status::from)?;
        if !matches!(
            environment.state,
            StoredEnvironmentState::Running | StoredEnvironmentState::Error
        ) {
            return Err(Status::failed_precondition(
                "native local environment must be running or recoverable",
            ));
        }
        let existing = core
            .store
            .operation_by_request(request_id)
            .map_err(SupervisorError::from)
            .map_err(Status::from)?;
        let operation = if let Some(operation) = existing {
            let parameters = resize_operation_parameters(&operation);
            if operation.kind != OperationKind::Restart
                || operation.environment_id != Some(environment.id)
                || operation.payload.as_object().map(serde_json::Map::len) != Some(6)
                || !parameters.is_ok_and(|(vcpus, memory_mib, disk_bytes, was_running, _)| {
                    operation
                        .payload
                        .get("name")
                        .and_then(serde_json::Value::as_str)
                        == Some(name.as_str())
                        && vcpus == environment.vcpus
                        && memory_mib == environment.memory_mib
                        && disk_bytes == environment.disk_bytes
                        && was_running
                })
            {
                return Err(Status::aborted("local lifecycle request ID collision"));
            }
            operation
        } else {
            let target_generation = environment
                .generation
                .checked_add(1)
                .ok_or_else(|| Status::internal("local generation overflow"))?;
            let payload = serde_json::json!({
                "name": name,
                "vcpus": environment.vcpus,
                "memory_mib": environment.memory_mib,
                "disk_bytes": environment.disk_bytes,
                "was_running": true,
                "target_generation": target_generation,
            });
            core.store
                .begin_operation(
                    request_id,
                    Some(environment.id),
                    OperationKind::Restart,
                    &payload,
                )
                .map_err(SupervisorError::from)
                .map_err(Status::from)?
        };
        let response = operation_proto(&operation)?;
        drop(core);
        if !operation.phase.terminal() {
            self.schedule_operation_worker(false);
        }
        Ok(Response::new(response))
    }

    async fn refresh_environment_skills(
        &self,
        request: Request<v1::EnvironmentSelector>,
    ) -> Result<Response<v1::Operation>, Status> {
        let (name, request_id, expected_environment_id) = mutation_selection(request.into_inner())?;
        let mut core = self.core.lock().await;
        core.replay_pending_operations()
            .await
            .map_err(Status::from)?;
        core.reconcile(&name).await.map_err(Status::from)?;
        let environment = core.environment(&name).map_err(Status::from)?.clone();
        require_expected_environment(&environment, expected_environment_id)?;
        reject_environment_workload_secrets(&environment).map_err(Status::from)?;
        if !matches!(
            environment.state,
            StoredEnvironmentState::Running | StoredEnvironmentState::Stopped
        ) {
            return Err(Status::failed_precondition(
                "native local environment must be running or stopped",
            ));
        }
        let active = environment
            .active_workspace_generation
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("workspace generation is unavailable"))?;
        if active
            .skill_snapshot()
            .map_err(SupervisorError::from)
            .map_err(Status::from)?
            .is_none()
        {
            return Err(Status::failed_precondition(
                "native local environment has no selected skills",
            ));
        }
        let prior_storage_generation =
            workspace_storage_generation(active).map_err(Status::from)?;
        let target_generation = environment
            .generation
            .checked_add(1)
            .ok_or_else(|| Status::internal("local generation overflow"))?;
        let current_project_json = environment
            .project_spec_json
            .as_deref()
            .ok_or_else(|| Status::internal("current project intent is unavailable"))?;
        let current_project_sha256 = environment
            .project_spec_sha256
            .as_deref()
            .ok_or_else(|| Status::internal("current project intent is unavailable"))?;
        active
            .validate_for_project_intent(current_project_json, current_project_sha256)
            .map_err(SupervisorError::from)
            .map_err(Status::from)?;
        let payload = serde_json::json!({
            "name": name,
            "project_spec_json": std::str::from_utf8(current_project_json)
                .map_err(|_| Status::internal("workspace project is not UTF-8"))?,
            "project_spec_sha256": current_project_sha256,
            "prior_storage_generation": prior_storage_generation,
            "target_generation": target_generation,
            "was_running": environment.state == StoredEnvironmentState::Running,
            "refresh_skills": true,
        });
        let existing = core
            .store
            .operation_by_request(request_id)
            .map_err(SupervisorError::from)
            .map_err(Status::from)?;
        let operation = if let Some(operation) = existing {
            if operation.kind != OperationKind::UpdateWorkspace
                || operation.environment_id != Some(environment.id)
                || operation.payload != payload
            {
                return Err(Status::aborted("local lifecycle request ID collision"));
            }
            operation
        } else {
            core.store
                .begin_operation(
                    request_id,
                    Some(environment.id),
                    OperationKind::UpdateWorkspace,
                    &payload,
                )
                .map_err(SupervisorError::from)
                .map_err(Status::from)?
        };
        let response = operation_proto(&operation)?;
        drop(core);
        if !operation.phase.terminal() {
            self.schedule_operation_worker(false);
        }
        Ok(Response::new(response))
    }

    async fn resize_environment(
        &self,
        request: Request<v1::ResizeEnvironmentRequest>,
    ) -> Result<Response<v1::Operation>, Status> {
        let request = request.into_inner();
        let request_id = validate_resize(&request).map_err(Status::from)?;
        let expected_environment_id =
            parse_optional_environment_id(&request.environment_id).map_err(Status::from)?;
        let mut core = self.core.lock().await;
        core.replay_pending_operations()
            .await
            .map_err(Status::from)?;
        let environment = core
            .environment(&request.name)
            .map_err(Status::from)?
            .clone();
        require_expected_environment(&environment, expected_environment_id)?;
        reject_environment_workload_secrets(&environment).map_err(Status::from)?;

        let existing = core
            .store
            .operation_by_request(request_id)
            .map_err(SupervisorError::from)
            .map_err(Status::from)?;
        let operation = if let Some(operation) = existing {
            let matches_request = matches!(
                operation.kind,
                OperationKind::Restart | OperationKind::GrowDisk
            ) && operation.environment_id == Some(environment.id)
                && resize_operation_parameters(&operation).is_ok()
                && operation
                    .payload
                    .get("name")
                    .and_then(serde_json::Value::as_str)
                    == Some(request.name.as_str())
                && operation
                    .payload
                    .get("vcpus")
                    .and_then(serde_json::Value::as_u64)
                    == Some(u64::from(request.vcpus))
                && operation
                    .payload
                    .get("memory_mib")
                    .and_then(serde_json::Value::as_u64)
                    == Some(u64::from(request.memory_mib))
                && operation
                    .payload
                    .get("disk_bytes")
                    .and_then(serde_json::Value::as_u64)
                    == Some(request.disk_bytes)
                && operation
                    .payload
                    .get("public_request_id")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default()
                    == request.public_request_id
                && operation
                    .payload
                    .get("public_disruption_policy")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default()
                    == request.public_disruption_policy;
            if !matches_request {
                return Err(Status::aborted("local lifecycle request ID collision"));
            }
            operation
        } else {
            if request.disk_bytes < environment.disk_bytes {
                return Err(Status::invalid_argument(
                    "native local state disk shrink is not supported",
                ));
            }
            if request.vcpus == u32::from(environment.vcpus)
                && request.memory_mib == environment.memory_mib
                && request.disk_bytes == environment.disk_bytes
            {
                return Err(Status::invalid_argument(
                    "requested resources already match the environment",
                ));
            }
            let was_running = environment.state == StoredEnvironmentState::Running;
            let target_generation = if was_running {
                environment
                    .generation
                    .checked_add(1)
                    .ok_or_else(|| Status::internal("local generation overflow"))?
            } else {
                environment.generation
            };
            let payload = serde_json::json!({
                "name": request.name,
                "vcpus": request.vcpus,
                "memory_mib": request.memory_mib,
                "disk_bytes": request.disk_bytes,
                "was_running": was_running,
                "target_generation": target_generation,
                "previous_vcpus": environment.vcpus,
                "previous_memory_mib": environment.memory_mib,
                "previous_disk_bytes": environment.disk_bytes,
                "public_request_id": request.public_request_id,
                "public_disruption_policy": request.public_disruption_policy,
            });
            let kind = if !was_running
                && request.vcpus == u32::from(environment.vcpus)
                && request.memory_mib == environment.memory_mib
                && request.disk_bytes > environment.disk_bytes
            {
                OperationKind::GrowDisk
            } else {
                OperationKind::Restart
            };
            core.store
                .begin_operation(request_id, Some(environment.id), kind, &payload)
                .map_err(SupervisorError::from)
                .map_err(Status::from)?
        };
        let response = operation_proto(&operation)?;
        drop(core);
        if !operation.phase.terminal() {
            self.schedule_operation_worker(false);
        }
        Ok(Response::new(response))
    }

    async fn update_environment_sources(
        &self,
        request: Request<v1::UpdateEnvironmentSourcesRequest>,
    ) -> Result<Response<v1::Operation>, Status> {
        self.admit_source_update(request.into_inner()).await
    }

    async fn delete_environment(
        &self,
        request: Request<v1::EnvironmentSelector>,
    ) -> Result<Response<v1::Operation>, Status> {
        let (name, request_id, expected_environment_id) = mutation_selection(request.into_inner())?;
        let mut core = self.core.lock().await;
        // Preserve the selector's stable-identity precondition before replaying
        // any durable work. A replay may remove this environment (including
        // when this request ID names the pending delete itself), but it must
        // not turn a stale caller's NotFound into an effect or replay error.
        match core
            .store
            .operation_by_request(request_id)
            .map_err(SupervisorError::from)
            .map_err(Status::from)?
        {
            Some(operation) => {
                if operation.kind != OperationKind::Delete
                    || delete_operation_revoke_access(&operation, &name).is_err()
                {
                    return Err(Status::aborted("local lifecycle request ID collision"));
                }
                if expected_environment_id.is_some()
                    && operation.environment_id != expected_environment_id
                {
                    return Err(Status::not_found("local environment was not found"));
                }
            }
            None => {
                let environment = core.environment(&name).map_err(Status::from)?;
                require_expected_environment(environment, expected_environment_id)?;
            }
        }
        core.replay_pending_operations()
            .await
            .map_err(Status::from)?;
        let existing = core
            .store
            .operation_by_request(request_id)
            .map_err(SupervisorError::from)
            .map_err(Status::from)?;
        let operation = match existing {
            Some(operation) => {
                if operation.kind != OperationKind::Delete
                    || delete_operation_revoke_access(&operation, &name).is_err()
                {
                    return Err(Status::aborted("local lifecycle request ID collision"));
                }
                if expected_environment_id.is_some()
                    && operation.environment_id != expected_environment_id
                {
                    return Err(Status::not_found("local environment was not found"));
                }
                operation
            }
            None => {
                let environment = core.environment(&name).map_err(Status::from)?;
                require_expected_environment(environment, expected_environment_id)?;
                let environment_id = environment.id;
                let payload = serde_json::json!({
                    "name": name,
                    "revoke_access": environment_uses_access_profile(environment)
                        .map_err(Status::from)?,
                });
                core.store
                    .begin_operation(
                        request_id,
                        Some(environment_id),
                        OperationKind::Delete,
                        &payload,
                    )
                    .map_err(SupervisorError::from)
                    .map_err(Status::from)?
            }
        };
        let response = operation_proto(&operation)?;
        drop(core);
        if !operation.phase.terminal() {
            self.schedule_operation_worker(false);
        }
        Ok(Response::new(response))
    }

    async fn get_operation(
        &self,
        request: Request<v1::GetOperationRequest>,
    ) -> Result<Response<v1::Operation>, Status> {
        let operation_id = parse_operation_id(&request.into_inner().operation_id)?;
        let operation = self.operation(operation_id).await?;
        operation_proto(&operation).map(Response::new)
    }

    type WatchOperationStream =
        Pin<Box<dyn Stream<Item = Result<v1::Operation, Status>> + Send + 'static>>;

    async fn watch_operation(
        &self,
        request: Request<v1::WatchOperationRequest>,
    ) -> Result<Response<Self::WatchOperationStream>, Status> {
        let operation_id = parse_operation_id(&request.into_inner().operation_id)?;
        // Subscribe before reading the durable snapshot. Events racing the
        // read remain queued and are de-duplicated by checkpoint below.
        let mut events = self.operation_events.subscribe();
        let mut progress_events = self.operation_progress.subscribe();
        let initial = self.operation(operation_id).await?;
        let initial_terminal = initial.phase.terminal();
        let initial_checkpoint = initial.checkpoint;
        let initial = operation_proto(&initial)?;
        let reader = Arc::clone(&self.operation_reader);
        let (sender, receiver) = mpsc::channel(OPERATION_WATCH_BUFFER);
        tokio::spawn(async move {
            if sender.send(Ok(initial)).await.is_err() || initial_terminal {
                return;
            }
            let mut checkpoint = initial_checkpoint;
            let mut progress_sequence = 0_u64;
            let mut progress_open = true;
            loop {
                tokio::select! {
                    journal = events.recv() => {
                        let operation = match journal {
                            Ok(operation)
                                if operation.operation_id == operation_id
                                    && operation.checkpoint > checkpoint =>
                            {
                                operation
                            }
                            Ok(_) => continue,
                            Err(broadcast::error::RecvError::Lagged(_)) => {
                                let latest = reader.lock().await.operation_by_id(operation_id);
                                match latest {
                                    Ok(Some(operation)) if operation.checkpoint > checkpoint => operation,
                                    Ok(Some(_)) => continue,
                                    Ok(None) => {
                                        let _ = sender
                                            .send(Err(Status::not_found(
                                                "local lifecycle operation was not found",
                                            )))
                                            .await;
                                        return;
                                    }
                                    Err(_) => {
                                        let _ = sender
                                            .send(Err(Status::internal(
                                                "read local lifecycle operation failed",
                                            )))
                                            .await;
                                        return;
                                    }
                                }
                            }
                            Err(broadcast::error::RecvError::Closed) => {
                                let _ = sender
                                    .send(Err(Status::unavailable(
                                        "local lifecycle operation stream closed",
                                    )))
                                    .await;
                                return;
                            }
                        };
                        checkpoint = operation.checkpoint;
                        let terminal = operation.phase.terminal();
                        let update = match operation_proto(&operation) {
                            Ok(update) => update,
                            Err(error) => {
                                let _ = sender.send(Err(error)).await;
                                return;
                            }
                        };
                        if sender.send(Ok(update)).await.is_err() || terminal {
                            return;
                        }
                    }
                    progress = progress_events.recv(), if progress_open => {
                        let progress = match progress {
                            Ok(progress)
                                if progress.operation_id == operation_id
                                    && progress.event.sequence > progress_sequence => progress,
                            Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => continue,
                            Err(broadcast::error::RecvError::Closed) => {
                                progress_open = false;
                                continue;
                            }
                        };
                        let operation = match reader.lock().await.operation_by_id(operation_id) {
                            Ok(Some(operation)) => operation,
                            Ok(None) => {
                                let _ = sender
                                    .send(Err(Status::not_found(
                                        "local lifecycle operation was not found",
                                    )))
                                    .await;
                                return;
                            }
                            Err(_) => {
                                let _ = sender
                                    .send(Err(Status::internal(
                                        "read local lifecycle operation failed",
                                    )))
                                    .await;
                                return;
                            }
                        };
                        progress_sequence = progress.event.sequence;
                        let terminal = operation.phase.terminal();
                        let update = match operation_proto_with_runner(&operation, &progress.event) {
                            Ok(update) => update,
                            Err(error) => {
                                let _ = sender.send(Err(error)).await;
                                return;
                            }
                        };
                        if sender.send(Ok(update)).await.is_err() || terminal {
                            return;
                        }
                    }
                }
            }
        });
        Ok(Response::new(Box::pin(ReceiverStream::new(receiver))))
    }

    async fn get_daemon_access(
        &self,
        request: Request<v1::EnvironmentSelector>,
    ) -> Result<Response<v1::DaemonAccess>, Status> {
        let name = selected_name(request.into_inner())?;
        let mut core = self.core.lock().await;
        core.replay_pending_operations()
            .await
            .map_err(Status::from)?;
        core.daemon_access(&name)
            .await
            .map(Response::new)
            .map_err(Status::from)
    }

    async fn ensure_credential_broker(
        &self,
        request: Request<v1::EnvironmentSelector>,
    ) -> Result<Response<v1::CredentialBrokerRuntime>, Status> {
        let name = selected_name(request.into_inner())?;
        let broker_request = {
            let mut core = self.core.lock().await;
            core.replay_pending_operations()
                .await
                .map_err(Status::from)?;
            core.reconcile_active_environment_before_protected_effect(&name)
                .await
                .map_err(Status::from)?;
            core.credential_broker_ensure_request(&name)
                .map_err(Status::from)?
        };
        ensure_credential_broker(broker_request)
            .await
            .map(credential_broker_runtime_proto)
            .map(Response::new)
            .map_err(Status::from)
    }
}

fn parse_operation_id(value: &str) -> Result<Uuid, Status> {
    let operation_id =
        Uuid::parse_str(value).map_err(|_| Status::invalid_argument("invalid operation ID"))?;
    if operation_id.is_nil() {
        return Err(Status::invalid_argument("invalid operation ID"));
    }
    Ok(operation_id)
}

struct RunnerStartRelayContext {
    operation_id: Uuid,
    environment_id: Uuid,
    artifact_generation: String,
    prior_generation: u64,
    prior_state: StoredEnvironmentState,
    target_generation: u64,
    progress: broadcast::Sender<OperationProgress>,
}

async fn relay_runner_start_events(
    mut events: tonic::Streaming<v1::RunnerEvent>,
    context: RunnerStartRelayContext,
) -> Result<Option<String>, SupervisorError> {
    let mut sequence = 0_u64;
    let mut guest_sequence = 0_u64;
    let mut guest_stage = None;
    let mut accepted_prior_baseline = false;
    let mut target_started = false;
    for _ in 0..MAXIMUM_RUNNER_EVENTS {
        let event = events
            .message()
            .await
            .map_err(|_| SupervisorError::RunnerUnavailable)?
            .ok_or(SupervisorError::RunnerUnavailable)?;
        if event.sequence <= sequence {
            return Err(SupervisorError::InvalidRunnerResponse);
        }
        sequence = event.sequence;
        let runner = event
            .runner
            .as_ref()
            .ok_or(SupervisorError::InvalidRunnerResponse)?;
        if runner.environment_id != context.environment_id.to_string()
            || runner.artifact_generation != context.artifact_generation
            || runner.generation > context.target_generation
        {
            return Err(SupervisorError::InvalidRunnerResponse);
        }
        let runner_state = StoredEnvironmentState::from_proto(runner.state)?;
        if runner.error_code != event.error_code {
            return Err(SupervisorError::InvalidRunnerResponse);
        }
        let stage = v1::RunnerStage::try_from(event.stage)
            .map_err(|_| SupervisorError::InvalidRunnerResponse)?;
        let parsed_guest_stage = v1::GuestBootStage::try_from(event.guest_stage)
            .map_err(|_| SupervisorError::InvalidRunnerResponse)?;
        let error_code_valid = runner_event_error_code_valid(&event.error_code);
        if !target_started
            && !accepted_prior_baseline
            && runner_event_is_prior_baseline(
                runner.generation,
                runner_state,
                stage,
                event.guest_sequence,
                parsed_guest_stage,
                error_code_valid,
                (context.prior_generation, context.prior_state),
            )
        {
            accepted_prior_baseline = true;
            continue;
        }
        if runner.generation != context.target_generation {
            return Err(SupervisorError::InvalidRunnerResponse);
        }
        target_started = true;
        if !matches!(
            stage,
            v1::RunnerStage::PreparingVm
                | v1::RunnerStage::StartingVmm
                | v1::RunnerStage::WaitingGuest
                | v1::RunnerStage::GuestInit
                | v1::RunnerStage::DaemonReady
                | v1::RunnerStage::Error
        ) {
            return Err(SupervisorError::InvalidRunnerResponse);
        }
        let state_matches_stage = match stage {
            v1::RunnerStage::PreparingVm
            | v1::RunnerStage::StartingVmm
            | v1::RunnerStage::WaitingGuest
            | v1::RunnerStage::GuestInit => runner_state == StoredEnvironmentState::Starting,
            v1::RunnerStage::DaemonReady => runner_state == StoredEnvironmentState::Running,
            v1::RunnerStage::Error => runner_state == StoredEnvironmentState::Error,
            _ => false,
        };
        if !state_matches_stage {
            return Err(SupervisorError::InvalidRunnerResponse);
        }
        if event.guest_sequence == 0 {
            if parsed_guest_stage != v1::GuestBootStage::Unspecified {
                return Err(SupervisorError::InvalidRunnerResponse);
            }
        } else {
            if stage != v1::RunnerStage::GuestInit
                || event.guest_sequence <= guest_sequence
                || parsed_guest_stage == v1::GuestBootStage::Unspecified
                || guest_stage.is_some_and(|prior| (parsed_guest_stage as i32) < (prior as i32))
            {
                return Err(SupervisorError::InvalidRunnerResponse);
            }
            guest_sequence = event.guest_sequence;
            guest_stage = Some(parsed_guest_stage);
        }
        if (stage == v1::RunnerStage::Error) != error_code_valid {
            return Err(SupervisorError::InvalidRunnerResponse);
        }
        let terminal = matches!(stage, v1::RunnerStage::DaemonReady | v1::RunnerStage::Error);
        let terminal_error_code =
            (stage == v1::RunnerStage::Error).then(|| event.error_code.clone());
        let _ = context.progress.send(OperationProgress {
            operation_id: context.operation_id,
            event,
        });
        if terminal {
            return Ok(terminal_error_code);
        }
    }
    Err(SupervisorError::InvalidRunnerResponse)
}

fn runner_event_error_code_valid(error_code: &str) -> bool {
    !error_code.is_empty()
        && error_code.len() <= 64
        && error_code
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
}

fn runner_event_is_prior_baseline(
    generation: u64,
    state: StoredEnvironmentState,
    stage: v1::RunnerStage,
    guest_sequence: u64,
    guest_stage: v1::GuestBootStage,
    error_code_valid: bool,
    prior: (u64, StoredEnvironmentState),
) -> bool {
    generation == prior.0
        && state == prior.1
        && guest_sequence == 0
        && guest_stage == v1::GuestBootStage::Unspecified
        && match state {
            StoredEnvironmentState::Stopped => {
                matches!(stage, v1::RunnerStage::Ready | v1::RunnerStage::Stopped)
                    && !error_code_valid
            }
            StoredEnvironmentState::Error => stage == v1::RunnerStage::Error && error_code_valid,
            StoredEnvironmentState::Starting
            | StoredEnvironmentState::Running
            | StoredEnvironmentState::Orphaned => false,
        }
}

fn operation_proto(operation: &OperationRecord) -> Result<v1::Operation, Status> {
    let kind = match operation.kind {
        OperationKind::Create => v1::OperationKind::Create,
        OperationKind::Start => v1::OperationKind::Start,
        OperationKind::Stop => v1::OperationKind::Stop,
        OperationKind::Restart => v1::OperationKind::Restart,
        OperationKind::UpdateWorkspace => v1::OperationKind::UpdateWorkspace,
        OperationKind::RollbackWorkspace => v1::OperationKind::RollbackWorkspace,
        OperationKind::UpdateEnvironmentSources => v1::OperationKind::UpdateEnvironmentSources,
        OperationKind::Delete => v1::OperationKind::Delete,
        OperationKind::GrowDisk => v1::OperationKind::GrowDisk,
        OperationKind::Reconcile => v1::OperationKind::Reconcile,
    };
    let phase = match operation.phase {
        OperationPhase::Intent => v1::OperationPhase::Intent,
        OperationPhase::EffectApplied => v1::OperationPhase::EffectApplied,
        OperationPhase::Completed => v1::OperationPhase::Completed,
        OperationPhase::Failed => v1::OperationPhase::Failed,
        OperationPhase::Interrupted => v1::OperationPhase::Interrupted,
    };
    let stage = operation_stage(operation)?;
    let result = operation
        .result
        .as_ref()
        .map(|result| operation_result_proto(operation, result))
        .transpose()?;
    Ok(v1::Operation {
        operation_id: operation.operation_id.to_string(),
        request_id: operation.request_id.to_string(),
        environment_id: operation
            .environment_id
            .map(|id| id.to_string())
            .unwrap_or_default(),
        kind: kind as i32,
        phase: phase as i32,
        checkpoint: operation.checkpoint,
        stage: stage as i32,
        created_unix_ms: operation.created_unix_ms,
        updated_unix_ms: operation.updated_unix_ms,
        error_code: operation.error_code.clone().unwrap_or_default(),
        result,
        progress_sequence: 0,
        runner_stage: v1::RunnerStage::Unspecified as i32,
        guest_sequence: 0,
        guest_stage: v1::GuestBootStage::Unspecified as i32,
        runner_error_code: String::new(),
    })
}

fn operation_proto_with_runner(
    operation: &OperationRecord,
    event: &v1::RunnerEvent,
) -> Result<v1::Operation, Status> {
    let runner = event
        .runner
        .as_ref()
        .ok_or_else(|| Status::internal("runner progress identity is missing"))?;
    if event.sequence == 0
        || operation.environment_id.map(|id| id.to_string()).as_deref()
            != Some(runner.environment_id.as_str())
    {
        return Err(Status::internal("runner progress identity is invalid"));
    }
    let stage = v1::RunnerStage::try_from(event.stage)
        .ok()
        .filter(|stage| *stage != v1::RunnerStage::Unspecified)
        .ok_or_else(|| Status::internal("runner progress stage is invalid"))?;
    StoredEnvironmentState::from_proto(runner.state).map_err(Status::from)?;
    let guest_stage = v1::GuestBootStage::try_from(event.guest_stage)
        .map_err(|_| Status::internal("guest progress stage is invalid"))?;
    if (event.guest_sequence == 0) != (guest_stage == v1::GuestBootStage::Unspecified) {
        return Err(Status::internal("guest progress identity is invalid"));
    }
    let runner_error_valid = !event.error_code.is_empty()
        && event.error_code.len() <= 64
        && event
            .error_code
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'_');
    if (stage == v1::RunnerStage::Error) != runner_error_valid {
        return Err(Status::internal("runner progress error code is invalid"));
    }
    let mut operation = operation_proto(operation)?;
    operation.progress_sequence = event.sequence;
    operation.runner_stage = event.stage;
    operation.guest_sequence = event.guest_sequence;
    operation.guest_stage = event.guest_stage;
    operation.runner_error_code = event.error_code.clone();
    Ok(operation)
}

fn operation_stage(operation: &OperationRecord) -> Result<v1::OperationStage, Status> {
    match operation.phase {
        OperationPhase::Completed => return Ok(v1::OperationStage::Completed),
        OperationPhase::Failed => return Ok(v1::OperationStage::Failed),
        OperationPhase::Interrupted => return Ok(v1::OperationStage::Interrupted),
        OperationPhase::Intent | OperationPhase::EffectApplied => {}
    }
    let Some(effect) =
        supervisor_effect(operation.kind, operation.checkpoint).map_err(Status::from)?
    else {
        return Ok(v1::OperationStage::Finalizing);
    };
    Ok(match effect {
        LifecycleEffect::RecordEnvironment => v1::OperationStage::RecordEnvironment,
        LifecycleEffect::BindEnvironmentAccess => v1::OperationStage::BindEnvironmentAccess,
        LifecycleEffect::RequireEnvironmentAccess => v1::OperationStage::RequireEnvironmentAccess,
        LifecycleEffect::ProvisionWorkspace => v1::OperationStage::ProvisionWorkspace,
        LifecycleEffect::StageWorkspaceGeneration => v1::OperationStage::StageWorkspaceGeneration,
        LifecycleEffect::RecordStarting => v1::OperationStage::RecordStarting,
        LifecycleEffect::EnsureRunner => v1::OperationStage::EnsureRunner,
        LifecycleEffect::StartVm => v1::OperationStage::StartVm,
        LifecycleEffect::RecordRunning => v1::OperationStage::RecordRunning,
        LifecycleEffect::StopVm => v1::OperationStage::StopVm,
        LifecycleEffect::RecordStopped => v1::OperationStage::RecordStopped,
        LifecycleEffect::GrowDisk => v1::OperationStage::GrowDisk,
        LifecycleEffect::RecordResources => v1::OperationStage::RecordResources,
        LifecycleEffect::RestartVm => v1::OperationStage::RestartVm,
        LifecycleEffect::RecordResizeOutcome => v1::OperationStage::RecordResizeOutcome,
        LifecycleEffect::StageRollbackGeneration => v1::OperationStage::StageRollbackGeneration,
        LifecycleEffect::RestoreDesiredPower => v1::OperationStage::RestoreDesiredPower,
        LifecycleEffect::RecordWorkspaceTransition => v1::OperationStage::RecordWorkspaceTransition,
        LifecycleEffect::ApplySourceAccessBinding => v1::OperationStage::ApplySourceAccessBinding,
        LifecycleEffect::RecordEnvironmentSources => v1::OperationStage::RecordEnvironmentSources,
        LifecycleEffect::RecordSourceOutcome => v1::OperationStage::RecordSourceOutcome,
        LifecycleEffect::PrepareDelete => v1::OperationStage::PrepareDelete,
        LifecycleEffect::MoveToTrash => v1::OperationStage::MoveToTrash,
        LifecycleEffect::RevokeEnvironmentAccess => v1::OperationStage::RevokeEnvironmentAccess,
        LifecycleEffect::RemoveEnvironment => v1::OperationStage::RemoveEnvironment,
        LifecycleEffect::CleanupTrash => v1::OperationStage::CleanupTrash,
        LifecycleEffect::RecordObservation => v1::OperationStage::RecordObservation,
    })
}

fn operation_result_proto(
    operation: &OperationRecord,
    result: &serde_json::Value,
) -> Result<v1::OperationResult, Status> {
    let fields = result
        .as_object()
        .ok_or_else(|| Status::internal("local lifecycle operation result is invalid"))?;
    let value = if operation.kind == OperationKind::Delete {
        if fields.len() != 3 {
            return Err(Status::internal(
                "local lifecycle deletion result is invalid",
            ));
        }
        let name = fields
            .get("name")
            .and_then(serde_json::Value::as_str)
            .filter(|name| valid_environment_name(name))
            .ok_or_else(|| Status::internal("local lifecycle deletion result is invalid"))?;
        let removed = fields
            .get("removed")
            .and_then(serde_json::Value::as_bool)
            .filter(|removed| *removed)
            .ok_or_else(|| Status::internal("local lifecycle deletion result is invalid"))?;
        let cleanup_pending = fields
            .get("cleanup_pending")
            .and_then(serde_json::Value::as_bool)
            .ok_or_else(|| Status::internal("local lifecycle deletion result is invalid"))?;
        v1::operation_result::Value::Deletion(v1::DeleteEnvironmentResponse {
            name: name.to_owned(),
            removed,
            cleanup_pending,
        })
    } else {
        if fields.len() != 4 {
            return Err(Status::internal(
                "local lifecycle environment result is invalid",
            ));
        }
        let environment_id = fields
            .get("environment_id")
            .and_then(serde_json::Value::as_str)
            .and_then(|value| Uuid::parse_str(value).ok())
            .filter(|id| Some(*id) == operation.environment_id && !id.is_nil())
            .ok_or_else(|| Status::internal("local lifecycle environment result is invalid"))?;
        let name = fields
            .get("name")
            .and_then(serde_json::Value::as_str)
            .filter(|name| valid_environment_name(name))
            .ok_or_else(|| Status::internal("local lifecycle environment result is invalid"))?;
        let state = fields
            .get("state")
            .and_then(serde_json::Value::as_str)
            .and_then(StoredEnvironmentState::parse)
            .ok_or_else(|| Status::internal("local lifecycle environment result is invalid"))?;
        let generation = fields
            .get("generation")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| Status::internal("local lifecycle environment result is invalid"))?;
        v1::operation_result::Value::Environment(v1::EnvironmentOperationResult {
            environment_id: environment_id.to_string(),
            name: name.to_owned(),
            state: state.proto() as i32,
            generation,
        })
    };
    Ok(v1::OperationResult { value: Some(value) })
}

fn selected_name(request: v1::EnvironmentSelector) -> Result<String, Status> {
    if !valid_environment_name(&request.name) {
        return Err(Status::invalid_argument("invalid environment name"));
    }
    Ok(request.name)
}

fn mutation_selection(
    request: v1::EnvironmentSelector,
) -> Result<(String, Uuid, Option<Uuid>), Status> {
    let request_id = parse_request_id(&request.request_id).map_err(Status::from)?;
    let environment_id =
        parse_optional_environment_id(&request.environment_id).map_err(Status::from)?;
    let name = selected_name(request)?;
    Ok((name, request_id, environment_id))
}

fn parse_optional_environment_id(value: &str) -> Result<Option<Uuid>, SupervisorError> {
    if value.is_empty() {
        return Ok(None);
    }
    Uuid::parse_str(value)
        .ok()
        .filter(|id| !id.is_nil())
        .map(Some)
        .ok_or(SupervisorError::InvalidRequest)
}

fn require_expected_environment(
    environment: &EnvironmentRecord,
    expected: Option<Uuid>,
) -> Result<(), Status> {
    if expected.is_some_and(|expected| expected != environment.id) {
        return Err(Status::not_found("local environment was not found"));
    }
    Ok(())
}

fn canonicalize_host_ports_proto(
    bindings: &[v1::HostPortBinding],
) -> Result<Vec<v1::HostPortBinding>, SupervisorError> {
    let bindings = bindings
        .iter()
        .map(|binding| {
            Ok(HostPortBinding {
                host_port: u16::try_from(binding.host_port)
                    .map_err(|_| SupervisorError::InvalidRequest)?,
                guest_port: u16::try_from(binding.guest_port)
                    .map_err(|_| SupervisorError::InvalidRequest)?,
            })
        })
        .collect::<Result<Vec<_>, SupervisorError>>()?;
    canonical_host_port_bindings(bindings)
        .map(|bindings| host_ports_to_proto(&bindings))
        .map_err(|_| SupervisorError::InvalidRequest)
}

fn host_ports_from_proto(
    bindings: &[v1::HostPortBinding],
) -> Result<Vec<HostPortBinding>, SupervisorError> {
    let canonical = canonicalize_host_ports_proto(bindings)?;
    if canonical != bindings {
        return Err(SupervisorError::InvalidRequest);
    }
    canonical
        .into_iter()
        .map(|binding| {
            Ok(HostPortBinding {
                host_port: u16::try_from(binding.host_port)
                    .map_err(|_| SupervisorError::InvalidRequest)?,
                guest_port: u16::try_from(binding.guest_port)
                    .map_err(|_| SupervisorError::InvalidRequest)?,
            })
        })
        .collect()
}

fn host_ports_to_proto(bindings: &[HostPortBinding]) -> Vec<v1::HostPortBinding> {
    bindings
        .iter()
        .map(|binding| v1::HostPortBinding {
            host_port: u32::from(binding.host_port),
            guest_port: u32::from(binding.guest_port),
        })
        .collect()
}

fn direct_share_attachments_to_proto(
    plan: &WorkspacePlan,
) -> Result<Vec<v1::DirectShareAttachment>, SupervisorError> {
    plan.direct_share_plan()
        .map_err(|_| SupervisorError::InvalidState)?;
    Ok(plan
        .inputs
        .iter()
        .filter_map(|input| match input {
            WorkspaceInput::Direct {
                source_path,
                identity,
                destination,
                read_only,
            } => Some(v1::DirectShareAttachment {
                source_path: source_path.clone(),
                device_major: identity.device_major(),
                device_minor: identity.device_minor(),
                inode: identity.inode(),
                mount_id: identity.mount_id(),
                owner_uid: identity.owner_uid(),
                filesystem_magic: identity.filesystem_magic(),
                destination: destination.clone(),
                read_only: *read_only,
            }),
            WorkspaceInput::Local { .. } | WorkspaceInput::Repository { .. } => None,
        })
        .collect())
}

fn revalidate_direct_shares_for_boot(
    plan: &WorkspacePlan,
    forbidden_roots: &[PathBuf],
) -> Result<(), WorkspacePlanError> {
    // A persisted plan may have been admitted under an older supervisor
    // configuration. Recheck the current private roots before any boot-side
    // effects; the runner separately reopens the exact identity at launch.
    plan.validate()?;
    for input in &plan.inputs {
        drop(input.direct_source(forbidden_roots)?);
    }
    Ok(())
}

fn environment_may_expose_direct_shares(environment: &EnvironmentRecord) -> bool {
    // A stopped VM has no live virtiofs device. Its idle runner may remain
    // available while metadata is changed without reopening the direct share.
    environment.state == StoredEnvironmentState::Running
        || (environment.state != StoredEnvironmentState::Stopped && environment.runner.is_some())
}

fn canonicalize_mesh_attachment_proto(
    attachment: Option<&v1::MeshAttachment>,
) -> Result<Option<v1::MeshAttachment>, SupervisorError> {
    let Some(attachment) = attachment else {
        return Ok(None);
    };
    let guest_ports = attachment
        .guest_ports
        .iter()
        .map(|port| u16::try_from(*port).map_err(|_| SupervisorError::InvalidRequest))
        .collect::<Result<Vec<_>, _>>()?;
    let auth_source = mesh_auth_source_from_proto(attachment.auth_source)?;
    let attachment = MeshAttachment::new_with_auth_source(
        auth_source,
        &attachment.mesh_url,
        &attachment.organization_id,
        &attachment.network_id,
        &attachment.node_name,
        guest_ports,
    )
    .map_err(|_| SupervisorError::InvalidRequest)?;
    Ok(mesh_attachment_to_proto(Some(&attachment)))
}

fn mesh_attachment_from_proto(
    attachment: Option<&v1::MeshAttachment>,
) -> Result<Option<MeshAttachment>, SupervisorError> {
    let canonical = canonicalize_mesh_attachment_proto(attachment)?;
    if canonical.as_ref() != attachment {
        return Err(SupervisorError::InvalidRequest);
    }
    canonical
        .map(|attachment| {
            MeshAttachment::new_with_auth_source(
                mesh_auth_source_from_proto(attachment.auth_source)?,
                &attachment.mesh_url,
                &attachment.organization_id,
                &attachment.network_id,
                &attachment.node_name,
                attachment
                    .guest_ports
                    .into_iter()
                    .map(|port| u16::try_from(port).expect("canonical Mesh port fits u16")),
            )
            .map_err(|_| SupervisorError::InvalidRequest)
        })
        .transpose()
}

fn mesh_attachment_to_proto(attachment: Option<&MeshAttachment>) -> Option<v1::MeshAttachment> {
    attachment.map(|attachment| v1::MeshAttachment {
        mesh_url: attachment.mesh_url.clone(),
        organization_id: attachment.organization_id.clone(),
        network_id: attachment.network_id.clone(),
        node_name: attachment.node_name.clone(),
        guest_ports: attachment
            .guest_ports
            .iter()
            .map(|port| u32::from(*port))
            .collect(),
        auth_source: mesh_auth_source_to_proto(attachment.auth_source) as i32,
    })
}

fn mesh_auth_source_from_proto(raw: i32) -> Result<MeshEnrollmentAuthSource, SupervisorError> {
    match v1::MeshEnrollmentAuthSource::try_from(raw) {
        Ok(v1::MeshEnrollmentAuthSource::StandaloneLocal) => {
            Ok(MeshEnrollmentAuthSource::StandaloneLocal)
        }
        Ok(v1::MeshEnrollmentAuthSource::HostedCurrent) => {
            Ok(MeshEnrollmentAuthSource::HostedCurrent)
        }
        Ok(v1::MeshEnrollmentAuthSource::Unspecified) | Err(_) => {
            Err(SupervisorError::InvalidRequest)
        }
    }
}

fn mesh_auth_source_to_proto(source: MeshEnrollmentAuthSource) -> v1::MeshEnrollmentAuthSource {
    match source {
        MeshEnrollmentAuthSource::StandaloneLocal => v1::MeshEnrollmentAuthSource::StandaloneLocal,
        MeshEnrollmentAuthSource::HostedCurrent => v1::MeshEnrollmentAuthSource::HostedCurrent,
    }
}

fn validate_host_ports_for_project(
    bindings: &[HostPortBinding],
    project: &codewire_project::ProjectSpec,
) -> Result<(), SupervisorError> {
    validate_canonical_host_port_bindings(bindings).map_err(|_| SupervisorError::InvalidRequest)?;
    let application_ports = project
        .application_ports
        .iter()
        .map(|port| port.port)
        .collect::<BTreeSet<_>>();
    if bindings
        .iter()
        .any(|binding| !application_ports.contains(&binding.guest_port))
    {
        return Err(SupervisorError::InvalidRequest);
    }
    Ok(())
}

fn validate_mesh_for_project(
    attachment: &MeshAttachment,
    project: &codewire_project::ProjectSpec,
) -> Result<(), SupervisorError> {
    attachment
        .validate()
        .map_err(|_| SupervisorError::InvalidRequest)?;
    let guest_ports =
        canonical_mesh_ingress_ports(project.application_ports.iter().map(|port| port.port))
            .map_err(|_| SupervisorError::InvalidRequest)?;
    if attachment.guest_ports != guest_ports {
        return Err(SupervisorError::InvalidRequest);
    }
    validate_canonical_mesh_ingress_ports(&attachment.guest_ports)
        .map_err(|_| SupervisorError::InvalidRequest)
}

fn validate_create(request: &v1::CreateEnvironmentRequest) -> Result<Uuid, SupervisorError> {
    if !valid_environment_name(&request.name)
        || request.vcpus == 0
        || request.vcpus > 32
        || !(128..=65_536).contains(&request.memory_mib)
        || request.disk_bytes < crate::linux::state::MINIMUM_STATE_DISK_BYTES
        || !request.disk_bytes.is_multiple_of(1024 * 1024)
        || (request.docker_disk_bytes != 0
            && (request.docker_disk_bytes < crate::linux::state::MINIMUM_DOCKER_DISK_BYTES
                || !request.docker_disk_bytes.is_multiple_of(1024 * 1024)))
        || validate_project_intent(
            &request.project_spec_json,
            &request.project_spec_sha256,
            Some((request.vcpus, request.memory_mib, request.disk_bytes)),
        )
        .is_err()
    {
        return Err(SupervisorError::InvalidRequest);
    }
    let project: codewire_project::ProjectSpec = serde_json::from_slice(&request.project_spec_json)
        .map_err(|_| SupervisorError::InvalidRequest)?;
    reject_undeliverable_workload_secrets(&project)?;
    validate_host_ports_for_project(&host_ports_from_proto(&request.host_ports)?, &project)?;
    if let Some(mesh) = mesh_attachment_from_proto(request.mesh.as_ref())?.as_ref() {
        if mesh.node_name != request.name {
            return Err(SupervisorError::InvalidRequest);
        }
        validate_mesh_for_project(mesh, &project)?;
    }
    create_request_access_selection(request, &project)?;
    validate_local_mount_requests(&request.local_mounts)?;
    validate_request_destinations(&project, &request.local_mounts)?;
    if project.repositories.is_empty() && request.local_mounts.is_empty() {
        parse_implicit_path_mode(&request.implicit_path_mode)?;
        if request.source_path.is_empty() || !Path::new(&request.source_path).is_absolute() {
            return Err(SupervisorError::InvalidRequest);
        }
    } else if !request.source_path.is_empty() || !request.implicit_path_mode.is_empty() {
        return Err(SupervisorError::InvalidRequest);
    }
    parse_request_id(&request.request_id)
}

fn validate_local_mount_requests(mounts: &[v1::LocalMountInput]) -> Result<(), SupervisorError> {
    const MAXIMUM_HOST_PATH_BYTES: usize = 4096;

    if mounts.len() > codewire_project::MAX_LOCAL_MOUNTS {
        return Err(SupervisorError::InvalidRequest);
    }
    for mount in mounts {
        if mount.source_path.is_empty()
            || mount.source_path.len() > MAXIMUM_HOST_PATH_BYTES
            || mount.source_path.contains(&0)
            || validate_local_mount_destination(&mount.destination).is_err()
        {
            return Err(SupervisorError::InvalidRequest);
        }
        match v1::LocalMountMode::try_from(mount.mode) {
            Ok(v1::LocalMountMode::Copy) if mount.read_only.is_none() => {}
            Ok(v1::LocalMountMode::Direct) if mount.read_only.is_some() => {}
            _ => return Err(SupervisorError::InvalidRequest),
        }
        let path = PathBuf::from(OsString::from_vec(mount.source_path.clone()));
        if !path.is_absolute() || path == Path::new("/") {
            return Err(SupervisorError::InvalidRequest);
        }
        let mut normalized = PathBuf::from("/");
        for component in path.components().skip(1) {
            let std::path::Component::Normal(component) = component else {
                return Err(SupervisorError::InvalidRequest);
            };
            normalized.push(component);
        }
        if normalized.as_os_str().as_bytes() != mount.source_path {
            return Err(SupervisorError::InvalidRequest);
        }
    }
    Ok(())
}

fn validate_request_destinations(
    project: &codewire_project::ProjectSpec,
    mounts: &[v1::LocalMountInput],
) -> Result<(), SupervisorError> {
    let mut destinations = project
        .repositories
        .iter()
        .map(|repository| repository.destination.as_str())
        .chain(mounts.iter().map(|mount| mount.destination.as_str()))
        .collect::<Vec<_>>();
    destinations.sort_unstable();
    for pair in destinations.windows(2) {
        if pair[0] == pair[1]
            || pair[1]
                .strip_prefix(pair[0])
                .is_some_and(|suffix| suffix.starts_with('/'))
        {
            return Err(SupervisorError::InvalidRequest);
        }
    }
    Ok(())
}

fn validate_project_intent(
    canonical_json: &[u8],
    expected_sha256: &str,
    expected_resources: Option<(u32, u32, u64)>,
) -> Result<(), ()> {
    const GIB: u64 = 1024 * 1024 * 1024;

    if canonical_json.is_empty()
        || canonical_json.len() > codewire_project::MAX_PROJECT_DOCUMENT_BYTES
        || !valid_sha256(expected_sha256)
    {
        return Err(());
    }
    let spec: codewire_project::ProjectSpec =
        serde_json::from_slice(canonical_json).map_err(|_| ())?;
    spec.validate().map_err(|_| ())?;
    if spec.canonical_json().map_err(|_| ())? != canonical_json
        || format!("{:x}", Sha256::digest(canonical_json)) != expected_sha256
        || spec.image.is_empty()
        || !spec.preset.is_empty()
        || spec.agents.install == Some(true)
    {
        return Err(());
    }
    if let Some((vcpus, memory_mib, disk_bytes)) = expected_resources
        && (!disk_bytes.is_multiple_of(GIB)
            || spec.resources.cpu_millicores != vcpus.checked_mul(1_000)
            || spec.resources.memory_mib != Some(u64::from(memory_mib))
            || spec.resources.disk_gib != Some(disk_bytes / GIB))
    {
        return Err(());
    }
    Ok(())
}

fn create_request_access_selection(
    request: &v1::CreateEnvironmentRequest,
    project: &codewire_project::ProjectSpec,
) -> Result<Option<(AccessProfileId, u64, AccessProfileReference)>, SupervisorError> {
    sources::validate_source_metadata(
        project,
        &request.access_profile_id,
        request.access_profile_revision,
        &request.access_profile_reference,
        request.platform_source_authority.as_ref(),
    )
}

fn create_request_access_binding(
    request: &v1::CreateEnvironmentRequest,
    environment_id: Uuid,
) -> Result<Option<(EnvironmentAccessBinding, AccessProfileReference)>, SupervisorError> {
    let project: codewire_project::ProjectSpec = serde_json::from_slice(&request.project_spec_json)
        .map_err(|_| SupervisorError::InvalidRequest)?;
    let Some((profile_id, profile_revision, reference)) =
        create_request_access_selection(request, &project)?
    else {
        return Ok(None);
    };
    Ok(Some((
        EnvironmentAccessBinding {
            environment_id: access_environment_id(environment_id)?,
            profile_id,
            profile_revision,
        },
        reference,
    )))
}

fn access_environment_id(environment_id: Uuid) -> Result<EnvironmentId, SupervisorError> {
    EnvironmentId::parse(environment_id.to_string()).map_err(|_| SupervisorError::InvalidState)
}

fn environment_uses_access_profile(
    environment: &EnvironmentRecord,
) -> Result<bool, SupervisorError> {
    if !environment_access_metadata_valid(environment) {
        return Err(SupervisorError::InvalidState);
    }
    Ok(environment.access_binding.is_some())
}

fn environment_access_metadata_valid(environment: &EnvironmentRecord) -> bool {
    let Some(json) = environment.project_spec_json.as_deref() else {
        return false;
    };
    let Some(sha256) = environment.project_spec_sha256.as_deref() else {
        return false;
    };
    if validate_project_intent(json, sha256, None).is_err() {
        return false;
    }
    let Ok(project) = serde_json::from_slice::<codewire_project::ProjectSpec>(json) else {
        return false;
    };
    let (profile_id, revision, reference) = match (
        environment.access_profile.as_ref(),
        environment.access_binding.as_ref(),
    ) {
        (None, None) => (String::new(), 0, String::new()),
        (Some(reference), Some(binding)) => {
            if binding.validate().is_err()
                || !access_environment_id(environment.id).is_ok_and(|environment_id| {
                    environment_id.as_str() == binding.environment_id.as_str()
                })
            {
                return false;
            }
            (
                binding.profile_id.to_string(),
                binding.profile_revision,
                reference.to_string(),
            )
        }
        _ => return false,
    };
    let authority = environment
        .platform_source_authority
        .as_ref()
        .map(PlatformSourceAuthority::proto);
    sources::validate_source_metadata(
        &project,
        &profile_id,
        revision,
        &reference,
        authority.as_ref(),
    )
    .is_ok()
}

fn delete_operation_revoke_access(
    operation: &OperationRecord,
    name: &str,
) -> Result<bool, SupervisorError> {
    let fields = operation
        .payload
        .as_object()
        .filter(|fields| fields.len() == 2)
        .ok_or(SupervisorError::InvalidState)?;
    if fields.get("name").and_then(serde_json::Value::as_str) != Some(name) {
        return Err(SupervisorError::InvalidState);
    }
    fields
        .get("revoke_access")
        .and_then(serde_json::Value::as_bool)
        .ok_or(SupervisorError::InvalidState)
}

fn credential_control_error(status: Status) -> SupervisorError {
    match status.code() {
        tonic::Code::Unavailable | tonic::Code::DeadlineExceeded | tonic::Code::Unknown => {
            SupervisorError::CredentialAuthorityUnavailable
        }
        _ => SupervisorError::EnvironmentAccessUnavailable,
    }
}

fn parse_implicit_path_mode(value: &str) -> Result<WorkspaceSourceMode, SupervisorError> {
    match value {
        "clone" => Ok(WorkspaceSourceMode::Clone),
        "copy" => Ok(WorkspaceSourceMode::Copy),
        _ => Err(SupervisorError::InvalidRequest),
    }
}

fn workspace_selection(value: WorkspaceSourceMode) -> WorkspaceSelection {
    match value {
        WorkspaceSourceMode::Clone => WorkspaceSelection::Clone,
        WorkspaceSourceMode::Copy => WorkspaceSelection::Copy,
    }
}

fn validate_resize(request: &v1::ResizeEnvironmentRequest) -> Result<Uuid, SupervisorError> {
    if !valid_environment_name(&request.name)
        || request.vcpus == 0
        || request.vcpus > 32
        || !(128..=65_536).contains(&request.memory_mib)
        || request.disk_bytes < crate::linux::state::MINIMUM_STATE_DISK_BYTES
        || !request.disk_bytes.is_multiple_of(1024 * 1024)
        || request.public_request_id.len() > 128
        || !matches!(
            request.public_disruption_policy.as_str(),
            "" | "live_only" | "allow_restart"
        )
    {
        return Err(SupervisorError::InvalidRequest);
    }
    parse_request_id(&request.request_id)
}

fn parse_request_id(value: &str) -> Result<Uuid, SupervisorError> {
    let id = Uuid::parse_str(value).map_err(|_| SupervisorError::InvalidRequest)?;
    if id.is_nil() {
        return Err(SupervisorError::InvalidRequest);
    }
    Ok(id)
}

fn begin_create_operation(
    store: &SupervisorStore,
    request_id: Uuid,
    environment_id: Uuid,
    payload: &serde_json::Value,
) -> Result<OperationRecord, SupervisorError> {
    if request_id.is_nil() || environment_id.is_nil() {
        return Err(SupervisorError::InvalidRequest);
    }
    match store.operation_by_request(request_id)? {
        Some(operation)
            if operation.kind == OperationKind::Create
                && operation.environment_id == Some(environment_id)
                && operation.payload == *payload =>
        {
            Ok(operation)
        }
        Some(_) => Err(SupervisorStoreError::RequestCollision.into()),
        None => store
            .begin_operation(
                request_id,
                Some(environment_id),
                OperationKind::Create,
                payload,
            )
            .map_err(Into::into),
    }
}

fn create_operation_payload(
    request: &v1::CreateEnvironmentRequest,
    workspace_plan: &WorkspacePlan,
) -> Result<serde_json::Value, SupervisorError> {
    validate_create(request)?;
    let project: codewire_project::ProjectSpec = serde_json::from_slice(&request.project_spec_json)
        .map_err(|_| SupervisorError::InvalidRequest)?;
    validate_request_workspace_plan(request, &project, workspace_plan)?;
    let project_spec_json = std::str::from_utf8(&request.project_spec_json)
        .expect("validated canonical project JSON is UTF-8");
    let host_ports = host_ports_from_proto(&request.host_ports)?;
    let mesh = mesh_attachment_from_proto(request.mesh.as_ref())?;
    workspace_plan.validate()?;
    let platform_source_authority = request
        .platform_source_authority
        .as_ref()
        .map(PlatformSourceAuthority::from_proto)
        .transpose()?;
    Ok(serde_json::json!({
        "name": request.name,
        "source_path": request.source_path,
        "vcpus": request.vcpus,
        "memory_mib": request.memory_mib,
        "disk_bytes": request.disk_bytes,
        "docker_disk_bytes": request.docker_disk_bytes,
        "project_spec_json": project_spec_json,
        "project_spec_sha256": request.project_spec_sha256,
        "implicit_path_mode": request.implicit_path_mode,
        "host_ports": host_ports,
        "mesh": mesh,
        "access_profile_id": request.access_profile_id,
        "access_profile_revision": request.access_profile_revision,
        "access_profile_reference": request.access_profile_reference,
        "platform_source_authority": platform_source_authority,
        "workspace_plan": workspace_plan,
    }))
}

fn create_request_from_operation(
    operation: &OperationRecord,
) -> Result<(v1::CreateEnvironmentRequest, WorkspacePlan), SupervisorError> {
    if operation.kind != OperationKind::Create {
        return Err(SupervisorError::InvalidState);
    }
    let fields = operation
        .payload
        .as_object()
        .filter(|fields| fields.len() == 16)
        .ok_or(SupervisorError::InvalidState)?;
    let name = fields
        .get("name")
        .and_then(serde_json::Value::as_str)
        .ok_or(SupervisorError::InvalidState)?
        .to_owned();
    let source_path = fields
        .get("source_path")
        .and_then(serde_json::Value::as_str)
        .ok_or(SupervisorError::InvalidState)?
        .to_owned();
    let vcpus = fields
        .get("vcpus")
        .and_then(serde_json::Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or(SupervisorError::InvalidState)?;
    let memory_mib = fields
        .get("memory_mib")
        .and_then(serde_json::Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or(SupervisorError::InvalidState)?;
    let disk_bytes = fields
        .get("disk_bytes")
        .and_then(serde_json::Value::as_u64)
        .ok_or(SupervisorError::InvalidState)?;
    let docker_disk_bytes = fields
        .get("docker_disk_bytes")
        .and_then(serde_json::Value::as_u64)
        .ok_or(SupervisorError::InvalidState)?;
    let project_spec_json = fields
        .get("project_spec_json")
        .and_then(serde_json::Value::as_str)
        .ok_or(SupervisorError::InvalidState)?
        .as_bytes()
        .to_vec();
    let project_spec_sha256 = fields
        .get("project_spec_sha256")
        .and_then(serde_json::Value::as_str)
        .ok_or(SupervisorError::InvalidState)?
        .to_owned();
    let implicit_path_mode = fields
        .get("implicit_path_mode")
        .and_then(serde_json::Value::as_str)
        .ok_or(SupervisorError::InvalidState)?
        .to_owned();
    let host_ports = serde_json::from_value::<Vec<HostPortBinding>>(
        fields
            .get("host_ports")
            .cloned()
            .ok_or(SupervisorError::InvalidState)?,
    )
    .map_err(|_| SupervisorError::InvalidState)?;
    validate_canonical_host_port_bindings(&host_ports)
        .map_err(|_| SupervisorError::InvalidState)?;
    let mesh = serde_json::from_value::<Option<MeshAttachment>>(
        fields
            .get("mesh")
            .cloned()
            .ok_or(SupervisorError::InvalidState)?,
    )
    .map_err(|_| SupervisorError::InvalidState)?;
    if mesh.as_ref().is_some_and(|mesh| mesh.validate().is_err()) {
        return Err(SupervisorError::InvalidState);
    }
    let access_profile_id = fields
        .get("access_profile_id")
        .and_then(serde_json::Value::as_str)
        .ok_or(SupervisorError::InvalidState)?
        .to_owned();
    let access_profile_revision = fields
        .get("access_profile_revision")
        .and_then(serde_json::Value::as_u64)
        .ok_or(SupervisorError::InvalidState)?;
    let workspace_plan: WorkspacePlan = serde_json::from_value(
        fields
            .get("workspace_plan")
            .cloned()
            .ok_or(SupervisorError::InvalidState)?,
    )
    .map_err(|_| SupervisorError::InvalidState)?;
    workspace_plan
        .validate()
        .map_err(|_| SupervisorError::InvalidState)?;
    let project: codewire_project::ProjectSpec =
        serde_json::from_slice(&project_spec_json).map_err(|_| SupervisorError::InvalidState)?;
    let local_mounts = local_mounts_from_workspace_plan(
        &source_path,
        project.repositories.len(),
        &workspace_plan,
    )?;
    let request = v1::CreateEnvironmentRequest {
        name,
        source_path,
        vcpus,
        memory_mib,
        disk_bytes,
        docker_disk_bytes,
        request_id: operation.request_id.to_string(),
        project_spec_json,
        project_spec_sha256,
        implicit_path_mode,
        local_mounts,
        host_ports: host_ports_to_proto(&host_ports),
        mesh: mesh_attachment_to_proto(mesh.as_ref()),
        access_profile_id,
        access_profile_revision,
        access_profile_reference: fields
            .get("access_profile_reference")
            .and_then(serde_json::Value::as_str)
            .ok_or(SupervisorError::InvalidState)?
            .to_owned(),
        platform_source_authority: serde_json::from_value::<Option<PlatformSourceAuthority>>(
            fields
                .get("platform_source_authority")
                .cloned()
                .ok_or(SupervisorError::InvalidState)?,
        )
        .map_err(|_| SupervisorError::InvalidState)?
        .map(|authority| authority.proto()),
    };
    validate_create(&request)?;
    validate_request_workspace_plan(&request, &project, &workspace_plan)
        .map_err(|_| SupervisorError::InvalidState)?;
    Ok((request, workspace_plan))
}

fn validate_request_workspace_plan(
    request: &v1::CreateEnvironmentRequest,
    project: &codewire_project::ProjectSpec,
    workspace_plan: &WorkspacePlan,
) -> Result<(), SupervisorError> {
    workspace_plan.validate_for_project(project)?;
    let repository_count = project.repositories.len();
    if !request.source_path.is_empty() {
        let [
            WorkspaceInput::Local {
                source_path,
                mode,
                destination,
                ..
            },
        ] = workspace_plan.inputs.as_slice()
        else {
            return Err(SupervisorError::InvalidRequest);
        };
        if source_path != OsStr::new(&request.source_path).as_bytes()
            || *mode != parse_implicit_path_mode(&request.implicit_path_mode)?
            || destination != "/workspace"
            || !request.local_mounts.is_empty()
        {
            return Err(SupervisorError::InvalidRequest);
        }
        return Ok(());
    }

    let local_inputs = workspace_plan
        .inputs
        .get(repository_count..)
        .ok_or(SupervisorError::InvalidRequest)?;
    if local_inputs.len() != request.local_mounts.len() {
        return Err(SupervisorError::InvalidRequest);
    }
    for (input, mount) in local_inputs.iter().zip(&request.local_mounts) {
        match input {
            WorkspaceInput::Local {
                source_path,
                mode,
                destination,
                ..
            } if source_path == &mount.source_path
                && *mode == WorkspaceSourceMode::Copy
                && destination == &mount.destination
                && mount.mode == v1::LocalMountMode::Copy as i32
                && mount.read_only.is_none() => {}
            WorkspaceInput::Direct {
                source_path,
                destination,
                read_only,
                ..
            } if source_path == &mount.source_path
                && destination == &mount.destination
                && mount.mode == v1::LocalMountMode::Direct as i32
                && mount.read_only == Some(*read_only) => {}
            _ => return Err(SupervisorError::InvalidRequest),
        }
    }
    Ok(())
}

fn local_mounts_from_workspace_plan(
    source_path: &str,
    repository_count: usize,
    workspace_plan: &WorkspacePlan,
) -> Result<Vec<v1::LocalMountInput>, SupervisorError> {
    if !source_path.is_empty() {
        return Ok(Vec::new());
    }
    workspace_plan
        .inputs
        .get(repository_count..)
        .ok_or(SupervisorError::InvalidState)?
        .iter()
        .map(|input| match input {
            WorkspaceInput::Local {
                source_path,
                mode: WorkspaceSourceMode::Copy,
                destination,
                ..
            } => {
                validate_local_mount_destination(destination)
                    .map_err(|_| SupervisorError::InvalidState)?;
                Ok(v1::LocalMountInput {
                    source_path: source_path.clone(),
                    destination: destination.clone(),
                    mode: v1::LocalMountMode::Copy as i32,
                    read_only: None,
                })
            }
            WorkspaceInput::Direct {
                source_path,
                destination,
                read_only,
                ..
            } => {
                validate_local_mount_destination(destination)
                    .map_err(|_| SupervisorError::InvalidState)?;
                Ok(v1::LocalMountInput {
                    source_path: source_path.clone(),
                    destination: destination.clone(),
                    mode: v1::LocalMountMode::Direct as i32,
                    read_only: Some(*read_only),
                })
            }
            _ => Err(SupervisorError::InvalidState),
        })
        .collect()
}

fn supervisor_effect(
    kind: OperationKind,
    checkpoint: u32,
) -> Result<Option<LifecycleEffect>, SupervisorError> {
    next_effect(kind, checkpoint).map_err(|_| SupervisorError::InvalidState)
}

fn environment_operation_result(environment: &EnvironmentRecord) -> serde_json::Value {
    serde_json::json!({
        "environment_id": environment.id,
        "name": environment.name,
        "state": environment.state.as_str(),
        "generation": environment.generation,
    })
}

fn prepare_workspace_boot(
    engine_state_root: &Path,
    user_skills_root: &Path,
    forbidden_direct_roots: &[PathBuf],
    environment: &EnvironmentRecord,
) -> Result<PreparedWorkspaceBoot, SupervisorError> {
    let (workspace, staging) = match environment.staging_workspace_generation.as_ref() {
        Some(generation) => (generation, true),
        None => (
            environment
                .active_workspace_generation
                .as_ref()
                .ok_or(SupervisorError::InvalidState)?,
            false,
        ),
    };
    artifact_generation_for_boot(environment, staging)?;
    if staging {
        workspace.validate()?;
    } else {
        workspace.validate_for_project_intent(
            environment
                .project_spec_json
                .as_deref()
                .ok_or(SupervisorError::InvalidState)?,
            environment
                .project_spec_sha256
                .as_deref()
                .ok_or(SupervisorError::InvalidState)?,
        )?;
    };
    let root_generation = workspace_storage_generation(workspace)?;
    let root_disk_bytes = workspace.root_disk_bytes;
    let setup_root_generation = workspace.root_generation.clone();
    let skill_snapshot = workspace.skill_snapshot()?;
    let skill_snapshot_sha256 = skill_snapshot
        .map(codewire_vmm_guest_probe::SkillSnapshotPlan::sha256)
        .transpose()
        .map_err(|_| SupervisorError::WorkspaceGeneration)?
        .unwrap_or_default();
    // Provision at the replayable start boundary, not only during create.
    // An active generation normally reuses its admitted root without needing
    // the CAS. If its root was removed, rebuilding it still uses the exact
    // committed descriptors rather than resolving a moving tag again.
    let root = match ensure_root_generation(
        engine_state_root,
        environment.id,
        &root_generation,
        root_disk_bytes,
        skill_snapshot.is_some(),
        None,
    ) {
        Ok(root) => root,
        Err(GenerationError::SkillSnapshotSeedRequired) => {
            let project: codewire_project::ProjectSpec =
                serde_json::from_slice(workspace.project_spec_json()?)
                    .map_err(|_| SupervisorError::InvalidState)?;
            let expected = skill_snapshot.ok_or(SupervisorError::InvalidState)?;
            let prepared = prepare_skill_snapshot(SkillSnapshotRequest {
                engine_state_root,
                vm_id: environment.id,
                workspace_plan: &environment.workspace_plan,
                project: &project,
                project_sha256: &workspace.project_sha256,
                user_skills_root,
                forbidden_direct_roots,
                plan_generation: expected.plan_generation(),
                expected: Some(expected),
            })?
            .ok_or(SupervisorError::InvalidState)?;
            ensure_root_generation(
                engine_state_root,
                environment.id,
                &root_generation,
                root_disk_bytes,
                true,
                Some(prepared.root()),
            )?
        }
        Err(error) => return Err(error.into()),
    };
    let setup = if staging || root.created {
        let project_json = workspace.project_spec_json()?;
        let engine = PrivateRoot::open(engine_state_root)?;
        let content = ContentStore::create(&engine)?;
        Some(ensure_setup_pack(
            engine_state_root,
            environment.id,
            &content,
            SetupPackRequest {
                project_json,
                project_sha256: &workspace.project_sha256,
                storage_generation: &root_generation,
                root_generation: &workspace.root_generation,
                image: &workspace.image,
            },
        )?)
    } else {
        None
    };
    let setup_root_generation = setup
        .as_ref()
        .map(|_| setup_root_generation)
        .unwrap_or_default();

    Ok(PreparedWorkspaceBoot {
        root_generation,
        root_disk_bytes,
        setup_root_generation,
        setup_total_bytes: setup.as_ref().map_or(0, |pack| pack.header.total_bytes),
        setup_header_sha256: setup
            .map(|pack| pack.header_sha256.to_string())
            .unwrap_or_default(),
        skill_snapshot_sha256,
    })
}

fn reject_undeliverable_workload_secrets(
    project: &codewire_project::ProjectSpec,
) -> Result<(), SupervisorError> {
    sources::platform::requires_platform_authority(project).map(|_| ())
}

fn reject_environment_workload_secrets(
    environment: &EnvironmentRecord,
) -> Result<(), SupervisorError> {
    let project_json = environment
        .project_spec_json
        .as_deref()
        .ok_or(SupervisorError::InvalidState)?;
    let project_sha256 = environment
        .project_spec_sha256
        .as_deref()
        .ok_or(SupervisorError::InvalidState)?;
    validate_project_intent(project_json, project_sha256, None)
        .map_err(|_| SupervisorError::InvalidState)?;
    let project: codewire_project::ProjectSpec =
        serde_json::from_slice(project_json).map_err(|_| SupervisorError::InvalidState)?;
    reject_undeliverable_workload_secrets(&project)?;
    sources::platform::managed_clients(environment).map(|_| ())
}

fn validate_environment_workload_secret_delivery(
    environment: &EnvironmentRecord,
    staging: bool,
) -> Result<(), SupervisorError> {
    let workspace = if staging {
        environment.staging_workspace_generation.as_ref()
    } else {
        environment.active_workspace_generation.as_ref()
    }
    .ok_or(SupervisorError::InvalidState)?;
    if staging {
        workspace.validate()?;
    } else {
        workspace.validate_for_project_intent(
            environment
                .project_spec_json
                .as_deref()
                .ok_or(SupervisorError::InvalidState)?,
            environment
                .project_spec_sha256
                .as_deref()
                .ok_or(SupervisorError::InvalidState)?,
        )?;
    }
    // Built setup metadata may intentionally retain an older selection. Only
    // current environment intent determines this boot's required delivery.
    reject_environment_workload_secrets(environment)
}

fn reject_workspace_transition_workload_secrets(
    environment: &EnvironmentRecord,
    parameters: &WorkspaceTransitionParameters,
) -> Result<(), SupervisorError> {
    let project_json = match &parameters.intent {
        WorkspaceTransitionIntent::Update {
            project_spec_json, ..
        } => project_spec_json.as_slice(),
        WorkspaceTransitionIntent::Rollback {
            rollback_storage_generation,
        } => {
            let mut target = None;
            for candidate in [
                environment.active_workspace_generation.as_ref(),
                environment.staging_workspace_generation.as_ref(),
                environment.rollback_workspace_generation.as_ref(),
            ]
            .into_iter()
            .flatten()
            {
                if workspace_storage_generation(candidate)? == *rollback_storage_generation
                    && target.replace(candidate).is_some()
                {
                    return Err(SupervisorError::InvalidState);
                }
            }
            target
                .ok_or(SupervisorError::InvalidState)?
                .project_spec_json()?
        }
    };
    let project: codewire_project::ProjectSpec =
        serde_json::from_slice(project_json).map_err(|_| SupervisorError::InvalidState)?;
    if matches!(parameters.intent, WorkspaceTransitionIntent::Update { .. }) {
        // Preserve rejection of an undeliverable proposed source before any
        // staging. Exact source equality is checked at transition admission.
        reject_undeliverable_workload_secrets(&project)?;
    }
    reject_environment_workload_secrets(environment)
}

fn runner_artifact_identity_matches(recorded: &str, reported: &str) -> bool {
    valid_sha256(recorded) && reported == recorded
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RunnerArtifactDisposition {
    Reuse,
    ReplaceStopped,
    RejectLiveMismatch,
}

fn runner_artifact_disposition(
    recorded: &str,
    requested: &str,
    state: StoredEnvironmentState,
) -> RunnerArtifactDisposition {
    if recorded == requested {
        return RunnerArtifactDisposition::Reuse;
    }
    if matches!(
        state,
        StoredEnvironmentState::Running | StoredEnvironmentState::Starting
    ) {
        return RunnerArtifactDisposition::RejectLiveMismatch;
    }
    RunnerArtifactDisposition::ReplaceStopped
}

fn artifact_generation_for_boot(
    environment: &EnvironmentRecord,
    staging: bool,
) -> Result<&str, SupervisorError> {
    let fallback = if staging {
        environment
            .staging_artifact_generation
            .as_deref()
            .or(environment.active_artifact_generation.as_deref())
    } else {
        environment.active_artifact_generation.as_deref()
    };
    let fallback = fallback
        .filter(|generation| valid_sha256(generation))
        .ok_or(SupervisorError::InvalidState)?;
    let workspace = if staging {
        environment.staging_workspace_generation.as_ref()
    } else {
        environment.active_workspace_generation.as_ref()
    }
    .ok_or(SupervisorError::InvalidState)?;
    let generation = workspace.artifact_generation()?;
    if generation != fallback {
        return Err(SupervisorError::InvalidState);
    }
    Ok(generation)
}

fn oci_storage_generation(
    oci_generation: &str,
    artifact_generation: &str,
    root_disk_bytes: u64,
) -> Result<String, SupervisorError> {
    if !valid_sha256(oci_generation)
        || !valid_sha256(artifact_generation)
        || !valid_root_disk_bytes(root_disk_bytes)
    {
        return Err(SupervisorError::InvalidState);
    }
    let mut digest = Sha256::new();
    digest.update(b"codewire-root-generation-oci-storage-v1\0");
    digest.update(oci_generation.as_bytes());
    digest.update(artifact_generation.as_bytes());
    digest.update(root_disk_bytes.to_le_bytes());
    Ok(format!("{:x}", digest.finalize()))
}

fn workspace_storage_generation(
    generation: &WorkspaceGenerationRecord,
) -> Result<String, SupervisorError> {
    let oci = oci_storage_generation(
        &generation.root_generation,
        generation.artifact_generation()?,
        generation.root_disk_bytes,
    )?;
    let Some(snapshot) = generation.skill_snapshot()? else {
        return Ok(oci);
    };
    let snapshot_sha256 = snapshot
        .sha256()
        .map_err(|_| SupervisorError::WorkspaceGeneration)?;
    let mut digest = Sha256::new();
    digest.update(b"codewire-root-generation-with-skills-v1\0");
    digest.update(oci.as_bytes());
    digest.update(snapshot_sha256.as_bytes());
    Ok(format!("{:x}", digest.finalize()))
}

fn referenced_root_storage_generations(
    environment: &EnvironmentRecord,
) -> Result<BTreeSet<String>, SupervisorError> {
    let mut retained = BTreeSet::new();
    for generation in [
        environment.active_workspace_generation.as_ref(),
        environment.rollback_workspace_generation.as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        retained.insert(workspace_storage_generation(generation)?);
    }
    if let Some(generation) = environment.staging_workspace_generation.as_ref() {
        retained.insert(workspace_storage_generation(generation)?);
    }
    Ok(retained)
}

fn referenced_content_blobs(
    state: &SupervisorState,
) -> Result<BTreeMap<Sha256Digest, u64>, SupervisorError> {
    let mut retained = BTreeMap::new();
    for environment in state.environments.values() {
        retain_workspace_plan_content(&mut retained, &environment.workspace_plan)?;
        let generations = [
            environment.active_workspace_generation.as_ref(),
            environment.staging_workspace_generation.as_ref(),
            environment.rollback_workspace_generation.as_ref(),
        ];
        for generation in generations.into_iter().flatten() {
            generation.validate()?;
            retain_image_content(&mut retained, &generation.image)?;
        }
    }
    Ok(retained)
}

fn retain_image_content(
    retained: &mut BTreeMap<Sha256Digest, u64>,
    image: &ResolvedImage,
) -> Result<(), SupervisorError> {
    image
        .validate_metadata()
        .map_err(|_| SupervisorError::InvalidState)?;
    retain_content_descriptor(retained, &image.source)?;
    retain_content_descriptor(retained, &image.manifest)?;
    retain_content_descriptor(retained, &image.config)?;
    for layer in &image.layers {
        retain_content_descriptor(retained, &layer.descriptor)?;
    }
    Ok(())
}

fn retain_workspace_plan_content(
    retained: &mut BTreeMap<Sha256Digest, u64>,
    workspace_plan: &WorkspacePlan,
) -> Result<(), SupervisorError> {
    workspace_plan.validate()?;
    for (digest, size) in workspace_plan.retained_bundles() {
        retain_content_blob(retained, digest, size)?;
    }
    Ok(())
}

fn referenced_artifact_generations(
    state: &SupervisorState,
) -> Result<BTreeSet<String>, SupervisorError> {
    state.validate()?;
    let mut retained = BTreeSet::new();
    for environment in state.environments.values() {
        let active = environment
            .active_artifact_generation
            .as_deref()
            .ok_or(SupervisorError::InvalidState)?;
        retain_artifact_generation(&mut retained, active)?;
        if let Some(staging) = environment.staging_artifact_generation.as_deref() {
            retain_artifact_generation(&mut retained, staging)?;
        }
        if let Some(rollback) = environment.rollback_workspace_generation.as_ref() {
            retain_artifact_generation(&mut retained, rollback.artifact_generation()?)?;
        }
        if let Some(runner) = environment.runner.as_ref() {
            retain_artifact_generation(&mut retained, &runner.artifact_generation)?;
        }
    }
    Ok(retained)
}

fn retain_artifact_generation(
    retained: &mut BTreeSet<String>,
    generation: &str,
) -> Result<(), SupervisorError> {
    if !valid_sha256(generation) {
        return Err(SupervisorError::InvalidState);
    }
    retained.insert(generation.to_owned());
    Ok(())
}

fn retain_content_descriptor(
    retained: &mut BTreeMap<Sha256Digest, u64>,
    descriptor: &ResolvedDescriptor,
) -> Result<(), SupervisorError> {
    retain_content_blob(retained, &descriptor.digest, descriptor.size)
}

fn retain_content_blob(
    retained: &mut BTreeMap<Sha256Digest, u64>,
    digest: &Sha256Digest,
    size: u64,
) -> Result<(), SupervisorError> {
    if let Some(retained_size) = retained.get(digest) {
        return (*retained_size == size)
            .then_some(())
            .ok_or(SupervisorError::InvalidState);
    }
    retained.insert(digest.clone(), size);
    Ok(())
}

/// Reserve a monotonically increasing boot generation before any runner can
/// persist that generation. This prevents a failed runner from getting ahead
/// of supervisor state and making the next recovery attempt reuse its number.
fn reserve_boot_generation(
    environment: &mut EnvironmentRecord,
    target_generation: u64,
) -> Result<(), SupervisorError> {
    if target_generation == 0 {
        return Err(SupervisorError::InvalidState);
    }
    if environment.generation == target_generation {
        return matches!(
            environment.state,
            StoredEnvironmentState::Starting | StoredEnvironmentState::Running
        )
        .then_some(())
        .ok_or(SupervisorError::InvalidState);
    }
    if environment.generation.checked_add(1) != Some(target_generation) {
        return Err(SupervisorError::InvalidState);
    }
    environment.generation = target_generation;
    environment.state = StoredEnvironmentState::Starting;
    if let Some(runner) = environment.runner.as_mut() {
        runner.error_code = None;
    }
    Ok(())
}

fn start_operation_generation(operation: &OperationRecord) -> Result<u64, SupervisorError> {
    if operation.kind != OperationKind::Start {
        return Err(SupervisorError::InvalidState);
    }
    let fields = operation
        .payload
        .as_object()
        .filter(|fields| fields.len() == 2)
        .ok_or(SupervisorError::InvalidState)?;
    fields
        .get("name")
        .and_then(serde_json::Value::as_str)
        .filter(|name| valid_environment_name(name))
        .ok_or(SupervisorError::InvalidState)?;
    fields
        .get("generation")
        .and_then(serde_json::Value::as_u64)
        .filter(|generation| *generation > 0)
        .ok_or(SupervisorError::InvalidState)
}

struct ReconcilePrecondition {
    state: StoredEnvironmentState,
    generation: u64,
    runner: Option<RunnerRecord>,
}

struct ReconcileOperationParameters {
    name: String,
    state: StoredEnvironmentState,
    generation: u64,
    clear_runner: bool,
    runner_error_code: Option<String>,
    precondition: ReconcilePrecondition,
}

fn reconcile_operation_payload(
    environment: &EnvironmentRecord,
    state: StoredEnvironmentState,
    generation: u64,
    clear_runner: bool,
    runner_error_code: Option<&str>,
) -> serde_json::Value {
    serde_json::json!({
        "name": environment.name,
        "observed_state": state.as_str(),
        "generation": generation,
        "clear_runner": clear_runner,
        "runner_error_code": runner_error_code,
        "expected_observed_state": environment.state.as_str(),
        "expected_generation": environment.generation,
        "expected_runner": environment.runner,
    })
}

fn reconcile_operation_parameters(
    operation: &OperationRecord,
) -> Result<ReconcileOperationParameters, SupervisorError> {
    if operation.kind != OperationKind::Reconcile {
        return Err(SupervisorError::InvalidState);
    }
    let fields = operation
        .payload
        .as_object()
        .ok_or(SupervisorError::InvalidState)?;
    if fields.len() != 8 {
        return Err(SupervisorError::InvalidState);
    }
    let name = fields
        .get("name")
        .and_then(serde_json::Value::as_str)
        .filter(|name| valid_environment_name(name))
        .ok_or(SupervisorError::InvalidState)?
        .to_owned();
    let target_state = fields
        .get("observed_state")
        .and_then(serde_json::Value::as_str)
        .and_then(StoredEnvironmentState::parse)
        .ok_or(SupervisorError::InvalidState)?;
    let target_generation = fields
        .get("generation")
        .and_then(serde_json::Value::as_u64)
        .ok_or(SupervisorError::InvalidState)?;
    let clear_runner = fields
        .get("clear_runner")
        .and_then(serde_json::Value::as_bool)
        .ok_or(SupervisorError::InvalidState)?;
    let runner_error_code = match fields.get("runner_error_code") {
        Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(error_code))
            if runner_event_error_code_valid(error_code) =>
        {
            Some(error_code.clone())
        }
        _ => return Err(SupervisorError::InvalidState),
    };
    if clear_runner && runner_error_code.is_some()
        || (target_state == StoredEnvironmentState::Error) != runner_error_code.is_some()
            && !clear_runner
    {
        return Err(SupervisorError::InvalidState);
    }
    let expected_state = fields
        .get("expected_observed_state")
        .and_then(serde_json::Value::as_str)
        .and_then(StoredEnvironmentState::parse)
        .ok_or(SupervisorError::InvalidState)?;
    let expected_generation = fields
        .get("expected_generation")
        .and_then(serde_json::Value::as_u64)
        .ok_or(SupervisorError::InvalidState)?;
    let runner = serde_json::from_value::<Option<RunnerRecord>>(
        fields
            .get("expected_runner")
            .cloned()
            .ok_or(SupervisorError::InvalidState)?,
    )
    .map_err(|_| SupervisorError::InvalidState)?;
    if runner.as_ref().is_some_and(|runner| {
        runner
            .error_code
            .as_deref()
            .is_some_and(|error_code| !runner_event_error_code_valid(error_code))
    }) {
        return Err(SupervisorError::InvalidState);
    }
    let precondition = ReconcilePrecondition {
        state: expected_state,
        generation: expected_generation,
        runner,
    };
    Ok(ReconcileOperationParameters {
        name,
        state: target_state,
        generation: target_generation,
        clear_runner,
        runner_error_code,
        precondition,
    })
}

fn resize_operation_parameters(
    operation: &OperationRecord,
) -> Result<(u8, u32, u64, bool, u64), SupervisorError> {
    let fields = operation
        .payload
        .as_object()
        .ok_or(SupervisorError::InvalidState)?;
    const REQUIRED_FIELDS: [&str; 6] = [
        "name",
        "vcpus",
        "memory_mib",
        "disk_bytes",
        "was_running",
        "target_generation",
    ];
    const OPTIONAL_FIELDS: [&str; 5] = [
        "previous_vcpus",
        "previous_memory_mib",
        "previous_disk_bytes",
        "public_request_id",
        "public_disruption_policy",
    ];
    if !REQUIRED_FIELDS
        .iter()
        .all(|field| fields.contains_key(*field))
        || fields.keys().any(|field| {
            !REQUIRED_FIELDS.contains(&field.as_str()) && !OPTIONAL_FIELDS.contains(&field.as_str())
        })
    {
        return Err(SupervisorError::InvalidState);
    }
    let vcpus = fields
        .get("vcpus")
        .and_then(serde_json::Value::as_u64)
        .and_then(|value| u8::try_from(value).ok())
        .filter(|value| (1..=32).contains(value))
        .ok_or(SupervisorError::InvalidState)?;
    let memory_mib = fields
        .get("memory_mib")
        .and_then(serde_json::Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .filter(|value| (128..=65_536).contains(value))
        .ok_or(SupervisorError::InvalidState)?;
    let disk_bytes = fields
        .get("disk_bytes")
        .and_then(serde_json::Value::as_u64)
        .filter(|value| {
            *value >= crate::linux::state::MINIMUM_STATE_DISK_BYTES
                && value.is_multiple_of(1024 * 1024)
        })
        .ok_or(SupervisorError::InvalidState)?;
    let was_running = fields
        .get("was_running")
        .and_then(serde_json::Value::as_bool)
        .ok_or(SupervisorError::InvalidState)?;
    let target_generation = fields
        .get("target_generation")
        .and_then(serde_json::Value::as_u64)
        .filter(|generation| *generation > 0)
        .ok_or(SupervisorError::InvalidState)?;
    Ok((
        vcpus,
        memory_mib,
        disk_bytes,
        was_running,
        target_generation,
    ))
}

struct WorkspaceTransitionParameters {
    prior_storage_generation: String,
    target_generation: u64,
    was_running: bool,
    refresh_skills: bool,
    intent: WorkspaceTransitionIntent,
}

enum WorkspaceTransitionIntent {
    Update {
        project_spec_json: Vec<u8>,
        project_spec_sha256: String,
    },
    Rollback {
        rollback_storage_generation: String,
    },
}

fn workspace_transition_parameters(
    operation: &OperationRecord,
    environment: &EnvironmentRecord,
) -> Result<WorkspaceTransitionParameters, SupervisorError> {
    let fields = operation
        .payload
        .as_object()
        .ok_or(SupervisorError::InvalidState)?;
    let expected_fields = match operation.kind {
        OperationKind::UpdateWorkspace => {
            if fields.contains_key("refresh_skills") {
                7
            } else {
                6
            }
        }
        OperationKind::RollbackWorkspace => 5,
        _ => return Err(SupervisorError::InvalidState),
    };
    if fields.len() != expected_fields
        || fields.get("name").and_then(serde_json::Value::as_str) != Some(environment.name.as_str())
    {
        return Err(SupervisorError::InvalidState);
    }
    let prior_storage_generation = fields
        .get("prior_storage_generation")
        .and_then(serde_json::Value::as_str)
        .filter(|value| valid_sha256(value))
        .ok_or(SupervisorError::InvalidState)?
        .to_owned();
    let target_generation = fields
        .get("target_generation")
        .and_then(serde_json::Value::as_u64)
        .filter(|value| *value > 0)
        .ok_or(SupervisorError::InvalidState)?;
    let was_running = fields
        .get("was_running")
        .and_then(serde_json::Value::as_bool)
        .ok_or(SupervisorError::InvalidState)?;
    let refresh_skills = fields
        .get("refresh_skills")
        .map(|value| value.as_bool().ok_or(SupervisorError::InvalidState))
        .transpose()?
        .unwrap_or(false);
    if refresh_skills && operation.kind != OperationKind::UpdateWorkspace {
        return Err(SupervisorError::InvalidState);
    }
    let intent = match operation.kind {
        OperationKind::UpdateWorkspace => {
            let project_spec_json = fields
                .get("project_spec_json")
                .and_then(serde_json::Value::as_str)
                .ok_or(SupervisorError::InvalidState)?
                .as_bytes()
                .to_vec();
            let project_spec_sha256 = fields
                .get("project_spec_sha256")
                .and_then(serde_json::Value::as_str)
                .ok_or(SupervisorError::InvalidState)?
                .to_owned();
            validate_project_intent(
                &project_spec_json,
                &project_spec_sha256,
                Some((
                    u32::from(environment.vcpus),
                    environment.memory_mib,
                    environment.disk_bytes,
                )),
            )
            .map_err(|_| SupervisorError::InvalidState)?;
            WorkspaceTransitionIntent::Update {
                project_spec_json,
                project_spec_sha256,
            }
        }
        OperationKind::RollbackWorkspace => {
            let rollback_storage_generation = fields
                .get("rollback_storage_generation")
                .and_then(serde_json::Value::as_str)
                .filter(|value| valid_sha256(value))
                .ok_or(SupervisorError::InvalidState)?
                .to_owned();
            WorkspaceTransitionIntent::Rollback {
                rollback_storage_generation,
            }
        }
        _ => return Err(SupervisorError::InvalidState),
    };
    Ok(WorkspaceTransitionParameters {
        prior_storage_generation,
        target_generation,
        was_running,
        refresh_skills,
        intent,
    })
}

fn workspace_transition_requires_boot(
    environment: &EnvironmentRecord,
    parameters: &WorkspaceTransitionParameters,
) -> Result<bool, SupervisorError> {
    let active = environment
        .active_workspace_generation
        .as_ref()
        .ok_or(SupervisorError::InvalidState)?;
    if workspace_storage_generation(active)? != parameters.prior_storage_generation {
        return Err(SupervisorError::InvalidState);
    }
    match &parameters.intent {
        WorkspaceTransitionIntent::Update {
            project_spec_json,
            project_spec_sha256,
        } => match environment.staging_workspace_generation.as_ref() {
            Some(staging) => {
                staging.validate_for_project_intent(project_spec_json, project_spec_sha256)?;
                Ok(workspace_storage_generation(active)? != workspace_storage_generation(staging)?)
            }
            None => {
                active.validate_for_project_intent(project_spec_json, project_spec_sha256)?;
                Ok(false)
            }
        },
        WorkspaceTransitionIntent::Rollback {
            rollback_storage_generation,
        } => {
            let staging = environment
                .staging_workspace_generation
                .as_ref()
                .ok_or(SupervisorError::InvalidState)?;
            if environment.rollback_workspace_generation.is_some()
                || workspace_storage_generation(staging)? != *rollback_storage_generation
            {
                return Err(SupervisorError::InvalidState);
            }
            Ok(true)
        }
    }
}

fn validate_workspace_transition_start(
    environment: &EnvironmentRecord,
    parameters: &WorkspaceTransitionParameters,
) -> Result<(), SupervisorError> {
    let expected_generation = environment
        .generation
        .checked_add(1)
        .ok_or(SupervisorError::InvalidState)?;
    if !matches!(
        environment.state,
        StoredEnvironmentState::Running | StoredEnvironmentState::Stopped
    ) || parameters.was_running != (environment.state == StoredEnvironmentState::Running)
        || parameters.target_generation != expected_generation
        || environment.staging_workspace_generation.is_some()
    {
        return Err(SupervisorError::InvalidState);
    }
    let active = environment
        .active_workspace_generation
        .as_ref()
        .ok_or(SupervisorError::InvalidState)?;
    if workspace_storage_generation(active)? != parameters.prior_storage_generation {
        return Err(SupervisorError::InvalidState);
    }
    let (target_project_json, target_project_sha256) = match &parameters.intent {
        WorkspaceTransitionIntent::Update {
            project_spec_json,
            project_spec_sha256,
        } => (project_spec_json.as_slice(), project_spec_sha256.as_str()),
        WorkspaceTransitionIntent::Rollback { .. } => {
            let rollback = environment
                .rollback_workspace_generation
                .as_ref()
                .ok_or(SupervisorError::InvalidState)?;
            (
                rollback.project_spec_json()?,
                rollback.project_sha256.as_str(),
            )
        }
    };
    let target_project: codewire_project::ProjectSpec =
        serde_json::from_slice(target_project_json).map_err(|_| SupervisorError::InvalidState)?;
    if parameters.refresh_skills {
        let active = environment
            .active_workspace_generation
            .as_ref()
            .ok_or(SupervisorError::InvalidState)?;
        active.validate_for_project_intent(target_project_json, target_project_sha256)?;
        if active.skill_snapshot()?.is_none() || target_project.skills.is_empty() {
            return Err(SupervisorError::InvalidState);
        }
    }
    let current_project_json = environment
        .project_spec_json
        .as_deref()
        .ok_or(SupervisorError::InvalidState)?;
    let current_project_sha256 = environment
        .project_spec_sha256
        .as_deref()
        .ok_or(SupervisorError::InvalidState)?;
    active.validate_for_project_intent(current_project_json, current_project_sha256)?;
    if matches!(parameters.intent, WorkspaceTransitionIntent::Update { .. }) {
        let current: codewire_project::ProjectSpec = serde_json::from_slice(current_project_json)
            .map_err(|_| SupervisorError::InvalidState)?;
        if target_project.secrets != current.secrets
            || target_project.credentials != current.credentials
        {
            return Err(SupervisorError::InvalidState);
        }
    }
    if let WorkspaceTransitionIntent::Rollback {
        rollback_storage_generation,
    } = &parameters.intent
    {
        let rollback = environment
            .rollback_workspace_generation
            .as_ref()
            .ok_or(SupervisorError::InvalidState)?;
        if workspace_storage_generation(rollback)? != *rollback_storage_generation {
            return Err(SupervisorError::InvalidState);
        }
    }
    Ok(())
}

fn valid_environment_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 63
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn allocate_vsock_cid(environment_id: Uuid) -> u32 {
    let bytes = environment_id.as_bytes();
    let value = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    3 + value % (u32::MAX - 4)
}

fn prepare_runtime_root(path: &Path) -> Result<PrivateRoot, SupervisorError> {
    if !path.is_absolute() {
        return Err(SupervisorError::InvalidConfiguration);
    }
    let parent = path
        .parent()
        .filter(|parent| *parent != path)
        .ok_or(SupervisorError::InvalidConfiguration)?;
    if !parent.exists() {
        fs::create_dir_all(parent).map_err(|source| SupervisorError::Io {
            path: parent.to_owned(),
            source,
        })?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).map_err(|source| {
            SupervisorError::Io {
                path: parent.to_owned(),
                source,
            }
        })?;
    }
    let parent_root = PrivateRoot::open(parent)?;
    let root = match PrivateRoot::open(path) {
        Ok(root) => root,
        Err(PathError::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => {
            let leaf = path
                .file_name()
                .map(Path::new)
                .ok_or(SupervisorError::InvalidConfiguration)?;
            parent_root.create_dir(leaf, 0o700)?;
            PrivateRoot::open(path)?
        }
        Err(error) => return Err(error.into()),
    };
    root.ensure_dir(Path::new("engine"), 0o700)?;
    root.ensure_dir(Path::new("runners"), 0o700)?;
    Ok(root)
}

fn spawn_supervisor(config: &NativeRuntimeConfig) -> Result<Child, SupervisorError> {
    let mut command = Command::new(&config.executable);
    command
        .arg("__native-supervisor")
        .arg("--root")
        .arg(&config.root)
        .arg("--artifact-root")
        .arg(&config.artifact_root)
        .arg("--artifact-lock")
        .arg(&config.artifact_lock)
        .arg("--mesh-data-dir")
        .arg(&config.mesh_data_dir)
        .arg("--platform-config-dir")
        .arg(&config.platform_config_dir)
        .arg("--credential-authority-root")
        .arg(&config.credential_authority_root)
        .env_clear();
    command
        .current_dir(&config.root)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // SAFETY: scalar-only libc operations and one fixed-layout capset syscall
    // prepare a capability-empty, no-new-privileges, FD-clean detached
    // singleton before exec. The supervisor intentionally outlives this CLI.
    unsafe {
        command.pre_exec(|| {
            confine_spawned_process()?;
            if libc::setsid() < 0
                || libc::syscall(
                    libc::SYS_close_range,
                    3_u32,
                    u32::MAX,
                    libc::CLOSE_RANGE_CLOEXEC,
                ) != 0
            {
                return Err(io::Error::last_os_error());
            }
            libc::umask(0o077);
            Ok(())
        });
    }
    command
        .spawn()
        .map_err(|_| SupervisorError::SpawnSupervisor)
}

fn terminate_unadmitted_child(child: &mut Child) {
    if child.try_wait().ok().flatten().is_none() {
        let _ = signal_unreaped_child(child.id(), Signal::KILL);
        let _ = child.wait();
    }
}

fn confine_spawned_process() -> io::Result<()> {
    let header = LinuxCapabilityHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let empty = LinuxCapabilityData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    };
    let data = [empty; 2];
    // SAFETY: capset v3 reads one fixed header and exactly two fixed data
    // elements. pid=0 targets only this post-fork child thread.
    if unsafe { libc::syscall(libc::SYS_capset, std::ptr::addr_of!(header), data.as_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: both prctl operations use scalar arguments and mutate only this
    // post-fork child. Failure is fatal rather than launching less confined.
    if unsafe {
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL,
            0,
            0,
            0,
        )
    } != 0
        || unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

impl From<SupervisorError> for Status {
    fn from(error: SupervisorError) -> Self {
        match error {
            SupervisorError::InvalidRequest => Status::invalid_argument(error.to_string()),
            SupervisorError::AlreadyExists(_) => Status::already_exists(error.to_string()),
            SupervisorError::NotFound(_) => Status::not_found(error.to_string()),
            SupervisorError::NotRunning
            | SupervisorError::Orphaned
            | SupervisorError::OperationTerminal
            | SupervisorError::ArtifactGenerationChanged
            | SupervisorError::EnvironmentAccessUnavailable
            | SupervisorError::EnvironmentAccessBindingRejected(_)
            | SupervisorError::WorkloadSecretDeliveryUnavailable => {
                Status::failed_precondition(error.to_string())
            }
            SupervisorError::CredentialAuthorityUnavailable => {
                Status::unavailable(error.to_string())
            }
            SupervisorError::Workspace(workspace) => {
                Status::failed_precondition(workspace.to_string())
            }
            SupervisorError::WorkspacePlan(plan) => Status::failed_precondition(plan.to_string()),
            SupervisorError::RegistryReference(reference) => {
                Status::failed_precondition(reference.to_string())
            }
            SupervisorError::RegistryResolver(resolver) => {
                Status::failed_precondition(resolver.to_string())
            }
            SupervisorError::Runner(_) => Status::failed_precondition(error.to_string()),
            SupervisorError::VmStart(_)
            | SupervisorError::VmStop
            | SupervisorError::VmResize
            | SupervisorError::VmDelete => Status::failed_precondition(error.to_string()),
            SupervisorError::Store(SupervisorStoreError::RequestCollision)
            | SupervisorError::Store(SupervisorStoreError::JournalConflict) => {
                Status::aborted(error.to_string())
            }
            _ => Status::internal("native local supervisor operation failed"),
        }
    }
}

impl From<SupervisorConfigError> for SupervisorError {
    fn from(error: SupervisorConfigError) -> Self {
        match error {
            SupervisorConfigError::InvalidConfiguration => Self::InvalidConfiguration,
            SupervisorConfigError::SupervisorProtocolMismatch { expected, actual } => {
                Self::SupervisorProtocolMismatch { expected, actual }
            }
            SupervisorConfigError::InvalidSupervisorInfo => Self::InvalidSupervisorInfo,
            SupervisorConfigError::SupervisorConfigurationMismatch => {
                Self::SupervisorConfigurationMismatch
            }
            SupervisorConfigError::Io { path, source } => Self::Io { path, source },
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SupervisorError {
    #[error("native runtime configuration is invalid")]
    InvalidConfiguration,
    #[error("native environment request is invalid")]
    InvalidRequest,
    #[error("local environment {0:?} already exists")]
    AlreadyExists(String),
    #[error("native supervisor state is invalid")]
    InvalidState,
    #[error("native supervisor state must never contain a secret")]
    SecretInState,
    #[error("local credential authority is unavailable")]
    CredentialAuthorityUnavailable,
    #[error("native local workload-secret delivery is unavailable")]
    WorkloadSecretDeliveryUnavailable,
    #[error("local environment access binding is unavailable")]
    EnvironmentAccessUnavailable,
    #[error("local credential profile binding was rejected ({0})")]
    EnvironmentAccessBindingRejected(tonic::Code),
    #[error("local environment {0:?} was not found")]
    NotFound(String),
    #[error("local environment is not running")]
    NotRunning,
    #[error("local environment ownership is orphaned; inspect it with `cw doctor local`")]
    Orphaned,
    #[error("the native supervisor is already running")]
    AlreadyRunning,
    #[error("spawn native supervisor failed")]
    SpawnSupervisor,
    #[error("native supervisor startup timed out")]
    SupervisorStartTimeout,
    #[error("the running native supervisor does not implement the required compatibility protocol")]
    SupervisorProtocolUnavailable,
    #[error(
        "native supervisor protocol version mismatch: expected {expected}, running supervisor reported {actual}"
    )]
    SupervisorProtocolMismatch { expected: u32, actual: u32 },
    #[error("the running native supervisor returned invalid compatibility information")]
    InvalidSupervisorInfo,
    #[error("query running native supervisor compatibility failed")]
    SupervisorInfoUnavailable,
    #[error("the running native supervisor uses a different runtime configuration")]
    SupervisorConfigurationMismatch,
    #[error("spawn native environment runner failed")]
    SpawnRunner,
    #[error("native environment runner startup timed out")]
    RunnerStartTimeout,
    #[error("native environment runner adoption failed")]
    RunnerAdoption,
    #[error("native environment runner is unavailable")]
    RunnerUnavailable,
    #[error("native environment runner did not exit")]
    RunnerExitTimeout,
    #[error("native environment runner retirement failed")]
    RunnerRetirement,
    #[error("native environment runner returned invalid state")]
    InvalidRunnerResponse,
    #[error("native environment runner is live with a different runtime artifact generation")]
    ArtifactGenerationChanged,
    #[error("native VM start failed: {0}")]
    VmStart(String),
    #[error("native VM stop failed")]
    VmStop,
    #[error("native VM resize failed")]
    VmResize,
    #[error("native VM delete failed")]
    VmDelete,
    #[error("workspace provisioning task failed")]
    WorkspaceProvisionTask,
    #[error("workspace generation provisioning task failed")]
    WorkspaceGenerationProvisionTask,
    #[error("local lifecycle request is already terminal")]
    OperationTerminal,
    #[error("serve native supervisor failed")]
    Serve,
    #[error(transparent)]
    Runner(#[from] RunnerError),
    #[error(transparent)]
    Artifact(#[from] crate::artifact::ArtifactError),
    #[error("runtime artifact store operation failed")]
    ArtifactStore,
    #[error(transparent)]
    RunnerService(#[from] RunnerServiceError),
    #[error(transparent)]
    Recovery(#[from] RecoveryError),
    #[error(transparent)]
    Workspace(#[from] WorkspaceError),
    #[error(transparent)]
    WorkspacePlan(#[from] WorkspacePlanError),
    #[error(transparent)]
    RegistryReference(#[from] RegistryReferenceError),
    #[error(transparent)]
    RegistryResolver(#[from] RegistryResolverError),
    #[error(transparent)]
    ContentStore(#[from] ContentStoreError),
    #[error(transparent)]
    SetupPack(#[from] SetupPackError),
    #[error(transparent)]
    SkillSnapshot(#[from] SkillSnapshotPreparationError),
    #[error("workspace generation identity is invalid")]
    WorkspaceGeneration,
    #[error(transparent)]
    Generation(#[from] GenerationError),
    #[error(transparent)]
    Uds(#[from] UdsError),
    #[error(transparent)]
    Path(#[from] PathError),
    #[error(transparent)]
    State(#[from] StateError),
    #[error(transparent)]
    Store(#[from] SupervisorStoreError),
    #[error("filesystem operation failed for {path}: {source}")]
    Io { path: PathBuf, source: io::Error },
}

// Persist only closed classes, never Display/Debug or a source chain: nested
// registry, skill and filesystem errors can contain arbitrary upstream bytes
// or owner paths. The existing operation error_code is the diagnostic surface.
fn create_failure_code(error: &SupervisorError) -> &'static str {
    match error {
        SupervisorError::CredentialAuthorityUnavailable => {
            "create_credential_authority_unavailable"
        }
        SupervisorError::EnvironmentAccessUnavailable => "create_access_unavailable",
        SupervisorError::EnvironmentAccessBindingRejected(code) => match code {
            tonic::Code::InvalidArgument => "create_access_binding_invalid",
            tonic::Code::NotFound => "create_access_binding_not_found",
            tonic::Code::PermissionDenied | tonic::Code::Unauthenticated => {
                "create_access_binding_denied"
            }
            tonic::Code::FailedPrecondition => "create_access_binding_precondition",
            tonic::Code::DataLoss => "create_access_binding_metadata",
            _ => "create_access_binding_rejected",
        },
        SupervisorError::RegistryResolver(error) => match error {
            RegistryResolverError::Client => "create_registry_client",
            RegistryResolverError::Transport => "create_registry_transport",
            RegistryResolverError::AuthenticationRequired => "create_registry_auth_required",
            RegistryResolverError::AuthenticationFailed => "create_registry_auth_failed",
            RegistryResolverError::NotFound => "create_registry_not_found",
            RegistryResolverError::RegistryResponse => "create_registry_response",
            RegistryResolverError::UnsafeUrl
            | RegistryResolverError::UnsafeRedirect
            | RegistryResolverError::TooManyRedirects => "create_registry_url_rejected",
            RegistryResolverError::UnsupportedHostArchitecture
            | RegistryResolverError::PlatformUnavailable
            | RegistryResolverError::AmbiguousPlatform
            | RegistryResolverError::UnsupportedPlatform => "create_registry_platform",
            RegistryResolverError::Reference(_) => "create_registry_reference",
            RegistryResolverError::Content(ContentStoreError::Stream) => {
                "create_registry_blob_stream"
            }
            RegistryResolverError::Content(
                ContentStoreError::SizeMismatch { .. }
                | ContentStoreError::DigestMismatch
                | ContentStoreError::ExistingBlobInvalid,
            ) => "create_registry_blob_integrity",
            RegistryResolverError::Content(_) => "create_registry_content_store",
            _ => "create_registry_admission",
        },
        SupervisorError::RegistryReference(_) => "create_registry_reference",
        SupervisorError::SkillSnapshot(_) => "create_skill_snapshot",
        SupervisorError::WorkspaceGenerationProvisionTask => "create_workspace_generation_task",
        SupervisorError::WorkspaceGeneration => "create_workspace_generation_invalid",
        SupervisorError::ContentStore(_) => "create_content_store",
        SupervisorError::Path(_) | SupervisorError::Io { .. } => "create_filesystem",
        SupervisorError::InvalidState => "create_state_invalid",
        SupervisorError::InvalidConfiguration => "create_configuration_invalid",
        _ => "create_failed",
    }
}

impl SupervisorError {
    fn incompatible_supervisor(&self) -> bool {
        matches!(
            self,
            Self::SupervisorProtocolUnavailable
                | Self::SupervisorProtocolMismatch { .. }
                | Self::InvalidSupervisorInfo
                | Self::SupervisorInfoUnavailable
                | Self::SupervisorConfigurationMismatch
        )
    }
}

impl From<WorkspaceGenerationError> for SupervisorError {
    fn from(_: WorkspaceGenerationError) -> Self {
        Self::WorkspaceGeneration
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;

    use super::*;
    use crate::artifact::{
        ARTIFACT_LOCK_SCHEMA_VERSION, ArtifactArchitecture, ArtifactLock, ArtifactSpec,
        CLOUD_HYPERVISOR_RELEASE, ExecutableArtifactSpec,
    };
    use crate::oci::{OciArchitecture, ResolvedDescriptor, ResolvedImage, Sha256Digest};
    use crate::uds::bind_owner_only;
    use codewire_access::builtin_provider_catalog;
    use codewire_local_credentials::{LocalCredentialClient, serve_local_credential_authority};
    use codewire_protected_store::EphemeralProtectedStore;

    fn project_intent(vcpus: u32, memory_mib: u32, disk_gib: u64) -> (Vec<u8>, String) {
        let spec = codewire_project::ProjectSpec {
            image: "registry.example/codewire/workspace:latest".to_owned(),
            resources: codewire_project::ResourceSpec {
                cpu_millicores: Some(vcpus * 1_000),
                memory_mib: Some(u64::from(memory_mib)),
                disk_gib: Some(disk_gib),
            },
            ..Default::default()
        };
        let bytes = spec.canonical_json().unwrap();
        let digest = format!("{:x}", Sha256::digest(&bytes));
        (bytes, digest)
    }

    fn test_digest(seed: &[u8]) -> Sha256Digest {
        Sha256Digest::parse(&format!("sha256:{:x}", Sha256::digest(seed))).unwrap()
    }

    fn install_test_artifact_generation(
        engine: &PrivateRoot,
        kernel_bytes: &[u8],
    ) -> (String, String) {
        fn spec(path: &str, bytes: &[u8]) -> ArtifactSpec {
            ArtifactSpec {
                path: path.into(),
                size: bytes.len() as u64,
                sha256: format!("{:x}", Sha256::digest(bytes)),
                architecture: ArtifactArchitecture::host().unwrap(),
            }
        }

        let cloud_hypervisor = spec("bin/cloud-hypervisor", b"cloud-hypervisor");
        let kernel = spec("boot/kernel", kernel_bytes);
        let initramfs = spec("boot/initramfs", b"initramfs");
        let lock = ArtifactLock {
            schema_version: ARTIFACT_LOCK_SCHEMA_VERSION,
            cloud_hypervisor: ExecutableArtifactSpec {
                artifact: cloud_hypervisor.clone(),
                version: CLOUD_HYPERVISOR_RELEASE.to_owned(),
            },
            virtiofsd: None,
            kernel: kernel.clone(),
            initramfs: initramfs.clone(),
        };
        RuntimeArtifactStore::create(engine).unwrap();
        let blobs = engine.path().join("runtime-artifacts/blobs");
        for (prefix, artifact, bytes, permissions) in [
            (
                "x",
                &cloud_hypervisor,
                b"cloud-hypervisor".as_slice(),
                0o500,
            ),
            ("r", &kernel, kernel_bytes, 0o400),
            ("r", &initramfs, b"initramfs".as_slice(), 0o400),
        ] {
            let path = blobs.join(format!("{prefix}-{}", artifact.sha256));
            if !path.exists() {
                fs::write(&path, bytes).unwrap();
                fs::set_permissions(&path, fs::Permissions::from_mode(permissions)).unwrap();
            }
        }
        let generation = lock.generation().unwrap();
        let manifest = engine
            .path()
            .join("runtime-artifacts/generations")
            .join(format!("{generation}.json"));
        fs::write(&manifest, lock.canonical_json().unwrap()).unwrap();
        fs::set_permissions(&manifest, fs::Permissions::from_mode(0o400)).unwrap();
        (generation, kernel.sha256)
    }

    pub(super) fn test_workspace_generation(
        project_spec_json: &[u8],
        project_sha256: &str,
        seed: &[u8],
    ) -> WorkspaceGenerationRecord {
        test_workspace_generation_with_artifact(
            project_spec_json,
            project_sha256,
            &"b".repeat(64),
            seed,
        )
    }

    fn test_workspace_generation_with_artifact(
        project_spec_json: &[u8],
        project_sha256: &str,
        artifact_generation: &str,
        seed: &[u8],
    ) -> WorkspaceGenerationRecord {
        let project: codewire_project::ProjectSpec =
            serde_json::from_slice(project_spec_json).unwrap();
        let manifest = ResolvedDescriptor {
            media_type: "application/vnd.oci.image.manifest.v1+json".to_owned(),
            digest: test_digest(&[seed, b"-manifest"].concat()),
            size: 128,
        };
        WorkspaceGenerationRecord::new(
            project_spec_json,
            project_sha256.to_owned(),
            artifact_generation.to_owned(),
            ResolvedImage {
                source_reference: project.image,
                architecture: OciArchitecture::native().unwrap(),
                source: manifest.clone(),
                manifest,
                config: ResolvedDescriptor {
                    media_type: "application/vnd.oci.image.config.v1+json".to_owned(),
                    digest: test_digest(&[seed, b"-config"].concat()),
                    size: 128,
                },
                layers: Vec::new(),
            },
            crate::linux::state::MINIMUM_ROOT_DISK_BYTES,
        )
        .unwrap()
    }

    struct RuntimeTransitionFixture {
        old_artifact: String,
        next_artifact: String,
        old_workspace: WorkspaceGenerationRecord,
        next_workspace: WorkspaceGenerationRecord,
    }

    fn same_image_runtime_transition(environment: &EnvironmentRecord) -> RuntimeTransitionFixture {
        let project_json = environment.project_spec_json.as_deref().unwrap();
        let project_sha256 = environment.project_spec_sha256.as_deref().unwrap();
        let old_artifact = "b".repeat(64);
        let next_artifact = "c".repeat(64);
        let old_workspace = test_workspace_generation_with_artifact(
            project_json,
            project_sha256,
            &old_artifact,
            b"same-image",
        );
        let next_workspace = test_workspace_generation_with_artifact(
            project_json,
            project_sha256,
            &next_artifact,
            b"same-image",
        );
        assert_eq!(
            old_workspace.root_generation,
            next_workspace.root_generation
        );
        assert_ne!(
            workspace_storage_generation(&old_workspace).unwrap(),
            workspace_storage_generation(&next_workspace).unwrap()
        );
        RuntimeTransitionFixture {
            old_artifact,
            next_artifact,
            old_workspace,
            next_workspace,
        }
    }

    pub(super) fn project_environment() -> EnvironmentRecord {
        let (project_spec_json, project_spec_sha256) = project_intent(2, 16 * 1024, 20);
        EnvironmentRecord {
            id: Uuid::new_v4(),
            name: "dev".to_owned(),
            state: StoredEnvironmentState::Stopped,
            vcpus: 2,
            memory_mib: 16 * 1024,
            disk_bytes: 20 * 1024 * 1024 * 1024,
            docker_disk_bytes: 0,
            generation: 1,
            host_ports: Vec::new(),
            mesh: None,
            workspace_plan: WorkspacePlan::local(&crate::workspace::WorkspaceSource {
                source_path: PathBuf::from("/workspace/source"),
                commit: "a".repeat(40),
                mode: WorkspaceSourceMode::Clone,
            })
            .unwrap(),
            project_spec_json: Some(project_spec_json),
            project_spec_sha256: Some(project_spec_sha256),
            access_profile: None,
            access_binding: None,
            platform_source_authority: None,
            runner: None,
            active_artifact_generation: Some("b".repeat(64)),
            staging_artifact_generation: None,
            active_workspace_generation: None,
            staging_workspace_generation: None,
            rollback_workspace_generation: None,
        }
    }

    fn direct_workspace_plan(source: &Path) -> WorkspacePlan {
        let admitted = crate::direct_share::admit_direct_share(source, &[]).unwrap();
        WorkspacePlan::from_inputs(vec![WorkspaceInput::direct(
            &admitted,
            "/workspace/fixtures",
            true,
        )])
        .unwrap()
    }

    fn project_environment_with_secret_selection(
        secrets: codewire_project::SecretBindings,
        environment_values: BTreeMap<String, String>,
    ) -> EnvironmentRecord {
        let mut environment = project_environment();
        let mut project: codewire_project::ProjectSpec =
            serde_json::from_slice(environment.project_spec_json.as_deref().unwrap()).unwrap();
        project.secrets = secrets;
        project.environment = environment_values;
        if project.secrets.organization
            || project.secrets.user == Some(codewire_project::StoragePlacement::Platform)
            || project.secrets.project.starts_with("platform:")
        {
            environment.platform_source_authority = Some(
                sources::PlatformSourceAuthority::from_proto(&v1::PlatformSourceAuthority {
                    server_url: "https://codewire.example".into(),
                    organization_id: "synthetic-org".into(),
                    user_id: "synthetic-user".into(),
                    profile_slots: Vec::new(),
                })
                .unwrap(),
            );
        }
        let project_spec_json = project.canonical_json().unwrap();
        let project_spec_sha256 = format!("{:x}", Sha256::digest(&project_spec_json));
        environment.project_spec_json = Some(project_spec_json.clone());
        environment.project_spec_sha256 = Some(project_spec_sha256.clone());
        environment.active_workspace_generation = Some(test_workspace_generation(
            &project_spec_json,
            &project_spec_sha256,
            b"workload-secret-selection",
        ));
        environment.validate("dev").unwrap();
        environment
    }

    async fn start_test_credential_authority(
        core: &SupervisorCore,
    ) -> (
        LocalCredentialClient,
        tokio::task::JoinHandle<Result<(), codewire_local_credentials::AuthorityRuntimeError>>,
    ) {
        let config = core.config.credential_authority_config();
        let server_config = config.clone();
        let server = tokio::spawn(async move {
            serve_local_credential_authority(
                server_config,
                EphemeralProtectedStore::default(),
                builtin_provider_catalog(),
            )
            .await
        });
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        loop {
            match LocalCredentialClient::connect(&config).await {
                Ok(client) => return (client, server),
                Err(_) if tokio::time::Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Err(error) => panic!("test credential authority did not start: {error}"),
            }
        }
    }

    async fn bind_test_environment_access(
        core: &mut SupervisorCore,
        authority: &mut LocalCredentialClient,
    ) -> EnvironmentAccessBinding {
        let profile = authority
            .create_profile(
                &codewire_access::AccessProfileName::parse("work").unwrap(),
                &BTreeMap::new(),
            )
            .await
            .unwrap();
        let binding = EnvironmentAccessBinding {
            environment_id: access_environment_id(core.environment("dev").unwrap().id).unwrap(),
            profile_id: profile.profile.id,
            profile_revision: profile.profile.revision,
        };
        authority
            .create_environment_access_binding(&binding)
            .await
            .unwrap();
        let environment = core.environment_mut("dev").unwrap();
        environment.access_profile = Some("user/work".parse().unwrap());
        environment.access_binding = Some(binding.clone());
        let mut project: codewire_project::ProjectSpec =
            serde_json::from_slice(environment.project_spec_json.as_deref().unwrap()).unwrap();
        project.credentials = Some(codewire_project::CredentialBinding {
            profile: format!("local:id:{}", binding.profile_id),
        });
        let json = project.canonical_json().unwrap();
        environment.project_spec_sha256 = Some(format!("{:x}", Sha256::digest(&json)));
        environment.project_spec_json = Some(json);
        environment.validate("dev").unwrap();
        core.save().unwrap();
        binding
    }

    fn project_environment_with_access() -> EnvironmentRecord {
        let mut environment = project_environment();
        let mut project: codewire_project::ProjectSpec =
            serde_json::from_slice(environment.project_spec_json.as_deref().unwrap()).unwrap();
        project.credentials = Some(codewire_project::CredentialBinding {
            profile: "local:id:11111111-1111-4111-8111-111111111111".into(),
        });
        let project_spec_json = project.canonical_json().unwrap();
        environment.project_spec_sha256 = Some(format!(
            "{:x}",
            Sha256::digest(project_spec_json.as_slice())
        ));
        environment.project_spec_json = Some(project_spec_json);
        environment.access_profile = Some("user/work".parse().unwrap());
        environment.access_binding = Some(EnvironmentAccessBinding {
            environment_id: access_environment_id(environment.id).unwrap(),
            profile_id: AccessProfileId::parse("11111111-1111-4111-8111-111111111111").unwrap(),
            profile_revision: 7,
        });
        environment.validate("dev").unwrap();
        environment
    }

    fn workspace_update_payload(
        environment: &EnvironmentRecord,
        project_spec_json: &[u8],
        project_spec_sha256: &str,
        was_running: bool,
    ) -> serde_json::Value {
        let active = environment.active_workspace_generation.as_ref().unwrap();
        serde_json::json!({
            "name": environment.name,
            "project_spec_json": std::str::from_utf8(project_spec_json).unwrap(),
            "project_spec_sha256": project_spec_sha256,
            "prior_storage_generation": workspace_storage_generation(active).unwrap(),
            "target_generation": environment.generation + 1,
            "was_running": was_running,
        })
    }

    fn workspace_rollback_payload(
        environment: &EnvironmentRecord,
        was_running: bool,
    ) -> serde_json::Value {
        let active = environment.active_workspace_generation.as_ref().unwrap();
        let rollback = environment.rollback_workspace_generation.as_ref().unwrap();
        serde_json::json!({
            "name": environment.name,
            "prior_storage_generation": workspace_storage_generation(active).unwrap(),
            "rollback_storage_generation": workspace_storage_generation(rollback).unwrap(),
            "target_generation": environment.generation + 1,
            "was_running": was_running,
        })
    }

    fn test_workspace_transition_operation(
        environment: &EnvironmentRecord,
        kind: OperationKind,
        payload: serde_json::Value,
        checkpoint: u32,
    ) -> OperationRecord {
        OperationRecord {
            operation_id: Uuid::new_v4(),
            request_id: Uuid::new_v4(),
            environment_id: Some(environment.id),
            kind,
            phase: if checkpoint == 0 {
                OperationPhase::Intent
            } else {
                OperationPhase::EffectApplied
            },
            checkpoint,
            payload,
            result: None,
            error_code: None,
            created_unix_ms: 1,
            updated_unix_ms: 1,
        }
    }

    fn begin_and_advance_test_operation(
        store: &SupervisorStore,
        environment_id: Uuid,
        kind: OperationKind,
        payload: &serde_json::Value,
        checkpoint: u32,
    ) -> OperationRecord {
        assert!(usize::try_from(checkpoint).unwrap() <= crate::lifecycle::effects(kind).len());
        let mut operation = store
            .begin_operation(Uuid::new_v4(), Some(environment_id), kind, payload)
            .unwrap();
        for _ in 0..checkpoint {
            operation = store
                .advance_operation(
                    operation.operation_id,
                    operation.checkpoint,
                    OperationPhase::EffectApplied,
                    None,
                    None,
                )
                .unwrap();
        }
        operation
    }

    pub(super) fn test_supervisor_core(
        environment: EnvironmentRecord,
    ) -> (tempfile::TempDir, SupervisorCore) {
        let parent = tempfile::tempdir().unwrap();
        let root_path = parent.path().join("runtime");
        fs::create_dir(&root_path).unwrap();
        fs::set_permissions(&root_path, fs::Permissions::from_mode(0o700)).unwrap();
        let root = PrivateRoot::open(&root_path).unwrap();
        root.ensure_dir(Path::new("engine"), 0o700).unwrap();
        root.ensure_dir(Path::new("runners"), 0o700).unwrap();
        let lock = SupervisorLock::acquire(&root).unwrap();
        let (store, _) = SupervisorStore::open(&root).unwrap();
        let state = SupervisorState {
            schema_version: SUPERVISOR_STATE_SCHEMA,
            current: Some(environment.name.clone()),
            environments: [(environment.name.clone(), environment)].into(),
        };
        store.replace_state(&state).unwrap();
        let core = SupervisorCore {
            config: NativeRuntimeConfig {
                root: root_path,
                artifact_root: parent.path().join("artifacts"),
                artifact_lock: parent.path().join("artifacts.lock.json"),
                mesh_data_dir: parent.path().join("mesh-auth"),
                platform_config_dir: parent.path().join("platform-auth"),
                credential_authority_root: parent.path().join("credentials"),
                executable: PathBuf::from("/usr/bin/true"),
            },
            root,
            store,
            state,
            children: HashMap::new(),
            live_runners: HashMap::new(),
            operation_progress: broadcast::channel(OPERATION_PROGRESS_CAPACITY).0,
            _lock: lock,
        };
        (parent, core)
    }

    pub(super) fn test_supervisor_service(core: SupervisorCore) -> SupervisorRpc {
        let operation_reader = SupervisorOperationReader::open(&core.root).unwrap();
        let operation_events = core.store.operation_events();
        let operation_progress = core.operation_progress.clone();
        let info = supervisor_info(&core.config);
        let (shutdown, _shutdown_rx) = watch::channel(false);
        SupervisorRpc {
            info,
            core: Arc::new(Mutex::new(core)),
            shutdown,
            operation_reader: Arc::new(Mutex::new(operation_reader)),
            operation_events,
            operation_progress,
            worker_running: Arc::new(AtomicBool::new(false)),
        }
    }

    pub(super) fn spawn_test_supervisor_server(
        socket: &Path,
        service: SupervisorRpc,
    ) -> (
        SocketIdentity,
        tokio::sync::oneshot::Sender<()>,
        tokio::task::JoinHandle<()>,
    ) {
        let (listener, socket_identity) = bind_owner_only_listener(socket).unwrap();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(async move {
            axum::serve(listener, public_api::supervisor_router(service))
                .with_graceful_shutdown(async move {
                    let _ = shutdown_rx.await;
                })
                .await
                .unwrap();
        });
        (socket_identity, shutdown_tx, server)
    }

    #[derive(Clone, Copy)]
    enum TestRunnerProtocolReply {
        Version(u32),
        Failure(tonic::Code),
    }

    #[derive(Clone)]
    struct TestRunnerProtocolService {
        reply: TestRunnerProtocolReply,
        useful_calls: Arc<AtomicUsize>,
        shutdown_effect: Option<Arc<std::sync::Mutex<Option<std::process::ChildStdin>>>>,
    }

    impl TestRunnerProtocolService {
        fn unexpected_use<T>(&self) -> Result<Response<T>, Status> {
            self.useful_calls.fetch_add(1, Ordering::Relaxed);
            Err(Status::unimplemented("test runner RPC is not implemented"))
        }
    }

    #[tonic::async_trait]
    impl crate::control::v1::environment_runner_service_server::EnvironmentRunnerService
        for TestRunnerProtocolService
    {
        async fn get_runner_protocol_info(
            &self,
            _request: Request<v1::GetRunnerProtocolInfoRequest>,
        ) -> Result<Response<v1::RunnerProtocolInfo>, Status> {
            match self.reply {
                TestRunnerProtocolReply::Version(protocol_version) => {
                    Ok(Response::new(v1::RunnerProtocolInfo { protocol_version }))
                }
                TestRunnerProtocolReply::Failure(code) => {
                    Err(Status::new(code, "untrusted test peer detail"))
                }
            }
        }

        async fn adopt_runner(
            &self,
            _request: Request<v1::AdoptRunnerRequest>,
        ) -> Result<Response<v1::RunnerInfo>, Status> {
            self.unexpected_use()
        }

        async fn get_runner_info(
            &self,
            _request: Request<v1::GetRunnerInfoRequest>,
        ) -> Result<Response<v1::RunnerInfo>, Status> {
            self.unexpected_use()
        }

        type WatchRunnerStream =
            Pin<Box<dyn Stream<Item = Result<v1::RunnerEvent, Status>> + Send + 'static>>;

        async fn watch_runner(
            &self,
            _request: Request<v1::WatchRunnerRequest>,
        ) -> Result<Response<Self::WatchRunnerStream>, Status> {
            self.unexpected_use()
        }

        async fn start_vm(
            &self,
            _request: Request<v1::StartVmRequest>,
        ) -> Result<Response<v1::RunnerInfo>, Status> {
            self.unexpected_use()
        }

        async fn stop_vm(
            &self,
            _request: Request<v1::StopVmRequest>,
        ) -> Result<Response<v1::RunnerInfo>, Status> {
            self.unexpected_use()
        }

        async fn grow_state_disk(
            &self,
            _request: Request<v1::GrowStateDiskRequest>,
        ) -> Result<Response<v1::GrowStateDiskResponse>, Status> {
            self.unexpected_use()
        }

        async fn prepare_retire_runner(
            &self,
            _request: Request<v1::PrepareRetireRunnerRequest>,
        ) -> Result<Response<v1::PrepareRetireRunnerResponse>, Status> {
            self.unexpected_use()
        }

        async fn shutdown_runner(
            &self,
            _request: Request<v1::ShutdownRunnerRequest>,
        ) -> Result<Response<v1::ShutdownRunnerResponse>, Status> {
            if let Some(effect) = &self.shutdown_effect {
                if let Some(mut input) = effect.lock().unwrap().take() {
                    std::io::Write::write_all(&mut input, b"retire\n").unwrap();
                }
                return Err(Status::unavailable(
                    "synthetic response lost after shutdown effect",
                ));
            }
            self.unexpected_use()
        }

        async fn get_daemon_access(
            &self,
            _request: Request<v1::GetDaemonAccessRequest>,
        ) -> Result<Response<v1::DaemonAccess>, Status> {
            self.unexpected_use()
        }

        async fn get_generation_daemon_access(
            &self,
            _request: Request<v1::GetGenerationDaemonAccessRequest>,
        ) -> Result<Response<v1::DaemonAccess>, Status> {
            self.unexpected_use()
        }
    }

    fn spawn_test_runner_protocol_server(
        socket: &Path,
        reply: TestRunnerProtocolReply,
    ) -> (
        SocketIdentity,
        Arc<AtomicUsize>,
        tokio::sync::oneshot::Sender<()>,
        tokio::task::JoinHandle<()>,
    ) {
        let (incoming, socket_identity) = bind_owner_only(socket).unwrap();
        let useful_calls = Arc::new(AtomicUsize::new(0));
        let service = TestRunnerProtocolService {
            reply,
            useful_calls: Arc::clone(&useful_calls),
            shutdown_effect: None,
        };
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(
                    crate::control::v1::environment_runner_service_server::EnvironmentRunnerServiceServer::new(
                        service,
                    ),
                )
                .serve_with_incoming_shutdown(incoming, async move {
                    let _ = shutdown_rx.await;
                })
                .await
                .unwrap();
        });
        (socket_identity, useful_calls, shutdown_tx, server)
    }

    fn attach_test_runner_process(
        core: &mut SupervisorCore,
        socket_identity: SocketIdentity,
    ) -> (Uuid, ProcessIdentity) {
        attach_named_test_runner_process(core, "dev", socket_identity)
    }

    #[tokio::test]
    async fn unacknowledged_runner_shutdown_still_observes_natural_exit() {
        use crate::control::v1::environment_runner_service_server::EnvironmentRunnerServiceServer;
        let parent = tempfile::tempdir().unwrap();
        fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let socket = parent.path().join("shutdown.sock");
        let executable = fs::canonicalize("/bin/sh").unwrap();
        let mut child = Command::new(&executable)
            .args([
                "-c",
                "read -r retirement_command; test \"$retirement_command\" = retire",
            ])
            .stdin(Stdio::piped())
            .spawn()
            .unwrap();
        let live = LiveProcess::capture_child(child.id(), &executable).unwrap();
        let service = TestRunnerProtocolService {
            reply: TestRunnerProtocolReply::Version(3),
            useful_calls: Arc::new(AtomicUsize::new(0)),
            shutdown_effect: Some(Arc::new(std::sync::Mutex::new(child.stdin.take()))),
        };
        let (incoming, identity) = bind_owner_only(&socket).unwrap();
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(EnvironmentRunnerServiceServer::new(service))
                .serve_with_incoming_shutdown(incoming, async {
                    let _ = stopped.await;
                })
                .await
                .unwrap();
        });
        let mut client = RunnerClient::connect(&socket).await.unwrap();
        // The mock performs the actual child shutdown effect, then returns an
        // unavailable response. The supervisor must still observe normal exit,
        // with the Child retained here rather than moved into a detached wait.
        assert!(
            request_runner_shutdown_and_observe(&mut client, Uuid::new_v4(), 1, &live)
                .await
                .unwrap()
        );
        assert!(child.try_wait().unwrap().unwrap().success());
        assert!(live.is_exited().unwrap());
        drop(client);
        stop.send(()).unwrap();
        server.await.unwrap();
        remove_bound_socket(&socket, &identity).unwrap();
    }

    #[tokio::test]
    async fn unresponsive_runner_retains_child_and_exact_pidfd_for_fallback() {
        let parent = tempfile::tempdir().unwrap();
        fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let socket = parent.path().join("unresponsive.sock");
        let (identity, calls, stop, server) =
            spawn_test_runner_protocol_server(&socket, TestRunnerProtocolReply::Version(3));
        let executable = fs::canonicalize("/bin/sleep").unwrap();
        let mut child = Command::new(&executable).arg("60").spawn().unwrap();
        let live = LiveProcess::capture_child(child.id(), &executable).unwrap();
        let mut client = RunnerClient::connect(&socket).await.unwrap();
        assert!(
            !request_runner_shutdown_and_observe(&mut client, Uuid::new_v4(), 1, &live)
                .await
                .unwrap()
        );
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        assert!(child.try_wait().unwrap().is_none());
        live.signal(Signal::KILL).unwrap();
        assert!(!child.wait().unwrap().success());
        assert!(live.is_exited().unwrap());
        drop(client);
        stop.send(()).unwrap();
        server.await.unwrap();
        remove_bound_socket(&socket, &identity).unwrap();
    }

    fn attach_named_test_runner_process(
        core: &mut SupervisorCore,
        name: &str,
        socket_identity: SocketIdentity,
    ) -> (Uuid, ProcessIdentity) {
        let executable = fs::canonicalize("/bin/sleep").unwrap();
        let child = Command::new(&executable).arg("60").spawn().unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        while fs::read_link(format!("/proc/{}/exe", child.id()))
            .ok()
            .as_deref()
            != Some(executable.as_path())
        {
            assert!(
                std::time::Instant::now() < deadline,
                "test runner child did not reach its expected executable"
            );
            std::thread::yield_now();
        }
        let environment_id = core.environment(name).unwrap().id;
        let live = LiveProcess::capture_child(child.id(), &executable).unwrap();
        let process_identity = live.identity().clone();
        let runner = RunnerRecord {
            process: process_identity.clone(),
            socket: socket_identity,
            artifact_generation: core
                .environment(name)
                .unwrap()
                .active_artifact_generation
                .clone()
                .unwrap(),
            error_code: None,
        };
        let environment = core.environment_mut(name).unwrap();
        environment.state = StoredEnvironmentState::Running;
        environment.runner = Some(runner);
        core.save().unwrap();
        core.live_runners.insert(environment_id, live);
        core.children.insert(environment_id, child);
        (environment_id, process_identity)
    }

    fn test_supervisor_core_after_host_reboot(
        environment: EnvironmentRecord,
        kind: OperationKind,
        payload: &serde_json::Value,
        checkpoint: u32,
    ) -> (tempfile::TempDir, SupervisorCore) {
        assert!(checkpoint > 0);
        let parent = tempfile::tempdir().unwrap();
        let root_path = parent.path().join("runtime");
        fs::create_dir(&root_path).unwrap();
        fs::set_permissions(&root_path, fs::Permissions::from_mode(0o700)).unwrap();
        let root = PrivateRoot::open(&root_path).unwrap();
        root.ensure_dir(Path::new("engine"), 0o700).unwrap();
        root.ensure_dir(Path::new("runners"), 0o700).unwrap();
        let (store, _) = SupervisorStore::open_for_boot(&root, "boot-before").unwrap();
        let environment_id = environment.id;
        let state = SupervisorState {
            schema_version: SUPERVISOR_STATE_SCHEMA,
            current: Some(environment.name.clone()),
            environments: [(environment.name.clone(), environment)].into(),
        };
        store.replace_state(&state).unwrap();
        begin_and_advance_test_operation(&store, environment_id, kind, payload, checkpoint);
        drop(store);

        let (store, _) = SupervisorStore::open_for_boot(&root, "boot-after").unwrap();
        assert_eq!(
            store
                .host_reboot_interrupted_workspace_transitions()
                .unwrap()
                .len(),
            1
        );
        drop(store);
        let (store, state) = SupervisorStore::open_for_boot(&root, "boot-after-again").unwrap();
        assert_eq!(
            store
                .host_reboot_interrupted_workspace_transitions()
                .unwrap()
                .len(),
            1
        );
        let lock = SupervisorLock::acquire(&root).unwrap();
        let core = SupervisorCore {
            config: NativeRuntimeConfig {
                root: root_path,
                artifact_root: parent.path().join("artifacts"),
                artifact_lock: parent.path().join("artifacts.lock.json"),
                mesh_data_dir: parent.path().join("mesh-auth"),
                platform_config_dir: parent.path().join("platform-auth"),
                credential_authority_root: parent.path().join("credentials"),
                executable: PathBuf::from("/usr/bin/true"),
            },
            root,
            store,
            state,
            children: HashMap::new(),
            live_runners: HashMap::new(),
            operation_progress: broadcast::channel(OPERATION_PROGRESS_CAPACITY).0,
            _lock: lock,
        };
        (parent, core)
    }

    #[test]
    fn readiness_promotion_rotates_only_durable_workspace_generations() {
        let mut environment = project_environment();
        let project_spec_json = environment.project_spec_json.as_deref().unwrap();
        let project_sha256 = environment.project_spec_sha256.as_deref().unwrap();
        let active = test_workspace_generation(project_spec_json, project_sha256, b"active");
        let staging = test_workspace_generation(project_spec_json, project_sha256, b"staging");
        let old_rollback =
            test_workspace_generation(project_spec_json, project_sha256, b"old-rollback");
        environment.active_workspace_generation = Some(active.clone());
        environment.staging_workspace_generation = Some(staging.clone());
        environment.rollback_workspace_generation = Some(old_rollback.clone());
        environment.validate("dev").unwrap();

        let displaced = environment.promote_staging_workspace_generation().unwrap();

        assert_eq!(environment.active_workspace_generation, Some(staging));
        assert_eq!(environment.rollback_workspace_generation, Some(active));
        assert_eq!(displaced, Some(old_rollback));
        assert!(environment.staging_workspace_generation.is_none());
        environment.validate("dev").unwrap();
    }

    #[test]
    fn artifact_transition_and_rollback_keep_distinct_exact_storage_generations() {
        let mut environment = project_environment();
        let RuntimeTransitionFixture {
            old_artifact,
            next_artifact,
            old_workspace: active,
            next_workspace: staging,
        } = same_image_runtime_transition(&environment);
        environment.active_workspace_generation = Some(active.clone());
        environment.staging_workspace_generation = Some(staging.clone());
        environment.staging_artifact_generation = Some(next_artifact.clone());
        environment.validate("dev").unwrap();

        assert!(
            environment
                .promote_staging_workspace_generation()
                .unwrap()
                .is_none()
        );

        assert_eq!(environment.active_artifact_generation, Some(next_artifact));
        assert_eq!(
            environment.active_workspace_generation,
            Some(staging.clone())
        );
        assert_eq!(
            environment.rollback_workspace_generation,
            Some(active.clone())
        );
        assert_eq!(
            referenced_root_storage_generations(&environment)
                .unwrap()
                .len(),
            2
        );

        let active_storage =
            workspace_storage_generation(environment.active_workspace_generation.as_ref().unwrap())
                .unwrap();
        let rollback_storage = workspace_storage_generation(
            environment.rollback_workspace_generation.as_ref().unwrap(),
        )
        .unwrap();
        environment
            .stage_rollback_workspace_generation(&active_storage, &rollback_storage)
            .unwrap();
        assert_eq!(
            environment.staging_artifact_generation,
            Some(old_artifact.clone())
        );
        let _displaced = environment.promote_staging_workspace_generation().unwrap();

        assert_eq!(environment.active_artifact_generation, Some(old_artifact));
        assert_eq!(environment.active_workspace_generation, Some(active));
        assert_eq!(environment.rollback_workspace_generation, Some(staging));
        environment.validate("dev").unwrap();
    }

    #[tokio::test]
    async fn replayed_runtime_only_update_promotes_the_exact_staging_artifact() {
        let mut environment = project_environment();
        let project_json = environment.project_spec_json.clone().unwrap();
        let project_sha256 = environment.project_spec_sha256.clone().unwrap();
        let RuntimeTransitionFixture {
            old_artifact: _,
            next_artifact,
            old_workspace: active,
            next_workspace: staging,
        } = same_image_runtime_transition(&environment);
        environment.active_workspace_generation = Some(active.clone());
        environment.staging_workspace_generation = Some(staging.clone());
        environment.staging_artifact_generation = Some(next_artifact.clone());
        environment.validate("dev").unwrap();
        let payload = workspace_update_payload(&environment, &project_json, &project_sha256, false);
        let parameters = workspace_transition_parameters(
            &test_workspace_transition_operation(
                &environment,
                OperationKind::UpdateWorkspace,
                payload.clone(),
                1,
            ),
            &environment,
        )
        .unwrap();
        assert!(workspace_transition_requires_boot(&environment, &parameters).unwrap());
        reserve_boot_generation(&mut environment, parameters.target_generation).unwrap();
        let environment_id = environment.id;
        let (_parent, mut core) = test_supervisor_core(environment);
        let operation = begin_and_advance_test_operation(
            &core.store,
            environment_id,
            OperationKind::UpdateWorkspace,
            &payload,
            7,
        );
        let request_id = operation.request_id;

        core.replay_pending_operations().await.unwrap();

        let operation = core
            .store
            .operation_by_request(request_id)
            .unwrap()
            .unwrap();
        assert_eq!(operation.phase, OperationPhase::Completed);
        assert_eq!(operation.checkpoint, 10);
        let environment = core.environment("dev").unwrap();
        assert_eq!(environment.state, StoredEnvironmentState::Stopped);
        assert_eq!(environment.generation, 2);
        assert_eq!(environment.active_artifact_generation, Some(next_artifact));
        assert!(environment.staging_artifact_generation.is_none());
        assert_eq!(environment.active_workspace_generation, Some(staging));
        assert_eq!(environment.rollback_workspace_generation, Some(active));
        environment.validate("dev").unwrap();
    }

    #[test]
    fn workspace_update_journal_distinguishes_explicit_skill_refresh() {
        let mut environment = project_environment();
        let project_json = environment.project_spec_json.clone().unwrap();
        let project_sha256 = environment.project_spec_sha256.clone().unwrap();
        environment.active_workspace_generation = Some(test_workspace_generation(
            &project_json,
            &project_sha256,
            b"active",
        ));
        let mut payload =
            workspace_update_payload(&environment, &project_json, &project_sha256, false);
        payload
            .as_object_mut()
            .unwrap()
            .insert("refresh_skills".to_owned(), true.into());
        let operation = test_workspace_transition_operation(
            &environment,
            OperationKind::UpdateWorkspace,
            payload,
            0,
        );
        assert!(
            workspace_transition_parameters(&operation, &environment)
                .unwrap()
                .refresh_skills
        );
    }

    #[tokio::test]
    async fn replayed_runtime_only_rollback_restores_the_exact_prior_artifact() {
        let mut environment = project_environment();
        let RuntimeTransitionFixture {
            old_artifact: prior_artifact,
            next_artifact: current_artifact,
            old_workspace: rollback,
            next_workspace: active,
        } = same_image_runtime_transition(&environment);
        environment.state = StoredEnvironmentState::Running;
        environment.active_artifact_generation = Some(current_artifact.clone());
        environment.active_workspace_generation = Some(active.clone());
        environment.rollback_workspace_generation = Some(rollback.clone());
        environment.validate("dev").unwrap();
        let payload = workspace_rollback_payload(&environment, true);
        let parameters = workspace_transition_parameters(
            &test_workspace_transition_operation(
                &environment,
                OperationKind::RollbackWorkspace,
                payload.clone(),
                0,
            ),
            &environment,
        )
        .unwrap();
        let WorkspaceTransitionIntent::Rollback {
            rollback_storage_generation,
        } = &parameters.intent
        else {
            unreachable!()
        };
        environment
            .stage_rollback_workspace_generation(
                &parameters.prior_storage_generation,
                rollback_storage_generation,
            )
            .unwrap();
        assert_eq!(
            environment.staging_artifact_generation,
            Some(prior_artifact.clone())
        );
        environment.validate("dev").unwrap();
        reserve_boot_generation(&mut environment, parameters.target_generation).unwrap();
        let environment_id = environment.id;
        let (_parent, mut core) = test_supervisor_core(environment);
        let operation = begin_and_advance_test_operation(
            &core.store,
            environment_id,
            OperationKind::RollbackWorkspace,
            &payload,
            7,
        );
        let request_id = operation.request_id;

        core.replay_pending_operations().await.unwrap();

        let operation = core
            .store
            .operation_by_request(request_id)
            .unwrap()
            .unwrap();
        assert_eq!(operation.phase, OperationPhase::Completed);
        assert_eq!(operation.checkpoint, 10);
        let environment = core.environment("dev").unwrap();
        assert_eq!(environment.state, StoredEnvironmentState::Running);
        assert_eq!(environment.generation, 2);
        assert_eq!(environment.active_artifact_generation, Some(prior_artifact));
        assert!(environment.staging_artifact_generation.is_none());
        assert_eq!(environment.active_workspace_generation, Some(rollback));
        assert_eq!(environment.rollback_workspace_generation, Some(active));
        environment.validate("dev").unwrap();
    }

    #[test]
    fn rollback_journal_rejects_a_different_artifact_with_the_same_oci_root() {
        let mut environment = project_environment();
        let project_json = environment.project_spec_json.clone().unwrap();
        let project_sha256 = environment.project_spec_sha256.clone().unwrap();
        let active = test_workspace_generation_with_artifact(
            &project_json,
            &project_sha256,
            &"b".repeat(64),
            b"same-image",
        );
        let rollback = test_workspace_generation_with_artifact(
            &project_json,
            &project_sha256,
            &"c".repeat(64),
            b"same-image",
        );
        environment.active_workspace_generation = Some(active);
        environment.rollback_workspace_generation = Some(rollback);
        environment.validate("dev").unwrap();
        let operation = OperationRecord {
            operation_id: Uuid::new_v4(),
            request_id: Uuid::new_v4(),
            environment_id: Some(environment.id),
            kind: OperationKind::RollbackWorkspace,
            phase: OperationPhase::Intent,
            checkpoint: 0,
            payload: workspace_rollback_payload(&environment, false),
            result: None,
            error_code: None,
            created_unix_ms: 1,
            updated_unix_ms: 1,
        };
        let parameters = workspace_transition_parameters(&operation, &environment).unwrap();

        environment.rollback_workspace_generation = Some(test_workspace_generation_with_artifact(
            &project_json,
            &project_sha256,
            &"d".repeat(64),
            b"same-image",
        ));
        environment.validate("dev").unwrap();

        assert!(validate_workspace_transition_start(&environment, &parameters).is_err());
    }

    fn set_test_current_project(
        environment: &mut EnvironmentRecord,
        project: &codewire_project::ProjectSpec,
    ) {
        let bytes = project.canonical_json().unwrap();
        environment.project_spec_sha256 = Some(format!("{:x}", Sha256::digest(&bytes)));
        environment.project_spec_json = Some(bytes);
    }

    fn test_selectors() -> (
        codewire_project::SecretBindings,
        Option<codewire_project::CredentialBinding>,
    ) {
        (
            codewire_project::SecretBindings {
                project: "local:id:11111111-1111-4111-8111-111111111111".to_owned(),
                user: Some(codewire_project::StoragePlacement::Local),
                organization: false,
            },
            Some(codewire_project::CredentialBinding {
                profile: "local:id:22222222-2222-4222-8222-222222222222".to_owned(),
            }),
        )
    }

    fn workspace_with_test_skills(
        environment: &mut EnvironmentRecord,
    ) -> WorkspaceGenerationRecord {
        let baseline = test_workspace_generation(
            environment.project_spec_json.as_deref().unwrap(),
            environment.project_spec_sha256.as_deref().unwrap(),
            b"installed-skills",
        );
        let mut project: codewire_project::ProjectSpec =
            serde_json::from_slice(environment.project_spec_json.as_deref().unwrap()).unwrap();
        project.install_command = "printf installed".to_owned();
        project.agents.tools = vec!["codex".to_owned()];
        project.skills = vec![codewire_project::SkillSelection {
            source: codewire_project::SkillSource::User,
            reference: "rust".to_owned(),
            agents: vec!["codex".to_owned()],
        }];
        set_test_current_project(environment, &project);
        let skill = codewire_vmm_guest_probe::SkillSnapshot::new(
            codewire_vmm_guest_probe::SkillSnapshotSource::User,
            "user:rust".to_owned(),
            "rust".to_owned(),
            "c".repeat(64),
            "rust",
            &["codex".to_owned()],
        )
        .unwrap();
        let plan = codewire_vmm_guest_probe::SkillSnapshotPlan::new(
            environment.project_spec_sha256.clone().unwrap(),
            3,
            vec![skill],
        )
        .unwrap();
        WorkspaceGenerationRecord::new_with_skill_snapshot(
            environment.project_spec_json.as_deref().unwrap(),
            environment.project_spec_sha256.clone().unwrap(),
            baseline.artifact_generation,
            baseline.image,
            baseline.root_disk_bytes,
            Some(plan),
        )
        .unwrap()
    }

    #[test]
    fn workspace_update_and_rollback_preserve_current_sources_without_mutating_built_records() {
        let mut environment = project_environment();
        let mut historical: codewire_project::ProjectSpec =
            serde_json::from_slice(environment.project_spec_json.as_deref().unwrap()).unwrap();
        historical.secrets.project = "local:id:33333333-3333-4333-8333-333333333333".to_owned();
        historical.credentials = Some(codewire_project::CredentialBinding {
            profile: "local:id:44444444-4444-4444-8444-444444444444".to_owned(),
        });
        set_test_current_project(&mut environment, &historical);
        let active = test_workspace_generation(
            environment.project_spec_json.as_deref().unwrap(),
            environment.project_spec_sha256.as_deref().unwrap(),
            b"active",
        );
        let active_bytes = active.encode_canonical().unwrap();
        let mut current: codewire_project::ProjectSpec =
            serde_json::from_slice(environment.project_spec_json.as_deref().unwrap()).unwrap();
        (current.secrets, current.credentials) = test_selectors();
        set_test_current_project(&mut environment, &current);
        environment.active_workspace_generation = Some(active.clone());
        environment.access_profile = Some("user/current".parse().unwrap());
        environment.access_binding = Some(EnvironmentAccessBinding {
            environment_id: access_environment_id(environment.id).unwrap(),
            profile_id: AccessProfileId::parse("22222222-2222-4222-8222-222222222222").unwrap(),
            profile_revision: 7,
        });
        let selected_profile = environment.access_profile.clone();
        let selected_binding = environment.access_binding.clone();
        let mut target = current.clone();
        target.install_command = "printf newer-install".to_owned();
        let target_json = target.canonical_json().unwrap();
        let target_sha256 = format!("{:x}", Sha256::digest(&target_json));
        let staging = test_workspace_generation(&target_json, &target_sha256, b"staging");
        let staging_bytes = staging.encode_canonical().unwrap();
        environment.staging_workspace_generation = Some(staging.clone());
        environment.promote_staging_workspace_generation().unwrap();
        let after: codewire_project::ProjectSpec =
            serde_json::from_slice(environment.project_spec_json.as_deref().unwrap()).unwrap();
        assert_eq!(after, target);
        assert_eq!(environment.access_profile, selected_profile);
        assert_eq!(environment.access_binding, selected_binding);
        assert_eq!(
            environment
                .active_workspace_generation
                .as_ref()
                .unwrap()
                .encode_canonical()
                .unwrap(),
            staging_bytes
        );
        assert_eq!(
            environment
                .rollback_workspace_generation
                .as_ref()
                .unwrap()
                .encode_canonical()
                .unwrap(),
            active_bytes
        );

        // A later source-CAS clears both selectors. Rolling back the root may
        // restore old install intent, but cannot restore either old selector.
        current = target;
        current.secrets = Default::default();
        current.credentials = None;
        set_test_current_project(&mut environment, &current);
        environment.access_profile = None;
        environment.access_binding = None;
        environment
            .stage_rollback_workspace_generation(
                &workspace_storage_generation(&staging).unwrap(),
                &workspace_storage_generation(&active).unwrap(),
            )
            .unwrap();
        environment.promote_staging_workspace_generation().unwrap();
        let after: codewire_project::ProjectSpec =
            serde_json::from_slice(environment.project_spec_json.as_deref().unwrap()).unwrap();
        assert!(after.install_command.is_empty());
        assert!(after.secrets.is_empty());
        assert!(after.credentials.is_none());
        assert!(environment.access_profile.is_none());
        assert!(environment.access_binding.is_none());
        assert_eq!(
            environment
                .active_workspace_generation
                .as_ref()
                .unwrap()
                .encode_canonical()
                .unwrap(),
            active_bytes
        );
        assert_eq!(
            environment
                .rollback_workspace_generation
                .as_ref()
                .unwrap()
                .encode_canonical()
                .unwrap(),
            staging_bytes
        );
        active
            .validate_for_project_intent(
                environment.project_spec_json.as_deref().unwrap(),
                environment.project_spec_sha256.as_deref().unwrap(),
            )
            .unwrap();
    }

    #[test]
    fn workspace_no_boot_completion_retains_source_only_current_intent() {
        let mut environment = project_environment();
        let built = test_workspace_generation(
            environment.project_spec_json.as_deref().unwrap(),
            environment.project_spec_sha256.as_deref().unwrap(),
            b"same-root",
        );
        let built_bytes = built.encode_canonical().unwrap();
        let mut current: codewire_project::ProjectSpec =
            serde_json::from_slice(environment.project_spec_json.as_deref().unwrap()).unwrap();
        (current.secrets, current.credentials) = test_selectors();
        set_test_current_project(&mut environment, &current);
        let current_json = environment.project_spec_json.clone();
        let current_sha256 = environment.project_spec_sha256.clone();
        environment.active_workspace_generation = Some(built.clone());
        environment.staging_workspace_generation = Some(built);
        environment
            .finish_staging_workspace_update_without_boot()
            .unwrap();
        assert_eq!(environment.project_spec_json, current_json);
        assert_eq!(environment.project_spec_sha256, current_sha256);
        assert_eq!(
            environment
                .active_workspace_generation
                .as_ref()
                .unwrap()
                .encode_canonical()
                .unwrap(),
            built_bytes
        );
        assert!(environment.staging_workspace_generation.is_none());
    }

    #[test]
    fn workspace_source_drift_requires_the_dedicated_source_cas() {
        let mut environment = project_environment();
        environment.active_workspace_generation = Some(test_workspace_generation(
            environment.project_spec_json.as_deref().unwrap(),
            environment.project_spec_sha256.as_deref().unwrap(),
            b"active",
        ));
        let mut current: codewire_project::ProjectSpec =
            serde_json::from_slice(environment.project_spec_json.as_deref().unwrap()).unwrap();
        (current.secrets, current.credentials) = test_selectors();
        set_test_current_project(&mut environment, &current);
        let changes: &[fn(&mut codewire_project::ProjectSpec)] = &[
            |project| project.secrets.user = None,
            |project| project.secrets.project.clear(),
            |project| project.secrets.organization = true,
            |project| project.credentials = None,
        ];
        for change in changes {
            let mut target = current.clone();
            change(&mut target);
            let target_json = target.canonical_json().unwrap();
            let target_sha256 = format!("{:x}", Sha256::digest(&target_json));
            let operation = test_workspace_transition_operation(
                &environment,
                OperationKind::UpdateWorkspace,
                workspace_update_payload(&environment, &target_json, &target_sha256, false),
                0,
            );
            let parameters = workspace_transition_parameters(&operation, &environment).unwrap();
            assert!(validate_workspace_transition_start(&environment, &parameters).is_err());
        }
        let current_json = environment.project_spec_json.as_deref().unwrap();
        let current_sha256 = environment.project_spec_sha256.as_deref().unwrap();
        let operation = test_workspace_transition_operation(
            &environment,
            OperationKind::UpdateWorkspace,
            workspace_update_payload(&environment, current_json, current_sha256, false),
            0,
        );
        let parameters = workspace_transition_parameters(&operation, &environment).unwrap();
        validate_workspace_transition_start(&environment, &parameters).unwrap();
    }

    #[test]
    fn skill_refresh_allows_only_source_divergence_from_the_built_intent() {
        let mut environment = project_environment();
        let built = workspace_with_test_skills(&mut environment);
        let plan = built.skill_snapshot().unwrap().cloned();
        environment.active_workspace_generation = Some(built.clone());
        let mut current: codewire_project::ProjectSpec =
            serde_json::from_slice(environment.project_spec_json.as_deref().unwrap()).unwrap();
        (current.secrets, current.credentials) = test_selectors();
        set_test_current_project(&mut environment, &current);
        let mut payload = workspace_update_payload(
            &environment,
            environment.project_spec_json.as_deref().unwrap(),
            environment.project_spec_sha256.as_deref().unwrap(),
            false,
        );
        payload
            .as_object_mut()
            .unwrap()
            .insert("refresh_skills".to_owned(), true.into());
        let operation = test_workspace_transition_operation(
            &environment,
            OperationKind::UpdateWorkspace,
            payload,
            0,
        );
        let parameters = workspace_transition_parameters(&operation, &environment).unwrap();
        validate_workspace_transition_start(&environment, &parameters).unwrap();
        assert_eq!(
            environment
                .active_workspace_generation
                .as_ref()
                .unwrap()
                .skill_snapshot()
                .unwrap(),
            plan.as_ref()
        );
        let mut drift = current;
        drift.install_command = "printf unapproved-install-change".to_owned();
        let drift_json = drift.canonical_json().unwrap();
        let drift_sha256 = format!("{:x}", Sha256::digest(&drift_json));
        let mut payload = workspace_update_payload(&environment, &drift_json, &drift_sha256, false);
        payload
            .as_object_mut()
            .unwrap()
            .insert("refresh_skills".to_owned(), true.into());
        let operation = test_workspace_transition_operation(
            &environment,
            OperationKind::UpdateWorkspace,
            payload,
            0,
        );
        let parameters = workspace_transition_parameters(&operation, &environment).unwrap();
        assert!(validate_workspace_transition_start(&environment, &parameters).is_err());
    }

    #[tokio::test]
    async fn skill_refresh_replay_uses_current_intent_after_a_source_only_change() {
        let mut environment = project_environment();
        let mut historical: codewire_project::ProjectSpec =
            serde_json::from_slice(environment.project_spec_json.as_deref().unwrap()).unwrap();
        historical.secrets.project = "local:id:11111111-1111-4111-8111-111111111111".to_owned();
        set_test_current_project(&mut environment, &historical);
        let built = workspace_with_test_skills(&mut environment);
        environment.active_workspace_generation = Some(built.clone());
        let mut current: codewire_project::ProjectSpec =
            serde_json::from_slice(environment.project_spec_json.as_deref().unwrap()).unwrap();
        current.secrets = Default::default();
        set_test_current_project(&mut environment, &current);
        let mut payload = workspace_update_payload(
            &environment,
            environment.project_spec_json.as_deref().unwrap(),
            environment.project_spec_sha256.as_deref().unwrap(),
            false,
        );
        payload
            .as_object_mut()
            .unwrap()
            .insert("refresh_skills".to_owned(), true.into());
        assert_ne!(
            environment.project_spec_sha256.as_deref(),
            Some(built.project_sha256.as_str())
        );
        let environment_id = environment.id;
        let request_id = Uuid::new_v4();
        let (_parent, core) = test_supervisor_core(environment);
        // A terminal synthetic operation proves request/payload identity
        // without scheduling a runner, registry read or skill-material read.
        let operation = core
            .store
            .begin_operation(
                request_id,
                Some(environment_id),
                OperationKind::UpdateWorkspace,
                &payload,
            )
            .unwrap();
        let result = environment_operation_result(core.environment("dev").unwrap());
        core.store
            .advance_operation(
                operation.operation_id,
                operation.checkpoint,
                OperationPhase::Completed,
                Some(&result),
                None,
            )
            .unwrap();
        let service = test_supervisor_service(core);
        let response = service
            .refresh_environment_skills(Request::new(v1::EnvironmentSelector {
                name: "dev".to_owned(),
                request_id: request_id.to_string(),
                environment_id: environment_id.to_string(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.operation_id, operation.operation_id.to_string());
        assert_eq!(response.phase, v1::OperationPhase::Completed as i32);
        let core = service.core.lock().await;
        assert_eq!(
            core.store
                .operation_by_request(request_id)
                .unwrap()
                .unwrap()
                .payload,
            payload
        );
        assert_eq!(
            core.environment("dev").unwrap().active_workspace_generation,
            Some(built)
        );
        assert!(!core.config.credential_authority_root.exists());
    }

    #[test]
    fn workspace_update_cannot_change_the_bound_access_profile() {
        let mut environment = project_environment();
        let project_json = environment.project_spec_json.clone().unwrap();
        let project_sha256 = environment.project_spec_sha256.clone().unwrap();
        environment.active_workspace_generation = Some(test_workspace_generation(
            &project_json,
            &project_sha256,
            b"active",
        ));
        let mut next_project: codewire_project::ProjectSpec =
            serde_json::from_slice(&project_json).unwrap();
        next_project.credentials = Some(codewire_project::CredentialBinding {
            profile: "local:id:22222222-2222-4222-8222-222222222222".to_owned(),
        });
        let next_project_json = next_project.canonical_json().unwrap();
        let next_project_sha256 = format!("{:x}", Sha256::digest(&next_project_json));
        let payload = workspace_update_payload(
            &environment,
            &next_project_json,
            &next_project_sha256,
            false,
        );
        let parameters = workspace_transition_parameters(
            &test_workspace_transition_operation(
                &environment,
                OperationKind::UpdateWorkspace,
                payload,
                0,
            ),
            &environment,
        )
        .unwrap();

        assert!(validate_workspace_transition_start(&environment, &parameters).is_err());
    }

    #[test]
    fn workspace_update_enforces_exact_source_equality_before_staging() {
        let environment = project_environment_with_secret_selection(
            codewire_project::SecretBindings {
                user: Some(codewire_project::StoragePlacement::Platform),
                project: format!("local:id:{}", Uuid::new_v4()),
                ..Default::default()
            },
            BTreeMap::new(),
        );
        let original = environment.clone();
        let active_project_json = environment.project_spec_json.clone().unwrap();
        let active_project_sha256 = environment.project_spec_sha256.clone().unwrap();
        let mut target_project: codewire_project::ProjectSpec =
            serde_json::from_slice(&active_project_json).unwrap();
        target_project.secrets.project = format!("local:id:{}", Uuid::new_v4());
        let target_project_json = target_project.canonical_json().unwrap();
        let target_project_sha256 = format!("{:x}", Sha256::digest(&target_project_json));
        let changed = workspace_transition_parameters(
            &test_workspace_transition_operation(
                &environment,
                OperationKind::UpdateWorkspace,
                workspace_update_payload(
                    &environment,
                    &target_project_json,
                    &target_project_sha256,
                    false,
                ),
                0,
            ),
            &environment,
        )
        .unwrap();
        reject_workspace_transition_workload_secrets(&environment, &changed).unwrap();
        assert!(matches!(
            validate_workspace_transition_start(&environment, &changed),
            Err(SupervisorError::InvalidState)
        ));

        let unchanged = workspace_transition_parameters(
            &test_workspace_transition_operation(
                &environment,
                OperationKind::UpdateWorkspace,
                workspace_update_payload(
                    &environment,
                    &active_project_json,
                    &active_project_sha256,
                    false,
                ),
                0,
            ),
            &environment,
        )
        .unwrap();
        reject_workspace_transition_workload_secrets(&environment, &unchanged).unwrap();
        validate_workspace_transition_start(&environment, &unchanged).unwrap();

        assert_eq!(environment, original);
        assert!(environment.staging_workspace_generation.is_none());
    }

    #[test]
    fn workspace_rollback_uses_valid_current_mixed_sources_and_rejects_missing_authority() {
        let mut environment = project_environment();
        let original_project_json = environment.project_spec_json.clone().unwrap();
        let mut rollback_project: codewire_project::ProjectSpec =
            serde_json::from_slice(&original_project_json).unwrap();
        rollback_project.secrets.user = Some(codewire_project::StoragePlacement::Local);
        let rollback_project_json = rollback_project.canonical_json().unwrap();
        let rollback_project_sha256 = format!("{:x}", Sha256::digest(&rollback_project_json));
        let rollback = test_workspace_generation(
            &rollback_project_json,
            &rollback_project_sha256,
            b"secret-rollback",
        );
        let mut current: codewire_project::ProjectSpec =
            serde_json::from_slice(&original_project_json).unwrap();
        current.secrets.user = Some(codewire_project::StoragePlacement::Platform);
        current.secrets.project = format!("local:id:{}", Uuid::new_v4());
        set_test_current_project(&mut environment, &current);
        let active_project_json = environment.project_spec_json.clone().unwrap();
        let active_project_sha256 = environment.project_spec_sha256.clone().unwrap();
        environment.active_workspace_generation = Some(test_workspace_generation(
            &active_project_json,
            &active_project_sha256,
            b"active-before-secret-rollback",
        ));
        environment.rollback_workspace_generation = Some(rollback.clone());
        environment.platform_source_authority =
            project_environment_with_secret_selection(current.secrets.clone(), BTreeMap::new())
                .platform_source_authority;
        environment.validate("dev").unwrap();
        let payload = workspace_rollback_payload(&environment, false);
        let parameters = workspace_transition_parameters(
            &test_workspace_transition_operation(
                &environment,
                OperationKind::RollbackWorkspace,
                payload,
                0,
            ),
            &environment,
        )
        .unwrap();
        let original = environment.clone();
        reject_workspace_transition_workload_secrets(&environment, &parameters).unwrap();
        validate_workspace_transition_start(&environment, &parameters).unwrap();

        let mut staged = environment.clone();
        staged
            .stage_rollback_workspace_generation(
                &parameters.prior_storage_generation,
                match &parameters.intent {
                    WorkspaceTransitionIntent::Rollback {
                        rollback_storage_generation,
                    } => rollback_storage_generation,
                    _ => unreachable!(),
                },
            )
            .unwrap();
        assert_eq!(staged.project_spec_json, original.project_spec_json);
        assert_eq!(staged.project_spec_sha256, original.project_spec_sha256);
        assert_eq!(staged.staging_workspace_generation, Some(rollback));
        assert!(staged.rollback_workspace_generation.is_none());
        let boot = sources::projection_environment_for_boot(&staged).unwrap();
        let boot_project: codewire_project::ProjectSpec =
            serde_json::from_slice(boot.project_spec_json.as_deref().unwrap()).unwrap();
        assert_eq!(boot_project.secrets, current.secrets);

        let mut missing_authority = original.clone();
        missing_authority.platform_source_authority = None;
        assert!(matches!(
            reject_workspace_transition_workload_secrets(&missing_authority, &parameters),
            Err(SupervisorError::EnvironmentAccessUnavailable)
        ));
        assert_eq!(
            missing_authority.project_spec_json,
            original.project_spec_json
        );
        assert_eq!(
            missing_authority.rollback_workspace_generation,
            original.rollback_workspace_generation
        );
    }

    #[tokio::test]
    async fn exact_noop_update_replays_without_reboot_or_rollback_rotation() {
        let mut environment = project_environment();
        let project_json = environment.project_spec_json.clone().unwrap();
        let project_sha256 = environment.project_spec_sha256.clone().unwrap();
        let active = test_workspace_generation(&project_json, &project_sha256, b"active");
        let rollback = test_workspace_generation(&project_json, &project_sha256, b"rollback");
        environment.state = StoredEnvironmentState::Running;
        environment.active_workspace_generation = Some(active.clone());
        environment.staging_workspace_generation = Some(active.clone());
        environment.rollback_workspace_generation = Some(rollback.clone());
        environment.staging_artifact_generation = Some("b".repeat(64));
        environment.validate("dev").unwrap();
        let environment_id = environment.id;
        let payload = workspace_update_payload(&environment, &project_json, &project_sha256, true);
        let (_parent, mut core) = test_supervisor_core(environment);
        let operation = core
            .store
            .begin_operation(
                Uuid::new_v4(),
                Some(environment_id),
                OperationKind::UpdateWorkspace,
                &payload,
            )
            .unwrap();
        let mut operation = operation;
        for _ in 0..2 {
            operation = core
                .store
                .advance_operation(
                    operation.operation_id,
                    operation.checkpoint,
                    OperationPhase::EffectApplied,
                    None,
                    None,
                )
                .unwrap();
        }

        core.replay_pending_operations().await.unwrap();

        let completed = core
            .store
            .operation_by_request(operation.request_id)
            .unwrap()
            .unwrap();
        assert_eq!(completed.phase, OperationPhase::Completed);
        let environment = core.environment("dev").unwrap();
        assert_eq!(environment.state, StoredEnvironmentState::Running);
        assert_eq!(environment.generation, 1);
        assert_eq!(environment.active_workspace_generation, Some(active));
        assert!(environment.staging_workspace_generation.is_none());
        assert_eq!(environment.rollback_workspace_generation, Some(rollback));
        assert!(environment.staging_artifact_generation.is_none());
        environment.validate("dev").unwrap();
    }

    #[test]
    fn changed_project_promotion_keeps_the_active_generation_rebuildable() {
        let mut environment = project_environment();
        let old_project_json = environment.project_spec_json.clone().unwrap();
        let old_project_sha256 = environment.project_spec_sha256.clone().unwrap();
        let active = test_workspace_generation(&old_project_json, &old_project_sha256, b"active");
        let mut next_project: codewire_project::ProjectSpec =
            serde_json::from_slice(&old_project_json).unwrap();
        next_project.image = "registry.example/codewire/workspace:next".to_owned();
        let next_project_json = next_project.canonical_json().unwrap();
        let next_project_sha256 = format!("{:x}", Sha256::digest(&next_project_json));
        let staging =
            test_workspace_generation(&next_project_json, &next_project_sha256, b"staging");
        environment.active_workspace_generation = Some(active.clone());
        environment.staging_workspace_generation = Some(staging.clone());
        environment.validate("dev").unwrap();

        assert!(
            environment
                .promote_staging_workspace_generation()
                .unwrap()
                .is_none()
        );

        assert_eq!(environment.project_spec_json, Some(next_project_json));
        assert_eq!(
            environment.project_spec_sha256.as_deref(),
            Some(next_project_sha256.as_str())
        );
        assert_eq!(environment.active_workspace_generation, Some(staging));
        let rollback = environment.rollback_workspace_generation.as_ref().unwrap();
        assert_eq!(rollback.root_generation, active.root_generation);
        assert_eq!(rollback.project_spec_json.as_bytes(), old_project_json);
        rollback.validate().unwrap();
        environment.validate("dev").unwrap();
    }

    #[tokio::test]
    async fn failed_workspace_update_discards_only_staging_and_keeps_active_bootable() {
        let mut environment = project_environment();
        let old_project_json = environment.project_spec_json.clone().unwrap();
        let old_project_sha256 = environment.project_spec_sha256.clone().unwrap();
        let active = test_workspace_generation(&old_project_json, &old_project_sha256, b"active");
        let mut next_project: codewire_project::ProjectSpec =
            serde_json::from_slice(&old_project_json).unwrap();
        next_project.image = "registry.example/codewire/workspace:next".to_owned();
        let next_project_json = next_project.canonical_json().unwrap();
        let next_project_sha256 = format!("{:x}", Sha256::digest(&next_project_json));
        let staging =
            test_workspace_generation(&next_project_json, &next_project_sha256, b"staging");
        environment.state = StoredEnvironmentState::Running;
        environment.active_workspace_generation = Some(active.clone());
        environment.staging_workspace_generation = Some(staging);
        let environment_id = environment.id;
        let payload =
            workspace_update_payload(&environment, &next_project_json, &next_project_sha256, true);
        let (_parent, mut core) = test_supervisor_core(environment);
        let operation = core
            .store
            .begin_operation(
                Uuid::new_v4(),
                Some(environment_id),
                OperationKind::UpdateWorkspace,
                &payload,
            )
            .unwrap();
        let operation = core
            .store
            .advance_operation(
                operation.operation_id,
                operation.checkpoint,
                OperationPhase::EffectApplied,
                None,
                None,
            )
            .unwrap();

        let failed = core
            .abort_workspace_transition(&operation, "dev", "workspace_update_failed")
            .await
            .unwrap();

        assert_eq!(failed.phase, OperationPhase::Failed);
        let environment = core.environment("dev").unwrap();
        assert_eq!(environment.state, StoredEnvironmentState::Stopped);
        assert_eq!(environment.active_workspace_generation, Some(active));
        assert!(environment.staging_workspace_generation.is_none());
        assert_eq!(
            environment.project_spec_json.as_deref(),
            Some(old_project_json.as_slice())
        );
        environment.validate("dev").unwrap();
    }

    #[test]
    fn boot_projection_tracks_incoming_workspace_and_current_sources_through_promotion() {
        for rollback in [false, true] {
            let mut environment = project_environment_with_secret_selection(
                codewire_project::SecretBindings {
                    user: Some(codewire_project::StoragePlacement::Local),
                    ..Default::default()
                },
                BTreeMap::from([("OLD_KEY".into(), "old-ordinary-value".into())]),
            );
            let original_json = environment.project_spec_json.clone();
            let original_hash = environment.project_spec_sha256.clone();
            let mut incoming: codewire_project::ProjectSpec =
                serde_json::from_slice(original_json.as_ref().unwrap()).unwrap();
            incoming.environment =
                BTreeMap::from([("NEW_KEY".into(), "new-ordinary-value".into())]);
            // Saved workspace metadata may predate a source change. Neither a
            // rebuild nor rollback may revive its old source selection.
            incoming.secrets = Default::default();
            let json = incoming.canonical_json().unwrap();
            let hash = format!("{:x}", Sha256::digest(&json));
            let generation = test_workspace_generation(&json, &hash, b"incoming");
            if rollback {
                environment.rollback_workspace_generation = Some(generation);
                let active_storage = workspace_storage_generation(
                    environment.active_workspace_generation.as_ref().unwrap(),
                )
                .unwrap();
                let rollback_storage = workspace_storage_generation(
                    environment.rollback_workspace_generation.as_ref().unwrap(),
                )
                .unwrap();
                environment
                    .stage_rollback_workspace_generation(&active_storage, &rollback_storage)
                    .unwrap();
            } else {
                environment.staging_workspace_generation = Some(generation);
            }
            let boot = sources::projection_environment_for_boot(&environment).unwrap();
            assert_eq!(environment.project_spec_json, original_json);
            assert_eq!(environment.project_spec_sha256, original_hash);
            let binding = sources::local_launch_projection(&boot).unwrap().unwrap();
            assert!(binding.selection.user);
            assert_eq!(
                binding.selection.overridden_keys,
                BTreeSet::from(["NEW_KEY".into()])
            );
            assert_ne!(boot.project_spec_sha256, original_hash);
            environment.promote_staging_workspace_generation().unwrap();
            assert_eq!(environment.project_spec_json, boot.project_spec_json);
            assert_eq!(environment.project_spec_sha256, boot.project_spec_sha256);
            assert_eq!(
                sources::local_launch_projection(&environment).unwrap(),
                Some(binding)
            );
        }
    }

    #[test]
    fn platform_profile_routing_requires_exact_metadata_not_a_local_fallback() {
        let mut project: codewire_project::ProjectSpec =
            serde_json::from_slice(project_environment().project_spec_json.as_ref().unwrap())
                .unwrap();
        project.credentials = Some(codewire_project::CredentialBinding {
            profile: "platform:id:11111111-1111-4111-8111-111111111111".into(),
        });
        assert!(project.secrets.is_empty());
        reject_undeliverable_workload_secrets(&project).unwrap();
        assert!(
            sources::validate_source_metadata(
                &project,
                "11111111-1111-4111-8111-111111111111",
                7,
                "user/work",
                None
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn replayed_workspace_promotion_atomically_rotates_project_and_generation() {
        let mut environment = project_environment();
        let old_project_json = environment.project_spec_json.clone().unwrap();
        let old_project_sha256 = environment.project_spec_sha256.clone().unwrap();
        let active = test_workspace_generation(&old_project_json, &old_project_sha256, b"active");
        let mut next_project: codewire_project::ProjectSpec =
            serde_json::from_slice(&old_project_json).unwrap();
        next_project.image = "registry.example/codewire/workspace:next".to_owned();
        let next_project_json = next_project.canonical_json().unwrap();
        let next_project_sha256 = format!("{:x}", Sha256::digest(&next_project_json));
        let staging =
            test_workspace_generation(&next_project_json, &next_project_sha256, b"staging");
        environment.active_workspace_generation = Some(active.clone());
        environment.staging_workspace_generation = Some(staging.clone());
        let environment_id = environment.id;
        let payload = workspace_update_payload(
            &environment,
            &next_project_json,
            &next_project_sha256,
            false,
        );
        reserve_boot_generation(&mut environment, 2).unwrap();
        let (_parent, mut core) = test_supervisor_core(environment);
        let mut operation = core
            .store
            .begin_operation(
                Uuid::new_v4(),
                Some(environment_id),
                OperationKind::UpdateWorkspace,
                &payload,
            )
            .unwrap();
        for _ in 0..7 {
            operation = core
                .store
                .advance_operation(
                    operation.operation_id,
                    operation.checkpoint,
                    OperationPhase::EffectApplied,
                    None,
                    None,
                )
                .unwrap();
        }

        core.recover_host_reboot_workspace_transitions().unwrap();
        assert!(
            core.environment("dev")
                .unwrap()
                .staging_workspace_generation
                .is_some()
        );

        let request_id = operation.request_id;
        core.replay_pending_operations().await.unwrap();
        let operation = core
            .store
            .operation_by_request(request_id)
            .unwrap()
            .unwrap();

        assert_eq!(operation.phase, OperationPhase::Completed);
        assert_eq!(operation.checkpoint, 10);
        let environment = core.environment("dev").unwrap();
        assert_eq!(environment.state, StoredEnvironmentState::Stopped);
        assert_eq!(environment.generation, 2);
        assert_eq!(environment.active_workspace_generation, Some(staging));
        assert_eq!(environment.rollback_workspace_generation, Some(active));
        assert_eq!(
            environment.project_spec_json.as_deref(),
            Some(next_project_json.as_slice())
        );
        environment.validate("dev").unwrap();
    }

    #[tokio::test]
    async fn replayed_workspace_rollback_atomically_restores_the_prior_project() {
        let mut environment = project_environment();
        let old_project_json = environment.project_spec_json.clone().unwrap();
        let old_project_sha256 = environment.project_spec_sha256.clone().unwrap();
        let rollback =
            test_workspace_generation(&old_project_json, &old_project_sha256, b"rollback");
        let mut next_project: codewire_project::ProjectSpec =
            serde_json::from_slice(&old_project_json).unwrap();
        next_project.image = "registry.example/codewire/workspace:next".to_owned();
        let next_project_json = next_project.canonical_json().unwrap();
        let next_project_sha256 = format!("{:x}", Sha256::digest(&next_project_json));
        let active = test_workspace_generation(&next_project_json, &next_project_sha256, b"active");
        environment.project_spec_json = Some(next_project_json);
        environment.project_spec_sha256 = Some(next_project_sha256);
        environment.active_workspace_generation = Some(active.clone());
        environment.rollback_workspace_generation = Some(rollback.clone());
        let payload = workspace_rollback_payload(&environment, true);
        let parameters = workspace_transition_parameters(
            &OperationRecord {
                operation_id: Uuid::new_v4(),
                request_id: Uuid::new_v4(),
                environment_id: Some(environment.id),
                kind: OperationKind::RollbackWorkspace,
                phase: OperationPhase::Intent,
                checkpoint: 0,
                payload: payload.clone(),
                result: None,
                error_code: None,
                created_unix_ms: 1,
                updated_unix_ms: 1,
            },
            &environment,
        )
        .unwrap();
        let WorkspaceTransitionIntent::Rollback {
            rollback_storage_generation,
        } = &parameters.intent
        else {
            unreachable!()
        };
        environment
            .stage_rollback_workspace_generation(
                &parameters.prior_storage_generation,
                rollback_storage_generation,
            )
            .unwrap();
        reserve_boot_generation(&mut environment, parameters.target_generation).unwrap();
        let environment_id = environment.id;
        let (_parent, mut core) = test_supervisor_core(environment);
        let mut operation = core
            .store
            .begin_operation(
                Uuid::new_v4(),
                Some(environment_id),
                OperationKind::RollbackWorkspace,
                &payload,
            )
            .unwrap();
        for _ in 0..7 {
            operation = core
                .store
                .advance_operation(
                    operation.operation_id,
                    operation.checkpoint,
                    OperationPhase::EffectApplied,
                    None,
                    None,
                )
                .unwrap();
        }
        let request_id = operation.request_id;

        core.replay_pending_operations().await.unwrap();

        let operation = core
            .store
            .operation_by_request(request_id)
            .unwrap()
            .unwrap();
        assert_eq!(operation.phase, OperationPhase::Completed);
        assert_eq!(operation.checkpoint, 10);
        let environment = core.environment("dev").unwrap();
        assert_eq!(environment.state, StoredEnvironmentState::Running);
        assert_eq!(environment.generation, 2);
        assert_eq!(environment.active_workspace_generation, Some(rollback));
        assert_eq!(environment.rollback_workspace_generation, Some(active));
        assert_eq!(
            environment.project_spec_json.as_deref(),
            Some(old_project_json.as_slice())
        );
        environment.validate("dev").unwrap();
    }

    #[test]
    fn rollback_staging_and_abort_restore_the_exact_prior_slots() {
        let mut environment = project_environment();
        let project_json = environment.project_spec_json.clone().unwrap();
        let project_sha256 = environment.project_spec_sha256.clone().unwrap();
        let active = test_workspace_generation(&project_json, &project_sha256, b"active");
        let rollback = test_workspace_generation(&project_json, &project_sha256, b"rollback");
        environment.active_workspace_generation = Some(active.clone());
        environment.rollback_workspace_generation = Some(rollback.clone());
        let payload = workspace_rollback_payload(&environment, true);
        let operation = OperationRecord {
            operation_id: Uuid::new_v4(),
            request_id: Uuid::new_v4(),
            environment_id: Some(environment.id),
            kind: OperationKind::RollbackWorkspace,
            phase: OperationPhase::Intent,
            checkpoint: 0,
            payload,
            result: None,
            error_code: None,
            created_unix_ms: 1,
            updated_unix_ms: 1,
        };
        let parameters = workspace_transition_parameters(&operation, &environment).unwrap();

        environment
            .stage_rollback_workspace_generation(
                &parameters.prior_storage_generation,
                match &parameters.intent {
                    WorkspaceTransitionIntent::Rollback {
                        rollback_storage_generation,
                    } => rollback_storage_generation,
                    WorkspaceTransitionIntent::Update { .. } => unreachable!(),
                },
            )
            .unwrap();
        assert_eq!(
            environment.active_workspace_generation,
            Some(active.clone())
        );
        assert_eq!(
            environment.staging_workspace_generation,
            Some(rollback.clone())
        );
        assert!(environment.rollback_workspace_generation.is_none());
        assert!(workspace_transition_requires_boot(&environment, &parameters).unwrap());

        environment
            .restore_staged_rollback_workspace_generation(
                &parameters.prior_storage_generation,
                match &parameters.intent {
                    WorkspaceTransitionIntent::Rollback {
                        rollback_storage_generation,
                    } => rollback_storage_generation,
                    WorkspaceTransitionIntent::Update { .. } => unreachable!(),
                },
            )
            .unwrap();
        assert_eq!(environment.active_workspace_generation, Some(active));
        assert!(environment.staging_workspace_generation.is_none());
        assert_eq!(environment.rollback_workspace_generation, Some(rollback));
        environment.validate("dev").unwrap();
    }

    #[test]
    fn host_reboot_discards_a_runtime_update_at_every_precommit_checkpoint() {
        let mut environment = project_environment();
        let project_json = environment.project_spec_json.clone().unwrap();
        let project_sha256 = environment.project_spec_sha256.clone().unwrap();
        let RuntimeTransitionFixture {
            old_artifact: active_artifact,
            next_artifact: staging_artifact,
            old_workspace: active,
            next_workspace: staging,
        } = same_image_runtime_transition(&environment);
        environment.state = StoredEnvironmentState::Running;
        environment.active_workspace_generation = Some(active.clone());
        environment.validate("dev").unwrap();
        let payload = workspace_update_payload(&environment, &project_json, &project_sha256, true);

        for checkpoint in 1..=7 {
            let mut interrupted = environment.clone();
            if checkpoint >= 2 {
                interrupted.staging_workspace_generation = Some(staging.clone());
                interrupted.staging_artifact_generation = Some(staging_artifact.clone());
            }
            if checkpoint >= 4 {
                interrupted.state = StoredEnvironmentState::Stopped;
            }
            if checkpoint >= 5 {
                reserve_boot_generation(&mut interrupted, 2).unwrap();
            }
            let (_parent, mut core) = test_supervisor_core_after_host_reboot(
                interrupted,
                OperationKind::UpdateWorkspace,
                &payload,
                checkpoint,
            );

            core.recover_host_reboot_workspace_transitions().unwrap();

            let recovered = core.environment("dev").unwrap();
            assert_eq!(recovered.active_workspace_generation, Some(active.clone()));
            assert_eq!(
                recovered.active_artifact_generation,
                Some(active_artifact.clone())
            );
            assert!(recovered.staging_workspace_generation.is_none());
            assert!(recovered.staging_artifact_generation.is_none());
            assert_eq!(recovered.state, StoredEnvironmentState::Stopped);
            assert_eq!(recovered.generation, if checkpoint >= 5 { 2 } else { 1 });
            recovered.validate("dev").unwrap();
            core.ensure_no_unowned_workspace_staging().unwrap();
            assert!(
                core.store
                    .host_reboot_interrupted_workspace_transitions()
                    .unwrap()
                    .is_empty()
            );
        }
    }

    #[test]
    fn host_reboot_restores_a_runtime_rollback_at_every_precommit_checkpoint() {
        let mut base = project_environment();
        let RuntimeTransitionFixture {
            old_artifact: rollback_artifact,
            next_artifact: active_artifact,
            old_workspace: rollback,
            next_workspace: active,
        } = same_image_runtime_transition(&base);
        base.state = StoredEnvironmentState::Running;
        base.active_artifact_generation = Some(active_artifact.clone());
        base.active_workspace_generation = Some(active.clone());
        base.rollback_workspace_generation = Some(rollback.clone());
        base.validate("dev").unwrap();
        let payload = workspace_rollback_payload(&base, true);
        let parameters = workspace_transition_parameters(
            &test_workspace_transition_operation(
                &base,
                OperationKind::RollbackWorkspace,
                payload.clone(),
                0,
            ),
            &base,
        )
        .unwrap();
        let WorkspaceTransitionIntent::Rollback {
            rollback_storage_generation,
        } = &parameters.intent
        else {
            unreachable!()
        };
        for checkpoint in 1..=7 {
            let mut interrupted = base.clone();
            if checkpoint >= 2 {
                interrupted
                    .stage_rollback_workspace_generation(
                        &parameters.prior_storage_generation,
                        rollback_storage_generation,
                    )
                    .unwrap();
            }
            if checkpoint >= 4 {
                interrupted.state = StoredEnvironmentState::Stopped;
            }
            if checkpoint >= 5 {
                reserve_boot_generation(&mut interrupted, 2).unwrap();
            }
            assert_eq!(
                interrupted.staging_artifact_generation,
                (checkpoint >= 2).then(|| rollback_artifact.clone())
            );
            interrupted.validate("dev").unwrap();
            let (_parent, mut core) = test_supervisor_core_after_host_reboot(
                interrupted,
                OperationKind::RollbackWorkspace,
                &payload,
                checkpoint,
            );

            core.recover_host_reboot_workspace_transitions().unwrap();

            let recovered = core.environment("dev").unwrap();
            assert_eq!(recovered.active_workspace_generation, Some(active.clone()));
            assert_eq!(
                recovered.active_artifact_generation,
                Some(active_artifact.clone())
            );
            assert!(recovered.staging_workspace_generation.is_none());
            assert!(recovered.staging_artifact_generation.is_none());
            assert_eq!(
                recovered.rollback_workspace_generation,
                Some(rollback.clone())
            );
            assert_eq!(recovered.state, StoredEnvironmentState::Stopped);
            assert_eq!(recovered.generation, if checkpoint >= 5 { 2 } else { 1 });
            recovered.validate("dev").unwrap();
            core.ensure_no_unowned_workspace_staging().unwrap();
            assert!(
                core.store
                    .host_reboot_interrupted_workspace_transitions()
                    .unwrap()
                    .is_empty()
            );
        }
    }

    #[test]
    fn host_reboot_keeps_a_committed_runtime_update() {
        let mut environment = project_environment();
        let project_json = environment.project_spec_json.clone().unwrap();
        let project_sha256 = environment.project_spec_sha256.clone().unwrap();
        let RuntimeTransitionFixture {
            old_artifact: _,
            next_artifact,
            old_workspace: active,
            next_workspace: staging,
        } = same_image_runtime_transition(&environment);
        environment.state = StoredEnvironmentState::Running;
        environment.active_workspace_generation = Some(active.clone());
        environment.staging_workspace_generation = Some(staging.clone());
        environment.staging_artifact_generation = Some(next_artifact.clone());
        environment.validate("dev").unwrap();
        let payload = workspace_update_payload(&environment, &project_json, &project_sha256, true);
        environment.promote_staging_workspace_generation().unwrap();
        environment.generation = 2;
        environment.validate("dev").unwrap();
        let (_parent, mut core) = test_supervisor_core_after_host_reboot(
            environment,
            OperationKind::UpdateWorkspace,
            &payload,
            8,
        );

        core.recover_host_reboot_workspace_transitions().unwrap();

        let recovered = core.environment("dev").unwrap();
        assert_eq!(recovered.state, StoredEnvironmentState::Stopped);
        assert_eq!(recovered.generation, 2);
        assert_eq!(recovered.active_artifact_generation, Some(next_artifact));
        assert!(recovered.staging_artifact_generation.is_none());
        assert_eq!(recovered.active_workspace_generation, Some(staging));
        assert_eq!(recovered.rollback_workspace_generation, Some(active));
        recovered.validate("dev").unwrap();
        assert!(
            core.store
                .host_reboot_interrupted_workspace_transitions()
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn host_reboot_keeps_a_committed_runtime_rollback() {
        let mut environment = project_environment();
        let RuntimeTransitionFixture {
            old_artifact: rollback_artifact,
            next_artifact: active_artifact,
            old_workspace: rollback,
            next_workspace: active,
        } = same_image_runtime_transition(&environment);
        environment.active_artifact_generation = Some(active_artifact);
        environment.active_workspace_generation = Some(active.clone());
        environment.rollback_workspace_generation = Some(rollback.clone());
        environment.validate("dev").unwrap();
        let payload = workspace_rollback_payload(&environment, false);
        let parameters = workspace_transition_parameters(
            &test_workspace_transition_operation(
                &environment,
                OperationKind::RollbackWorkspace,
                payload.clone(),
                0,
            ),
            &environment,
        )
        .unwrap();
        let WorkspaceTransitionIntent::Rollback {
            rollback_storage_generation,
        } = &parameters.intent
        else {
            unreachable!()
        };
        environment
            .stage_rollback_workspace_generation(
                &parameters.prior_storage_generation,
                rollback_storage_generation,
            )
            .unwrap();
        environment.promote_staging_workspace_generation().unwrap();
        environment.generation = 2;
        environment.validate("dev").unwrap();
        let (_parent, mut core) = test_supervisor_core_after_host_reboot(
            environment,
            OperationKind::RollbackWorkspace,
            &payload,
            8,
        );

        core.recover_host_reboot_workspace_transitions().unwrap();

        let recovered = core.environment("dev").unwrap();
        assert_eq!(recovered.state, StoredEnvironmentState::Stopped);
        assert_eq!(recovered.generation, 2);
        assert_eq!(
            recovered.active_artifact_generation,
            Some(rollback_artifact)
        );
        assert!(recovered.staging_artifact_generation.is_none());
        assert_eq!(recovered.active_workspace_generation, Some(rollback));
        assert_eq!(recovered.rollback_workspace_generation, Some(active));
        recovered.validate("dev").unwrap();
        assert!(
            core.store
                .host_reboot_interrupted_workspace_transitions()
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn durable_workspace_records_are_the_only_retained_storage_generations() {
        let mut environment = project_environment();
        let project_spec_json = environment.project_spec_json.as_deref().unwrap();
        let project_sha256 = environment.project_spec_sha256.as_deref().unwrap();
        let active = test_workspace_generation(project_spec_json, project_sha256, b"active");
        let staging = test_workspace_generation(project_spec_json, project_sha256, b"staging");
        let old_rollback =
            test_workspace_generation(project_spec_json, project_sha256, b"old-rollback");
        let artifact = environment
            .active_artifact_generation
            .as_deref()
            .unwrap()
            .to_owned();
        environment.active_workspace_generation = Some(active.clone());
        environment.staging_workspace_generation = Some(staging.clone());
        environment.rollback_workspace_generation = Some(old_rollback.clone());

        let before = referenced_root_storage_generations(&environment).unwrap();
        assert_eq!(before.len(), 3);
        for generation in [&active, &staging, &old_rollback] {
            assert!(
                before.contains(
                    &oci_storage_generation(
                        &generation.root_generation,
                        &artifact,
                        generation.root_disk_bytes,
                    )
                    .unwrap()
                )
            );
        }

        assert_eq!(
            environment.promote_staging_workspace_generation().unwrap(),
            Some(old_rollback.clone())
        );
        let after = referenced_root_storage_generations(&environment).unwrap();
        assert_eq!(after.len(), 2);
        assert!(
            !after.contains(
                &oci_storage_generation(
                    &old_rollback.root_generation,
                    &artifact,
                    old_rollback.root_disk_bytes,
                )
                .unwrap()
            )
        );
    }

    #[test]
    fn artifact_retention_includes_active_staging_rollback_and_runner() {
        let mut environment = project_environment();
        let project_json = environment.project_spec_json.clone().unwrap();
        let project_sha256 = environment.project_spec_sha256.clone().unwrap();
        let active = "b".repeat(64);
        let staging = "c".repeat(64);
        let rollback = "d".repeat(64);
        let runner = "e".repeat(64);
        environment.active_workspace_generation = Some(test_workspace_generation_with_artifact(
            &project_json,
            &project_sha256,
            &active,
            b"active",
        ));
        environment.staging_artifact_generation = Some(staging.clone());
        environment.staging_workspace_generation = Some(test_workspace_generation_with_artifact(
            &project_json,
            &project_sha256,
            &staging,
            b"staging",
        ));
        environment.rollback_workspace_generation = Some(test_workspace_generation_with_artifact(
            &project_json,
            &project_sha256,
            &rollback,
            b"rollback",
        ));
        environment.runner = Some(RunnerRecord {
            process: ProcessIdentity {
                pid: 42,
                boot_id: "boot".to_owned(),
                start_time_ticks: 7,
                executable: PathBuf::from("/proc/self/exe"),
                executable_file: crate::linux::path::FileIdentity {
                    device: 1,
                    inode: 2,
                    size: 3,
                    uid: 4,
                    mode: 0o100500,
                    links: 1,
                },
                executable_sha256: "f".repeat(64),
            },
            socket: SocketIdentity {
                device: 1,
                inode: 2,
                uid: 4,
                mode: 0o140600,
            },
            artifact_generation: runner.clone(),
            error_code: None,
        });
        let state = SupervisorState {
            schema_version: SUPERVISOR_STATE_SCHEMA,
            current: Some("dev".to_owned()),
            environments: [("dev".to_owned(), environment)].into(),
        };

        assert_eq!(
            referenced_artifact_generations(&state).unwrap(),
            BTreeSet::from([active, staging, rollback, runner])
        );
    }

    #[test]
    fn shared_content_reachability_rejects_conflicting_descriptor_sizes() {
        let mut first = project_environment();
        first.active_workspace_generation = Some(test_workspace_generation(
            first.project_spec_json.as_deref().unwrap(),
            first.project_spec_sha256.as_deref().unwrap(),
            b"first",
        ));
        let mut second = project_environment();
        second.id = Uuid::new_v4();
        second.name = "second".to_owned();
        let mut second_generation = test_workspace_generation(
            second.project_spec_json.as_deref().unwrap(),
            second.project_spec_sha256.as_deref().unwrap(),
            b"second",
        );
        second_generation.image.config.digest = first
            .active_workspace_generation
            .as_ref()
            .unwrap()
            .image
            .config
            .digest
            .clone();
        second_generation.image.config.size += 1;
        second.active_workspace_generation = Some(second_generation);
        let state = SupervisorState {
            schema_version: SUPERVISOR_STATE_SCHEMA,
            current: Some("dev".to_owned()),
            environments: [("dev".to_owned(), first), ("second".to_owned(), second)].into(),
        };

        assert!(matches!(
            referenced_content_blobs(&state),
            Err(SupervisorError::InvalidState)
        ));
    }

    #[test]
    fn admitted_active_workspace_boots_without_registry_or_cas_access() {
        let engine = tempfile::tempdir().unwrap();
        fs::set_permissions(engine.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let mut environment = project_environment();
        let generation = test_workspace_generation(
            environment.project_spec_json.as_deref().unwrap(),
            environment.project_spec_sha256.as_deref().unwrap(),
            b"offline-active",
        );
        let storage_generation = oci_storage_generation(
            &generation.root_generation,
            environment.active_artifact_generation.as_deref().unwrap(),
            generation.root_disk_bytes,
        )
        .unwrap();
        crate::generation::ensure_empty_root_generation(
            engine.path(),
            environment.id,
            &storage_generation,
            generation.root_disk_bytes,
        )
        .unwrap();
        environment.active_workspace_generation = Some(generation.clone());

        let boot = prepare_workspace_boot(engine.path(), engine.path(), &[], &environment).unwrap();

        assert_eq!(boot.root_generation, storage_generation);
        assert_eq!(boot.root_disk_bytes, generation.root_disk_bytes);
        assert!(boot.setup_root_generation.is_empty());
        assert_eq!(boot.setup_total_bytes, 0);
        assert!(boot.setup_header_sha256.is_empty());
        assert!(!engine.path().join("content").exists());
    }

    #[test]
    fn source_only_changes_reuse_the_admitted_root_setup_and_skill_identity() {
        let engine = tempfile::tempdir().unwrap();
        fs::set_permissions(engine.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let mut environment = project_environment();
        let built = workspace_with_test_skills(&mut environment);
        let built_bytes = built.encode_canonical().unwrap();
        let skill_sha256 = built
            .skill_snapshot()
            .unwrap()
            .unwrap()
            .sha256()
            .unwrap()
            .to_string();
        let storage_generation = workspace_storage_generation(&built).unwrap();
        let root = crate::generation::ensure_empty_root_generation(
            engine.path(),
            environment.id,
            &storage_generation,
            built.root_disk_bytes,
        )
        .unwrap();
        let identity = root.identity;
        let modified = fs::metadata(&root.path).unwrap().modified().unwrap();
        environment.active_workspace_generation = Some(built.clone());
        let mut current: codewire_project::ProjectSpec =
            serde_json::from_slice(environment.project_spec_json.as_deref().unwrap()).unwrap();
        (current.secrets, current.credentials) = test_selectors();
        set_test_current_project(&mut environment, &current);
        for state in [
            StoredEnvironmentState::Stopped,
            StoredEnvironmentState::Running,
        ] {
            environment.state = state;
            let boot =
                prepare_workspace_boot(engine.path(), engine.path(), &[], &environment).unwrap();
            assert_eq!(boot.root_generation, storage_generation);
            assert_eq!(boot.skill_snapshot_sha256, skill_sha256);
            assert!(boot.setup_root_generation.is_empty());
            assert!(boot.setup_header_sha256.is_empty());
            assert_eq!(boot.setup_total_bytes, 0);
            assert_eq!(
                crate::linux::state::StateDiskIdentity::capture(&root.path).unwrap(),
                identity
            );
            assert_eq!(
                fs::metadata(&root.path).unwrap().modified().unwrap(),
                modified
            );
            assert_eq!(
                environment
                    .active_workspace_generation
                    .as_ref()
                    .unwrap()
                    .encode_canonical()
                    .unwrap(),
                built_bytes
            );
        }
        assert!(!engine.path().join("content").exists());
    }

    #[test]
    fn boot_and_rollback_delivery_checks_use_current_not_historical_sources() {
        let mut environment = project_environment();
        let empty = test_workspace_generation(
            environment.project_spec_json.as_deref().unwrap(),
            environment.project_spec_sha256.as_deref().unwrap(),
            b"empty-built-sources",
        );
        let mut selected: codewire_project::ProjectSpec =
            serde_json::from_slice(environment.project_spec_json.as_deref().unwrap()).unwrap();
        selected.secrets.user = Some(codewire_project::StoragePlacement::Platform);
        let selected_json = selected.canonical_json().unwrap();
        let selected_sha256 = format!("{:x}", Sha256::digest(&selected_json));
        let historical =
            test_workspace_generation(&selected_json, &selected_sha256, b"historical-sources");
        environment.active_workspace_generation = Some(empty.clone());
        environment.rollback_workspace_generation = Some(historical.clone());
        let parameters = workspace_transition_parameters(
            &test_workspace_transition_operation(
                &environment,
                OperationKind::RollbackWorkspace,
                workspace_rollback_payload(&environment, false),
                0,
            ),
            &environment,
        )
        .unwrap();
        // Historical selectors are metadata, not current delivery authority.
        reject_workspace_transition_workload_secrets(&environment, &parameters).unwrap();
        validate_workspace_transition_start(&environment, &parameters).unwrap();
        environment.staging_workspace_generation = Some(historical.clone());
        validate_environment_workload_secret_delivery(&environment, true).unwrap();
        environment.active_workspace_generation = Some(historical);
        validate_environment_workload_secret_delivery(&environment, false).unwrap();

        set_test_current_project(&mut environment, &selected);
        environment.active_workspace_generation = Some(empty);
        for staging in [false, true] {
            assert!(matches!(
                validate_environment_workload_secret_delivery(&environment, staging),
                Err(SupervisorError::EnvironmentAccessUnavailable),
            ));
        }
        let mut corrupt = environment;
        corrupt.project_spec_sha256 = Some("f".repeat(64));
        assert!(matches!(
            validate_environment_workload_secret_delivery(&corrupt, true),
            Err(SupervisorError::InvalidState),
        ));
    }

    #[tokio::test]
    async fn native_create_rejects_each_unpinned_platform_source_before_state_mutation() {
        for (index, secrets) in [
            codewire_project::SecretBindings {
                organization: true,
                ..Default::default()
            },
            codewire_project::SecretBindings {
                project: "platform:id:11111111-1111-4111-8111-111111111111".to_owned(),
                ..Default::default()
            },
            codewire_project::SecretBindings {
                user: Some(codewire_project::StoragePlacement::Platform),
                ..Default::default()
            },
        ]
        .into_iter()
        .enumerate()
        {
            let selected = project_environment_with_secret_selection(secrets, BTreeMap::new());
            let name = format!("secret-{index}");
            let request_id = Uuid::new_v4();
            let request = v1::CreateEnvironmentRequest {
                name: name.clone(),
                source_path: "/workspace/source".to_owned(),
                vcpus: u32::from(selected.vcpus),
                memory_mib: selected.memory_mib,
                disk_bytes: selected.disk_bytes,
                docker_disk_bytes: 0,
                request_id: request_id.to_string(),
                project_spec_json: selected.project_spec_json.unwrap(),
                project_spec_sha256: selected.project_spec_sha256.unwrap(),
                implicit_path_mode: "clone".to_owned(),
                local_mounts: Vec::new(),
                host_ports: Vec::new(),
                mesh: None,
                access_profile_id: String::new(),
                access_profile_revision: 0,
                access_profile_reference: String::new(),
                platform_source_authority: None,
            };
            let (_parent, core) = test_supervisor_core(project_environment());
            let credential_root = core.config.credential_authority_root.clone();
            let service = test_supervisor_service(core);

            let error = service
                .create_environment(Request::new(request))
                .await
                .unwrap_err();

            assert_eq!(error.code(), tonic::Code::InvalidArgument);
            let core = service.core.lock().await;
            assert!(
                core.store
                    .operation_by_request(request_id)
                    .unwrap()
                    .is_none()
            );
            assert!(!core.state.environments.contains_key(&name));
            assert!(!credential_root.exists());
        }
    }

    #[tokio::test]
    async fn native_start_journals_admitted_mixed_sources_before_runtime_authority() {
        let environment = project_environment_with_secret_selection(
            codewire_project::SecretBindings {
                user: Some(codewire_project::StoragePlacement::Platform),
                project: format!("local:id:{}", Uuid::new_v4()),
                ..Default::default()
            },
            BTreeMap::new(),
        );
        let environment_id = environment.id;
        let expected_generation = environment.generation.checked_add(1).unwrap();
        let (_parent, core) = test_supervisor_core(environment);
        let credential_root = core.config.credential_authority_root.clone();
        let service = test_supervisor_service(core);
        service.worker_running.store(true, Ordering::Release);
        let request_id = Uuid::new_v4();

        let submitted = service
            .start_environment(Request::new(v1::EnvironmentSelector {
                name: "dev".to_owned(),
                request_id: request_id.to_string(),
                environment_id: environment_id.to_string(),
            }))
            .await
            .unwrap()
            .into_inner();

        assert_eq!(submitted.kind, v1::OperationKind::Start as i32);
        assert_eq!(submitted.phase, v1::OperationPhase::Intent as i32);
        assert_eq!(submitted.checkpoint, 0);
        let core = service.core.lock().await;
        let pending = core
            .store
            .operation_by_request(request_id)
            .unwrap()
            .unwrap();
        assert_eq!(pending.request_id, request_id);
        assert_eq!(pending.environment_id, Some(environment_id));
        assert_eq!(pending.kind, OperationKind::Start);
        assert_eq!(pending.phase, OperationPhase::Intent);
        assert_eq!(pending.checkpoint, 0);
        assert_eq!(
            pending.payload,
            serde_json::json!({"name": "dev", "generation": expected_generation})
        );
        assert_eq!(pending.operation_id.to_string(), submitted.operation_id);
        assert_eq!(
            supervisor_effect(pending.kind, pending.checkpoint).unwrap(),
            Some(LifecycleEffect::RequireEnvironmentAccess)
        );
        assert_eq!(
            core.environment("dev").unwrap().state,
            StoredEnvironmentState::Stopped
        );
        assert!(!credential_root.exists());
    }

    #[test]
    fn platform_sources_are_admitted_at_boot_with_exact_material_free_binding() {
        for secrets in [
            codewire_project::SecretBindings {
                organization: true,
                ..Default::default()
            },
            codewire_project::SecretBindings {
                project: "platform:id:11111111-1111-4111-8111-111111111111".to_owned(),
                ..Default::default()
            },
            codewire_project::SecretBindings {
                user: Some(codewire_project::StoragePlacement::Platform),
                ..Default::default()
            },
        ] {
            let environment = project_environment_with_secret_selection(secrets, BTreeMap::new());
            validate_environment_workload_secret_delivery(&environment, false).unwrap();
            assert!(
                sources::platform::broker_binding(&environment, Path::new("/synthetic/config"))
                    .unwrap()
                    .is_some()
            );
        }
    }

    #[test]
    fn ordinary_environment_keys_do_not_require_the_credential_authority() {
        let environment = project_environment_with_secret_selection(
            codewire_project::SecretBindings::default(),
            BTreeMap::from([("PUBLIC_VALUE".to_owned(), "ordinary-value".to_owned())]),
        );
        validate_environment_workload_secret_delivery(&environment, false).unwrap();
    }

    #[test]
    fn local_application_sources_are_admitted_with_original_key_precedence_and_no_profile() {
        for secrets in [
            codewire_project::SecretBindings {
                user: Some(codewire_project::StoragePlacement::Local),
                ..Default::default()
            },
            codewire_project::SecretBindings {
                project: "local:id:11111111-1111-4111-8111-111111111111".into(),
                ..Default::default()
            },
        ] {
            let environment = project_environment_with_secret_selection(
                secrets,
                BTreeMap::from([("EXPLICIT".into(), "ordinary-value".into())]),
            );
            validate_environment_workload_secret_delivery(&environment, false).unwrap();
            let projection = sources::local_launch_projection(&environment)
                .unwrap()
                .unwrap();
            assert!(projection.selection.overridden_keys.contains("EXPLICIT"));
            assert!(environment.access_binding.is_none());
            assert!(environment.proto(false).requires_credential_authority);
        }
    }

    #[test]
    fn environment_proto_requires_the_authority_for_selected_sources_or_profiles() {
        assert!(
            !project_environment()
                .proto(false)
                .requires_credential_authority
        );
        assert!(
            project_environment_with_access()
                .proto(false)
                .requires_credential_authority
        );
        for secrets in [
            codewire_project::SecretBindings {
                organization: true,
                ..Default::default()
            },
            codewire_project::SecretBindings {
                project: "local:id:11111111-1111-4111-8111-111111111111".to_owned(),
                ..Default::default()
            },
            codewire_project::SecretBindings {
                user: Some(codewire_project::StoragePlacement::Local),
                ..Default::default()
            },
        ] {
            assert!(
                project_environment_with_secret_selection(secrets, BTreeMap::new())
                    .proto(false)
                    .requires_credential_authority
            );
        }
        assert!(
            !project_environment_with_secret_selection(
                codewire_project::SecretBindings::default(),
                BTreeMap::from([("PUBLIC_VALUE".to_owned(), "ordinary-value".to_owned())]),
            )
            .proto(false)
            .requires_credential_authority
        );
    }

    #[test]
    fn staging_workspace_never_boots_when_exact_cached_content_is_absent() {
        let engine = tempfile::tempdir().unwrap();
        fs::set_permissions(engine.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let mut environment = project_environment();
        environment.staging_workspace_generation = Some(test_workspace_generation(
            environment.project_spec_json.as_deref().unwrap(),
            environment.project_spec_sha256.as_deref().unwrap(),
            b"missing-content",
        ));

        assert!(matches!(
            prepare_workspace_boot(engine.path(), engine.path(), &[], &environment),
            Err(SupervisorError::SetupPack(SetupPackError::Registry(
                RegistryResolverError::Content(ContentStoreError::BlobMissing)
            )))
        ));
        assert!(environment.active_workspace_generation.is_none());
    }

    #[test]
    fn environment_names_are_single_safe_components() {
        for valid in ["dev", "dev-1", "a_b.c", "9"] {
            assert!(valid_environment_name(valid));
        }
        for invalid in ["", "-dev", "../dev", "dev/name", "two words"] {
            assert!(!valid_environment_name(invalid));
        }
    }

    #[test]
    fn supervisor_state_serialization_contains_no_secret_field() {
        let environment = project_environment_with_access();
        let state = SupervisorState {
            schema_version: SUPERVISOR_STATE_SCHEMA,
            current: Some(environment.name.clone()),
            environments: [(environment.name.clone(), environment)].into(),
        };
        state.validate().unwrap();
        let encoded = serde_json::to_string(&state).unwrap().to_ascii_lowercase();
        assert!(encoded.contains("11111111-1111-4111-8111-111111111111"));
        assert!(!encoded.contains("token"));
        assert!(!encoded.contains("credential"));
        assert!(!encoded.contains("capability"));
    }

    #[test]
    fn canonical_project_intent_is_digest_and_resource_bound() {
        let (bytes, digest) = project_intent(2, 16 * 1024, 20);
        let disk_bytes = 20 * 1024 * 1024 * 1024;
        validate_project_intent(&bytes, &digest, Some((2, 16 * 1024, disk_bytes))).unwrap();

        let mut selected: codewire_project::ProjectSpec = serde_json::from_slice(&bytes).unwrap();
        selected.secrets.user = Some(codewire_project::StoragePlacement::Local);
        selected
            .environment
            .insert("EXPLICIT".into(), "wins".into());
        let selected = selected.canonical_json().unwrap();
        let selected_digest = format!("{:x}", Sha256::digest(&selected));
        validate_project_intent(
            &selected,
            &selected_digest,
            Some((2, 16 * 1024, disk_bytes)),
        )
        .unwrap();

        let mut wrong_digest = digest.clone();
        wrong_digest.replace_range(0..1, "f");
        if wrong_digest == digest {
            wrong_digest.replace_range(0..1, "e");
        }
        assert!(
            validate_project_intent(&bytes, &wrong_digest, Some((2, 16 * 1024, disk_bytes)),)
                .is_err()
        );
        assert!(
            validate_project_intent(&bytes, &digest, Some((4, 16 * 1024, disk_bytes))).is_err()
        );

        let mut noncanonical = bytes.clone();
        noncanonical.push(b'\n');
        let noncanonical_digest = format!("{:x}", Sha256::digest(&noncanonical));
        assert!(
            validate_project_intent(
                &noncanonical,
                &noncanonical_digest,
                Some((2, 16 * 1024, disk_bytes)),
            )
            .is_err()
        );
    }

    #[test]
    fn canonical_project_setup_is_admitted_but_still_digest_bound() {
        let (bytes, _) = project_intent(2, 16 * 1024, 20);
        let mut project: codewire_project::ProjectSpec = serde_json::from_slice(&bytes).unwrap();
        project.install_command = "printf install".to_owned();
        project.startup_script = "printf startup".to_owned();
        let bytes = project.canonical_json().unwrap();
        let digest = format!("{:x}", Sha256::digest(&bytes));
        validate_project_intent(
            &bytes,
            &digest,
            Some((2, 16 * 1024, 20 * 1024 * 1024 * 1024)),
        )
        .unwrap();
        project.startup_script = "printf changed".to_owned();
        assert!(
            validate_project_intent(&project.canonical_json().unwrap(), &digest, None).is_err()
        );
        project.agents.install = Some(true);
        let bytes = project.canonical_json().unwrap();
        let digest = format!("{:x}", Sha256::digest(&bytes));
        assert!(validate_project_intent(&bytes, &digest, None).is_err());
    }

    #[test]
    fn stored_creation_intent_remains_valid_after_runtime_resource_resize() {
        let mut environment = project_environment();
        let creation_intent = environment.project_spec_json.clone().unwrap();
        let creation_digest = environment.project_spec_sha256.clone().unwrap();

        environment.vcpus = 3;
        environment.memory_mib = 12 * 1024;
        environment.disk_bytes = 21 * 1024 * 1024 * 1024;

        environment.validate("dev").unwrap();
        assert_eq!(environment.project_spec_json, Some(creation_intent));
        assert_eq!(environment.project_spec_sha256, Some(creation_digest));
    }

    #[test]
    fn create_journal_reconstructs_exact_canonical_project_intent() {
        let (project_spec_json, _) = project_intent(2, 16 * 1024, 20);
        let mut project: codewire_project::ProjectSpec =
            serde_json::from_slice(&project_spec_json).unwrap();
        project.application_ports = vec![codewire_project::ApplicationPort {
            port: 3_000,
            label: "app".to_owned(),
            access: String::new(),
        }];
        project.credentials = Some(codewire_project::CredentialBinding {
            profile: "local:id:11111111-1111-4111-8111-111111111111".into(),
        });
        project.install_command = "printf install".to_owned();
        project.startup_script = "printf startup".to_owned();
        let project_spec_json = project.canonical_json().unwrap();
        let project_spec_sha256 = format!("{:x}", Sha256::digest(&project_spec_json));
        let request = v1::CreateEnvironmentRequest {
            name: "dev".to_owned(),
            source_path: "/workspace/source".to_owned(),
            vcpus: 2,
            memory_mib: 16 * 1024,
            disk_bytes: 20 * 1024 * 1024 * 1024,
            docker_disk_bytes: crate::linux::state::MINIMUM_DOCKER_DISK_BYTES,
            request_id: Uuid::new_v4().to_string(),
            project_spec_json,
            project_spec_sha256,
            implicit_path_mode: "clone".to_owned(),
            local_mounts: Vec::new(),
            host_ports: vec![v1::HostPortBinding {
                host_port: 18_080,
                guest_port: 3_000,
            }],
            mesh: Some(v1::MeshAttachment {
                mesh_url: "https://mesh.example.test/base".to_owned(),
                organization_id: "org-test".to_owned(),
                network_id: "network-test".to_owned(),
                node_name: "dev".to_owned(),
                guest_ports: vec![3_000],
                auth_source: v1::MeshEnrollmentAuthSource::StandaloneLocal as i32,
            }),
            access_profile_id: "11111111-1111-4111-8111-111111111111".to_owned(),
            access_profile_revision: 7,
            access_profile_reference: "user/work".to_owned(),
            platform_source_authority: None,
        };
        validate_create(&request).unwrap();
        let mut incomplete = request.clone();
        incomplete.access_profile_revision = 0;
        assert!(matches!(
            validate_create(&incomplete),
            Err(SupervisorError::InvalidRequest)
        ));
        let mut invalid_docker = request.clone();
        invalid_docker.docker_disk_bytes = crate::linux::state::MINIMUM_DOCKER_DISK_BYTES - 1;
        assert!(matches!(
            validate_create(&invalid_docker),
            Err(SupervisorError::InvalidRequest)
        ));
        let workspace_plan = WorkspacePlan::local(&crate::workspace::WorkspaceSource {
            source_path: PathBuf::from("/workspace/source"),
            commit: "a".repeat(40),
            mode: WorkspaceSourceMode::Clone,
        })
        .unwrap();
        let operation = OperationRecord {
            operation_id: Uuid::new_v4(),
            request_id: Uuid::parse_str(&request.request_id).unwrap(),
            environment_id: Some(Uuid::new_v4()),
            kind: OperationKind::Create,
            phase: OperationPhase::Intent,
            checkpoint: 0,
            payload: create_operation_payload(&request, &workspace_plan).unwrap(),
            result: None,
            error_code: None,
            created_unix_ms: 1,
            updated_unix_ms: 1,
        };

        let environment_id = operation.environment_id.unwrap();
        assert_eq!(
            create_request_from_operation(&operation).unwrap(),
            (request, workspace_plan)
        );
        let (binding, reference) = create_request_access_binding(
            &create_request_from_operation(&operation).unwrap().0,
            environment_id,
        )
        .unwrap()
        .unwrap();
        assert_eq!(binding.environment_id.as_str(), environment_id.to_string());
        assert_eq!(
            binding.profile_id.as_str(),
            "11111111-1111-4111-8111-111111111111"
        );
        assert_eq!(binding.profile_revision, 7);
        assert_eq!(reference.to_string(), "user/work");
    }

    #[test]
    fn local_host_ports_are_canonical_and_must_target_declared_application_ports() {
        let canonical = canonicalize_host_ports_proto(&[
            v1::HostPortBinding {
                host_port: 18_081,
                guest_port: 3_001,
            },
            v1::HostPortBinding {
                host_port: 18_080,
                guest_port: 3_000,
            },
        ])
        .unwrap();
        assert_eq!(canonical[0].host_port, 18_080);
        assert_eq!(canonical[1].host_port, 18_081);

        let project = codewire_project::ProjectSpec {
            application_ports: vec![codewire_project::ApplicationPort {
                port: 3_000,
                label: String::new(),
                access: String::new(),
            }],
            ..Default::default()
        };
        assert!(
            validate_host_ports_for_project(
                &[HostPortBinding::new(18_080, 3_000).unwrap()],
                &project,
            )
            .is_ok()
        );
        assert!(matches!(
            validate_host_ports_for_project(
                &[HostPortBinding::new(18_081, 3_001).unwrap()],
                &project,
            ),
            Err(SupervisorError::InvalidRequest)
        ));
    }

    #[test]
    fn local_mesh_attachment_is_exact_environment_and_project_port_intent() {
        let project = codewire_project::ProjectSpec {
            application_ports: vec![
                codewire_project::ApplicationPort {
                    port: 8_080,
                    ..Default::default()
                },
                codewire_project::ApplicationPort {
                    port: 3_000,
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let raw = v1::MeshAttachment {
            mesh_url: " https://MESH.example.test/base/ ".to_owned(),
            organization_id: " org-test ".to_owned(),
            network_id: " network-test ".to_owned(),
            node_name: " dev ".to_owned(),
            guest_ports: vec![8_080, 3_000],
            auth_source: v1::MeshEnrollmentAuthSource::HostedCurrent as i32,
        };
        let canonical = canonicalize_mesh_attachment_proto(Some(&raw))
            .unwrap()
            .unwrap();
        assert_eq!(canonical.mesh_url, "https://mesh.example.test/base");
        assert_eq!(canonical.node_name, "dev");
        assert_eq!(canonical.guest_ports, vec![3_000, 8_080]);
        assert_eq!(
            canonical.auth_source,
            v1::MeshEnrollmentAuthSource::HostedCurrent as i32
        );
        let attachment = mesh_attachment_from_proto(Some(&canonical))
            .unwrap()
            .unwrap();
        assert_eq!(
            attachment.auth_source,
            MeshEnrollmentAuthSource::HostedCurrent
        );
        validate_mesh_for_project(&attachment, &project).unwrap();

        let mut wrong_ports = attachment.clone();
        wrong_ports.guest_ports = vec![3_000];
        assert!(validate_mesh_for_project(&wrong_ports, &project).is_err());
    }

    #[test]
    fn create_journal_reconstructs_copy_mounts_and_accepts_explicit_direct_shape() {
        let project = codewire_project::ProjectSpec {
            image: "registry.example/codewire/workspace:latest".to_owned(),
            working_directory: "/workspace/fixtures".to_owned(),
            resources: codewire_project::ResourceSpec {
                cpu_millicores: Some(2_000),
                memory_mib: Some(16 * 1024),
                disk_gib: Some(20),
            },
            ..Default::default()
        };
        let project_spec_json = project.canonical_json().unwrap();
        let request = v1::CreateEnvironmentRequest {
            name: "copy".to_owned(),
            source_path: String::new(),
            vcpus: 2,
            memory_mib: 16 * 1024,
            disk_bytes: 20 * 1024 * 1024 * 1024,
            docker_disk_bytes: 0,
            request_id: Uuid::new_v4().to_string(),
            project_spec_sha256: format!("{:x}", Sha256::digest(&project_spec_json)),
            project_spec_json,
            implicit_path_mode: String::new(),
            local_mounts: vec![v1::LocalMountInput {
                source_path: b"/host/fixtures".to_vec(),
                destination: "/workspace/fixtures".to_owned(),
                mode: v1::LocalMountMode::Copy as i32,
                read_only: None,
            }],
            host_ports: Vec::new(),
            mesh: None,
            access_profile_id: String::new(),
            access_profile_revision: 0,
            access_profile_reference: String::new(),
            platform_source_authority: None,
        };
        validate_create(&request).unwrap();
        let workspace_plan = WorkspacePlan::from_inputs(vec![WorkspaceInput::local(
            &crate::workspace::WorkspaceSource {
                source_path: PathBuf::from("/host/fixtures"),
                commit: "a".repeat(40),
                mode: WorkspaceSourceMode::Copy,
            },
            "/workspace/fixtures",
        )])
        .unwrap();
        let operation = OperationRecord {
            operation_id: Uuid::new_v4(),
            request_id: Uuid::parse_str(&request.request_id).unwrap(),
            environment_id: Some(Uuid::new_v4()),
            kind: OperationKind::Create,
            phase: OperationPhase::Intent,
            checkpoint: 0,
            payload: create_operation_payload(&request, &workspace_plan).unwrap(),
            result: None,
            error_code: None,
            created_unix_ms: 1,
            updated_unix_ms: 1,
        };

        assert_eq!(
            create_request_from_operation(&operation).unwrap(),
            (request.clone(), workspace_plan)
        );

        let mut direct = request;
        direct.local_mounts[0].mode = v1::LocalMountMode::Direct as i32;
        direct.local_mounts[0].read_only = Some(true);
        validate_create(&direct).unwrap();
        direct.local_mounts[0].read_only = None;
        assert!(matches!(
            validate_create(&direct),
            Err(SupervisorError::InvalidRequest)
        ));
    }

    #[tokio::test]
    async fn create_preparation_admits_an_explicit_copy_mount_without_an_implicit_path() {
        let source = tempfile::tempdir().unwrap();
        fs::write(source.path().join("fixture.txt"), b"copy fixture").unwrap();
        let source = fs::canonicalize(source.path()).unwrap();
        let project = codewire_project::ProjectSpec {
            image: "registry.example/codewire/workspace:latest".to_owned(),
            working_directory: "/workspace/fixtures".to_owned(),
            resources: codewire_project::ResourceSpec {
                cpu_millicores: Some(2_000),
                memory_mib: Some(16 * 1024),
                disk_gib: Some(20),
            },
            ..Default::default()
        };
        let project_spec_json = project.canonical_json().unwrap();
        let request = v1::CreateEnvironmentRequest {
            name: "copy".to_owned(),
            source_path: String::new(),
            vcpus: 2,
            memory_mib: 16 * 1024,
            disk_bytes: 20 * 1024 * 1024 * 1024,
            docker_disk_bytes: 0,
            request_id: Uuid::new_v4().to_string(),
            project_spec_sha256: format!("{:x}", Sha256::digest(&project_spec_json)),
            project_spec_json,
            implicit_path_mode: String::new(),
            local_mounts: vec![v1::LocalMountInput {
                source_path: source.as_os_str().as_bytes().to_vec(),
                destination: "/workspace/fixtures".to_owned(),
                mode: v1::LocalMountMode::Copy as i32,
                read_only: None,
            }],
            host_ports: Vec::new(),
            mesh: None,
            access_profile_id: String::new(),
            access_profile_revision: 0,
            access_profile_reference: String::new(),
            platform_source_authority: None,
        };
        validate_create(&request).unwrap();
        let (_parent, mut core) = test_supervisor_core(project_environment());
        let plan = core
            .prepare_create_workspace_plan(&request, Uuid::new_v4())
            .await
            .unwrap();

        assert_eq!(plan.inputs.len(), 1);
        assert!(matches!(
            &plan.inputs[0],
            WorkspaceInput::Local {
                source_path,
                mode: WorkspaceSourceMode::Copy,
                destination,
                ..
            } if source_path == source.as_os_str().as_bytes()
                && destination == "/workspace/fixtures"
        ));
        plan.validate_for_project(&project).unwrap();
    }

    #[tokio::test]
    async fn create_preparation_binds_an_explicit_direct_mount_for_durable_replay() {
        let source = tempfile::tempdir().unwrap();
        fs::write(source.path().join("fixture.txt"), b"direct fixture").unwrap();
        let source = fs::canonicalize(source.path()).unwrap();
        let project = codewire_project::ProjectSpec {
            image: "registry.example/codewire/workspace:latest".to_owned(),
            working_directory: "/workspace/fixtures".to_owned(),
            resources: codewire_project::ResourceSpec {
                cpu_millicores: Some(2_000),
                memory_mib: Some(16 * 1024),
                disk_gib: Some(20),
            },
            ..Default::default()
        };
        let project_spec_json = project.canonical_json().unwrap();
        let request = v1::CreateEnvironmentRequest {
            name: "direct".to_owned(),
            source_path: String::new(),
            vcpus: 2,
            memory_mib: 16 * 1024,
            disk_bytes: 20 * 1024 * 1024 * 1024,
            docker_disk_bytes: 0,
            request_id: Uuid::new_v4().to_string(),
            project_spec_sha256: format!("{:x}", Sha256::digest(&project_spec_json)),
            project_spec_json,
            implicit_path_mode: String::new(),
            local_mounts: vec![v1::LocalMountInput {
                source_path: source.as_os_str().as_bytes().to_vec(),
                destination: "/workspace/fixtures".to_owned(),
                mode: v1::LocalMountMode::Direct as i32,
                read_only: Some(false),
            }],
            host_ports: Vec::new(),
            mesh: None,
            access_profile_id: String::new(),
            access_profile_revision: 0,
            access_profile_reference: String::new(),
            platform_source_authority: None,
        };
        validate_create(&request).unwrap();
        let (_parent, mut core) = test_supervisor_core(project_environment());
        let plan = core
            .prepare_create_workspace_plan(&request, Uuid::new_v4())
            .await
            .unwrap();

        assert_eq!(plan.inputs.len(), 1);
        assert!(matches!(
            &plan.inputs[0],
            WorkspaceInput::Direct {
                source_path,
                destination,
                read_only: false,
                ..
            } if source_path == source.as_os_str().as_bytes()
                && destination == "/workspace/fixtures"
        ));
        plan.validate_for_project(&project).unwrap();
        let guest = plan.direct_share_plan().unwrap().unwrap();
        assert_eq!(guest.mounts()[0].tag(), "cw-direct-00");
        assert!(
            !guest
                .encode_canonical()
                .unwrap()
                .windows(source.as_os_str().as_bytes().len())
                .any(|window| window == source.as_os_str().as_bytes())
        );

        let encoded = create_operation_payload(&request, &plan).unwrap();
        let operation = OperationRecord {
            operation_id: Uuid::new_v4(),
            request_id: Uuid::parse_str(&request.request_id).unwrap(),
            environment_id: Some(Uuid::new_v4()),
            kind: OperationKind::Create,
            phase: OperationPhase::Intent,
            checkpoint: 0,
            payload: encoded,
            result: None,
            error_code: None,
            created_unix_ms: 1,
            updated_unix_ms: 1,
        };
        assert_eq!(
            create_request_from_operation(&operation).unwrap(),
            (request, plan)
        );
    }

    #[tokio::test]
    async fn create_revalidates_a_direct_share_before_its_first_lifecycle_effect() {
        let source = tempfile::tempdir().unwrap();
        let source = fs::canonicalize(source.path()).unwrap();
        let workspace_plan = direct_workspace_plan(&source);
        let fixture = project_environment_with_access();
        let request = v1::CreateEnvironmentRequest {
            name: "new-environment".to_owned(),
            source_path: String::new(),
            vcpus: u32::from(fixture.vcpus),
            memory_mib: fixture.memory_mib,
            disk_bytes: fixture.disk_bytes,
            docker_disk_bytes: fixture.docker_disk_bytes,
            request_id: Uuid::new_v4().to_string(),
            project_spec_json: fixture.project_spec_json.unwrap(),
            project_spec_sha256: fixture.project_spec_sha256.unwrap(),
            implicit_path_mode: String::new(),
            local_mounts: vec![v1::LocalMountInput {
                source_path: source.as_os_str().as_bytes().to_vec(),
                destination: "/workspace/fixtures".to_owned(),
                mode: v1::LocalMountMode::Direct as i32,
                read_only: Some(true),
            }],
            host_ports: Vec::new(),
            mesh: None,
            access_profile_id: "11111111-1111-4111-8111-111111111111".to_owned(),
            access_profile_revision: 7,
            access_profile_reference: "user/work".to_owned(),
            platform_source_authority: None,
        };
        validate_create(&request).unwrap();
        let (_parent, mut core) = test_supervisor_core(project_environment());
        let environment_id = Uuid::new_v4();
        let operation = core
            .store
            .begin_operation(
                Uuid::parse_str(&request.request_id).unwrap(),
                Some(environment_id),
                OperationKind::Create,
                &create_operation_payload(&request, &workspace_plan).unwrap(),
            )
            .unwrap();
        let credential_root = source.join("new-credential-authority");
        core.config.credential_authority_root = credential_root.clone();

        let error = core
            .create(&request, &workspace_plan, &operation)
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            SupervisorError::WorkspacePlan(WorkspacePlanError::DirectShareChanged)
        ));
        let pending = core
            .store
            .operation_by_request(operation.request_id)
            .unwrap()
            .unwrap();
        assert_eq!(pending.checkpoint, 0);
        assert!(!core.state.environments.contains_key(&request.name));
        assert!(!credential_root.exists());
        assert!(core.children.is_empty());
        assert!(core.live_runners.is_empty());
    }

    #[tokio::test]
    async fn replayed_create_quarantines_its_live_runner_when_private_roots_are_unresolvable() {
        let source = tempfile::tempdir().unwrap();
        let source = fs::canonicalize(source.path()).unwrap();
        let workspace_plan = direct_workspace_plan(&source);
        let mut environment = project_environment();
        environment.workspace_plan = workspace_plan.clone();
        let environment_id = environment.id;
        let request = v1::CreateEnvironmentRequest {
            name: "dev".to_owned(),
            source_path: String::new(),
            vcpus: u32::from(environment.vcpus),
            memory_mib: environment.memory_mib,
            disk_bytes: environment.disk_bytes,
            docker_disk_bytes: environment.docker_disk_bytes,
            request_id: Uuid::new_v4().to_string(),
            project_spec_sha256: environment.project_spec_sha256.clone().unwrap(),
            project_spec_json: environment.project_spec_json.clone().unwrap(),
            implicit_path_mode: String::new(),
            local_mounts: vec![v1::LocalMountInput {
                source_path: source.as_os_str().as_bytes().to_vec(),
                destination: "/workspace/fixtures".to_owned(),
                mode: v1::LocalMountMode::Direct as i32,
                read_only: Some(true),
            }],
            host_ports: Vec::new(),
            mesh: None,
            access_profile_id: String::new(),
            access_profile_revision: 0,
            access_profile_reference: String::new(),
            platform_source_authority: None,
        };
        let (_parent, mut core) = test_supervisor_core(environment);
        let operation = core
            .store
            .begin_operation(
                Uuid::parse_str(&request.request_id).unwrap(),
                Some(environment_id),
                OperationKind::Create,
                &create_operation_payload(&request, &workspace_plan).unwrap(),
            )
            .unwrap();
        let runner_socket = core.config.runner_socket(environment_id);
        let (runner_socket_identity, useful_calls, shutdown_tx, runner_server) =
            spawn_test_runner_protocol_server(&runner_socket, TestRunnerProtocolReply::Version(2));
        let (attached_environment_id, process_identity) =
            attach_test_runner_process(&mut core, runner_socket_identity);
        assert_eq!(attached_environment_id, environment_id);
        core.environment_mut("dev").unwrap().state = StoredEnvironmentState::Starting;
        core.save().unwrap();
        let platform_alias = _parent.path().join("platform-alias");
        std::os::unix::fs::symlink(_parent.path().join("missing-platform"), &platform_alias)
            .unwrap();
        core.config.platform_config_dir = platform_alias;

        let error = core
            .create(&request, &workspace_plan, &operation)
            .await
            .unwrap_err();

        assert!(matches!(error, SupervisorError::InvalidConfiguration));
        let pending = core
            .store
            .operation_by_request(operation.request_id)
            .unwrap()
            .unwrap();
        assert_eq!(pending.checkpoint, 0);
        let environment = core.environment("dev").unwrap();
        assert_eq!(environment.state, StoredEnvironmentState::Error);
        assert!(environment.runner.is_none());
        assert!(!runner_socket.exists());
        assert_eq!(useful_calls.load(Ordering::Relaxed), 0);
        assert!(matches!(
            LiveProcess::recover(&process_identity),
            Err(RecoveryError::ProcessExited | RecoveryError::ReadProcess(_))
        ));

        shutdown_tx.send(()).unwrap();
        runner_server.await.unwrap();
    }

    #[tokio::test]
    async fn start_revalidates_a_direct_share_before_access_and_runner_effects() {
        let source = tempfile::tempdir().unwrap();
        let source = fs::canonicalize(source.path()).unwrap();
        let mut environment = project_environment_with_access();
        environment.workspace_plan = direct_workspace_plan(&source);
        let original_generation = environment.generation;
        let environment_id = environment.id;
        let (_parent, mut core) = test_supervisor_core(environment);
        let operation = core
            .store
            .begin_operation(
                Uuid::new_v4(),
                Some(environment_id),
                OperationKind::Start,
                &serde_json::json!({"name": "dev", "generation": original_generation + 1}),
            )
            .unwrap();
        let credential_root = source.join("new-credential-authority");
        core.config.credential_authority_root = credential_root.clone();

        let error = core.start("dev", &operation).await.unwrap_err();

        assert!(matches!(
            error,
            SupervisorError::WorkspacePlan(WorkspacePlanError::DirectShareChanged)
        ));
        let pending = core
            .store
            .operation_by_request(operation.request_id)
            .unwrap()
            .unwrap();
        assert_eq!(pending.checkpoint, 0);
        let environment = core.environment("dev").unwrap();
        assert_eq!(environment.state, StoredEnvironmentState::Stopped);
        assert_eq!(environment.generation, original_generation);
        assert!(environment.runner.is_none());
        assert!(!credential_root.exists());
        assert!(core.children.is_empty());
        assert!(core.live_runners.is_empty());
    }

    #[tokio::test]
    async fn workspace_transition_revalidates_a_direct_share_before_access_and_staging() {
        let source = tempfile::tempdir().unwrap();
        let source = fs::canonicalize(source.path()).unwrap();
        let mut environment = project_environment_with_access();
        environment.workspace_plan = direct_workspace_plan(&source);
        let project_spec_json = environment.project_spec_json.clone().unwrap();
        let project_spec_sha256 = environment.project_spec_sha256.clone().unwrap();
        let active = test_workspace_generation(
            &project_spec_json,
            &project_spec_sha256,
            b"direct-share-transition",
        );
        environment.active_workspace_generation = Some(active.clone());
        environment.state = StoredEnvironmentState::Running;
        environment.validate("dev").unwrap();
        let environment_id = environment.id;
        let payload =
            workspace_update_payload(&environment, &project_spec_json, &project_spec_sha256, true);
        let (_parent, mut core) = test_supervisor_core(environment);
        let operation = core
            .store
            .begin_operation(
                Uuid::new_v4(),
                Some(environment_id),
                OperationKind::UpdateWorkspace,
                &payload,
            )
            .unwrap();
        let credential_root = source.join("new-credential-authority");
        core.config.credential_authority_root = credential_root.clone();

        let error = core
            .workspace_transition("dev", &operation)
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            SupervisorError::WorkspacePlan(WorkspacePlanError::DirectShareChanged)
        ));
        let pending = core
            .store
            .operation_by_request(operation.request_id)
            .unwrap()
            .unwrap();
        assert_eq!(pending.checkpoint, 0);
        let environment = core.environment("dev").unwrap();
        assert_eq!(environment.state, StoredEnvironmentState::Running);
        assert_eq!(environment.active_workspace_generation, Some(active));
        assert!(environment.staging_workspace_generation.is_none());
        assert!(environment.runner.is_none());
        assert!(!credential_root.exists());
        assert!(core.children.is_empty());
        assert!(core.live_runners.is_empty());
    }

    #[tokio::test]
    async fn restart_revalidates_a_direct_share_before_access_and_stop_effects() {
        let source = tempfile::tempdir().unwrap();
        let source = fs::canonicalize(source.path()).unwrap();
        let mut environment = project_environment_with_access();
        environment.workspace_plan = direct_workspace_plan(&source);
        environment.state = StoredEnvironmentState::Running;
        let environment_id = environment.id;
        let payload = serde_json::json!({
            "name": "dev",
            "vcpus": environment.vcpus,
            "memory_mib": environment.memory_mib,
            "disk_bytes": environment.disk_bytes,
            "was_running": true,
            "target_generation": environment.generation + 1,
        });
        let (_parent, mut core) = test_supervisor_core(environment);
        let operation = core
            .store
            .begin_operation(
                Uuid::new_v4(),
                Some(environment_id),
                OperationKind::Restart,
                &payload,
            )
            .unwrap();
        let credential_root = source.join("new-credential-authority");
        core.config.credential_authority_root = credential_root.clone();

        let error = core.resize("dev", &operation).await.unwrap_err();

        assert!(matches!(
            error,
            SupervisorError::WorkspacePlan(WorkspacePlanError::DirectShareChanged)
        ));
        let pending = core
            .store
            .operation_by_request(operation.request_id)
            .unwrap()
            .unwrap();
        assert_eq!(pending.checkpoint, 0);
        let environment = core.environment("dev").unwrap();
        assert_eq!(environment.state, StoredEnvironmentState::Running);
        assert!(environment.runner.is_none());
        assert!(!credential_root.exists());
        assert!(core.children.is_empty());
        assert!(core.live_runners.is_empty());
    }

    #[tokio::test]
    async fn ensure_vm_started_revalidates_a_direct_share_as_defense_in_depth() {
        let source = tempfile::tempdir().unwrap();
        let source = fs::canonicalize(source.path()).unwrap();
        let mut environment = project_environment();
        environment.workspace_plan = direct_workspace_plan(&source);
        let (_parent, mut core) = test_supervisor_core(environment);
        core.config.credential_authority_root = source.join("new-credential-authority");

        let error = core
            .ensure_vm_started("dev", 2, Uuid::new_v4())
            .await
            .unwrap_err();

        assert!(matches!(
            &error,
            SupervisorError::WorkspacePlan(WorkspacePlanError::DirectShareChanged)
        ));
        assert!(core.environment("dev").unwrap().runner.is_none());
    }

    #[tokio::test]
    async fn ensure_vm_started_quarantines_a_live_runner_for_an_unresolvable_private_root() {
        let source = tempfile::tempdir().unwrap();
        let source = fs::canonicalize(source.path()).unwrap();
        let mut environment = project_environment();
        environment.workspace_plan = direct_workspace_plan(&source);
        let environment_id = environment.id;
        let (_parent, mut core) = test_supervisor_core(environment);
        let runner_socket = core.config.runner_socket(environment_id);
        let (runner_socket_identity, useful_calls, shutdown_tx, runner_server) =
            spawn_test_runner_protocol_server(&runner_socket, TestRunnerProtocolReply::Version(2));
        let (attached_environment_id, process_identity) =
            attach_test_runner_process(&mut core, runner_socket_identity);
        assert_eq!(attached_environment_id, environment_id);
        core.environment_mut("dev").unwrap().state = StoredEnvironmentState::Starting;
        core.save().unwrap();
        let platform_alias = _parent.path().join("platform-alias");
        std::os::unix::fs::symlink(_parent.path().join("missing-platform"), &platform_alias)
            .unwrap();
        core.config.platform_config_dir = platform_alias;

        let error = core
            .ensure_vm_started("dev", 2, Uuid::new_v4())
            .await
            .unwrap_err();

        assert!(matches!(error, SupervisorError::InvalidConfiguration));
        let environment = core.environment("dev").unwrap();
        assert_eq!(environment.state, StoredEnvironmentState::Error);
        assert!(environment.runner.is_none());
        assert!(!runner_socket.exists());
        assert_eq!(useful_calls.load(Ordering::Relaxed), 0);
        assert!(matches!(
            LiveProcess::recover(&process_identity),
            Err(RecoveryError::ProcessExited | RecoveryError::ReadProcess(_))
        ));

        shutdown_tx.send(()).unwrap();
        runner_server.await.unwrap();
    }

    #[test]
    fn vsock_cid_is_stable_and_not_reserved() {
        let id = Uuid::parse_str("12345678-1234-5678-9abc-def012345678").unwrap();
        assert_eq!(allocate_vsock_cid(id), allocate_vsock_cid(id));
        assert!((3..u32::MAX).contains(&allocate_vsock_cid(id)));
    }

    #[test]
    fn supervisor_lock_excludes_a_second_store_mutator_until_release() {
        let parent = tempfile::tempdir().unwrap();
        fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let root = PrivateRoot::open(parent.path()).unwrap();
        let first = SupervisorLock::acquire(&root).unwrap();

        assert!(matches!(
            SupervisorLock::acquire(&root),
            Err(SupervisorError::AlreadyRunning)
        ));
        drop(first);
        SupervisorLock::acquire(&root).unwrap();
    }

    #[test]
    fn supervisor_lock_tolerates_a_transient_inherited_descriptor() {
        let parent = tempfile::tempdir().unwrap();
        fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let root = PrivateRoot::open(parent.path()).unwrap();
        let first = SupervisorLock::acquire(&root).unwrap();
        let inherited = first.0.try_clone().unwrap();
        drop(first);

        let releaser = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(40));
            drop(inherited);
        });
        SupervisorLock::acquire(&root).unwrap();
        releaser.join().unwrap();
    }

    #[test]
    fn native_state_requires_project_intent_and_runtime_generation() {
        let mut environment = project_environment();
        assert!(environment.validate("dev").is_ok());

        environment.project_spec_json = None;
        environment.project_spec_sha256 = None;
        assert!(matches!(
            environment.validate("dev"),
            Err(SupervisorError::InvalidState)
        ));

        let mut environment = project_environment();
        environment.active_artifact_generation = None;
        assert!(matches!(
            environment.validate("dev"),
            Err(SupervisorError::InvalidState)
        ));
    }

    #[test]
    fn start_operation_requires_an_exact_explicit_generation() {
        let operation = |payload| OperationRecord {
            operation_id: Uuid::new_v4(),
            request_id: Uuid::new_v4(),
            environment_id: Some(Uuid::new_v4()),
            kind: OperationKind::Start,
            phase: OperationPhase::Intent,
            checkpoint: 0,
            payload,
            result: None,
            error_code: None,
            created_unix_ms: 1,
            updated_unix_ms: 1,
        };

        assert_eq!(
            start_operation_generation(&operation(serde_json::json!({
                "name": "dev",
                "generation": 2,
            })))
            .unwrap(),
            2
        );
        for payload in [
            serde_json::json!({"name": "dev"}),
            serde_json::json!({"name": "dev", "generation": 0}),
            serde_json::json!({"name": "dev", "generation": 2, "compat": true}),
            serde_json::json!({"generation": 2, "compat": true}),
        ] {
            assert!(matches!(
                start_operation_generation(&operation(payload)),
                Err(SupervisorError::InvalidState)
            ));
        }
    }

    #[test]
    fn boot_generation_is_reserved_monotonically_before_runner_use() {
        let mut environment = project_environment();
        assert_eq!(environment.generation, 1);

        reserve_boot_generation(&mut environment, 2).unwrap();
        assert_eq!(environment.generation, 2);
        assert_eq!(environment.state, StoredEnvironmentState::Starting);
        reserve_boot_generation(&mut environment, 2).unwrap();

        environment.state = StoredEnvironmentState::Error;
        assert!(matches!(
            reserve_boot_generation(&mut environment, 2),
            Err(SupervisorError::InvalidState)
        ));
        reserve_boot_generation(&mut environment, 3).unwrap();
        assert_eq!(environment.generation, 3);
        assert_eq!(environment.state, StoredEnvironmentState::Starting);
        assert!(matches!(
            reserve_boot_generation(&mut environment, 2),
            Err(SupervisorError::InvalidState)
        ));
    }

    #[test]
    fn oci_storage_generation_binds_content_artifacts_and_disk_policy() {
        let oci_generation = "a".repeat(64);
        let artifact_generation = "b".repeat(64);
        let first = oci_storage_generation(
            &oci_generation,
            &artifact_generation,
            DEFAULT_OCI_ROOT_DISK_BYTES,
        )
        .unwrap();
        assert!(valid_sha256(&first));
        assert_eq!(
            oci_storage_generation(
                &oci_generation,
                &artifact_generation,
                DEFAULT_OCI_ROOT_DISK_BYTES,
            )
            .unwrap(),
            first
        );
        assert_ne!(
            oci_storage_generation(
                &"c".repeat(64),
                &artifact_generation,
                DEFAULT_OCI_ROOT_DISK_BYTES,
            )
            .unwrap(),
            first
        );
        assert_ne!(
            oci_storage_generation(
                &oci_generation,
                &"c".repeat(64),
                DEFAULT_OCI_ROOT_DISK_BYTES,
            )
            .unwrap(),
            first
        );
        assert_ne!(
            oci_storage_generation(
                &oci_generation,
                &artifact_generation,
                DEFAULT_OCI_ROOT_DISK_BYTES + 1024 * 1024,
            )
            .unwrap(),
            first
        );
    }

    #[test]
    fn staging_artifacts_are_selected_only_for_a_staging_boot() {
        let mut environment = project_environment();
        let project_json = environment.project_spec_json.clone().unwrap();
        let project_sha256 = environment.project_spec_sha256.clone().unwrap();
        environment.active_workspace_generation = Some(test_workspace_generation_with_artifact(
            &project_json,
            &project_sha256,
            &"b".repeat(64),
            b"active",
        ));
        environment.staging_workspace_generation = Some(test_workspace_generation_with_artifact(
            &project_json,
            &project_sha256,
            &"b".repeat(64),
            b"staging",
        ));
        assert_eq!(
            artifact_generation_for_boot(&environment, true).unwrap(),
            "b".repeat(64)
        );
        environment.staging_artifact_generation = Some("c".repeat(64));
        environment.staging_workspace_generation = Some(test_workspace_generation_with_artifact(
            &project_json,
            &project_sha256,
            &"c".repeat(64),
            b"staging",
        ));
        assert_eq!(
            artifact_generation_for_boot(&environment, true).unwrap(),
            "c".repeat(64)
        );
        assert_eq!(
            artifact_generation_for_boot(&environment, false).unwrap(),
            "b".repeat(64)
        );
    }

    #[test]
    fn retried_create_keeps_the_first_journaled_environment_id() {
        let parent = tempfile::tempdir().unwrap();
        let root_path = parent.path().join("runtime");
        fs::create_dir(&root_path).unwrap();
        fs::set_permissions(&root_path, fs::Permissions::from_mode(0o700)).unwrap();
        let root = PrivateRoot::open(&root_path).unwrap();
        let (store, _) = SupervisorStore::open(&root).unwrap();
        let request_id = Uuid::new_v4();
        let payload = serde_json::json!({"name": "dev"});
        let environment_id = Uuid::new_v4();

        let first = begin_create_operation(&store, request_id, environment_id, &payload).unwrap();
        let retried = begin_create_operation(&store, request_id, environment_id, &payload).unwrap();

        assert_eq!(retried, first);
        assert_eq!(first.environment_id, Some(environment_id));
        for (changed_id, changed_payload) in [
            (Uuid::new_v4(), payload.clone()),
            (environment_id, serde_json::json!({"name": "other"})),
        ] {
            assert!(matches!(
                begin_create_operation(&store, request_id, changed_id, &changed_payload),
                Err(SupervisorError::Store(
                    SupervisorStoreError::RequestCollision
                ))
            ));
        }
        assert!(begin_create_operation(&store, request_id, Uuid::nil(), &payload).is_err());
    }

    #[test]
    fn operation_watch_failure_preserves_code_and_safe_operation_identity() {
        let operation_id = Uuid::new_v4().to_string();
        let failure = operation_watch_failure(
            &operation_id,
            Status::cancelled("raw transport detail must not be reflected"),
        );

        assert_eq!(failure.code(), tonic::Code::Cancelled);
        assert_eq!(
            failure.message(),
            format!(
                "local lifecycle operation {operation_id} watch failed before a terminal result"
            )
        );
        assert!(!failure.message().contains("raw transport detail"));
    }

    #[tokio::test]
    async fn staging_boundary_collects_only_unreferenced_root_and_content_storage() {
        let parent = tempfile::tempdir().unwrap();
        let root_path = parent.path().join("runtime");
        fs::create_dir(&root_path).unwrap();
        fs::set_permissions(&root_path, fs::Permissions::from_mode(0o700)).unwrap();
        let root = PrivateRoot::open(&root_path).unwrap();
        root.ensure_dir(Path::new("engine"), 0o700).unwrap();
        root.ensure_dir(Path::new("runners"), 0o700).unwrap();
        let lock = SupervisorLock::acquire(&root).unwrap();
        let (store, _) = SupervisorStore::open(&root).unwrap();
        let engine = PrivateRoot::open(&root_path.join("engine")).unwrap();
        let (active_artifact, active_kernel) =
            install_test_artifact_generation(&engine, b"current-kernel");
        let (stale_artifact, stale_kernel) =
            install_test_artifact_generation(&engine, b"stale-kernel");
        let mut environment = project_environment();
        environment.active_artifact_generation = Some(active_artifact.clone());
        let active = test_workspace_generation_with_artifact(
            environment.project_spec_json.as_deref().unwrap(),
            environment.project_spec_sha256.as_deref().unwrap(),
            &active_artifact,
            b"active",
        );
        let active_storage = oci_storage_generation(
            &active.root_generation,
            environment.active_artifact_generation.as_deref().unwrap(),
            active.root_disk_bytes,
        )
        .unwrap();
        let stale_storage = "f".repeat(64);
        environment.active_workspace_generation = Some(active);
        let paths = VmPaths::create(&engine, environment.id).unwrap();
        for storage in [&active_storage, &stale_storage] {
            let generation =
                crate::linux::state::RootGenerationPaths::create(&paths, storage).unwrap();
            fs::write(&generation.root_disk, b"root").unwrap();
            fs::set_permissions(&generation.root_disk, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let state = SupervisorState {
            schema_version: SUPERVISOR_STATE_SCHEMA,
            current: Some("dev".to_owned()),
            environments: [("dev".to_owned(), environment)].into(),
        };
        let retained_content = referenced_content_blobs(&state).unwrap();
        ContentStore::create(&engine).unwrap();
        let blobs = engine.path().join("content/blobs");
        for (digest, size) in &retained_content {
            fs::write(
                blobs.join(digest.hex()),
                vec![0_u8; usize::try_from(*size).unwrap()],
            )
            .unwrap();
            fs::set_permissions(blobs.join(digest.hex()), fs::Permissions::from_mode(0o400))
                .unwrap();
        }
        let stale_content = Sha256Digest::parse(&format!("sha256:{}", "e".repeat(64))).unwrap();
        fs::write(blobs.join(stale_content.hex()), b"stale").unwrap();
        fs::set_permissions(
            blobs.join(stale_content.hex()),
            fs::Permissions::from_mode(0o400),
        )
        .unwrap();
        store.replace_state(&state).unwrap();
        let mut core = SupervisorCore {
            config: NativeRuntimeConfig {
                root: root_path,
                artifact_root: parent.path().join("artifacts"),
                artifact_lock: parent.path().join("artifacts.lock.json"),
                mesh_data_dir: parent.path().join("mesh-auth"),
                platform_config_dir: parent.path().join("platform-auth"),
                credential_authority_root: parent.path().join("credentials"),
                executable: PathBuf::from("/usr/bin/true"),
            },
            root,
            store,
            state,
            children: HashMap::new(),
            live_runners: HashMap::new(),
            operation_progress: broadcast::channel(OPERATION_PROGRESS_CAPACITY).0,
            _lock: lock,
        };

        assert_eq!(
            core.stage_workspace_generation("dev").await.unwrap(),
            core.state
        );
        assert!(paths.generations_dir.join(active_storage).is_dir());
        assert!(!paths.generations_dir.join(stale_storage).exists());
        for digest in retained_content.keys() {
            assert!(blobs.join(digest.hex()).is_file());
        }
        assert!(!blobs.join(stale_content.hex()).exists());
        let artifact_manifests = engine.path().join("runtime-artifacts/generations");
        let artifact_blobs = engine.path().join("runtime-artifacts/blobs");
        assert!(
            artifact_manifests
                .join(format!("{active_artifact}.json"))
                .is_file()
        );
        assert!(artifact_blobs.join(format!("r-{active_kernel}")).is_file());
        assert!(
            !artifact_manifests
                .join(format!("{stale_artifact}.json"))
                .exists()
        );
        assert!(!artifact_blobs.join(format!("r-{stale_kernel}")).exists());
    }

    #[tokio::test]
    async fn select_environment_persists_the_new_current_environment() {
        let (_parent, mut core) = test_supervisor_core(project_environment());
        let mut selected = project_environment();
        selected.name = "selected".to_owned();
        let selected_id = selected.id;
        core.state
            .environments
            .insert(selected.name.clone(), selected);
        core.save().unwrap();
        let service = test_supervisor_service(core);

        let response = service
            .select_environment(Request::new(v1::EnvironmentSelector {
                name: "selected".to_owned(),
                request_id: Uuid::new_v4().to_string(),
                environment_id: selected_id.to_string(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.id, selected_id.to_string());
        assert!(response.selected);

        let core = service.core.lock().await;
        assert_eq!(core.state.current.as_deref(), Some("selected"));
        let (_, persisted) = SupervisorStore::inspect(&core.root).unwrap();
        assert_eq!(persisted.current.as_deref(), Some("selected"));
    }

    #[tokio::test]
    async fn select_environment_rejects_a_recreated_identity_without_changing_current() {
        let (_parent, core) = test_supervisor_core(project_environment());
        let service = test_supervisor_service(core);

        let error = service
            .select_environment(Request::new(v1::EnvironmentSelector {
                name: "dev".to_owned(),
                request_id: Uuid::new_v4().to_string(),
                environment_id: Uuid::new_v4().to_string(),
            }))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::NotFound);

        let core = service.core.lock().await;
        assert_eq!(core.state.current.as_deref(), Some("dev"));
    }

    #[tokio::test]
    async fn lifecycle_rpc_commits_before_the_detached_worker_completes() {
        let (_parent, core) = test_supervisor_core(project_environment());
        let service = test_supervisor_service(core);
        let submitted = service
            .stop_environment(Request::new(v1::EnvironmentSelector {
                name: "dev".to_owned(),
                request_id: Uuid::new_v4().to_string(),
                environment_id: String::new(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(
            v1::OperationPhase::try_from(submitted.phase).unwrap(),
            v1::OperationPhase::Intent
        );
        assert_eq!(submitted.checkpoint, 0);

        let response = service
            .watch_operation(Request::new(v1::WatchOperationRequest {
                operation_id: submitted.operation_id.clone(),
            }))
            .await
            .unwrap();
        let mut stream = response.into_inner();
        let terminal = tokio::time::timeout(Duration::from_secs(1), async {
            while let Some(update) = futures::StreamExt::next(&mut stream).await {
                let update = update.unwrap();
                if operation_terminal(&update).unwrap() {
                    return update;
                }
            }
            panic!("operation watch ended before completion")
        })
        .await
        .unwrap();
        assert_eq!(
            v1::OperationPhase::try_from(terminal.phase).unwrap(),
            v1::OperationPhase::Completed
        );
        assert!(terminal.checkpoint > submitted.checkpoint);
    }

    #[tokio::test]
    async fn broker_stop_does_not_treat_missing_authority_as_proven_child_death() {
        let (_parent, mut core) = test_supervisor_core(project_environment_with_access());
        let environment = core.environment("dev").unwrap().clone();
        assert!(environment.generation > 0);
        assert!(matches!(
            core.stop_environment_broker_if_present(&environment).await,
            Err(SupervisorError::CredentialAuthorityUnavailable)
        ));
    }

    #[tokio::test]
    async fn broker_stop_accepts_exact_authority_ack_without_changing_profile_binding() {
        let (_parent, mut core) = test_supervisor_core(project_environment());
        let (mut authority, server) = start_test_credential_authority(&core).await;
        let binding = bind_test_environment_access(&mut core, &mut authority).await;
        let environment = core.environment("dev").unwrap().clone();
        core.stop_environment_broker_if_present(&environment)
            .await
            .unwrap();
        assert_eq!(
            authority
                .get_environment_access_binding(&binding.environment_id)
                .await
                .unwrap()
                .binding,
            binding
        );
        drop(authority);
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn client_bootstrap_requires_the_exact_profile_binding_without_material_access() {
        let (_parent, mut core) = test_supervisor_core(project_environment());
        let empty = core.environment("dev").unwrap().clone();
        assert_eq!(
            core.managed_credential_clients_for_boot(&empty)
                .await
                .unwrap(),
            Default::default()
        );
        let (mut authority, server) = start_test_credential_authority(&core).await;
        let binding = bind_test_environment_access(&mut core, &mut authority).await;
        let environment = core.environment("dev").unwrap().clone();
        assert_eq!(
            core.managed_credential_clients_for_boot(&environment)
                .await
                .unwrap(),
            Default::default()
        );
        let mut wrong = environment.clone();
        wrong.access_binding.as_mut().unwrap().profile_revision = binding.profile_revision + 1;
        assert!(matches!(
            core.managed_credential_clients_for_boot(&wrong).await,
            Err(SupervisorError::EnvironmentAccessUnavailable)
        ));
        let mut platform = environment.clone();
        let mut spec: codewire_project::ProjectSpec =
            serde_json::from_slice(platform.project_spec_json.as_deref().unwrap()).unwrap();
        spec.credentials.as_mut().unwrap().profile = format!("platform:id:{}", binding.profile_id);
        set_test_current_project(&mut platform, &spec);
        assert!(matches!(
            core.managed_credential_clients_for_boot(&platform).await,
            Err(SupervisorError::EnvironmentAccessUnavailable)
        ));
        drop(authority);
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn bound_environment_fails_closed_when_the_authority_is_unavailable() {
        let environment = project_environment_with_access();
        let public = environment.proto(true);
        assert_eq!(public.access_profile, "user/work");
        assert_eq!(public.access_profile_revision, 7);
        assert_eq!(
            public.access_profile_id,
            "11111111-1111-4111-8111-111111111111"
        );
        let (_parent, mut core) = test_supervisor_core(environment);

        assert!(matches!(
            core.require_environment_access("dev").await,
            Err(SupervisorError::CredentialAuthorityUnavailable)
        ));
        assert!(
            core.revoke_environment_access_best_effort(Uuid::new_v4())
                .await
        );
    }

    #[tokio::test]
    async fn credential_broker_rpc_quarantines_an_unsafe_runner_before_authority_use() {
        let source = tempfile::tempdir().unwrap();
        let source = fs::canonicalize(source.path()).unwrap();
        let mut environment = project_environment_with_access();
        environment.workspace_plan = direct_workspace_plan(&source);
        let environment_id = environment.id;
        let (_parent, mut core) = test_supervisor_core(environment);
        let socket = core.config.runner_socket(environment_id);
        let (socket_identity, useful_calls, shutdown_tx, runner_server) =
            spawn_test_runner_protocol_server(&socket, TestRunnerProtocolReply::Version(2));
        let (attached_environment_id, process_identity) =
            attach_test_runner_process(&mut core, socket_identity);
        assert_eq!(attached_environment_id, environment_id);
        let mut detached_child = core.children.remove(&environment_id).unwrap();
        core.live_runners.remove(&environment_id).unwrap();
        core.config.credential_authority_root = source.join("new-credential-authority");
        let service = test_supervisor_service(core);

        let error = LocalSupervisorService::ensure_credential_broker(
            &service,
            Request::new(read_selector("dev")),
        )
        .await
        .unwrap_err();

        assert_eq!(error.code(), tonic::Code::FailedPrecondition);
        assert_eq!(
            error.message(),
            "direct-share source changed after admission"
        );
        let core = service.core.lock().await;
        let environment = core.environment("dev").unwrap();
        assert_eq!(environment.state, StoredEnvironmentState::Error);
        assert!(environment.runner.is_none());
        assert!(!core.live_runners.contains_key(&environment_id));
        assert!(!core.children.contains_key(&environment_id));
        assert!(!socket.exists());
        assert_eq!(useful_calls.load(Ordering::Relaxed), 0);
        assert!(matches!(
            LiveProcess::recover(&process_identity),
            Err(RecoveryError::ProcessExited | RecoveryError::ReadProcess(_))
        ));
        let _ = detached_child.wait().unwrap();
        drop(core);

        shutdown_tx.send(()).unwrap();
        runner_server.await.unwrap();
    }

    #[tokio::test]
    async fn credential_broker_requires_an_exact_runner_after_reconciliation() {
        let mut environment = project_environment_with_access();
        environment.state = StoredEnvironmentState::Running;
        let (_parent, core) = test_supervisor_core(environment);
        assert!(matches!(
            core.credential_broker_ensure_request("dev"),
            Err(SupervisorError::NotRunning)
        ));
        let service = test_supervisor_service(core);

        let error = LocalSupervisorService::ensure_credential_broker(
            &service,
            Request::new(read_selector("dev")),
        )
        .await
        .unwrap_err();

        assert_eq!(error.code(), tonic::Code::FailedPrecondition);
        assert_eq!(error.message(), "local environment is not running");
        let core = service.core.lock().await;
        let environment = core.environment("dev").unwrap();
        assert_eq!(environment.state, StoredEnvironmentState::Error);
        assert!(environment.runner.is_none());
    }

    #[tokio::test]
    async fn credential_broker_rejects_a_replaced_runner_socket_before_authority_use() {
        let environment = project_environment_with_access();
        let environment_id = environment.id;
        let (_parent, mut core) = test_supervisor_core(environment);
        let socket = core.config.runner_socket(environment_id);
        let (socket_identity, useful_calls, shutdown_tx, runner_server) =
            spawn_test_runner_protocol_server(&socket, TestRunnerProtocolReply::Version(2));
        let recorded_socket = socket_identity.clone();
        let (attached_environment_id, process_identity) =
            attach_test_runner_process(&mut core, socket_identity);
        assert_eq!(attached_environment_id, environment_id);
        let mut detached_child = core.children.remove(&environment_id).unwrap();
        core.live_runners.remove(&environment_id).unwrap();
        remove_bound_socket(&socket, &recorded_socket).unwrap();
        fs::write(&socket, b"untrusted replacement").unwrap();
        let service = test_supervisor_service(core);

        let error = LocalSupervisorService::ensure_credential_broker(
            &service,
            Request::new(read_selector("dev")),
        )
        .await
        .unwrap_err();

        assert_eq!(error.code(), tonic::Code::FailedPrecondition);
        assert_eq!(
            error.message(),
            "local environment ownership is orphaned; inspect it with `cw doctor local`"
        );
        let core = service.core.lock().await;
        let environment = core.environment("dev").unwrap();
        assert_eq!(environment.state, StoredEnvironmentState::Orphaned);
        assert!(environment.runner.is_some());
        assert_eq!(fs::read(&socket).unwrap(), b"untrusted replacement");
        assert_eq!(useful_calls.load(Ordering::Relaxed), 0);
        assert!(LiveProcess::recover(&process_identity).is_ok());
        drop(core);

        detached_child.kill().unwrap();
        detached_child.wait().unwrap();
        shutdown_tx.send(()).unwrap();
        runner_server.await.unwrap();
    }

    #[test]
    fn reconcile_observation_applies_the_target_state_and_generation() {
        let (_parent, mut core) = test_supervisor_core(project_environment());
        let before = core.environment("dev").unwrap().clone();
        let target_generation = before.generation + 1;
        let payload = reconcile_operation_payload(
            &before,
            StoredEnvironmentState::Running,
            target_generation,
            false,
            None,
        );
        let operation = core
            .store
            .begin_operation(
                Uuid::new_v4(),
                Some(before.id),
                OperationKind::Reconcile,
                &payload,
            )
            .unwrap();

        let applied = core.apply_reconcile_operation(&operation).unwrap();

        assert_eq!(applied.checkpoint, 1);
        assert_eq!(
            core.environment("dev").unwrap().state,
            StoredEnvironmentState::Running
        );
        assert_eq!(
            core.environment("dev").unwrap().generation,
            target_generation
        );
    }

    #[test]
    fn stale_reconcile_observation_is_checkpointed_without_overwriting_newer_state() {
        let runner_record = |pid, inode| RunnerRecord {
            process: ProcessIdentity {
                pid,
                boot_id: "synthetic-boot".to_owned(),
                start_time_ticks: u64::from(pid),
                executable: PathBuf::from("/usr/bin/true"),
                executable_file: crate::linux::path::FileIdentity {
                    device: 1,
                    inode,
                    size: 1,
                    uid: crate::linux::path::current_uid(),
                    mode: 0o100755,
                    links: 1,
                },
                executable_sha256: "f".repeat(64),
            },
            socket: SocketIdentity {
                device: 1,
                inode,
                uid: crate::linux::path::current_uid(),
                mode: 0o140600,
            },
            artifact_generation: "b".repeat(64),
            error_code: None,
        };
        let mut environment = project_environment();
        environment.runner = Some(runner_record(41, 101));
        let (_parent, mut core) = test_supervisor_core(environment);
        let before = core.environment("dev").unwrap().clone();
        let payload = reconcile_operation_payload(
            &before,
            StoredEnvironmentState::Running,
            before.generation + 1,
            false,
            None,
        );
        let operation = core
            .store
            .begin_operation(
                Uuid::new_v4(),
                Some(before.id),
                OperationKind::Reconcile,
                &payload,
            )
            .unwrap();
        let replacement = runner_record(42, 102);
        core.environment_mut("dev").unwrap().runner = Some(replacement.clone());
        core.save().unwrap();

        let applied = core.apply_reconcile_operation(&operation).unwrap();

        assert_eq!(applied.checkpoint, 1);
        assert_eq!(core.environment("dev").unwrap().state, before.state);
        assert_eq!(
            core.environment("dev").unwrap().generation,
            before.generation
        );
        assert_eq!(core.environment("dev").unwrap().runner, Some(replacement));
    }

    #[test]
    fn reconcile_intent_rejects_missing_precondition_fields() {
        let (_parent, mut core) = test_supervisor_core(project_environment());
        let before = core.environment("dev").unwrap().clone();
        let operation = core
            .store
            .begin_operation(
                Uuid::new_v4(),
                Some(before.id),
                OperationKind::Reconcile,
                &serde_json::json!({
                    "name": "dev",
                    "observed_state": "running",
                    "generation": before.generation + 1,
                    "clear_runner": false,
                    "runner_error_code": null,
                }),
            )
            .unwrap();

        assert!(matches!(
            core.apply_reconcile_operation(&operation),
            Err(SupervisorError::InvalidState)
        ));
        let persisted = core
            .store
            .operation_by_request(operation.request_id)
            .unwrap()
            .unwrap();

        assert_eq!(persisted.phase, OperationPhase::Intent);
        assert_eq!(persisted.checkpoint, 0);
        assert_eq!(core.environment("dev").unwrap(), &before);
    }

    #[tokio::test]
    async fn startup_quarantines_an_exposing_unsafe_runner_before_listen_but_preserves_an_idle_one()
    {
        for persisted_state in [
            StoredEnvironmentState::Running,
            StoredEnvironmentState::Stopped,
        ] {
            let source = tempfile::tempdir().unwrap();
            let source = fs::canonicalize(source.path()).unwrap();
            let mut environment = project_environment();
            environment.workspace_plan = direct_workspace_plan(&source);
            let environment_id = environment.id;
            let (_parent, mut core) = test_supervisor_core(environment);
            fs::set_permissions(_parent.path(), fs::Permissions::from_mode(0o700)).unwrap();
            let runner_socket = core.config.runner_socket(environment_id);
            let (runner_socket_identity, useful_calls, shutdown_tx, runner_server) =
                spawn_test_runner_protocol_server(
                    &runner_socket,
                    TestRunnerProtocolReply::Version(2),
                );
            let recorded_runner_socket = runner_socket_identity.clone();
            let (attached_environment_id, process_identity) =
                attach_test_runner_process(&mut core, runner_socket_identity);
            assert_eq!(attached_environment_id, environment_id);
            core.environment_mut("dev").unwrap().state = persisted_state;
            core.save().unwrap();
            let mut detached_child = core.children.remove(&environment_id).unwrap();
            core.live_runners.remove(&environment_id).unwrap();
            core.config.credential_authority_root = source.join("new-credential-authority");
            let config = core.config.clone();
            assert!(core.store.pending_operations().unwrap().is_empty());
            drop(core);

            let supervisor_socket = config.supervisor_socket();
            let mut supervisor = tokio::spawn(serve_supervisor(config.clone()));
            let supervisor_socket_identity = tokio::select! {
                result = &mut supervisor => {
                    panic!("supervisor exited before listening: {result:?}");
                }
                identity = tokio::time::timeout(Duration::from_secs(2), async {
                    loop {
                        if let Ok(identity) = SocketIdentity::capture(&supervisor_socket) {
                            break identity;
                        }
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                }) => identity.expect("supervisor did not reach its listener after startup reconciliation"),
            };

            let root = PrivateRoot::open(&config.root).unwrap();
            let (_store, state) = SupervisorStore::inspect(&root).unwrap();
            let environment = state.environments.get("dev").unwrap();
            assert_eq!(useful_calls.load(Ordering::Relaxed), 0);
            if persisted_state == StoredEnvironmentState::Running {
                assert_eq!(environment.state, StoredEnvironmentState::Error);
                assert!(environment.runner.is_none());
                assert!(!runner_socket.exists());
                assert!(matches!(
                    LiveProcess::recover(&process_identity),
                    Err(RecoveryError::ProcessExited | RecoveryError::ReadProcess(_))
                ));
            } else {
                assert_eq!(environment.state, StoredEnvironmentState::Stopped);
                assert!(environment.runner.is_some());
                assert!(runner_socket.exists());
                assert!(LiveProcess::recover(&process_identity).is_ok());
            }
            drop(_store);
            drop(root);

            supervisor.abort();
            assert!(supervisor.await.unwrap_err().is_cancelled());
            remove_bound_socket(&supervisor_socket, &supervisor_socket_identity).unwrap();
            if persisted_state == StoredEnvironmentState::Stopped {
                detached_child.kill().unwrap();
            }
            let _ = detached_child.wait().unwrap();
            shutdown_tx.send(()).unwrap();
            runner_server.await.unwrap();
            if persisted_state == StoredEnvironmentState::Stopped {
                remove_bound_socket(&runner_socket, &recorded_runner_socket).unwrap();
            }
        }
    }

    #[tokio::test]
    async fn startup_replay_cannot_restore_a_runner_quarantined_for_an_unsafe_share() {
        let source = tempfile::tempdir().unwrap();
        let source = fs::canonicalize(source.path()).unwrap();
        let mut environment = project_environment();
        environment.workspace_plan = direct_workspace_plan(&source);
        let environment_id = environment.id;
        let (_parent, mut core) = test_supervisor_core(environment);
        fs::set_permissions(_parent.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let runner_socket = core.config.runner_socket(environment_id);
        let (runner_socket_identity, useful_calls, shutdown_tx, runner_server) =
            spawn_test_runner_protocol_server(&runner_socket, TestRunnerProtocolReply::Version(2));
        let (attached_environment_id, process_identity) =
            attach_test_runner_process(&mut core, runner_socket_identity);
        assert_eq!(attached_environment_id, environment_id);
        core.environment_mut("dev").unwrap().state = StoredEnvironmentState::Starting;
        core.save().unwrap();
        let before = core.environment("dev").unwrap().clone();
        let stale_payload = reconcile_operation_payload(
            &before,
            StoredEnvironmentState::Running,
            before.generation,
            false,
            None,
        );
        let stale = core
            .store
            .begin_operation(
                Uuid::new_v4(),
                Some(environment_id),
                OperationKind::Reconcile,
                &stale_payload,
            )
            .unwrap();
        let mut detached_child = core.children.remove(&environment_id).unwrap();
        core.live_runners.remove(&environment_id).unwrap();
        core.config.credential_authority_root = source.join("new-credential-authority");
        let config = core.config.clone();
        drop(core);

        let supervisor_socket = config.supervisor_socket();
        let mut supervisor = tokio::spawn(serve_supervisor(config.clone()));
        let supervisor_socket_identity = tokio::select! {
            result = &mut supervisor => {
                panic!("supervisor exited before listening: {result:?}");
            }
            identity = tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    if let Ok(identity) = SocketIdentity::capture(&supervisor_socket) {
                        break identity;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }) => identity.expect("supervisor did not listen after quarantining the unsafe runner"),
        };
        let root = PrivateRoot::open(&config.root).unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let reader = SupervisorOperationReader::open(&root).unwrap();
                let operation = reader.operation_by_id(stale.operation_id).unwrap().unwrap();
                if operation.phase == OperationPhase::Completed {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();

        let (_store, state) = SupervisorStore::inspect(&root).unwrap();
        let environment = state.environments.get("dev").unwrap();
        assert_eq!(environment.state, StoredEnvironmentState::Error);
        assert!(environment.runner.is_none());
        assert!(!runner_socket.exists());
        assert_eq!(useful_calls.load(Ordering::Relaxed), 0);
        assert!(matches!(
            LiveProcess::recover(&process_identity),
            Err(RecoveryError::ProcessExited | RecoveryError::ReadProcess(_))
        ));
        let _ = detached_child.wait().unwrap();
        drop(_store);
        drop(root);

        supervisor.abort();
        assert!(supervisor.await.unwrap_err().is_cancelled());
        remove_bound_socket(&supervisor_socket, &supervisor_socket_identity).unwrap();
        shutdown_tx.send(()).unwrap();
        runner_server.await.unwrap();
    }

    #[tokio::test]
    async fn startup_quarantines_an_exposing_runner_when_a_private_root_is_unresolvable() {
        let source = tempfile::tempdir().unwrap();
        let source = fs::canonicalize(source.path()).unwrap();
        let mut environment = project_environment();
        environment.workspace_plan = direct_workspace_plan(&source);
        let environment_id = environment.id;
        let (_parent, mut core) = test_supervisor_core(environment);
        fs::set_permissions(_parent.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let runner_socket = core.config.runner_socket(environment_id);
        let (runner_socket_identity, useful_calls, shutdown_tx, runner_server) =
            spawn_test_runner_protocol_server(&runner_socket, TestRunnerProtocolReply::Version(2));
        let (attached_environment_id, process_identity) =
            attach_test_runner_process(&mut core, runner_socket_identity);
        assert_eq!(attached_environment_id, environment_id);
        let mut detached_child = core.children.remove(&environment_id).unwrap();
        core.live_runners.remove(&environment_id).unwrap();
        let platform_alias = _parent.path().join("platform-alias");
        std::os::unix::fs::symlink(_parent.path().join("missing-platform"), &platform_alias)
            .unwrap();
        core.config.platform_config_dir = platform_alias;
        let config = core.config.clone();
        drop(core);

        let error = serve_supervisor(config.clone()).await.unwrap_err();

        assert!(matches!(error, SupervisorError::InvalidConfiguration));
        assert!(!config.supervisor_socket().exists());
        let root = PrivateRoot::open(&config.root).unwrap();
        let (_store, state) = SupervisorStore::inspect(&root).unwrap();
        let environment = state.environments.get("dev").unwrap();
        assert_eq!(environment.state, StoredEnvironmentState::Error);
        assert!(environment.runner.is_none());
        assert!(!runner_socket.exists());
        assert_eq!(useful_calls.load(Ordering::Relaxed), 0);
        assert!(matches!(
            LiveProcess::recover(&process_identity),
            Err(RecoveryError::ProcessExited | RecoveryError::ReadProcess(_))
        ));
        let _ = detached_child.wait().unwrap();

        shutdown_tx.send(()).unwrap();
        runner_server.await.unwrap();
    }

    #[tokio::test]
    async fn startup_quarantines_every_unsafe_runner_before_returning_an_earlier_runner_error() {
        let unsafe_source = tempfile::tempdir().unwrap();
        let unsafe_source = fs::canonicalize(unsafe_source.path()).unwrap();
        let mut valid_environment = project_environment();
        valid_environment.name = "a-valid".to_owned();
        let (_parent, mut core) = test_supervisor_core(valid_environment);
        fs::set_permissions(_parent.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let valid_environment_id = core.environment("a-valid").unwrap().id;
        let mut unsafe_environment = project_environment();
        unsafe_environment.id = Uuid::new_v4();
        unsafe_environment.name = "z-unsafe".to_owned();
        unsafe_environment.workspace_plan = direct_workspace_plan(&unsafe_source);
        let unsafe_environment_id = unsafe_environment.id;
        core.state
            .environments
            .insert(unsafe_environment.name.clone(), unsafe_environment);
        core.save().unwrap();

        let valid_socket = core.config.runner_socket(valid_environment_id);
        let (valid_socket_identity, valid_calls, valid_shutdown, valid_server) =
            spawn_test_runner_protocol_server(
                &valid_socket,
                TestRunnerProtocolReply::Failure(tonic::Code::Unavailable),
            );
        let recorded_valid_socket = valid_socket_identity.clone();
        let (attached_valid_id, valid_process_identity) =
            attach_named_test_runner_process(&mut core, "a-valid", valid_socket_identity);
        assert_eq!(attached_valid_id, valid_environment_id);
        let mut valid_child = core.children.remove(&valid_environment_id).unwrap();
        core.live_runners.remove(&valid_environment_id).unwrap();

        let unsafe_socket = core.config.runner_socket(unsafe_environment_id);
        let (unsafe_socket_identity, unsafe_calls, unsafe_shutdown, unsafe_server) =
            spawn_test_runner_protocol_server(&unsafe_socket, TestRunnerProtocolReply::Version(2));
        let (attached_unsafe_id, unsafe_process_identity) =
            attach_named_test_runner_process(&mut core, "z-unsafe", unsafe_socket_identity);
        assert_eq!(attached_unsafe_id, unsafe_environment_id);
        let mut unsafe_child = core.children.remove(&unsafe_environment_id).unwrap();
        core.live_runners.remove(&unsafe_environment_id).unwrap();
        core.config.credential_authority_root = unsafe_source.join("new-credential-authority");
        let config = core.config.clone();
        assert!(core.store.pending_operations().unwrap().is_empty());
        drop(core);

        let error = serve_supervisor(config.clone()).await.unwrap_err();

        assert!(
            matches!(
                error,
                SupervisorError::RunnerService(RunnerServiceError::RunnerProtocolInfoUnavailable)
            ),
            "unexpected startup error: {error:?}"
        );
        assert!(!config.supervisor_socket().exists());
        let root = PrivateRoot::open(&config.root).unwrap();
        let (_store, state) = SupervisorStore::inspect(&root).unwrap();
        let valid_environment = state.environments.get("a-valid").unwrap();
        assert_eq!(valid_environment.state, StoredEnvironmentState::Running);
        assert!(valid_environment.runner.is_some());
        assert!(valid_socket.exists());
        assert!(LiveProcess::recover(&valid_process_identity).is_ok());
        let unsafe_environment = state.environments.get("z-unsafe").unwrap();
        assert_eq!(unsafe_environment.state, StoredEnvironmentState::Error);
        assert!(unsafe_environment.runner.is_none());
        assert!(!unsafe_socket.exists());
        assert!(matches!(
            LiveProcess::recover(&unsafe_process_identity),
            Err(RecoveryError::ProcessExited | RecoveryError::ReadProcess(_))
        ));
        assert_eq!(valid_calls.load(Ordering::Relaxed), 0);
        assert_eq!(unsafe_calls.load(Ordering::Relaxed), 0);

        valid_child.kill().unwrap();
        valid_child.wait().unwrap();
        let _ = unsafe_child.wait().unwrap();
        valid_shutdown.send(()).unwrap();
        valid_server.await.unwrap();
        remove_bound_socket(&valid_socket, &recorded_valid_socket).unwrap();
        unsafe_shutdown.send(()).unwrap();
        unsafe_server.await.unwrap();
    }

    #[tokio::test]
    async fn startup_does_not_serve_a_running_state_without_an_exact_runner() {
        let mut environment = project_environment();
        environment.state = StoredEnvironmentState::Running;
        let (_parent, core) = test_supervisor_core(environment);
        fs::set_permissions(_parent.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let config = core.config.clone();
        assert!(core.store.pending_operations().unwrap().is_empty());
        drop(core);

        let supervisor_socket = config.supervisor_socket();
        let mut supervisor = tokio::spawn(serve_supervisor(config.clone()));
        let supervisor_socket_identity = tokio::select! {
            result = &mut supervisor => {
                panic!("supervisor exited before listening: {result:?}");
            }
            identity = tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    if let Ok(identity) = SocketIdentity::capture(&supervisor_socket) {
                        break identity;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }) => identity.expect("supervisor did not reach its listener after startup reconciliation"),
        };

        let root = PrivateRoot::open(&config.root).unwrap();
        let (_store, state) = SupervisorStore::inspect(&root).unwrap();
        let environment = state.environments.get("dev").unwrap();
        assert_eq!(environment.state, StoredEnvironmentState::Error);
        assert!(environment.runner.is_none());
        drop(_store);
        drop(root);

        supervisor.abort();
        assert!(supervisor.await.unwrap_err().is_cancelled());
        remove_bound_socket(&supervisor_socket, &supervisor_socket_identity).unwrap();
    }

    #[tokio::test]
    async fn recovering_start_waits_for_the_owner_authority_without_losing_intent() {
        let environment = project_environment_with_access();
        let environment_id = environment.id;
        let (_parent, mut core) = test_supervisor_core(environment);
        let operation = core
            .store
            .begin_operation(
                Uuid::new_v4(),
                Some(environment_id),
                OperationKind::Start,
                &serde_json::json!({"name": "dev", "generation": 2}),
            )
            .unwrap();

        assert!(matches!(
            core.replay_pending_operations().await,
            Err(SupervisorError::CredentialAuthorityUnavailable)
        ));
        let pending = core
            .store
            .operation_by_request(operation.request_id)
            .unwrap()
            .unwrap();
        assert_eq!(pending.phase, OperationPhase::Intent);
        assert_eq!(pending.checkpoint, 0);
        assert_eq!(
            core.environment("dev").unwrap().state,
            StoredEnvironmentState::Stopped
        );
    }

    #[tokio::test]
    async fn recovering_create_waits_at_its_latest_checkpoint_for_the_owner_authority() {
        let mut environment = project_environment_with_access();
        environment.state = StoredEnvironmentState::Starting;
        environment.generation = 0;
        let environment_id = environment.id;
        let workspace_plan = environment.workspace_plan.clone();
        let request = v1::CreateEnvironmentRequest {
            name: environment.name.clone(),
            source_path: "/workspace/source".to_owned(),
            vcpus: u32::from(environment.vcpus),
            memory_mib: environment.memory_mib,
            disk_bytes: environment.disk_bytes,
            docker_disk_bytes: environment.docker_disk_bytes,
            request_id: Uuid::new_v4().to_string(),
            project_spec_json: environment.project_spec_json.clone().unwrap(),
            project_spec_sha256: environment.project_spec_sha256.clone().unwrap(),
            implicit_path_mode: "clone".to_owned(),
            local_mounts: Vec::new(),
            host_ports: Vec::new(),
            mesh: None,
            access_profile_id: "11111111-1111-4111-8111-111111111111".to_owned(),
            access_profile_revision: 7,
            access_profile_reference: "user/work".to_owned(),
            platform_source_authority: None,
        };
        let payload = create_operation_payload(&request, &workspace_plan).unwrap();
        let (_parent, mut core) = test_supervisor_core(environment);
        let operation = begin_and_advance_test_operation(
            &core.store,
            environment_id,
            OperationKind::Create,
            &payload,
            1,
        );

        assert!(matches!(
            core.replay_pending_operations().await,
            Err(SupervisorError::CredentialAuthorityUnavailable)
        ));
        let pending = core
            .store
            .operation_by_request(operation.request_id)
            .unwrap()
            .unwrap();
        assert_eq!(pending.phase, OperationPhase::EffectApplied);
        assert_eq!(pending.checkpoint, 1);
        assert_eq!(
            core.environment("dev").unwrap().state,
            StoredEnvironmentState::Starting
        );
    }

    #[tokio::test]
    async fn recovering_restart_waits_for_the_owner_authority_without_losing_intent() {
        let mut environment = project_environment_with_access();
        environment.state = StoredEnvironmentState::Running;
        let environment_id = environment.id;
        let payload = serde_json::json!({
            "name": "dev",
            "vcpus": environment.vcpus,
            "memory_mib": environment.memory_mib,
            "disk_bytes": environment.disk_bytes,
            "was_running": true,
            "target_generation": environment.generation + 1,
        });
        let (_parent, mut core) = test_supervisor_core(environment);
        let operation = core
            .store
            .begin_operation(
                Uuid::new_v4(),
                Some(environment_id),
                OperationKind::Restart,
                &payload,
            )
            .unwrap();

        assert!(matches!(
            core.replay_pending_operations().await,
            Err(SupervisorError::CredentialAuthorityUnavailable)
        ));
        let pending = core
            .store
            .operation_by_request(operation.request_id)
            .unwrap()
            .unwrap();
        assert_eq!(pending.phase, OperationPhase::Intent);
        assert_eq!(pending.checkpoint, 0);
        assert_eq!(
            core.environment("dev").unwrap().state,
            StoredEnvironmentState::Running
        );
    }

    #[tokio::test]
    async fn recovering_workspace_update_is_not_aborted_while_the_authority_is_absent() {
        let mut environment = project_environment_with_access();
        let project_spec_json = environment.project_spec_json.clone().unwrap();
        let project_spec_sha256 = environment.project_spec_sha256.clone().unwrap();
        let active = test_workspace_generation(
            &project_spec_json,
            &project_spec_sha256,
            b"authority-recovery",
        );
        environment.active_workspace_generation = Some(active.clone());
        environment.state = StoredEnvironmentState::Running;
        environment.validate("dev").unwrap();
        let environment_id = environment.id;
        let payload =
            workspace_update_payload(&environment, &project_spec_json, &project_spec_sha256, true);
        let (_parent, mut core) = test_supervisor_core(environment);
        let operation = core
            .store
            .begin_operation(
                Uuid::new_v4(),
                Some(environment_id),
                OperationKind::UpdateWorkspace,
                &payload,
            )
            .unwrap();

        assert!(matches!(
            core.replay_pending_operations().await,
            Err(SupervisorError::CredentialAuthorityUnavailable)
        ));
        let pending = core
            .store
            .operation_by_request(operation.request_id)
            .unwrap()
            .unwrap();
        assert_eq!(pending.phase, OperationPhase::Intent);
        assert_eq!(pending.checkpoint, 0);
        let environment = core.environment("dev").unwrap();
        assert_eq!(environment.state, StoredEnvironmentState::Running);
        assert_eq!(environment.active_workspace_generation, Some(active));
        assert!(environment.staging_workspace_generation.is_none());
    }

    #[tokio::test]
    async fn a_new_mutation_cannot_terminalize_an_authority_deferred_recovery() {
        let environment = project_environment_with_access();
        let environment_id = environment.id;
        let (_parent, core) = test_supervisor_core(environment);
        let pending_request_id = Uuid::new_v4();
        core.store
            .begin_operation(
                pending_request_id,
                Some(environment_id),
                OperationKind::Start,
                &serde_json::json!({"name": "dev", "generation": 2}),
            )
            .unwrap();
        let service = test_supervisor_service(core);
        let new_request_id = Uuid::new_v4();

        let error = service
            .stop_environment(Request::new(v1::EnvironmentSelector {
                name: "dev".to_owned(),
                request_id: new_request_id.to_string(),
                environment_id: environment_id.to_string(),
            }))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::Unavailable);
        assert_eq!(error.message(), "local credential authority is unavailable");
        let core = service.core.lock().await;
        assert!(
            core.store
                .operation_by_request(new_request_id)
                .unwrap()
                .is_none()
        );
        let pending = core
            .store
            .operation_by_request(pending_request_id)
            .unwrap()
            .unwrap();
        assert_eq!(pending.phase, OperationPhase::Intent);
        assert_eq!(pending.checkpoint, 0);
        assert_eq!(
            core.environment("dev").unwrap().state,
            StoredEnvironmentState::Stopped
        );
    }

    #[tokio::test]
    async fn preboot_delete_replays_after_failed_workspace_admission() {
        for (staged, revoke_access) in [(false, false), (false, true), (true, false)] {
            let mut environment = project_environment();
            environment.generation = 0;
            environment.state = StoredEnvironmentState::Starting;
            if staged {
                environment.staging_workspace_generation =
                    Some(test_workspace_generation_with_artifact(
                        environment.project_spec_json.as_deref().unwrap(),
                        environment.project_spec_sha256.as_deref().unwrap(),
                        environment.active_artifact_generation.as_deref().unwrap(),
                        b"synthetic-preboot-image",
                    ));
            }
            let environment_id = environment.id;
            let (parent, mut core) = test_supervisor_core(environment);
            // A spawn would fail: deleting this preboot state must need
            // neither an executable runner nor an admitted workspace image.
            core.config.executable = parent.path().join("must-not-spawn");
            let engine = PrivateRoot::open(&core.config.engine_root()).unwrap();
            let paths = VmPaths::create(&engine, environment_id).unwrap();
            let create = begin_and_advance_test_operation(
                &core.store,
                environment_id,
                OperationKind::Create,
                &serde_json::json!({"name": "dev"}),
                if staged { 4 } else { 3 },
            );
            assert_eq!(
                supervisor_effect(create.kind, create.checkpoint).unwrap(),
                Some(if staged {
                    LifecycleEffect::RecordStarting
                } else {
                    LifecycleEffect::StageWorkspaceGeneration
                }),
            );
            let failure_code = if staged {
                "create_failed"
            } else {
                "create_registry_blob_stream"
            };
            core.fail_operation_with_environment_error(&create, "dev", failure_code)
                .unwrap();
            let delete = core
                .store
                .begin_operation(
                    Uuid::new_v4(),
                    Some(environment_id),
                    OperationKind::Delete,
                    &serde_json::json!({"name": "dev", "revoke_access": revoke_access}),
                )
                .unwrap();

            core.replay_pending_operations().await.unwrap();

            let reader = SupervisorOperationReader::open(&core.root).unwrap();
            let deleted = reader
                .operation_by_id(delete.operation_id)
                .unwrap()
                .unwrap();
            assert_eq!(deleted.phase, OperationPhase::Completed);
            assert_eq!(deleted.result.as_ref().unwrap()["removed"], true);
            // Absent authority remains an honest pending revocation, not a
            // reason to boot the failed environment or conceal cleanup work.
            assert_eq!(
                deleted.result.as_ref().unwrap()["cleanup_pending"],
                revoke_access
            );
            let failed = reader
                .operation_by_id(create.operation_id)
                .unwrap()
                .unwrap();
            assert_eq!(failed.phase, OperationPhase::Failed);
            assert_eq!(failed.error_code.as_deref(), Some(failure_code));
            assert!(core.state.environments.is_empty());
            assert!(core.state.current.is_none());
            assert!(core.children.is_empty());
            assert!(core.live_runners.is_empty());
            assert!(!paths.vm_dir.exists());
            assert!(matches!(
                deletion_tree_location(
                    &core.config.engine_root(),
                    environment_id,
                    delete.operation_id
                )
                .unwrap(),
                DeletionTreeLocation::Missing,
            ));
        }
    }

    #[tokio::test]
    async fn preboot_delete_does_not_skip_missing_workspace_after_boot_or_stop() {
        for (generation, state) in [
            (1, StoredEnvironmentState::Error),
            (1, StoredEnvironmentState::Stopped),
            (0, StoredEnvironmentState::Stopped),
        ] {
            let mut environment = project_environment();
            environment.generation = generation;
            environment.state = state;
            let environment_id = environment.id;
            let (_parent, mut core) = test_supervisor_core(environment);
            let engine = PrivateRoot::open(&core.config.engine_root()).unwrap();
            let paths = VmPaths::create(&engine, environment_id).unwrap();

            assert!(matches!(
                core.prepare_environment_for_delete("dev").await,
                Err(SupervisorError::InvalidState),
            ));
            assert!(paths.vm_dir.exists());
            assert!(core.state.environments.contains_key("dev"));
        }
    }

    #[tokio::test]
    async fn preboot_delete_does_not_reclassify_a_recorded_dead_runner() {
        let environment = project_environment();
        let environment_id = environment.id;
        let (_parent, mut core) = test_supervisor_core(environment);
        let engine = PrivateRoot::open(&core.config.engine_root()).unwrap();
        let paths = VmPaths::create(&engine, environment_id).unwrap();
        let (listener, identity) =
            bind_owner_only_listener(&core.config.runner_socket(environment_id)).unwrap();
        attach_test_runner_process(&mut core, identity);
        let environment = core.environment_mut("dev").unwrap();
        environment.generation = 0;
        environment.state = StoredEnvironmentState::Error;
        core.save().unwrap();
        let child = core.children.get_mut(&environment_id).unwrap();
        child.kill().unwrap();
        child.wait().unwrap();

        assert!(matches!(
            core.prepare_environment_for_delete("dev").await,
            Err(SupervisorError::InvalidState),
        ));
        assert!(
            core.environment("dev").unwrap().runner.is_none(),
            "reconciliation observed the dead runner"
        );
        assert!(paths.vm_dir.exists());
        drop(listener);
    }

    #[tokio::test]
    async fn delete_replay_preserves_the_stable_environment_precondition() {
        let environment = project_environment();
        let environment_id = environment.id;
        let request_id = Uuid::new_v4();
        let (_parent, core) = test_supervisor_core(environment);
        core.store
            .begin_operation(
                request_id,
                Some(environment_id),
                OperationKind::Delete,
                &serde_json::json!({"name": "dev", "revoke_access": false}),
            )
            .unwrap();
        let service = test_supervisor_service(core);

        let error = service
            .delete_environment(Request::new(v1::EnvironmentSelector {
                name: "dev".to_owned(),
                request_id: request_id.to_string(),
                environment_id: Uuid::new_v4().to_string(),
            }))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::NotFound);
        assert_eq!(error.message(), "local environment was not found");
        let core = service.core.lock().await;
        let pending = core
            .store
            .operation_by_request(request_id)
            .unwrap()
            .unwrap();
        assert_eq!(pending.phase, OperationPhase::Intent);
        assert_eq!(pending.checkpoint, 0);
        assert_eq!(core.environment("dev").unwrap().id, environment_id);
    }

    #[tokio::test]
    async fn start_replay_cannot_cross_a_recreated_environment_identity() {
        let environment = project_environment();
        let current_environment_id = environment.id;
        let prior_environment_id = Uuid::new_v4();
        let request_id = Uuid::new_v4();
        let (_parent, core) = test_supervisor_core(environment);
        core.store
            .begin_operation(
                request_id,
                Some(prior_environment_id),
                OperationKind::Start,
                &serde_json::json!({"name": "dev", "generation": 2}),
            )
            .unwrap();
        let service = test_supervisor_service(core);

        let error = service
            .start_environment(Request::new(v1::EnvironmentSelector {
                name: "dev".to_owned(),
                request_id: request_id.to_string(),
                environment_id: current_environment_id.to_string(),
            }))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::Aborted);
        assert_eq!(error.message(), "local lifecycle request ID collision");
    }

    #[tokio::test]
    async fn native_client_waits_for_the_durable_terminal_operation() {
        let (_parent, core) = test_supervisor_core(project_environment());
        let socket = core.config.supervisor_socket();
        let service = test_supervisor_service(core);
        let (listener, socket_identity) = bind_owner_only_listener(&socket).unwrap();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let server_service = service.clone();
        let server = tokio::spawn(async move {
            axum::serve(listener, public_api::supervisor_router(server_service))
                .with_graceful_shutdown(async move {
                    let _ = shutdown_rx.await;
                })
                .await
                .unwrap();
        });

        let mut client = NativeSupervisorClient::connect(&socket).await.unwrap();
        let environment = client.stop("dev").await.unwrap();
        assert_eq!(
            v1::EnvironmentState::try_from(environment.state).unwrap(),
            v1::EnvironmentState::Stopped
        );
        {
            let core = service.core.lock().await;
            assert!(core.store.pending_operations().unwrap().is_empty());
        }

        drop(client);
        shutdown_tx.send(()).unwrap();
        server.await.unwrap();
        remove_bound_socket(&socket, &socket_identity).unwrap();
    }

    #[tokio::test]
    async fn native_client_admits_the_current_protocol_and_configuration() {
        let (_parent, core) = test_supervisor_core(project_environment());
        let config = core.config.clone();
        let socket = config.supervisor_socket();
        let service = test_supervisor_service(core);
        let (socket_identity, shutdown_tx, server) = spawn_test_supervisor_server(&socket, service);

        let mut client = NativeSupervisorClient::connect_for_config(&socket, &config)
            .await
            .unwrap();
        assert_eq!(client.list().await.unwrap().len(), 1);

        drop(client);
        shutdown_tx.send(()).unwrap();
        server.await.unwrap();
        remove_bound_socket(&socket, &socket_identity).unwrap();
    }

    #[tokio::test]
    async fn native_client_rejects_an_old_supervisor_without_the_info_rpc() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("runtime");
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let socket = root.join("supervisor.sock");
        let (listener, socket_identity) = bind_owner_only_listener(&socket).unwrap();
        let app = axum::Router::new().route(
            "/codewire.local.v1.LocalSupervisorService/GetSupervisorInfo",
            axum::routing::post(|| async {
                let mut response = axum::response::Response::new(axum::body::Body::empty());
                response.headers_mut().insert(
                    http::header::CONTENT_TYPE,
                    http::HeaderValue::from_static("application/grpc"),
                );
                response.headers_mut().insert(
                    http::HeaderName::from_static("grpc-status"),
                    http::HeaderValue::from_static("12"),
                );
                response
            }),
        );
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = shutdown_rx.await;
                })
                .await
                .unwrap();
        });

        let error = match NativeSupervisorClient::connect(&socket).await {
            Ok(_) => panic!("old supervisor was admitted"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            SupervisorError::SupervisorProtocolUnavailable
        ));
        assert_eq!(
            error.to_string(),
            "the running native supervisor does not implement the required compatibility protocol"
        );

        shutdown_tx.send(()).unwrap();
        server.await.unwrap();
        remove_bound_socket(&socket, &socket_identity).unwrap();
    }

    #[tokio::test]
    async fn connect_or_start_rejects_a_live_supervisor_with_different_configuration() {
        let (parent, core) = test_supervisor_core(project_environment());
        fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let config = core.config.clone();
        let socket = config.supervisor_socket();
        let service = test_supervisor_service(core);
        let (socket_identity, shutdown_tx, server) = spawn_test_supervisor_server(&socket, service);
        let mut wrong_config = config.clone();
        wrong_config.credential_authority_root = config
            .credential_authority_root
            .with_file_name("different-credentials");

        let error = match NativeSupervisorClient::connect_or_start(&wrong_config).await {
            Ok(_) => panic!("differently configured supervisor was admitted"),
            Err(error) => error,
        };
        assert!(
            matches!(&error, SupervisorError::SupervisorConfigurationMismatch),
            "unexpected compatibility error: {error:?}"
        );
        assert_eq!(
            error.to_string(),
            "the running native supervisor uses a different runtime configuration"
        );
        // The incompatible live process remains available; only this reuse
        // attempt failed, and no replacement was started over its socket.
        assert!(NativeSupervisorClient::connect(&socket).await.is_ok());

        shutdown_tx.send(()).unwrap();
        server.await.unwrap();
        remove_bound_socket(&socket, &socket_identity).unwrap();
    }

    #[tokio::test]
    async fn reconcile_quarantines_an_unsafe_recovered_runner_without_trusting_its_socket() {
        for replace_socket in [false, true] {
            let source = tempfile::tempdir().unwrap();
            let source = fs::canonicalize(source.path()).unwrap();
            let mut environment = project_environment();
            environment.workspace_plan = direct_workspace_plan(&source);
            let (_parent, mut core) = test_supervisor_core(environment);
            let socket = core
                .config
                .runner_socket(core.environment("dev").unwrap().id);
            let (socket_identity, useful_calls, shutdown_tx, server) =
                spawn_test_runner_protocol_server(&socket, TestRunnerProtocolReply::Version(2));
            let recorded_socket = socket_identity.clone();
            let (environment_id, process_identity) =
                attach_test_runner_process(&mut core, socket_identity);
            let mut detached_child = core.children.remove(&environment_id).unwrap();
            core.live_runners.remove(&environment_id).unwrap();

            if replace_socket {
                remove_bound_socket(&socket, &recorded_socket).unwrap();
                fs::write(&socket, b"untrusted replacement").unwrap();
            }
            core.config.credential_authority_root = source.join("new-credential-authority");

            core.reconcile("dev").await.unwrap();

            let environment = core.environment("dev").unwrap();
            assert_eq!(environment.state, StoredEnvironmentState::Error);
            assert!(environment.runner.is_none());
            assert!(!core.live_runners.contains_key(&environment_id));
            assert!(!core.children.contains_key(&environment_id));
            assert_eq!(useful_calls.load(Ordering::Relaxed), 0);
            if replace_socket {
                assert_eq!(fs::read(&socket).unwrap(), b"untrusted replacement");
            } else {
                assert!(!socket.exists());
            }
            let _ = detached_child.wait().unwrap();
            assert!(matches!(
                LiveProcess::recover(&process_identity),
                Err(RecoveryError::ProcessExited | RecoveryError::ReadProcess(_))
            ));

            shutdown_tx.send(()).unwrap();
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn reconcile_kills_and_clears_an_exact_incompatible_runner() {
        for reply in [
            TestRunnerProtocolReply::Version(0),
            TestRunnerProtocolReply::Failure(tonic::Code::Unimplemented),
        ] {
            let (_parent, mut core) = test_supervisor_core(project_environment());
            let socket = core
                .config
                .runner_socket(core.environment("dev").unwrap().id);
            let (socket_identity, useful_calls, shutdown_tx, server) =
                spawn_test_runner_protocol_server(&socket, reply);
            let (environment_id, process_identity) =
                attach_test_runner_process(&mut core, socket_identity);

            core.reconcile("dev").await.unwrap();

            let environment = core.environment("dev").unwrap();
            assert_eq!(environment.state, StoredEnvironmentState::Error);
            assert!(environment.runner.is_none());
            assert!(!core.live_runners.contains_key(&environment_id));
            assert!(!core.children.contains_key(&environment_id));
            assert!(!socket.exists());
            assert_eq!(useful_calls.load(Ordering::Relaxed), 0);
            assert!(matches!(
                LiveProcess::recover(&process_identity),
                Err(RecoveryError::ProcessExited | RecoveryError::ReadProcess(_))
            ));

            shutdown_tx.send(()).unwrap();
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn reconcile_does_not_kill_a_runner_for_a_transient_protocol_query_failure() {
        let (_parent, mut core) = test_supervisor_core(project_environment());
        let socket = core
            .config
            .runner_socket(core.environment("dev").unwrap().id);
        let (socket_identity, useful_calls, shutdown_tx, server) =
            spawn_test_runner_protocol_server(
                &socket,
                TestRunnerProtocolReply::Failure(tonic::Code::Unavailable),
            );
        let (environment_id, _process_identity) =
            attach_test_runner_process(&mut core, socket_identity);

        let error = core.reconcile("dev").await.unwrap_err();

        assert!(matches!(
            error,
            SupervisorError::RunnerService(RunnerServiceError::RunnerProtocolInfoUnavailable)
        ));
        assert!(!error.to_string().contains("untrusted test peer detail"));
        assert!(core.environment("dev").unwrap().runner.is_some());
        assert!(core.live_runners.contains_key(&environment_id));
        assert!(
            core.children
                .get_mut(&environment_id)
                .unwrap()
                .try_wait()
                .unwrap()
                .is_none()
        );
        assert!(socket.exists());
        assert_eq!(useful_calls.load(Ordering::Relaxed), 0);

        core.terminate_recorded_runner("dev").await.unwrap();
        core.mark_runner_dead("dev").unwrap();
        shutdown_tx.send(()).unwrap();
        server.await.unwrap();
    }

    #[test]
    fn supervisor_info_requires_the_exact_protocol_and_valid_digest_shape() {
        let config = test_supervisor_core(project_environment()).1.config;
        let mut info = supervisor_info(&config);
        info.protocol_version = NATIVE_SUPERVISOR_PROTOCOL_VERSION + 1;
        let error = admit_supervisor_info(&info, None).unwrap_err();
        assert!(matches!(
            error,
            SupervisorError::SupervisorProtocolMismatch {
                expected: NATIVE_SUPERVISOR_PROTOCOL_VERSION,
                actual,
            } if actual == NATIVE_SUPERVISOR_PROTOCOL_VERSION + 1
        ));
        assert!(error.to_string().contains("protocol version mismatch"));

        info.protocol_version = NATIVE_SUPERVISOR_PROTOCOL_VERSION - 1;
        assert!(matches!(
            admit_supervisor_info(&info, None),
            Err(SupervisorError::SupervisorProtocolMismatch { .. })
        ));

        info.protocol_version = NATIVE_SUPERVISOR_PROTOCOL_VERSION;
        info.configuration_sha256.pop();
        assert!(matches!(
            admit_supervisor_info(&info, None),
            Err(SupervisorError::InvalidSupervisorInfo)
        ));
    }

    #[test]
    fn forbidden_direct_roots_resolve_existing_configuration_symlinks() {
        let private = tempfile::tempdir().unwrap();
        let real_platform = private.path().join("real-platform");
        fs::create_dir(&real_platform).unwrap();
        fs::set_permissions(&real_platform, fs::Permissions::from_mode(0o700)).unwrap();
        let platform_alias = private.path().join("platform-alias");
        std::os::unix::fs::symlink(&real_platform, &platform_alias).unwrap();
        let (_runtime, mut core) = test_supervisor_core(project_environment());
        core.config.platform_config_dir = platform_alias;

        let forbidden_roots = core.config.direct_share_forbidden_roots().unwrap();

        assert!(forbidden_roots.contains(&fs::canonicalize(&real_platform).unwrap()));
        assert!(matches!(
            prepare_direct_input(
                &fs::canonicalize(private.path()).unwrap(),
                "/workspace/private",
                true,
                &forbidden_roots,
            ),
            Err(WorkspacePlanError::DirectShareInvalid)
        ));
        assert!(matches!(
            prepare_direct_input(
                &fs::canonicalize(&real_platform).unwrap(),
                "/workspace/private",
                true,
                &forbidden_roots,
            ),
            Err(WorkspacePlanError::DirectShareInvalid)
        ));
    }

    #[test]
    fn forbidden_direct_roots_resolve_missing_suffix_beneath_a_symlink() {
        let private = tempfile::tempdir().unwrap();
        let real_platform = private.path().join("real-platform");
        fs::create_dir(&real_platform).unwrap();
        let platform_alias = private.path().join("platform-alias");
        std::os::unix::fs::symlink(&real_platform, &platform_alias).unwrap();
        let configured = platform_alias.join("future/config");
        let expected = real_platform.join("future/config");
        let (_runtime, mut core) = test_supervisor_core(project_environment());
        core.config.platform_config_dir = configured;

        let before_creation = core.config.direct_share_forbidden_roots().unwrap();
        assert!(before_creation.contains(&expected));

        fs::create_dir_all(&expected).unwrap();
        let after_creation = core.config.direct_share_forbidden_roots().unwrap();
        assert!(after_creation.contains(&fs::canonicalize(expected).unwrap()));
    }

    #[tokio::test]
    async fn operation_watch_starts_from_durable_state_and_ends_at_terminal_state() {
        let (_parent, core) = test_supervisor_core(project_environment());
        let service = test_supervisor_service(core);
        let operation = {
            let core = service.core.lock().await;
            let environment = core.environment("dev").unwrap();
            core.store
                .begin_operation(
                    Uuid::new_v4(),
                    Some(environment.id),
                    OperationKind::Start,
                    &serde_json::json!({"name": "dev", "generation": 1}),
                )
                .unwrap()
        };
        let operation_id = operation.operation_id;
        let response = service
            .watch_operation(Request::new(v1::WatchOperationRequest {
                operation_id: operation_id.to_string(),
            }))
            .await
            .unwrap();
        let mut stream = response.into_inner();
        let initial = tokio::time::timeout(
            Duration::from_secs(1),
            futures::StreamExt::next(&mut stream),
        )
        .await
        .unwrap()
        .unwrap()
        .unwrap();
        assert_eq!(initial.operation_id, operation_id.to_string());
        assert_eq!(initial.checkpoint, 0);
        assert_eq!(
            v1::OperationStage::try_from(initial.stage).unwrap(),
            v1::OperationStage::RequireEnvironmentAccess
        );

        assert!(
            service
                .operation_progress
                .send(OperationProgress {
                    operation_id,
                    event: v1::RunnerEvent {
                        sequence: 4,
                        runner: Some(v1::RunnerInfo {
                            environment_id: operation.environment_id.unwrap().to_string(),
                            state: v1::EnvironmentState::Starting as i32,
                            generation: 1,
                            artifact_generation: "a".repeat(64),
                            error_code: String::new(),
                        }),
                        stage: v1::RunnerStage::GuestInit as i32,
                        guest_sequence: 3,
                        guest_stage: v1::GuestBootStage::WorkspacePlanReady as i32,
                        error_code: String::new(),
                    },
                })
                .is_ok()
        );
        let progress = tokio::time::timeout(
            Duration::from_secs(1),
            futures::StreamExt::next(&mut stream),
        )
        .await
        .unwrap()
        .unwrap()
        .unwrap();
        assert_eq!(progress.checkpoint, initial.checkpoint);
        assert_eq!(progress.progress_sequence, 4);
        assert_eq!(
            v1::RunnerStage::try_from(progress.runner_stage).unwrap(),
            v1::RunnerStage::GuestInit
        );
        assert_eq!(progress.guest_sequence, 3);

        {
            let core = service.core.lock().await;
            let result = environment_operation_result(core.environment("dev").unwrap());
            core.store
                .advance_operation(
                    operation_id,
                    operation.checkpoint,
                    OperationPhase::Completed,
                    Some(&result),
                    None,
                )
                .unwrap();
        }
        let terminal = tokio::time::timeout(
            Duration::from_secs(1),
            futures::StreamExt::next(&mut stream),
        )
        .await
        .unwrap()
        .unwrap()
        .unwrap();
        assert_eq!(
            v1::OperationPhase::try_from(terminal.phase).unwrap(),
            v1::OperationPhase::Completed
        );
        assert_eq!(
            v1::OperationStage::try_from(terminal.stage).unwrap(),
            v1::OperationStage::Completed
        );
        assert!(terminal.result.is_some());
        assert!(
            tokio::time::timeout(
                Duration::from_secs(1),
                futures::StreamExt::next(&mut stream)
            )
            .await
            .unwrap()
            .is_none()
        );
    }

    #[tokio::test]
    async fn dropping_an_operation_watch_does_not_cancel_the_durable_operation() {
        let (_parent, core) = test_supervisor_core(project_environment());
        let service = test_supervisor_service(core);
        let operation = {
            let core = service.core.lock().await;
            let environment = core.environment("dev").unwrap();
            core.store
                .begin_operation(
                    Uuid::new_v4(),
                    Some(environment.id),
                    OperationKind::Stop,
                    &serde_json::json!({"name": "dev"}),
                )
                .unwrap()
        };
        let response = service
            .watch_operation(Request::new(v1::WatchOperationRequest {
                operation_id: operation.operation_id.to_string(),
            }))
            .await
            .unwrap();
        let mut stream = response.into_inner();
        assert!(futures::StreamExt::next(&mut stream).await.unwrap().is_ok());
        drop(stream);

        let completed = {
            let core = service.core.lock().await;
            let result = environment_operation_result(core.environment("dev").unwrap());
            core.store
                .advance_operation(
                    operation.operation_id,
                    operation.checkpoint,
                    OperationPhase::Completed,
                    Some(&result),
                    None,
                )
                .unwrap()
        };
        assert_eq!(
            service.operation(operation.operation_id).await.unwrap(),
            completed
        );
    }

    #[tokio::test]
    async fn generation_publication_serializes_all_generation_collectors() {
        let (_parent, core) = test_supervisor_core(project_environment());
        let service = test_supervisor_service(core);

        // Model the create/staging transaction after it has published bytes to
        // the three generation stores but before it has durably published the
        // references. Every RPC mutation and every collector must wait for the
        // same supervisor-core guard across that entire boundary.
        let mut create = service.core.lock().await;
        let engine = PrivateRoot::open(&create.config.engine_root()).unwrap();
        let (candidate_artifact, candidate_kernel) =
            install_test_artifact_generation(&engine, b"candidate-kernel");
        let (stale_artifact, stale_kernel) =
            install_test_artifact_generation(&engine, b"stale-kernel");
        let candidate_workspace = test_workspace_generation_with_artifact(
            create
                .environment("dev")
                .unwrap()
                .project_spec_json
                .as_deref()
                .unwrap(),
            create
                .environment("dev")
                .unwrap()
                .project_spec_sha256
                .as_deref()
                .unwrap(),
            &candidate_artifact,
            b"candidate",
        );
        let candidate_storage = workspace_storage_generation(&candidate_workspace).unwrap();
        let stale_storage = "f".repeat(64);
        let paths = VmPaths::create(&engine, create.environment("dev").unwrap().id).unwrap();
        for storage in [&candidate_storage, &stale_storage] {
            let generation =
                crate::linux::state::RootGenerationPaths::create(&paths, storage).unwrap();
            fs::write(&generation.root_disk, b"root").unwrap();
            fs::set_permissions(&generation.root_disk, fs::Permissions::from_mode(0o600)).unwrap();
        }

        let mut published_state = create.state.clone();
        let published_environment = published_state.environments.get_mut("dev").unwrap();
        published_environment.active_artifact_generation = Some(candidate_artifact.clone());
        published_environment.active_workspace_generation = Some(candidate_workspace);
        let retained_content = referenced_content_blobs(&published_state).unwrap();
        ContentStore::create(&engine).unwrap();
        let blobs = engine.path().join("content/blobs");
        for (digest, size) in &retained_content {
            fs::write(
                blobs.join(digest.hex()),
                vec![0_u8; usize::try_from(*size).unwrap()],
            )
            .unwrap();
            fs::set_permissions(blobs.join(digest.hex()), fs::Permissions::from_mode(0o400))
                .unwrap();
        }
        let stale_content = Sha256Digest::parse(&format!("sha256:{}", "e".repeat(64))).unwrap();
        fs::write(blobs.join(stale_content.hex()), b"stale").unwrap();
        fs::set_permissions(
            blobs.join(stale_content.hex()),
            fs::Permissions::from_mode(0o400),
        )
        .unwrap();

        let (collector_started, collector_reached_lock) = tokio::sync::oneshot::channel();
        let collector_core = Arc::clone(&service.core);
        let collector = tokio::spawn(async move {
            collector_started.send(()).unwrap();
            let mut core = collector_core.lock().await;
            let roots = core.collect_unreferenced_workspace_roots("dev").unwrap();
            core.collect_unreferenced_content().unwrap();
            core.collect_unreferenced_runtime_artifacts().unwrap();
            roots
        });
        collector_reached_lock.await.unwrap();
        tokio::task::yield_now().await;
        assert!(!collector.is_finished());

        create.state = published_state;
        create.save().unwrap();
        drop(create);

        assert_eq!(collector.await.unwrap(), vec![stale_storage]);
        assert!(paths.generations_dir.join(candidate_storage).is_dir());
        for digest in retained_content.keys() {
            assert!(blobs.join(digest.hex()).is_file());
        }
        assert!(!blobs.join(stale_content.hex()).exists());
        let artifact_manifests = engine.path().join("runtime-artifacts/generations");
        let artifact_blobs = engine.path().join("runtime-artifacts/blobs");
        assert!(
            artifact_manifests
                .join(format!("{candidate_artifact}.json"))
                .is_file()
        );
        assert!(
            artifact_blobs
                .join(format!("r-{candidate_kernel}"))
                .is_file()
        );
        assert!(
            !artifact_manifests
                .join(format!("{stale_artifact}.json"))
                .exists()
        );
        assert!(!artifact_blobs.join(format!("r-{stale_kernel}")).exists());
    }

    #[cfg(feature = "synthetic-oci-input-smoke")]
    #[tokio::test]
    async fn synthetic_image_pin_reopens_matches_exactly_and_survives_precreate_collection() {
        let (_parent, mut core) = test_supervisor_core(project_environment());
        let engine = PrivateRoot::open(&core.config.engine_root()).unwrap();
        let image = crate::oci::install_test_synthetic_image_pin(&engine).await;
        let exact = RegistryReference::parse(&image.source_reference).unwrap();
        let ordinary =
            RegistryReference::parse("registry.example/codewire/workspace:latest").unwrap();
        let same_digest_other_repository = RegistryReference::parse(&format!(
            "registry.example/other/workspace@{}",
            image.source.digest
        ))
        .unwrap();

        core.admit_synthetic_workspace_image_pin().unwrap();
        assert_eq!(
            core.matching_synthetic_workspace_image(&exact).unwrap(),
            Some(image.clone())
        );
        assert_eq!(
            core.matching_synthetic_workspace_image(&ordinary).unwrap(),
            None
        );
        assert_eq!(
            core.matching_synthetic_workspace_image(&same_digest_other_repository)
                .unwrap(),
            None
        );

        let content = ContentStore::create(&engine).unwrap();
        let stale_bytes = bytes::Bytes::from_static(b"stale pre-create content");
        let stale_digest = test_digest(&stale_bytes);
        content
            .admit_bytes(&stale_digest, stale_bytes.clone())
            .await
            .unwrap();

        core.collect_unreferenced_content().unwrap();

        for descriptor in [&image.source, &image.manifest, &image.config] {
            assert!(
                content
                    .contains_verified(&descriptor.digest, descriptor.size)
                    .unwrap()
            );
        }
        for layer in &image.layers {
            assert!(
                content
                    .contains_verified(&layer.descriptor.digest, layer.descriptor.size)
                    .unwrap()
            );
        }
        assert!(
            !content
                .contains_verified(&stale_digest, stale_bytes.len() as u64)
                .unwrap()
        );
        let inventory =
            orphan_inventory_response(&core.root, &core.state, &BTreeSet::new()).unwrap();
        assert!(
            inventory
                .orphans
                .iter()
                .all(|orphan| orphan.kind != "oci_content")
        );

        // The supervisor keeps no in-memory pin; a second admission and match
        // exercise the same verified disk reopen used after a process restart.
        core.admit_synthetic_workspace_image_pin().unwrap();
        assert_eq!(
            core.matching_synthetic_workspace_image(&exact).unwrap(),
            Some(image)
        );
    }

    #[tokio::test]
    async fn content_collection_retains_bundles_owned_by_pending_creates() {
        let (_parent, mut core) = test_supervisor_core(project_environment());
        let engine = PrivateRoot::open(&core.config.engine_root()).unwrap();
        let content = ContentStore::create(&engine).unwrap();
        let bundle_bytes = bytes::Bytes::from_static(b"pending repository bundle");
        let bundle_digest = test_digest(&bundle_bytes);
        content
            .admit_bytes(&bundle_digest, bundle_bytes.clone())
            .await
            .unwrap();
        let stale_bytes = bytes::Bytes::from_static(b"stale content");
        let stale_digest = test_digest(&stale_bytes);
        content
            .admit_bytes(&stale_digest, stale_bytes.clone())
            .await
            .unwrap();

        let project = codewire_project::ProjectSpec {
            image: "registry.example/codewire/workspace:latest".to_owned(),
            repositories: vec![codewire_project::RepositorySpec {
                source: "https://example.test/org/app.git".to_owned(),
                revision: String::new(),
                branch: "main".to_owned(),
                destination: "/workspace/app".to_owned(),
                known_hosts: Vec::new(),
            }],
            working_directory: "/workspace/app".to_owned(),
            resources: codewire_project::ResourceSpec {
                cpu_millicores: Some(2_000),
                memory_mib: Some(16 * 1024),
                disk_gib: Some(20),
            },
            ..Default::default()
        };
        let project_spec_json = project.canonical_json().unwrap();
        let request_id = Uuid::new_v4();
        let request = v1::CreateEnvironmentRequest {
            name: "pending".to_owned(),
            source_path: String::new(),
            vcpus: 2,
            memory_mib: 16 * 1024,
            disk_bytes: 20 * 1024 * 1024 * 1024,
            docker_disk_bytes: 0,
            request_id: request_id.to_string(),
            project_spec_sha256: format!("{:x}", Sha256::digest(&project_spec_json)),
            project_spec_json,
            implicit_path_mode: String::new(),
            local_mounts: Vec::new(),
            host_ports: Vec::new(),
            mesh: None,
            access_profile_id: String::new(),
            access_profile_revision: 0,
            access_profile_reference: String::new(),
            platform_source_authority: None,
        };
        let workspace_plan = WorkspacePlan {
            schema_version: 1,
            inputs: vec![crate::workspace_plan::WorkspaceInput::Repository {
                source: "https://example.test/org/app.git".to_owned(),
                commit: "a".repeat(40),
                branch: "main".to_owned(),
                destination: "/workspace/app".to_owned(),
                bundle_digest: bundle_digest.clone(),
                bundle_size: bundle_bytes.len() as u64,
            }],
        };
        let payload = create_operation_payload(&request, &workspace_plan).unwrap();
        let operation = core
            .store
            .begin_operation(
                request_id,
                Some(Uuid::new_v4()),
                OperationKind::Create,
                &payload,
            )
            .unwrap();

        core.collect_unreferenced_content().unwrap();
        assert!(
            content
                .contains_verified(&bundle_digest, bundle_bytes.len() as u64)
                .unwrap()
        );
        assert!(
            !content
                .contains_verified(&stale_digest, stale_bytes.len() as u64)
                .unwrap()
        );

        core.store
            .advance_operation(
                operation.operation_id,
                operation.checkpoint,
                OperationPhase::Failed,
                None,
                Some("test_failure"),
            )
            .unwrap();
        core.collect_unreferenced_content().unwrap();
        assert!(
            !content
                .contains_verified(&bundle_digest, bundle_bytes.len() as u64)
                .unwrap()
        );
    }

    #[test]
    fn create_failure_codes_are_closed_and_discard_opaque_error_details() {
        const CANARY: &str = "synthetic-create-failure-secret-must-not-escape";
        let cases = [
            (
                SupervisorError::CredentialAuthorityUnavailable,
                "create_credential_authority_unavailable",
            ),
            (
                SupervisorError::EnvironmentAccessUnavailable,
                "create_access_unavailable",
            ),
            (
                SupervisorError::EnvironmentAccessBindingRejected(tonic::Code::NotFound),
                "create_access_binding_not_found",
            ),
            (
                SupervisorError::EnvironmentAccessBindingRejected(tonic::Code::FailedPrecondition),
                "create_access_binding_precondition",
            ),
            (
                SupervisorError::EnvironmentAccessBindingRejected(tonic::Code::DataLoss),
                "create_access_binding_metadata",
            ),
            (
                SupervisorError::RegistryResolver(RegistryResolverError::Transport),
                "create_registry_transport",
            ),
            (
                SupervisorError::RegistryResolver(RegistryResolverError::AuthenticationFailed),
                "create_registry_auth_failed",
            ),
            (
                SupervisorError::RegistryResolver(RegistryResolverError::NotFound),
                "create_registry_not_found",
            ),
            (
                SupervisorError::RegistryResolver(RegistryResolverError::InvalidManifest),
                "create_registry_admission",
            ),
            (
                SupervisorError::RegistryResolver(RegistryResolverError::Content(
                    ContentStoreError::Stream,
                )),
                "create_registry_blob_stream",
            ),
            (
                SupervisorError::RegistryResolver(RegistryResolverError::Content(
                    ContentStoreError::SizeMismatch {
                        expected: 3,
                        actual: 2,
                    },
                )),
                "create_registry_blob_integrity",
            ),
            (
                SupervisorError::RegistryResolver(RegistryResolverError::Content(
                    ContentStoreError::UnexpectedObject(PathBuf::from(CANARY)),
                )),
                "create_registry_content_store",
            ),
            (
                SupervisorError::SkillSnapshot(
                    SkillSnapshotPreparationError::MissingRepositorySkill(CANARY.to_owned()),
                ),
                "create_skill_snapshot",
            ),
            (
                SupervisorError::SkillSnapshot(SkillSnapshotPreparationError::Io {
                    path: PathBuf::from(CANARY),
                    source: io::Error::other(CANARY),
                }),
                "create_skill_snapshot",
            ),
            (
                SupervisorError::ContentStore(ContentStoreError::Io(io::Error::other(CANARY))),
                "create_content_store",
            ),
            (
                SupervisorError::Io {
                    path: PathBuf::from(CANARY),
                    source: io::Error::other(CANARY),
                },
                "create_filesystem",
            ),
            (SupervisorError::VmStart(CANARY.to_owned()), "create_failed"),
        ];
        for (error, expected) in cases {
            let code = create_failure_code(&error);
            assert_eq!(code, expected);
            assert!(code.len() <= 64);
            assert!(
                code.bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
            );
            assert!(!code.contains(CANARY));
        }
    }

    #[tokio::test]
    async fn create_failure_code_survives_replay_storage_and_public_operation_without_details() {
        const CANARY: &str = "synthetic-content-path-must-not-escape";
        for (recovering, expected_code) in [
            (false, "create_content_store"),
            (true, "create_interrupted"),
        ] {
            let mut environment = project_environment();
            environment.generation = 0;
            let environment_id = environment.id;
            let request = v1::CreateEnvironmentRequest {
                name: environment.name.clone(),
                source_path: "/workspace/source".to_owned(),
                vcpus: u32::from(environment.vcpus),
                memory_mib: environment.memory_mib,
                disk_bytes: environment.disk_bytes,
                docker_disk_bytes: 0,
                request_id: Uuid::new_v4().to_string(),
                project_spec_json: environment.project_spec_json.clone().unwrap(),
                project_spec_sha256: environment.project_spec_sha256.clone().unwrap(),
                implicit_path_mode: "clone".to_owned(),
                ..Default::default()
            };
            let payload = create_operation_payload(&request, &environment.workspace_plan).unwrap();
            let (_parent, mut core) = test_supervisor_core(environment);
            let operation = begin_and_advance_test_operation(
                &core.store,
                environment_id,
                OperationKind::Create,
                &payload,
                3,
            );
            assert_eq!(
                supervisor_effect(operation.kind, operation.checkpoint).unwrap(),
                Some(LifecycleEffect::StageWorkspaceGeneration),
            );
            let engine = PrivateRoot::open(&core.config.engine_root()).unwrap();
            ContentStore::create(&engine).unwrap();
            // The real staging boundary rejects this synthetic unknown object
            // before any registry request, skill execution, runner or VM boot.
            let unexpected = engine.path().join("content").join(CANARY);
            fs::write(&unexpected, b"synthetic-invalid-content-object").unwrap();

            core.run_pending_operations(recovering).await.unwrap();

            let reader = SupervisorOperationReader::open(&core.root).unwrap();
            let persisted = reader
                .operation_by_id(operation.operation_id)
                .unwrap()
                .unwrap();
            assert_eq!(persisted.phase, OperationPhase::Failed);
            assert_eq!(persisted.checkpoint, 4);
            assert_eq!(persisted.error_code.as_deref(), Some(expected_code));
            assert!(persisted.result.is_none());
            let environment = core.environment("dev").unwrap();
            assert_eq!(environment.state, StoredEnvironmentState::Error);
            assert_eq!(environment.generation, 0);
            assert!(environment.runner.is_none());
            assert!(environment.staging_workspace_generation.is_none());
            assert!(unexpected.is_file(), "unsafe objects remain quarantined");
            let public = operation_proto(&persisted).unwrap();
            assert_eq!(public.error_code, expected_code);
            assert_eq!(public.checkpoint, 4);
            assert_eq!(public.stage, v1::OperationStage::Failed as i32);
            let failure = operation_outcome(public).unwrap_err();
            assert_eq!(failure.code(), tonic::Code::FailedPrecondition);
            assert!(failure.message().ends_with(expected_code));
            assert!(!failure.message().contains(CANARY));
            assert!(
                !serde_json::to_string(&persisted.payload)
                    .unwrap()
                    .contains(CANARY)
            );
        }
    }

    #[test]
    fn failed_create_never_marks_a_different_environment_error() {
        let parent = tempfile::tempdir().unwrap();
        let root_path = parent.path().join("runtime");
        fs::create_dir(&root_path).unwrap();
        fs::set_permissions(&root_path, fs::Permissions::from_mode(0o700)).unwrap();
        let root = PrivateRoot::open(&root_path).unwrap();
        let lock = SupervisorLock::acquire(&root).unwrap();
        let (store, _) = SupervisorStore::open(&root).unwrap();
        let existing_id = Uuid::new_v4();
        let (project_spec_json, project_spec_sha256) = project_intent(2, 16 * 1024, 20);
        let existing = EnvironmentRecord {
            id: existing_id,
            name: "dev".to_owned(),
            state: StoredEnvironmentState::Running,
            vcpus: 2,
            memory_mib: 16 * 1024,
            disk_bytes: crate::linux::state::MINIMUM_STATE_DISK_BYTES,
            docker_disk_bytes: 0,
            generation: 1,
            host_ports: Vec::new(),
            mesh: None,
            workspace_plan: WorkspacePlan::local(&crate::workspace::WorkspaceSource {
                source_path: PathBuf::from("/workspace/source"),
                commit: "a".repeat(40),
                mode: WorkspaceSourceMode::Clone,
            })
            .unwrap(),
            project_spec_json: Some(project_spec_json),
            project_spec_sha256: Some(project_spec_sha256),
            access_profile: None,
            access_binding: None,
            platform_source_authority: None,
            runner: None,
            active_artifact_generation: Some("b".repeat(64)),
            staging_artifact_generation: None,
            active_workspace_generation: None,
            staging_workspace_generation: None,
            rollback_workspace_generation: None,
        };
        let state = SupervisorState {
            schema_version: SUPERVISOR_STATE_SCHEMA,
            current: Some("dev".to_owned()),
            environments: [("dev".to_owned(), existing)].into(),
        };
        store.replace_state(&state).unwrap();
        let operation = store
            .begin_operation(
                Uuid::new_v4(),
                Some(Uuid::new_v4()),
                OperationKind::Create,
                &serde_json::json!({"name": "dev"}),
            )
            .unwrap();
        let mut core = SupervisorCore {
            config: NativeRuntimeConfig {
                root: root_path,
                artifact_root: parent.path().join("artifacts"),
                artifact_lock: parent.path().join("artifacts.lock.json"),
                mesh_data_dir: parent.path().join("mesh-auth"),
                platform_config_dir: parent.path().join("platform-auth"),
                credential_authority_root: parent.path().join("credentials"),
                executable: PathBuf::from("/usr/bin/true"),
            },
            root,
            store,
            state,
            children: HashMap::new(),
            live_runners: HashMap::new(),
            operation_progress: broadcast::channel(OPERATION_PROGRESS_CAPACITY).0,
            _lock: lock,
        };

        let failed = core
            .fail_operation_with_environment_error(&operation, "dev", "create_failed")
            .unwrap();

        assert_eq!(failed.phase, OperationPhase::Failed);
        assert_eq!(
            core.environment("dev").unwrap().state,
            StoredEnvironmentState::Running
        );
        assert_eq!(core.environment("dev").unwrap().id, existing_id);
    }

    #[test]
    fn replay_failure_uses_the_latest_checkpoint_and_unwedges_the_environment() {
        let parent = tempfile::tempdir().unwrap();
        let root_path = parent.path().join("runtime");
        fs::create_dir(&root_path).unwrap();
        fs::set_permissions(&root_path, fs::Permissions::from_mode(0o700)).unwrap();
        let root = PrivateRoot::open(&root_path).unwrap();
        let lock = SupervisorLock::acquire(&root).unwrap();
        let (store, _) = SupervisorStore::open(&root).unwrap();
        let environment = project_environment();
        let environment_id = environment.id;
        let state = SupervisorState {
            schema_version: SUPERVISOR_STATE_SCHEMA,
            current: Some("dev".to_owned()),
            environments: [("dev".to_owned(), environment)].into(),
        };
        store.replace_state(&state).unwrap();
        let request_id = Uuid::new_v4();
        let operation = store
            .begin_operation(
                request_id,
                Some(environment_id),
                OperationKind::Start,
                &serde_json::json!({"name": "dev", "generation": 2}),
            )
            .unwrap();
        store
            .advance_operation(
                operation.operation_id,
                operation.checkpoint,
                OperationPhase::EffectApplied,
                None,
                None,
            )
            .unwrap();
        let mut core = SupervisorCore {
            config: NativeRuntimeConfig {
                root: root_path,
                artifact_root: parent.path().join("artifacts"),
                artifact_lock: parent.path().join("artifacts.lock.json"),
                mesh_data_dir: parent.path().join("mesh-auth"),
                platform_config_dir: parent.path().join("platform-auth"),
                credential_authority_root: parent.path().join("credentials"),
                executable: PathBuf::from("/usr/bin/true"),
            },
            root,
            store,
            state,
            children: HashMap::new(),
            live_runners: HashMap::new(),
            operation_progress: broadcast::channel(OPERATION_PROGRESS_CAPACITY).0,
            _lock: lock,
        };

        core.fail_replayed_operation(&operation, "dev", "start_interrupted")
            .unwrap();

        let failed = core
            .store
            .operation_by_request(request_id)
            .unwrap()
            .unwrap();
        assert_eq!(failed.phase, OperationPhase::Failed);
        assert_eq!(failed.checkpoint, 2);
        assert_eq!(failed.error_code.as_deref(), Some("start_interrupted"));
        assert_eq!(
            core.environment("dev").unwrap().state,
            StoredEnvironmentState::Error
        );
    }

    #[test]
    fn runner_artifact_identity_is_exact() {
        let generation = "a".repeat(64);
        assert!(runner_artifact_identity_matches(&generation, &generation));
        assert!(!runner_artifact_identity_matches(
            &generation,
            &"b".repeat(64)
        ));
        assert!(!runner_artifact_identity_matches("invalid", "invalid"));
        assert!(!runner_artifact_identity_matches("", ""));
    }

    #[test]
    fn runner_start_accepts_only_the_exact_queried_prior_baseline() {
        let prior = (3, StoredEnvironmentState::Error);
        assert!(runner_event_is_prior_baseline(
            3,
            StoredEnvironmentState::Error,
            v1::RunnerStage::Error,
            0,
            v1::GuestBootStage::Unspecified,
            true,
            prior,
        ));
        for generation in [2, 4] {
            assert!(!runner_event_is_prior_baseline(
                generation,
                StoredEnvironmentState::Error,
                v1::RunnerStage::Error,
                0,
                v1::GuestBootStage::Unspecified,
                true,
                prior,
            ));
        }
        assert!(!runner_event_is_prior_baseline(
            3,
            StoredEnvironmentState::Error,
            v1::RunnerStage::Error,
            1,
            v1::GuestBootStage::RootMounted,
            true,
            prior,
        ));
        assert!(!runner_event_is_prior_baseline(
            3,
            StoredEnvironmentState::Error,
            v1::RunnerStage::Error,
            0,
            v1::GuestBootStage::Unspecified,
            false,
            prior,
        ));
        for stage in [v1::RunnerStage::Ready, v1::RunnerStage::Stopped] {
            assert!(runner_event_is_prior_baseline(
                3,
                StoredEnvironmentState::Stopped,
                stage,
                0,
                v1::GuestBootStage::Unspecified,
                false,
                (3, StoredEnvironmentState::Stopped),
            ));
        }
    }

    #[test]
    fn live_runner_mismatch_is_rejected_before_artifact_replacement() {
        let active = "a".repeat(64);
        let requested = "b".repeat(64);
        for state in [
            StoredEnvironmentState::Stopped,
            StoredEnvironmentState::Starting,
            StoredEnvironmentState::Running,
            StoredEnvironmentState::Error,
            StoredEnvironmentState::Orphaned,
        ] {
            assert_eq!(
                runner_artifact_disposition(&active, &active, state),
                RunnerArtifactDisposition::Reuse
            );
        }
        for state in [
            StoredEnvironmentState::Starting,
            StoredEnvironmentState::Running,
        ] {
            assert_eq!(
                runner_artifact_disposition(&active, &requested, state),
                RunnerArtifactDisposition::RejectLiveMismatch
            );
        }
        for state in [
            StoredEnvironmentState::Stopped,
            StoredEnvironmentState::Error,
            StoredEnvironmentState::Orphaned,
        ] {
            assert_eq!(
                runner_artifact_disposition(&active, &requested, state),
                RunnerArtifactDisposition::ReplaceStopped
            );
        }
    }
}
