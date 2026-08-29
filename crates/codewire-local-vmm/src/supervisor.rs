//! Per-user native local-environment supervisor.
//!
//! SQLite WAL and its operation journal own durable lifecycle state. Process
//! and socket identities are persisted, but daemon capabilities and workload
//! credentials never are.

use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File};
use std::io;
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use rustix::fs::{FlockOperation, flock};
use rustix::process::Signal;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tokio::sync::{Mutex, watch};
use tonic::{Request, Response, Status};
use uuid::Uuid;

use crate::control::v1;
use crate::control::v1::local_supervisor_service_client::LocalSupervisorServiceClient;
use crate::control::v1::local_supervisor_service_server::{
    LocalSupervisorService, LocalSupervisorServiceServer,
};
use crate::linux::path::{PathError, PrivateRoot, SocketIdentity};
use crate::linux::process::signal_unreaped_child;
use crate::linux::state::{
    DeletionTreeLocation, StateError, cleanup_trashed_vm, deletion_tree_location,
    move_stopped_vm_to_trash,
};
use crate::linux::{LiveProcess, ProcessIdentity, RecoveryError};
use crate::runner_service::{RunnerClient, RunnerServiceError};
use crate::supervisor_store::{
    OperationKind, OperationPhase, OperationRecord, SupervisorStore, SupervisorStoreError,
};
use crate::uds::{UdsError, bind_owner_only, connect_owner_only, remove_bound_socket};
use crate::workspace::{WorkspaceError, provision_clean_git_workspace};
use crate::{CloudHypervisorRunner, RunnerConfig, RunnerError};

pub(crate) const SUPERVISOR_STATE_SCHEMA: u32 = 1;
const RUNNER_START_TIMEOUT: Duration = Duration::from_secs(15);
const RUNNER_EXIT_TIMEOUT: Duration = Duration::from_secs(5);
const RESPONSE_DRAIN_DELAY: Duration = Duration::from_millis(100);
const DAEMON_VSOCK_PORT: u32 = 7777;
const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

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

#[derive(Debug, Clone)]
pub struct NativeRuntimeConfig {
    pub root: PathBuf,
    pub artifact_root: PathBuf,
    pub artifact_lock: PathBuf,
    pub executable: PathBuf,
}

impl NativeRuntimeConfig {
    pub fn supervisor_socket(&self) -> PathBuf {
        self.root.join("supervisor.sock")
    }

    fn engine_root(&self) -> PathBuf {
        self.root.join("engine")
    }

    fn runner_socket(&self, environment_id: Uuid) -> PathBuf {
        self.root
            .join("runners")
            .join(format!("{environment_id}.sock"))
    }

    fn validate(&self) -> Result<(), SupervisorError> {
        for path in [
            &self.root,
            &self.artifact_root,
            &self.artifact_lock,
            &self.executable,
        ] {
            if !path.is_absolute() {
                return Err(SupervisorError::InvalidConfiguration);
            }
        }
        if self.artifact_root.parent() != self.artifact_lock.parent() {
            return Err(SupervisorError::InvalidConfiguration);
        }
        let executable =
            fs::canonicalize(&self.executable).map_err(|source| SupervisorError::Io {
                path: self.executable.clone(),
                source,
            })?;
        if executable != self.executable {
            return Err(SupervisorError::InvalidConfiguration);
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct NativeSupervisorClient {
    inner: LocalSupervisorServiceClient<tonic::transport::Channel>,
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
            if let Ok(client) = Self::connect(&socket).await {
                return Ok(client);
            }
        }
        let mut child = spawn_supervisor(config)?;
        let deadline = tokio::time::Instant::now() + RUNNER_START_TIMEOUT;
        loop {
            if fs::symlink_metadata(&socket).is_ok() {
                match Self::connect(&socket).await {
                    Ok(client) => return Ok(client),
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
        let channel = connect_owner_only(socket).await?;
        Ok(Self {
            inner: LocalSupervisorServiceClient::new(channel),
        })
    }

    pub async fn create(
        &mut self,
        request: v1::CreateEnvironmentRequest,
    ) -> Result<v1::Environment, Status> {
        Ok(self.inner.create_environment(request).await?.into_inner())
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

    pub async fn list_orphans(&mut self) -> Result<v1::ListOrphansResponse, Status> {
        Ok(self
            .inner
            .list_orphans(v1::ListOrphansRequest {})
            .await?
            .into_inner())
    }

    pub async fn start(&mut self, name: &str) -> Result<v1::Environment, Status> {
        Ok(self
            .inner
            .start_environment(mutation_selector(name))
            .await?
            .into_inner())
    }

    pub async fn stop(&mut self, name: &str) -> Result<v1::Environment, Status> {
        Ok(self
            .inner
            .stop_environment(mutation_selector(name))
            .await?
            .into_inner())
    }

    pub async fn resize(
        &mut self,
        name: &str,
        vcpus: u32,
        memory_mib: u32,
        disk_bytes: u64,
    ) -> Result<v1::Environment, Status> {
        Ok(self
            .inner
            .resize_environment(v1::ResizeEnvironmentRequest {
                name: name.to_owned(),
                vcpus,
                memory_mib,
                disk_bytes,
                request_id: Uuid::new_v4().to_string(),
            })
            .await?
            .into_inner())
    }

    pub async fn delete(&mut self, name: &str) -> Result<v1::DeleteEnvironmentResponse, Status> {
        Ok(self
            .inner
            .delete_environment(mutation_selector(name))
            .await?
            .into_inner())
    }

    pub async fn daemon_access(&mut self, name: &str) -> Result<v1::DaemonAccess, Status> {
        Ok(self
            .inner
            .get_daemon_access(read_selector(name))
            .await?
            .into_inner())
    }
}

fn read_selector(name: &str) -> v1::EnvironmentSelector {
    v1::EnvironmentSelector {
        name: name.to_owned(),
        request_id: String::new(),
    }
}

fn mutation_selector(name: &str) -> v1::EnvironmentSelector {
    v1::EnvironmentSelector {
        name: name.to_owned(),
        request_id: Uuid::new_v4().to_string(),
    }
}

pub async fn serve_supervisor(config: NativeRuntimeConfig) -> Result<(), SupervisorError> {
    config.validate()?;
    let root = prepare_runtime_root(&config.root)?;
    let lock = SupervisorLock::acquire(&root)?;
    let (store, state) = SupervisorStore::open(&root)?;
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    let mut core = SupervisorCore {
        config: config.clone(),
        root,
        store,
        state,
        children: HashMap::new(),
        live_runners: HashMap::new(),
        _lock: lock,
    };
    core.replay_pending_operations().await?;
    let service = SupervisorRpc {
        core: Arc::new(Mutex::new(core)),
        shutdown: shutdown_tx,
    };
    let socket = config.supervisor_socket();
    let (incoming, socket_identity) = bind_owner_only(&socket)?;
    let result = tonic::transport::Server::builder()
        .add_service(LocalSupervisorServiceServer::new(service))
        .serve_with_incoming_shutdown(incoming, async move {
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
    Ok(orphan_inventory_response(
        &root,
        &state,
        &deletion_trash_names,
    ))
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
    pub(crate) generation: u64,
    pub(crate) workspace_commit: String,
    pub(crate) source_path: PathBuf,
    pub(crate) runner: Option<RunnerRecord>,
    #[serde(default)]
    pub(crate) active_artifact_generation: Option<String>,
    #[serde(default)]
    pub(crate) staging_artifact_generation: Option<String>,
}

impl EnvironmentRecord {
    fn proto(&self, selected: bool) -> v1::Environment {
        v1::Environment {
            id: self.id.to_string(),
            name: self.name.clone(),
            state: self.state.proto() as i32,
            vcpus: u32::from(self.vcpus),
            memory_mib: self.memory_mib,
            disk_bytes: self.disk_bytes,
            generation: self.generation,
            workspace_commit: self.workspace_commit.clone(),
            source_path: self.source_path.to_string_lossy().into_owned(),
            selected,
        }
    }

    fn validate(&self, key: &str) -> Result<(), SupervisorError> {
        if self.id.is_nil()
            || self.name != key
            || !valid_environment_name(&self.name)
            || self.vcpus == 0
            || self.vcpus > 32
            || !(128..=65_536).contains(&self.memory_mib)
            || self.disk_bytes < crate::linux::state::MINIMUM_STATE_DISK_BYTES
            || !self.disk_bytes.is_multiple_of(1024 * 1024)
            || !valid_object_id(&self.workspace_commit)
            || self
                .active_artifact_generation
                .as_ref()
                .is_some_and(|generation| !valid_sha256(generation))
            || self
                .staging_artifact_generation
                .as_ref()
                .is_some_and(|generation| !valid_sha256(generation))
            || !self.source_path.is_absolute()
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
    #[cfg(test)]
    pub(crate) fn write(&self, root: &PrivateRoot) -> Result<(), SupervisorError> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| SupervisorError::InvalidState)?;
        if bytes.len() as u64 > 1024 * 1024 {
            return Err(SupervisorError::InvalidState);
        }
        root.atomic_replace(Path::new("state.json"), &bytes, 0o600)?;
        Ok(())
    }

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
        flock(opened.file(), FlockOperation::NonBlockingLockExclusive)
            .map_err(|_| SupervisorError::AlreadyRunning)?;
        Ok(Self(opened.into_file()))
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
) -> v1::ListOrphansResponse {
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
    let orphans = crate::orphan::inventory(root, &environments, &runners, deletion_trash_names);
    let reclaimable_bytes = orphans.iter().fold(0_u64, |total, orphan| {
        total.saturating_add(orphan.reclaimable_bytes)
    });
    v1::ListOrphansResponse {
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
    }
}

struct SupervisorCore {
    config: NativeRuntimeConfig,
    root: PrivateRoot,
    store: SupervisorStore,
    state: SupervisorState,
    children: HashMap<Uuid, Child>,
    live_runners: HashMap<Uuid, LiveProcess>,
    _lock: SupervisorLock,
}

impl SupervisorCore {
    fn save(&self) -> Result<(), SupervisorError> {
        self.store.replace_state(&self.state)?;
        Ok(())
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

    fn orphan_inventory(&self) -> Result<v1::ListOrphansResponse, SupervisorError> {
        let deletion_trash_names = self.store.deletion_trash_names()?;
        Ok(orphan_inventory_response(
            &self.root,
            &self.state,
            &deletion_trash_names,
        ))
    }

    async fn preflight(&mut self) -> Result<String, SupervisorError> {
        let artifact_lock = crate::artifact::ArtifactLock::read(&self.config.artifact_lock)?;
        let artifact_generation = format!(
            "{:x}",
            Sha256::digest(
                serde_json::to_vec(&artifact_lock).map_err(|_| SupervisorError::InvalidState)?
            )
        );
        let runner = CloudHypervisorRunner::new(RunnerConfig {
            state_root: self.config.engine_root(),
            artifact_root: self.config.artifact_root.clone(),
            artifact_lock: self.config.artifact_lock.clone(),
        })
        .await?;
        runner.preflight()?;
        Ok(artifact_generation)
    }

    async fn create(
        &mut self,
        request: &v1::CreateEnvironmentRequest,
        id: Uuid,
    ) -> Result<v1::Environment, SupervisorError> {
        if let Some(environment) = self.state.environments.get(&request.name) {
            if environment.id != id {
                return Err(SupervisorError::AlreadyExists(request.name.clone()));
            }
            return self.start(&request.name).await;
        }
        let artifact_generation = self.preflight().await?;
        let source_path = PathBuf::from(&request.source_path);
        let disk_bytes = request.disk_bytes;
        let engine_root = self.config.engine_root();
        let snapshot = tokio::task::spawn_blocking(move || {
            provision_clean_git_workspace(&engine_root, id, &source_path, disk_bytes)
        })
        .await
        .map_err(|_| SupervisorError::WorkspaceProvisionTask)??;
        let vcpus = u8::try_from(request.vcpus).map_err(|_| SupervisorError::InvalidRequest)?;
        self.state.environments.insert(
            request.name.clone(),
            EnvironmentRecord {
                id,
                name: request.name.clone(),
                state: StoredEnvironmentState::Stopped,
                vcpus,
                memory_mib: request.memory_mib,
                disk_bytes: request.disk_bytes,
                generation: 0,
                workspace_commit: snapshot.commit,
                source_path: snapshot.source_path,
                runner: None,
                active_artifact_generation: Some(artifact_generation),
                staging_artifact_generation: None,
            },
        );
        self.state.current = Some(request.name.clone());
        self.save()?;
        match self.start(&request.name).await {
            Ok(environment) => Ok(environment),
            Err(error) => {
                if let Ok(environment) = self.environment_mut(&request.name) {
                    environment.state = StoredEnvironmentState::Error;
                    let _ = self.save();
                }
                Err(error)
            }
        }
    }

    async fn replay_pending_operations(&mut self) -> Result<(), SupervisorError> {
        for operation in self.store.pending_operations()? {
            let Some(name) = operation
                .payload
                .get("name")
                .and_then(|value| value.as_str())
            else {
                self.interrupt_operation(&operation, "invalid_replay_payload")?;
                continue;
            };
            if operation.kind == OperationKind::Delete {
                match self.delete(name, &operation).await {
                    Ok((operation, cleanup_pending)) => {
                        let result = serde_json::json!({
                            "name": name,
                            "removed": true,
                            "cleanup_pending": cleanup_pending,
                        });
                        self.complete_operation(&operation, &result)?;
                    }
                    Err(_) => {
                        self.interrupt_operation(&operation, "delete_replay_failed")?;
                    }
                }
                continue;
            }
            if matches!(
                operation.kind,
                OperationKind::Restart | OperationKind::GrowDisk
            ) {
                match self.resize(name, &operation).await {
                    Ok(operation) => {
                        let result = self
                            .state
                            .environments
                            .get(name)
                            .map(environment_operation_result)
                            .ok_or(SupervisorError::InvalidState)?;
                        self.complete_operation(&operation, &result)?;
                    }
                    Err(_) => {
                        self.interrupt_operation(&operation, "resize_replay_failed")?;
                    }
                }
                continue;
            }
            let result = match operation.kind {
                OperationKind::Create | OperationKind::Start => {
                    if let Some(environment) = self.state.environments.get(name) {
                        if operation.environment_id != Some(environment.id) {
                            None
                        } else {
                            self.reconcile(name).await?;
                            self.state
                                .environments
                                .get(name)
                                .filter(|environment| {
                                    environment.state == StoredEnvironmentState::Running
                                })
                                .map(environment_operation_result)
                        }
                    } else {
                        None
                    }
                }
                OperationKind::Stop => {
                    if let Some(environment) = self.state.environments.get(name) {
                        if operation.environment_id != Some(environment.id) {
                            None
                        } else {
                            self.reconcile(name).await?;
                            self.state
                                .environments
                                .get(name)
                                .filter(|environment| {
                                    environment.state == StoredEnvironmentState::Stopped
                                })
                                .map(environment_operation_result)
                        }
                    } else {
                        None
                    }
                }
                OperationKind::Delete => unreachable!("delete operations replay above"),
                OperationKind::Restart | OperationKind::GrowDisk => {
                    unreachable!("resize operations replay above")
                }
                OperationKind::Reconcile => None,
            };
            if let Some(result) = result {
                self.complete_operation(&operation, &result)?;
            } else {
                self.interrupt_operation(&operation, "replay_requires_user_action")?;
            }
        }
        Ok(())
    }

    fn complete_operation(
        &self,
        operation: &OperationRecord,
        result: &serde_json::Value,
    ) -> Result<OperationRecord, SupervisorError> {
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
        let Some(record) = self.environment(name)?.runner.clone() else {
            return Ok(());
        };
        let environment_id = self.environment(name)?.id;
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
        if record.socket.revalidate(&expected_socket).is_err() {
            self.mark_orphaned(name)?;
            return Ok(());
        }
        let mut client = RunnerClient::connect(&expected_socket).await?;
        let info = client
            .info()
            .await
            .map_err(|_| SupervisorError::RunnerUnavailable)?;
        if info.environment_id != environment_id.to_string() {
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
        let environment = self.environment_mut(name)?;
        environment.state = state;
        environment.generation = environment.generation.max(info.generation);
        self.save()
    }

    fn mark_orphaned(&mut self, name: &str) -> Result<(), SupervisorError> {
        self.environment_mut(name)?.state = StoredEnvironmentState::Orphaned;
        self.save()
    }

    fn mark_runner_dead(&mut self, name: &str) -> Result<(), SupervisorError> {
        let environment_id = self.environment(name)?.id;
        self.live_runners.remove(&environment_id);
        if let Some(mut child) = self.children.remove(&environment_id) {
            let _ = child.try_wait();
        }
        let environment = self.environment_mut(name)?;
        environment.runner = None;
        if matches!(
            environment.state,
            StoredEnvironmentState::Running | StoredEnvironmentState::Starting
        ) {
            environment.state = StoredEnvironmentState::Error;
        }
        self.save()
    }

    async fn runner_client(&mut self, name: &str) -> Result<RunnerClient, SupervisorError> {
        self.reconcile(name).await?;
        if self.environment(name)?.state == StoredEnvironmentState::Orphaned {
            return Err(SupervisorError::Orphaned);
        }
        if self.environment(name)?.runner.is_none() {
            return self.spawn_runner(name).await;
        }
        let socket = self.config.runner_socket(self.environment(name)?.id);
        RunnerClient::connect(&socket).await.map_err(Into::into)
    }

    async fn spawn_runner(&mut self, name: &str) -> Result<RunnerClient, SupervisorError> {
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
            .arg("--artifact-root")
            .arg(&self.config.artifact_root)
            .arg("--artifact-lock")
            .arg(&self.config.artifact_lock)
            .env_clear()
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
            socket: socket_identity,
        };
        self.environment_mut(name)?.runner = Some(runner_record);
        if let Err(error) = self.save() {
            self.environment_mut(name)?.runner = None;
            let _ = live.signal(Signal::KILL);
            let _ = child.wait();
            return Err(error);
        }
        let mut client = match RunnerClient::connect(&socket).await {
            Ok(client) => client,
            Err(error) => {
                let _ = live.signal(Signal::KILL);
                let _ = child.wait();
                self.environment_mut(name)?.runner = None;
                self.save()?;
                return Err(error.into());
            }
        };
        if client.adopt(environment_id).await.is_err() {
            let _ = live.signal(Signal::KILL);
            let _ = child.wait();
            self.environment_mut(name)?.runner = None;
            self.save()?;
            return Err(SupervisorError::RunnerAdoption);
        }
        self.live_runners.insert(environment_id, live);
        self.children.insert(environment_id, child);
        Ok(client)
    }

    async fn start(&mut self, name: &str) -> Result<v1::Environment, SupervisorError> {
        self.reconcile(name).await?;
        if self.environment(name)?.state == StoredEnvironmentState::Orphaned {
            return Err(SupervisorError::Orphaned);
        }
        if self.environment(name)?.state == StoredEnvironmentState::Running {
            return Ok(self.environment(name)?.proto(self.selected(name)));
        }
        let generation = self
            .environment(name)?
            .generation
            .checked_add(1)
            .ok_or(SupervisorError::InvalidState)?;
        self.environment_mut(name)?.state = StoredEnvironmentState::Starting;
        self.save()?;
        let mut client = self.runner_client(name).await?;
        let environment = self.environment(name)?.clone();
        let info = match client
            .start(v1::StartVmRequest {
                environment_id: environment.id.to_string(),
                generation,
                vsock_cid: allocate_vsock_cid(environment.id),
                daemon_vsock_port: DAEMON_VSOCK_PORT,
                state_disk_bytes: environment.disk_bytes,
                vcpus: u32::from(environment.vcpus),
                memory_mib: environment.memory_mib,
            })
            .await
        {
            Ok(info) => info,
            Err(status) => {
                self.environment_mut(name)?.state = StoredEnvironmentState::Error;
                self.save()?;
                return Err(SupervisorError::VmStart(status.message().to_owned()));
            }
        };
        if info.environment_id != environment.id.to_string()
            || info.generation != generation
            || info.state != v1::EnvironmentState::Running as i32
        {
            self.environment_mut(name)?.state = StoredEnvironmentState::Error;
            self.save()?;
            return Err(SupervisorError::InvalidRunnerResponse);
        }
        let selected = self.selected(name);
        let environment = self.environment_mut(name)?;
        environment.generation = generation;
        environment.state = StoredEnvironmentState::Running;
        self.save()?;
        Ok(self.environment(name)?.proto(selected))
    }

    async fn stop(&mut self, name: &str) -> Result<v1::Environment, SupervisorError> {
        self.reconcile(name).await?;
        if self.environment(name)?.state == StoredEnvironmentState::Orphaned {
            return Err(SupervisorError::Orphaned);
        }
        if self.environment(name)?.state == StoredEnvironmentState::Stopped {
            return Ok(self.environment(name)?.proto(self.selected(name)));
        }
        let mut client = self.runner_client(name).await?;
        let info = client.stop().await.map_err(|_| SupervisorError::VmStop)?;
        if info.environment_id != self.environment(name)?.id.to_string()
            || info.state != v1::EnvironmentState::Stopped as i32
        {
            return Err(SupervisorError::InvalidRunnerResponse);
        }
        let selected = self.selected(name);
        self.environment_mut(name)?.state = StoredEnvironmentState::Stopped;
        self.save()?;
        Ok(self.environment(name)?.proto(selected))
    }

    async fn prepare_environment_for_delete(&mut self, name: &str) -> Result<(), SupervisorError> {
        let environment_id = self.environment(name)?.id;
        let mut client = self.runner_client(name).await?;
        let runner = self
            .environment(name)?
            .runner
            .clone()
            .ok_or(SupervisorError::InvalidState)?;
        client
            .prepare_delete()
            .await
            .map_err(|_| SupervisorError::VmDelete)?;
        drop(client);

        let mut child = self.children.remove(&environment_id);
        let live = match self.live_runners.remove(&environment_id) {
            Some(live) => Some(live),
            None => match LiveProcess::recover(&runner.process) {
                Ok(live) => Some(live),
                Err(RecoveryError::ReadProcess(error))
                    if error.kind() == io::ErrorKind::NotFound =>
                {
                    None
                }
                Err(RecoveryError::ProcessExited | RecoveryError::IdentityMismatch) => None,
                Err(error) => return Err(error.into()),
            },
        };
        if let Some(live) = live.as_ref()
            && !live.is_exited()?
        {
            live.signal(Signal::KILL)?;
        }
        let exited = if let Some(mut owned_child) = child.take() {
            matches!(
                tokio::time::timeout(
                    RUNNER_EXIT_TIMEOUT,
                    tokio::task::spawn_blocking(move || owned_child.wait())
                )
                .await,
                Ok(Ok(Ok(_)))
            )
        } else if let Some(live) = live.as_ref() {
            live.wait_exited(RUNNER_EXIT_TIMEOUT).await?
        } else {
            true
        };
        if !exited {
            return Err(SupervisorError::RunnerExitTimeout);
        }
        let socket = self.config.runner_socket(environment_id);
        match fs::symlink_metadata(&socket) {
            Ok(_) => remove_bound_socket(&socket, &runner.socket)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(SupervisorError::Io {
                    path: socket,
                    source,
                });
            }
        }
        let environment = self.environment_mut(name)?;
        environment.runner = None;
        environment.state = StoredEnvironmentState::Stopped;
        self.save()
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
        ) || operation.checkpoint > 4
            || self.environment(name)?.id != environment_id
        {
            return Err(SupervisorError::InvalidState);
        }
        let (vcpus, memory_mib, disk_bytes, was_running) = resize_operation_parameters(operation)?;
        let mut operation = operation.clone();
        if operation.checkpoint == 0 {
            if self.environment(name)?.state != StoredEnvironmentState::Stopped {
                self.stop(name).await?;
            }
            operation = self.checkpoint_operation(&operation)?;
        }
        if operation.checkpoint == 1 {
            let current_disk_bytes = self.environment(name)?.disk_bytes;
            if disk_bytes < current_disk_bytes {
                return Err(SupervisorError::InvalidRequest);
            }
            if disk_bytes > current_disk_bytes {
                let mut runner = self.runner_client(name).await?;
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
        if operation.checkpoint == 2 {
            let environment = self.environment_mut(name)?;
            environment.vcpus = vcpus;
            environment.memory_mib = memory_mib;
            environment.disk_bytes = disk_bytes;
            self.save()?;
            operation = self.checkpoint_operation(&operation)?;
        }
        if operation.checkpoint == 3 {
            if was_running {
                self.start(name).await?;
            }
            operation = self.checkpoint_operation(&operation)?;
        }
        Ok(operation)
    }

    async fn delete(
        &mut self,
        name: &str,
        operation: &OperationRecord,
    ) -> Result<(OperationRecord, bool), SupervisorError> {
        let environment_id = operation
            .environment_id
            .ok_or(SupervisorError::InvalidState)?;
        if operation.kind != OperationKind::Delete || operation.checkpoint > 4 {
            return Err(SupervisorError::InvalidState);
        }
        if let Some(environment) = self.state.environments.get(name)
            && environment.id != environment_id
        {
            return Err(SupervisorError::InvalidState);
        }

        let engine_root = self.config.engine_root();
        let mut operation = operation.clone();
        if operation.checkpoint == 0 {
            match deletion_tree_location(&engine_root, environment_id, operation.operation_id)? {
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
        if operation.checkpoint == 1 {
            match deletion_tree_location(&engine_root, environment_id, operation.operation_id)? {
                DeletionTreeLocation::Active(_) => {
                    move_stopped_vm_to_trash(&engine_root, environment_id, operation.operation_id)?;
                }
                DeletionTreeLocation::Trash(_) => {}
                DeletionTreeLocation::Missing => {
                    if self.state.environments.contains_key(name) {
                        return Err(SupervisorError::State(StateError::MissingTrashSource(
                            engine_root.join("vms").join(environment_id.to_string()),
                        )));
                    }
                }
            }
            operation = self.checkpoint_operation(&operation)?;
        }
        if operation.checkpoint == 2 {
            self.state.environments.remove(name);
            if self.state.current.as_deref() == Some(name) {
                self.state.current = self.state.environments.keys().next().cloned();
            }
            self.save()?;
            operation = self.checkpoint_operation(&operation)?;
        }

        let mut cleanup_pending = false;
        if operation.checkpoint == 3 {
            if cleanup_trashed_vm(&engine_root, environment_id, operation.operation_id).is_err() {
                // Deletion is already durable. Any object that cannot pass the
                // exact allowlist remains quarantined for orphan inventory;
                // it is never recursively removed or silently adopted.
                cleanup_pending = true;
            }
            operation = self.checkpoint_operation(&operation)?;
        }
        if operation.checkpoint == 4 {
            cleanup_pending = matches!(
                deletion_tree_location(&engine_root, environment_id, operation.operation_id)?,
                DeletionTreeLocation::Trash(_)
            );
        }
        Ok((operation, cleanup_pending))
    }

    async fn daemon_access(&mut self, name: &str) -> Result<v1::DaemonAccess, SupervisorError> {
        self.reconcile(name).await?;
        if self.environment(name)?.state != StoredEnvironmentState::Running {
            return Err(SupervisorError::NotRunning);
        }
        let mut client = self.runner_client(name).await?;
        client
            .daemon_access()
            .await
            .map_err(|_| SupervisorError::RunnerUnavailable)
    }
}

#[derive(Clone)]
struct SupervisorRpc {
    core: Arc<Mutex<SupervisorCore>>,
    shutdown: watch::Sender<bool>,
}

#[tonic::async_trait]
impl LocalSupervisorService for SupervisorRpc {
    async fn create_environment(
        &self,
        request: Request<v1::CreateEnvironmentRequest>,
    ) -> Result<Response<v1::Environment>, Status> {
        let request = request.into_inner();
        let request_id = validate_create(&request).map_err(Status::from)?;
        let mut core = self.core.lock().await;
        core.replay_pending_operations()
            .await
            .map_err(Status::from)?;
        let payload = serde_json::json!({
            "name": request.name,
            "source_path": request.source_path,
            "vcpus": request.vcpus,
            "memory_mib": request.memory_mib,
            "disk_bytes": request.disk_bytes,
        });
        let operation =
            begin_create_operation(&core.store, request_id, &payload).map_err(Status::from)?;
        if operation.kind != OperationKind::Create
            || operation.payload != payload
            || operation.environment_id.is_none()
        {
            return Err(Status::aborted("local lifecycle request ID collision"));
        }
        if operation.phase == OperationPhase::Completed {
            let environment = core
                .environment(&request.name)
                .map_err(Status::from)?
                .proto(core.selected(&request.name));
            return Ok(Response::new(environment));
        }
        if matches!(
            operation.phase,
            OperationPhase::Failed | OperationPhase::Interrupted
        ) {
            return Err(Status::failed_precondition(
                "local create request is already terminal",
            ));
        }
        let environment_id = operation
            .environment_id
            .ok_or_else(|| Status::internal("local create operation lost its environment ID"))?;
        match core.create(&request, environment_id).await {
            Ok(environment) => {
                let result = core
                    .environment(&request.name)
                    .map(environment_operation_result)
                    .map_err(Status::from)?;
                core.complete_operation(&operation, &result)
                    .map_err(Status::from)?;
                Ok(Response::new(environment))
            }
            Err(error) => {
                core.fail_operation(&operation, "create_failed")
                    .map_err(Status::from)?;
                Err(Status::from(error))
            }
        }
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
    ) -> Result<Response<v1::Environment>, Status> {
        let (name, request_id) = mutation_selection(request.into_inner())?;
        let mut core = self.core.lock().await;
        core.replay_pending_operations()
            .await
            .map_err(Status::from)?;
        let environment_id = core.environment(&name).map_err(Status::from)?.id;
        let payload = serde_json::json!({"name": name});
        let operation = core
            .store
            .begin_operation(
                request_id,
                Some(environment_id),
                OperationKind::Start,
                &payload,
            )
            .map_err(SupervisorError::from)
            .map_err(Status::from)?;
        if operation.phase == OperationPhase::Completed {
            core.reconcile(&name).await.map_err(Status::from)?;
            return Ok(Response::new(
                core.environment(&name)
                    .map_err(Status::from)?
                    .proto(core.selected(&name)),
            ));
        }
        ensure_operation_pending(&operation)?;
        match core.start(&name).await {
            Ok(environment) => {
                let result = core
                    .environment(&name)
                    .map(environment_operation_result)
                    .map_err(Status::from)?;
                core.complete_operation(&operation, &result)
                    .map_err(Status::from)?;
                Ok(Response::new(environment))
            }
            Err(error) => {
                core.fail_operation(&operation, "start_failed")
                    .map_err(Status::from)?;
                Err(Status::from(error))
            }
        }
    }

    async fn stop_environment(
        &self,
        request: Request<v1::EnvironmentSelector>,
    ) -> Result<Response<v1::Environment>, Status> {
        let (name, request_id) = mutation_selection(request.into_inner())?;
        let mut core = self.core.lock().await;
        core.replay_pending_operations()
            .await
            .map_err(Status::from)?;
        let environment_id = core.environment(&name).map_err(Status::from)?.id;
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
        if operation.phase == OperationPhase::Completed {
            core.reconcile(&name).await.map_err(Status::from)?;
            return Ok(Response::new(
                core.environment(&name)
                    .map_err(Status::from)?
                    .proto(core.selected(&name)),
            ));
        }
        ensure_operation_pending(&operation)?;
        match core.stop(&name).await {
            Ok(environment) => {
                let result = core
                    .environment(&name)
                    .map(environment_operation_result)
                    .map_err(Status::from)?;
                core.complete_operation(&operation, &result)
                    .map_err(Status::from)?;
                Ok(Response::new(environment))
            }
            Err(error) => {
                core.fail_operation(&operation, "stop_failed")
                    .map_err(Status::from)?;
                Err(Status::from(error))
            }
        }
    }

    async fn resize_environment(
        &self,
        request: Request<v1::ResizeEnvironmentRequest>,
    ) -> Result<Response<v1::Environment>, Status> {
        let request = request.into_inner();
        let request_id = validate_resize(&request).map_err(Status::from)?;
        let mut core = self.core.lock().await;
        core.replay_pending_operations()
            .await
            .map_err(Status::from)?;

        let existing = core
            .store
            .operation_by_request(request_id)
            .map_err(SupervisorError::from)
            .map_err(Status::from)?;
        let operation = if let Some(operation) = existing {
            let matches_request = matches!(
                operation.kind,
                OperationKind::Restart | OperationKind::GrowDisk
            ) && operation
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
                    == Some(request.disk_bytes);
            if !matches_request {
                return Err(Status::aborted("local lifecycle request ID collision"));
            }
            operation
        } else {
            let environment = core
                .environment(&request.name)
                .map_err(Status::from)?
                .clone();
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
            let payload = serde_json::json!({
                "name": request.name,
                "vcpus": request.vcpus,
                "memory_mib": request.memory_mib,
                "disk_bytes": request.disk_bytes,
                "was_running": was_running,
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
        if operation.phase == OperationPhase::Completed {
            return Ok(Response::new(
                core.environment(&request.name)
                    .map_err(Status::from)?
                    .proto(core.selected(&request.name)),
            ));
        }
        ensure_operation_pending(&operation)?;
        let operation = core
            .resize(&request.name, &operation)
            .await
            .map_err(Status::from)?;
        let environment = core.environment(&request.name).map_err(Status::from)?;
        let response = environment.proto(core.selected(&request.name));
        let result = environment_operation_result(environment);
        core.complete_operation(&operation, &result)
            .map_err(Status::from)?;
        Ok(Response::new(response))
    }

    async fn delete_environment(
        &self,
        request: Request<v1::EnvironmentSelector>,
    ) -> Result<Response<v1::DeleteEnvironmentResponse>, Status> {
        let (name, request_id) = mutation_selection(request.into_inner())?;
        let mut core = self.core.lock().await;
        core.replay_pending_operations()
            .await
            .map_err(Status::from)?;
        let existing = core
            .store
            .operation_by_request(request_id)
            .map_err(SupervisorError::from)
            .map_err(Status::from)?;
        if let Some(operation) = existing.as_ref()
            && operation.kind == OperationKind::Delete
            && operation.payload == serde_json::json!({"name": name})
            && operation.phase == OperationPhase::Completed
        {
            return Ok(Response::new(v1::DeleteEnvironmentResponse {
                name,
                removed: true,
                cleanup_pending: operation
                    .result
                    .as_ref()
                    .and_then(|result| result.get("cleanup_pending"))
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false),
            }));
        }
        let environment_id = core.environment(&name).map_err(Status::from)?.id;
        let payload = serde_json::json!({"name": name});
        let operation = core
            .store
            .begin_operation(
                request_id,
                Some(environment_id),
                OperationKind::Delete,
                &payload,
            )
            .map_err(SupervisorError::from)
            .map_err(Status::from)?;
        ensure_operation_pending(&operation)?;
        let (operation, cleanup_pending) =
            core.delete(&name, &operation).await.map_err(Status::from)?;
        core.complete_operation(
            &operation,
            &serde_json::json!({
                "name": name,
                "removed": true,
                "cleanup_pending": cleanup_pending,
            }),
        )
        .map_err(Status::from)?;
        let empty = core.state.environments.is_empty();
        drop(core);
        if empty {
            let shutdown = self.shutdown.clone();
            tokio::spawn(async move {
                tokio::time::sleep(RESPONSE_DRAIN_DELAY).await;
                let _ = shutdown.send(true);
            });
        }
        Ok(Response::new(v1::DeleteEnvironmentResponse {
            name,
            removed: true,
            cleanup_pending,
        }))
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
}

fn selected_name(request: v1::EnvironmentSelector) -> Result<String, Status> {
    if !valid_environment_name(&request.name) {
        return Err(Status::invalid_argument("invalid environment name"));
    }
    Ok(request.name)
}

fn mutation_selection(request: v1::EnvironmentSelector) -> Result<(String, Uuid), Status> {
    let request_id = parse_request_id(&request.request_id).map_err(Status::from)?;
    let name = selected_name(request)?;
    Ok((name, request_id))
}

fn validate_create(request: &v1::CreateEnvironmentRequest) -> Result<Uuid, SupervisorError> {
    if !valid_environment_name(&request.name)
        || request.source_path.is_empty()
        || !Path::new(&request.source_path).is_absolute()
        || request.vcpus == 0
        || request.vcpus > 32
        || !(128..=65_536).contains(&request.memory_mib)
        || request.disk_bytes < crate::linux::state::MINIMUM_STATE_DISK_BYTES
        || !request.disk_bytes.is_multiple_of(1024 * 1024)
    {
        return Err(SupervisorError::InvalidRequest);
    }
    parse_request_id(&request.request_id)
}

fn validate_resize(request: &v1::ResizeEnvironmentRequest) -> Result<Uuid, SupervisorError> {
    if !valid_environment_name(&request.name)
        || request.vcpus == 0
        || request.vcpus > 32
        || !(128..=65_536).contains(&request.memory_mib)
        || request.disk_bytes < crate::linux::state::MINIMUM_STATE_DISK_BYTES
        || !request.disk_bytes.is_multiple_of(1024 * 1024)
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

fn ensure_operation_pending(operation: &OperationRecord) -> Result<(), Status> {
    match operation.phase {
        OperationPhase::Intent | OperationPhase::EffectApplied => Ok(()),
        OperationPhase::Completed => Err(Status::already_exists(
            "local lifecycle request is already complete",
        )),
        OperationPhase::Failed | OperationPhase::Interrupted => Err(Status::failed_precondition(
            "local lifecycle request is already terminal",
        )),
    }
}

fn begin_create_operation(
    store: &SupervisorStore,
    request_id: Uuid,
    payload: &serde_json::Value,
) -> Result<OperationRecord, SupervisorError> {
    match store.operation_by_request(request_id)? {
        Some(operation) => Ok(operation),
        None => store
            .begin_operation(
                request_id,
                Some(Uuid::new_v4()),
                OperationKind::Create,
                payload,
            )
            .map_err(Into::into),
    }
}

fn environment_operation_result(environment: &EnvironmentRecord) -> serde_json::Value {
    serde_json::json!({
        "environment_id": environment.id,
        "name": environment.name,
        "state": environment.state.as_str(),
        "generation": environment.generation,
    })
}

fn resize_operation_parameters(
    operation: &OperationRecord,
) -> Result<(u8, u32, u64, bool), SupervisorError> {
    let fields = operation
        .payload
        .as_object()
        .ok_or(SupervisorError::InvalidState)?;
    if fields.len() != 5 {
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
    Ok((vcpus, memory_mib, disk_bytes, was_running))
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

fn valid_object_id(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
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
        .env_clear()
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
            | SupervisorError::OperationTerminal => Status::failed_precondition(error.to_string()),
            SupervisorError::Workspace(workspace) => {
                Status::failed_precondition(workspace.to_string())
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
    #[error("native environment runner returned invalid state")]
    InvalidRunnerResponse,
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
    #[error("local lifecycle request is already terminal")]
    OperationTerminal,
    #[error("serve native supervisor failed")]
    Serve,
    #[error(transparent)]
    Runner(#[from] RunnerError),
    #[error(transparent)]
    Artifact(#[from] crate::artifact::ArtifactError),
    #[error(transparent)]
    RunnerService(#[from] RunnerServiceError),
    #[error(transparent)]
    Recovery(#[from] RecoveryError),
    #[error(transparent)]
    Workspace(#[from] WorkspaceError),
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

#[cfg(test)]
mod tests {
    use super::*;

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
        let state = SupervisorState::default();
        state.validate().unwrap();
        let encoded = serde_json::to_string(&state).unwrap().to_ascii_lowercase();
        assert!(!encoded.contains("token"));
        assert!(!encoded.contains("credential"));
        assert!(!encoded.contains("capability"));
    }

    #[test]
    fn vsock_cid_is_stable_and_not_reserved() {
        let id = Uuid::parse_str("12345678-1234-5678-9abc-def012345678").unwrap();
        assert_eq!(allocate_vsock_cid(id), allocate_vsock_cid(id));
        assert!((3..u32::MAX).contains(&allocate_vsock_cid(id)));
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

        let first = begin_create_operation(&store, request_id, &payload).unwrap();
        let retried = begin_create_operation(&store, request_id, &payload).unwrap();

        assert_eq!(retried, first);
        assert!(first.environment_id.is_some());
    }
}
