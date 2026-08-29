//! Per-user native local-environment supervisor.
//!
//! SQLite WAL and its operation journal own durable lifecycle state. Process
//! and socket identities are persisted, but daemon capabilities and workload
//! credentials never are.

use std::collections::{BTreeMap, BTreeSet, HashMap};
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

use crate::RunnerError;
use crate::artifact_store::RuntimeArtifactStore;
use crate::control::v1;
use crate::control::v1::local_supervisor_service_client::LocalSupervisorServiceClient;
use crate::control::v1::local_supervisor_service_server::{
    LocalSupervisorService, LocalSupervisorServiceServer,
};
use crate::generation::{GenerationError, ensure_empty_root_generation, valid_root_disk_bytes};
use crate::lifecycle::{EffectDurability, LifecycleEffect, next_effect};
use crate::linux::path::{PathError, PrivateRoot, SocketIdentity};
use crate::linux::process::signal_unreaped_child;
use crate::linux::state::{
    DEFAULT_ROOT_DISK_BYTES, DeletionTreeLocation, StateError, cleanup_trashed_vm,
    cleanup_unreferenced_root_generations, deletion_tree_location, move_stopped_vm_to_trash,
};
use crate::linux::{LiveProcess, ProcessIdentity, RecoveryError, VmPaths};
use crate::oci::{
    ContentStore, ContentStoreError, RegistryReference, RegistryReferenceError, RegistryResolver,
    RegistryResolverError, ResolvedDescriptor, Sha256Digest,
};
use crate::runner_service::{RunnerClient, RunnerServiceError};
use crate::setup_pack::{SetupPackError, SetupPackRequest, ensure_setup_pack};
use crate::supervisor_store::{
    OperationKind, OperationPhase, OperationRecord, SupervisorStore, SupervisorStoreError,
};
use crate::uds::{UdsError, bind_owner_only, connect_owner_only, remove_bound_socket};
use crate::workspace::{
    WorkspaceError, WorkspaceSource, cleanup_interrupted_workspace_provisioning,
    ensure_clean_git_workspace, inspect_clean_git_workspace,
};
use crate::workspace_generation::{WorkspaceGenerationError, WorkspaceGenerationRecord};

pub(crate) const SUPERVISOR_STATE_SCHEMA: u32 = 1;
const RUNNER_START_TIMEOUT: Duration = Duration::from_secs(15);
const RUNNER_EXIT_TIMEOUT: Duration = Duration::from_secs(5);
const RESPONSE_DRAIN_DELAY: Duration = Duration::from_millis(100);
const DAEMON_VSOCK_PORT: u32 = 7777;
const DEFAULT_OCI_ROOT_DISK_BYTES: u64 = 32 * 1024 * 1024 * 1024;
const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

#[derive(Debug, Clone, PartialEq, Eq)]
struct PreparedWorkspaceBoot {
    root_generation: String,
    root_disk_bytes: u64,
    setup_root_generation: String,
    setup_total_bytes: u64,
    setup_header_sha256: String,
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
    core.recover_host_reboot_workspace_transitions()?;
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) project_spec_json: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) project_spec_sha256: Option<String>,
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
            project_spec_sha256: self.project_spec_sha256.clone().unwrap_or_default(),
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
        let next_project_json = staging.project_spec_json()?.to_vec();
        let next_project_sha256 = staging.project_sha256.clone();
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
        let next_project_json = staging.project_spec_json()?.to_vec();
        let next_project_sha256 = staging.project_sha256.clone();
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
            (None, None) => {
                self.active_workspace_generation.is_some()
                    || self.staging_workspace_generation.is_some()
                    || self.rollback_workspace_generation.is_some()
            }
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
            || !valid_object_id(&self.workspace_commit)
            || match (&self.project_spec_json, &self.project_spec_sha256) {
                (None, None) => false,
                (Some(bytes), Some(digest)) => {
                    validate_project_intent(bytes, digest, None).is_err()
                }
                _ => true,
            }
            || self
                .active_artifact_generation
                .as_ref()
                .is_some_and(|generation| !valid_sha256(generation))
            || self
                .staging_artifact_generation
                .as_ref()
                .is_some_and(|generation| !valid_sha256(generation))
            || invalid_workspace_generation
            || (self.rollback_workspace_generation.is_some()
                && self.active_workspace_generation.is_none())
            || duplicate_workspace_generation(active_storage.as_ref(), rollback_storage.as_ref())
            || duplicate_workspace_generation(staging_storage.as_ref(), rollback_storage.as_ref())
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
    let content_blobs = referenced_content_blobs(state)?
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

    async fn stage_workspace_generation(
        &mut self,
        name: &str,
    ) -> Result<SupervisorState, SupervisorError> {
        self.collect_unreferenced_workspace_roots(name)?;
        self.collect_unreferenced_oci_content()?;
        self.collect_unreferenced_runtime_artifacts()?;
        let (project_json, project_sha256, artifact_generation) = {
            let environment = self.environment(name)?;
            if environment.project_spec_json.is_none()
                || environment.active_workspace_generation.is_some()
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
        let image = RegistryResolver::new(&content)?
            .resolve_anonymous(&reference)
            .await?;
        let generation = WorkspaceGenerationRecord::new(
            &project_json,
            project_sha256.to_owned(),
            artifact_generation,
            image,
            DEFAULT_OCI_ROOT_DISK_BYTES,
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
        self.collect_unreferenced_oci_content()?;
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
        let reference = RegistryReference::parse(&project.image)?;
        let artifact_generation = self.admit_current_artifact_generation().await?;
        let engine = PrivateRoot::open(&self.config.engine_root())?;
        let content = ContentStore::create(&engine)?;
        let image = RegistryResolver::new(&content)?
            .resolve_anonymous(&reference)
            .await?;
        let generation = WorkspaceGenerationRecord::new(
            project_spec_json,
            project_spec_sha256.clone(),
            artifact_generation.clone(),
            image,
            DEFAULT_OCI_ROOT_DISK_BYTES,
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

    fn collect_unreferenced_oci_content(&self) -> Result<(), SupervisorError> {
        let retained = referenced_content_blobs(&self.state)?;
        let engine = PrivateRoot::open(&self.config.engine_root())?;
        let content = ContentStore::create(&engine)?;
        let _collected = content.collect_unreferenced(&retained)?;
        Ok(())
    }

    fn collect_unreferenced_runtime_artifacts(&self) -> Result<(), SupervisorError> {
        let retained = referenced_artifact_generations(&self.state)?;
        let engine = PrivateRoot::open(&self.config.engine_root())?;
        let artifacts =
            RuntimeArtifactStore::create(&engine).map_err(|_| SupervisorError::ArtifactStore)?;
        let _collected = artifacts
            .collect_unreferenced(&retained)
            .map_err(|_| SupervisorError::ArtifactStore)?;
        Ok(())
    }

    async fn create(
        &mut self,
        request: &v1::CreateEnvironmentRequest,
        operation: &OperationRecord,
    ) -> Result<(v1::Environment, OperationRecord), SupervisorError> {
        let environment_id = operation
            .environment_id
            .ok_or(SupervisorError::InvalidState)?;
        if operation.kind != OperationKind::Create
            || operation.payload != create_operation_payload(request)
        {
            return Err(SupervisorError::InvalidState);
        }
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
                            || environment.project_spec_json.as_deref()
                                != Some(request.project_spec_json.as_slice())
                            || environment.project_spec_sha256.as_deref()
                                != Some(request.project_spec_sha256.as_str())
                        {
                            return Err(SupervisorError::AlreadyExists(request.name.clone()));
                        }
                    } else {
                        let artifact_generation = self.preflight().await?;
                        let requested_source = PathBuf::from(&request.source_path);
                        let source = tokio::task::spawn_blocking(move || {
                            inspect_clean_git_workspace(&requested_source)
                        })
                        .await
                        .map_err(|_| SupervisorError::WorkspaceProvisionTask)??;
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
                                generation: 0,
                                workspace_commit: source.commit,
                                source_path: source.source_path,
                                project_spec_json: Some(request.project_spec_json.clone()),
                                project_spec_sha256: Some(request.project_spec_sha256.clone()),
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
                LifecycleEffect::ProvisionWorkspace => {
                    let environment = self.environment(&request.name)?.clone();
                    let engine_root = self.config.engine_root();
                    let source = WorkspaceSource {
                        source_path: environment.source_path,
                        commit: environment.workspace_commit,
                    };
                    let expected_source = source.clone();
                    let disk_bytes = environment.disk_bytes;
                    let snapshot = tokio::task::spawn_blocking(move || {
                        ensure_clean_git_workspace(
                            &engine_root,
                            environment_id,
                            &source,
                            disk_bytes,
                        )
                    })
                    .await
                    .map_err(|_| SupervisorError::WorkspaceProvisionTask)??;
                    if snapshot.source_path != expected_source.source_path
                        || snapshot.commit != expected_source.commit
                    {
                        return Err(SupervisorError::InvalidState);
                    }
                    operation = self.checkpoint_operation(&operation)?;
                }
                LifecycleEffect::StageWorkspaceGeneration => {
                    let next_state = self.stage_workspace_generation(&request.name).await?;
                    operation = self.checkpoint_state_operation(&operation, next_state)?;
                }
                LifecycleEffect::EnsureRunner => {
                    let environment = self.environment(&request.name)?;
                    let artifact_generation = artifact_generation_for_boot(
                        environment,
                        environment.staging_workspace_generation.is_some(),
                    )?
                    .to_owned();
                    let _ = self
                        .runner_client_for_artifact(&request.name, &artifact_generation)
                        .await?;
                    operation = self.checkpoint_operation(&operation)?;
                }
                LifecycleEffect::StartVm => {
                    self.ensure_vm_started(&request.name, 1).await?;
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
            if operation.kind == OperationKind::Create {
                let request = match create_request_from_operation(&operation) {
                    Ok(request) => request,
                    Err(_) => {
                        self.interrupt_operation(&operation, "invalid_replay_payload")?;
                        continue;
                    }
                };
                let (_, operation) = match self.create(&request, &operation).await {
                    Ok(result) => result,
                    Err(_) => {
                        self.fail_replayed_operation(&operation, name, "create_interrupted")?;
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
                    Err(_) => {
                        self.fail_replayed_operation(&operation, name, "start_interrupted")?;
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
                let (_, operation) = self.stop(name, &operation).await?;
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
                let operation = self.resize(name, &operation).await?;
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
                    Err(_) => {
                        let error_code = match operation.kind {
                            OperationKind::UpdateWorkspace => "workspace_update_interrupted",
                            OperationKind::RollbackWorkspace => "workspace_rollback_interrupted",
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
        let generation = self.environment(name)?.generation.max(info.generation);
        self.record_reconcile_observation(name, state, generation, false)
    }

    fn apply_reconcile_operation(
        &mut self,
        operation: &OperationRecord,
    ) -> Result<OperationRecord, SupervisorError> {
        let (name, state, generation, clear_runner) = reconcile_operation_parameters(operation)?;
        let environment_id = operation
            .environment_id
            .ok_or(SupervisorError::InvalidState)?;
        if self.environment(&name)?.id != environment_id {
            return Err(SupervisorError::InvalidState);
        }
        let mut operation = operation.clone();
        while let Some(effect) = supervisor_effect(operation.kind, operation.checkpoint)? {
            match effect {
                LifecycleEffect::RecordObservation => {
                    let mut next_state = self.state.clone();
                    let environment = next_state
                        .environments
                        .get_mut(&name)
                        .ok_or_else(|| SupervisorError::NotFound(name.clone()))?;
                    environment.state = state;
                    environment.generation = generation;
                    if clear_runner {
                        environment.runner = None;
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
    ) -> Result<(), SupervisorError> {
        let environment = self.environment(name)?;
        if environment.state == state
            && environment.generation == generation
            && (!clear_runner || environment.runner.is_none())
        {
            return Ok(());
        }
        let payload = serde_json::json!({
            "name": name,
            "observed_state": state.as_str(),
            "generation": generation,
            "clear_runner": clear_runner,
        });
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
        self.record_reconcile_observation(name, StoredEnvironmentState::Orphaned, generation, false)
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
        self.record_reconcile_observation(name, state, generation, true)
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
            artifact_generation: artifact_generation.to_owned(),
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
    ) -> Result<(), SupervisorError> {
        let environment = self.environment(name)?.clone();
        let staging = environment.staging_workspace_generation.is_some();
        let expected_artifact_generation =
            artifact_generation_for_boot(&environment, staging)?.to_owned();
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
        let boot_environment = environment.clone();
        let workspace = tokio::task::spawn_blocking(move || {
            prepare_workspace_boot(&engine_root, &boot_environment)
        })
        .await
        .map_err(|_| SupervisorError::WorkspaceGenerationProvisionTask)??;
        let info = client
            .start(v1::StartVmRequest {
                environment_id: environment.id.to_string(),
                generation,
                vsock_cid: allocate_vsock_cid(environment.id),
                daemon_vsock_port: DAEMON_VSOCK_PORT,
                state_disk_bytes: environment.disk_bytes,
                vcpus: u32::from(environment.vcpus),
                memory_mib: environment.memory_mib,
                root_generation: workspace.root_generation,
                root_disk_bytes: workspace.root_disk_bytes,
                setup_total_bytes: workspace.setup_total_bytes,
                setup_header_sha256: workspace.setup_header_sha256,
                setup_root_generation: workspace.setup_root_generation,
            })
            .await
            .map_err(|status| SupervisorError::VmStart(status.message().to_owned()))?;
        if info.environment_id != environment.id.to_string()
            || info.generation != generation
            || info.state != v1::EnvironmentState::Running as i32
        {
            return Err(SupervisorError::InvalidRunnerResponse);
        }
        Ok(())
    }

    async fn ensure_vm_stopped(&mut self, name: &str) -> Result<(), SupervisorError> {
        self.reconcile(name).await?;
        if self.environment(name)?.state == StoredEnvironmentState::Orphaned {
            return Err(SupervisorError::Orphaned);
        }
        let environment = self.environment(name)?.clone();
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
        let target_generation = start_operation_generation(operation, self.environment(name)?)?;
        let mut operation = operation.clone();
        while let Some(effect) = supervisor_effect(operation.kind, operation.checkpoint)? {
            match effect {
                LifecycleEffect::RecordStarting => {
                    let mut next_state = self.state.clone();
                    let environment = next_state
                        .environments
                        .get_mut(name)
                        .ok_or_else(|| SupervisorError::NotFound(name.to_owned()))?;
                    if environment.state == StoredEnvironmentState::Running {
                        if environment.generation != target_generation {
                            return Err(SupervisorError::InvalidState);
                        }
                    } else {
                        if environment.generation >= target_generation {
                            return Err(SupervisorError::InvalidState);
                        }
                        environment.state = StoredEnvironmentState::Starting;
                    }
                    operation = self.checkpoint_state_operation(&operation, next_state)?;
                }
                LifecycleEffect::StageWorkspaceGeneration => {
                    let next_state = self.stage_workspace_generation(name).await?;
                    operation = self.checkpoint_state_operation(&operation, next_state)?;
                }
                LifecycleEffect::EnsureRunner => {
                    let environment = self.environment(name)?;
                    let artifact_generation = artifact_generation_for_boot(
                        environment,
                        environment.staging_workspace_generation.is_some(),
                    )?
                    .to_owned();
                    let _ = self
                        .runner_client_for_artifact(name, &artifact_generation)
                        .await?;
                    operation = self.checkpoint_operation(&operation)?;
                }
                LifecycleEffect::StartVm => {
                    self.ensure_vm_started(name, target_generation).await?;
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
        let Some(runner) = environment.runner.clone() else {
            return Ok(());
        };
        let socket = self.config.runner_socket(environment_id);
        let mut client = RunnerClient::connect(&socket).await?;
        client
            .prepare_retire()
            .await
            .map_err(|_| SupervisorError::RunnerRetirement)?;
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

    async fn prepare_environment_for_delete(&mut self, name: &str) -> Result<(), SupervisorError> {
        let environment = self.environment(name)?;
        let environment_id = environment.id;
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
        let (vcpus, memory_mib, disk_bytes, was_running) = resize_operation_parameters(operation)?;
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
                LifecycleEffect::GrowDisk => {
                    let current_disk_bytes = self.environment(name)?.disk_bytes;
                    if disk_bytes < current_disk_bytes {
                        return Err(SupervisorError::InvalidRequest);
                    }
                    if disk_bytes > current_disk_bytes {
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
                LifecycleEffect::RestartVm => {
                    if was_running {
                        let environment = self.environment(name)?;
                        let generation = if environment.state == StoredEnvironmentState::Running {
                            environment.generation
                        } else {
                            environment
                                .generation
                                .checked_add(1)
                                .ok_or(SupervisorError::InvalidState)?
                        };
                        self.ensure_vm_started(name, generation).await?;
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
                        if environment.state != StoredEnvironmentState::Running {
                            environment.generation = environment
                                .generation
                                .checked_add(1)
                                .ok_or(SupervisorError::InvalidState)?;
                        }
                        environment.state = StoredEnvironmentState::Running;
                    } else {
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
        let mut operation = operation.clone();
        while let Some(effect) = supervisor_effect(operation.kind, operation.checkpoint)? {
            match effect {
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
                LifecycleEffect::EnsureRunner => {
                    if workspace_transition_requires_boot(self.environment(name)?, &parameters)? {
                        let environment = self.environment(name)?;
                        let artifact_generation = artifact_generation_for_boot(
                            environment,
                            environment.staging_workspace_generation.is_some(),
                        )?
                        .to_owned();
                        let _ = self
                            .runner_client_for_artifact(name, &artifact_generation)
                            .await?;
                    }
                    operation = self.checkpoint_operation(&operation)?;
                }
                LifecycleEffect::StartVm => {
                    if workspace_transition_requires_boot(self.environment(name)?, &parameters)? {
                        self.ensure_vm_started(name, parameters.target_generation)
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
                    let content_pending = self.collect_unreferenced_oci_content().is_err();
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
        cleanup_pending |= self.collect_unreferenced_oci_content().is_err();
        cleanup_pending |= self.collect_unreferenced_runtime_artifacts().is_err();
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
        let payload = create_operation_payload(&request);
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
        match core.create(&request, &operation).await {
            Ok((environment, operation)) => {
                let result = core
                    .environment(&request.name)
                    .map(environment_operation_result)
                    .map_err(Status::from)?;
                core.complete_operation(&operation, &result)
                    .map_err(Status::from)?;
                Ok(Response::new(environment))
            }
            Err(error) => {
                let operation = core
                    .store
                    .operation_by_request(request_id)
                    .map_err(SupervisorError::from)
                    .map_err(Status::from)?
                    .ok_or_else(|| Status::internal("local create operation disappeared"))?;
                core.fail_operation_with_environment_error(
                    &operation,
                    &request.name,
                    "create_failed",
                )
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
        core.reconcile(&name).await.map_err(Status::from)?;
        let existing = core
            .store
            .operation_by_request(request_id)
            .map_err(SupervisorError::from)
            .map_err(Status::from)?;
        let operation = if let Some(operation) = existing {
            if operation.kind != OperationKind::Start
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
            let environment = core.environment(&name).map_err(Status::from)?.clone();
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
        if operation.phase == OperationPhase::Completed {
            core.reconcile(&name).await.map_err(Status::from)?;
            return Ok(Response::new(
                core.environment(&name)
                    .map_err(Status::from)?
                    .proto(core.selected(&name)),
            ));
        }
        ensure_operation_pending(&operation)?;
        match core.start(&name, &operation).await {
            Ok((environment, operation)) => {
                let result = core
                    .environment(&name)
                    .map(environment_operation_result)
                    .map_err(Status::from)?;
                core.complete_operation(&operation, &result)
                    .map_err(Status::from)?;
                Ok(Response::new(environment))
            }
            Err(error) => {
                let operation = core
                    .store
                    .operation_by_request(request_id)
                    .map_err(SupervisorError::from)
                    .map_err(Status::from)?
                    .ok_or_else(|| Status::internal("local start operation disappeared"))?;
                core.fail_operation_with_environment_error(&operation, &name, "start_failed")
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
        match core.stop(&name, &operation).await {
            Ok((environment, operation)) => {
                let result = core
                    .environment(&name)
                    .map(environment_operation_result)
                    .map_err(Status::from)?;
                core.complete_operation(&operation, &result)
                    .map_err(Status::from)?;
                Ok(Response::new(environment))
            }
            Err(error) => {
                let operation = core
                    .store
                    .operation_by_request(request_id)
                    .map_err(SupervisorError::from)
                    .map_err(Status::from)?
                    .ok_or_else(|| Status::internal("local stop operation disappeared"))?;
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
        || validate_project_intent(
            &request.project_spec_json,
            &request.project_spec_sha256,
            Some((request.vcpus, request.memory_mib, request.disk_bytes)),
        )
        .is_err()
    {
        return Err(SupervisorError::InvalidRequest);
    }
    parse_request_id(&request.request_id)
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
        || !spec.repositories.is_empty()
        || spec.working_directory != "/workspace"
        || !spec.install_command.is_empty()
        || !spec.startup_script.is_empty()
        || !spec.environment.is_empty()
        || !spec.agents.is_empty()
        || !spec.agent_environment.is_empty()
        || !spec.skills.is_empty()
        || !spec.application_ports.is_empty()
        || !spec.secrets.is_empty()
        || !spec.credentials.is_empty()
        || spec.workspace_mode != codewire_project::WorkspaceMode::Auto
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

fn create_operation_payload(request: &v1::CreateEnvironmentRequest) -> serde_json::Value {
    let project_spec_json = std::str::from_utf8(&request.project_spec_json)
        .expect("validated canonical project JSON is UTF-8");
    serde_json::json!({
        "name": request.name,
        "source_path": request.source_path,
        "vcpus": request.vcpus,
        "memory_mib": request.memory_mib,
        "disk_bytes": request.disk_bytes,
        "project_spec_json": project_spec_json,
        "project_spec_sha256": request.project_spec_sha256,
    })
}

fn create_request_from_operation(
    operation: &OperationRecord,
) -> Result<v1::CreateEnvironmentRequest, SupervisorError> {
    if operation.kind != OperationKind::Create {
        return Err(SupervisorError::InvalidState);
    }
    let fields = operation
        .payload
        .as_object()
        .filter(|fields| fields.len() == 7)
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
    let request = v1::CreateEnvironmentRequest {
        name,
        source_path,
        vcpus,
        memory_mib,
        disk_bytes,
        request_id: operation.request_id.to_string(),
        project_spec_json,
        project_spec_sha256,
    };
    validate_create(&request)?;
    Ok(request)
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
    environment: &EnvironmentRecord,
) -> Result<PreparedWorkspaceBoot, SupervisorError> {
    let (workspace, staging) = match environment.staging_workspace_generation.as_ref() {
        Some(generation) => (Some(generation), true),
        None => (environment.active_workspace_generation.as_ref(), false),
    };
    let artifact_generation = artifact_generation_for_boot(environment, staging)?;
    let (root_generation, root_disk_bytes, setup_root_generation) = match workspace {
        Some(generation) => {
            if staging {
                generation.validate()?;
            } else {
                generation.validate_for_project_intent(
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
            (
                oci_storage_generation(
                    &generation.root_generation,
                    artifact_generation,
                    generation.root_disk_bytes,
                )?,
                generation.root_disk_bytes,
                generation.root_generation.clone(),
            )
        }
        None => (
            foundation_root_generation(environment)?,
            DEFAULT_ROOT_DISK_BYTES,
            String::new(),
        ),
    };

    // Provision at the replayable start boundary, not only during create.
    // An active generation normally reuses its admitted root without needing
    // the CAS. If its root was removed, rebuilding it still uses the exact
    // committed descriptors rather than resolving a moving tag again.
    let root = ensure_empty_root_generation(
        engine_state_root,
        environment.id,
        &root_generation,
        root_disk_bytes,
    )?;
    let setup = match workspace {
        Some(generation) if staging || root.created => {
            let project_json = generation.project_spec_json()?;
            let engine = PrivateRoot::open(engine_state_root)?;
            let content = ContentStore::create(&engine)?;
            Some(ensure_setup_pack(
                engine_state_root,
                environment.id,
                &content,
                SetupPackRequest {
                    project_json,
                    project_sha256: &generation.project_sha256,
                    storage_generation: &root_generation,
                    root_generation: &generation.root_generation,
                    image: &generation.image,
                },
            )?)
        }
        Some(_) | None => None,
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
    })
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
    };
    let generation = match workspace {
        Some(workspace) => workspace.artifact_generation()?,
        None => fallback,
    };
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
    oci_storage_generation(
        &generation.root_generation,
        generation.artifact_generation()?,
        generation.root_disk_bytes,
    )
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
    if environment.project_spec_json.is_none() {
        retained.insert(foundation_root_generation(environment)?);
    }
    Ok(retained)
}

fn referenced_content_blobs(
    state: &SupervisorState,
) -> Result<BTreeMap<Sha256Digest, u64>, SupervisorError> {
    let mut retained = BTreeMap::new();
    for environment in state.environments.values() {
        let generations = [
            environment.active_workspace_generation.as_ref(),
            environment.staging_workspace_generation.as_ref(),
            environment.rollback_workspace_generation.as_ref(),
        ];
        for generation in generations.into_iter().flatten() {
            generation.validate()?;
            retain_content_descriptor(&mut retained, &generation.image.source)?;
            retain_content_descriptor(&mut retained, &generation.image.manifest)?;
            retain_content_descriptor(&mut retained, &generation.image.config)?;
            for layer in &generation.image.layers {
                retain_content_descriptor(&mut retained, &layer.descriptor)?;
            }
        }
    }
    Ok(retained)
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
    if let Some(size) = retained.get(&descriptor.digest) {
        return (*size == descriptor.size)
            .then_some(())
            .ok_or(SupervisorError::InvalidState);
    }
    retained.insert(descriptor.digest.clone(), descriptor.size);
    Ok(())
}

fn foundation_root_generation(environment: &EnvironmentRecord) -> Result<String, SupervisorError> {
    let artifact_generation = environment
        .active_artifact_generation
        .as_deref()
        .filter(|generation| valid_sha256(generation))
        .ok_or(SupervisorError::InvalidState)?;
    let mut digest = Sha256::new();
    digest.update(b"codewire-root-generation-foundation-v1\0");
    digest.update(artifact_generation.as_bytes());
    Ok(format!("{:x}", digest.finalize()))
}

fn start_operation_generation(
    operation: &OperationRecord,
    environment: &EnvironmentRecord,
) -> Result<u64, SupervisorError> {
    if operation.kind != OperationKind::Start {
        return Err(SupervisorError::InvalidState);
    }
    if let Some(generation) = operation
        .payload
        .get("generation")
        .and_then(serde_json::Value::as_u64)
    {
        return (generation > 0)
            .then_some(generation)
            .ok_or(SupervisorError::InvalidState);
    }
    // Compatibility for a pending operation written by the first SQLite
    // foundation. It had no effect checkpoints and stored only the name.
    if operation.payload.as_object().map(serde_json::Map::len) != Some(1) {
        return Err(SupervisorError::InvalidState);
    }
    if environment.state == StoredEnvironmentState::Running {
        Ok(environment.generation)
    } else {
        environment
            .generation
            .checked_add(1)
            .ok_or(SupervisorError::InvalidState)
    }
}

fn reconcile_operation_parameters(
    operation: &OperationRecord,
) -> Result<(String, StoredEnvironmentState, u64, bool), SupervisorError> {
    if operation.kind != OperationKind::Reconcile {
        return Err(SupervisorError::InvalidState);
    }
    let fields = operation
        .payload
        .as_object()
        .filter(|fields| fields.len() == 4)
        .ok_or(SupervisorError::InvalidState)?;
    let name = fields
        .get("name")
        .and_then(serde_json::Value::as_str)
        .filter(|name| valid_environment_name(name))
        .ok_or(SupervisorError::InvalidState)?
        .to_owned();
    let state = fields
        .get("observed_state")
        .and_then(serde_json::Value::as_str)
        .and_then(StoredEnvironmentState::parse)
        .ok_or(SupervisorError::InvalidState)?;
    let generation = fields
        .get("generation")
        .and_then(serde_json::Value::as_u64)
        .ok_or(SupervisorError::InvalidState)?;
    let clear_runner = fields
        .get("clear_runner")
        .and_then(serde_json::Value::as_bool)
        .ok_or(SupervisorError::InvalidState)?;
    Ok((name, state, generation, clear_runner))
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

struct WorkspaceTransitionParameters {
    prior_storage_generation: String,
    target_generation: u64,
    was_running: bool,
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
        OperationKind::UpdateWorkspace => 6,
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
            | SupervisorError::OperationTerminal
            | SupervisorError::ArtifactGenerationChanged => {
                Status::failed_precondition(error.to_string())
            }
            SupervisorError::Workspace(workspace) => {
                Status::failed_precondition(workspace.to_string())
            }
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
    RegistryReference(#[from] RegistryReferenceError),
    #[error(transparent)]
    RegistryResolver(#[from] RegistryResolverError),
    #[error(transparent)]
    ContentStore(#[from] ContentStoreError),
    #[error(transparent)]
    SetupPack(#[from] SetupPackError),
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

impl From<WorkspaceGenerationError> for SupervisorError {
    fn from(_: WorkspaceGenerationError) -> Self {
        Self::WorkspaceGeneration
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact::{
        ARTIFACT_LOCK_SCHEMA_VERSION, ArtifactArchitecture, ArtifactLock, ArtifactSpec,
        CLOUD_HYPERVISOR_RELEASE, ExecutableArtifactSpec,
    };
    use crate::oci::{OciArchitecture, ResolvedDescriptor, ResolvedImage, Sha256Digest};

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

    fn test_workspace_generation(
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

    fn project_environment() -> EnvironmentRecord {
        let (project_spec_json, project_spec_sha256) = project_intent(2, 16 * 1024, 20);
        EnvironmentRecord {
            id: Uuid::new_v4(),
            name: "dev".to_owned(),
            state: StoredEnvironmentState::Stopped,
            vcpus: 2,
            memory_mib: 16 * 1024,
            disk_bytes: 20 * 1024 * 1024 * 1024,
            generation: 1,
            workspace_commit: "a".repeat(40),
            source_path: PathBuf::from("/workspace/source"),
            project_spec_json: Some(project_spec_json),
            project_spec_sha256: Some(project_spec_sha256),
            runner: None,
            active_artifact_generation: Some("b".repeat(64)),
            staging_artifact_generation: None,
            active_workspace_generation: None,
            staging_workspace_generation: None,
            rollback_workspace_generation: None,
        }
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

    fn test_supervisor_core(environment: EnvironmentRecord) -> (tempfile::TempDir, SupervisorCore) {
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
                executable: PathBuf::from("/usr/bin/true"),
            },
            root,
            store,
            state,
            children: HashMap::new(),
            live_runners: HashMap::new(),
            _lock: lock,
        };
        (parent, core)
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
                executable: PathBuf::from("/usr/bin/true"),
            },
            root,
            store,
            state,
            children: HashMap::new(),
            live_runners: HashMap::new(),
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
        let environment_id = environment.id;
        let (_parent, mut core) = test_supervisor_core(environment);
        let operation = begin_and_advance_test_operation(
            &core.store,
            environment_id,
            OperationKind::UpdateWorkspace,
            &payload,
            6,
        );
        let request_id = operation.request_id;

        core.replay_pending_operations().await.unwrap();

        let operation = core
            .store
            .operation_by_request(request_id)
            .unwrap()
            .unwrap();
        assert_eq!(operation.phase, OperationPhase::Completed);
        assert_eq!(operation.checkpoint, 8);
        let environment = core.environment("dev").unwrap();
        assert_eq!(environment.state, StoredEnvironmentState::Stopped);
        assert_eq!(environment.generation, 2);
        assert_eq!(environment.active_artifact_generation, Some(next_artifact));
        assert!(environment.staging_artifact_generation.is_none());
        assert_eq!(environment.active_workspace_generation, Some(staging));
        assert_eq!(environment.rollback_workspace_generation, Some(active));
        environment.validate("dev").unwrap();
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
        environment.state = StoredEnvironmentState::Stopped;
        let environment_id = environment.id;
        let (_parent, mut core) = test_supervisor_core(environment);
        let operation = begin_and_advance_test_operation(
            &core.store,
            environment_id,
            OperationKind::RollbackWorkspace,
            &payload,
            6,
        );
        let request_id = operation.request_id;

        core.replay_pending_operations().await.unwrap();

        let operation = core
            .store
            .operation_by_request(request_id)
            .unwrap()
            .unwrap();
        assert_eq!(operation.phase, OperationPhase::Completed);
        assert_eq!(operation.checkpoint, 8);
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
        for _ in 0..6 {
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
        assert_eq!(operation.checkpoint, 8);
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
        for _ in 0..6 {
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
        assert_eq!(operation.checkpoint, 8);
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
        environment.staging_workspace_generation = Some(staging);
        environment.staging_artifact_generation = Some(staging_artifact);
        environment.validate("dev").unwrap();
        let payload = workspace_update_payload(&environment, &project_json, &project_sha256, true);

        for checkpoint in 1..=6 {
            let mut interrupted = environment.clone();
            if checkpoint >= 3 {
                interrupted.state = StoredEnvironmentState::Stopped;
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
        for checkpoint in 1..=6 {
            let mut interrupted = base.clone();
            interrupted
                .stage_rollback_workspace_generation(
                    &parameters.prior_storage_generation,
                    rollback_storage_generation,
                )
                .unwrap();
            if checkpoint >= 3 {
                interrupted.state = StoredEnvironmentState::Stopped;
            }
            assert_eq!(
                interrupted.staging_artifact_generation,
                Some(rollback_artifact.clone())
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
            7,
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
            7,
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
        ensure_empty_root_generation(
            engine.path(),
            environment.id,
            &storage_generation,
            generation.root_disk_bytes,
        )
        .unwrap();
        environment.active_workspace_generation = Some(generation.clone());

        let boot = prepare_workspace_boot(engine.path(), &environment).unwrap();

        assert_eq!(boot.root_generation, storage_generation);
        assert_eq!(boot.root_disk_bytes, generation.root_disk_bytes);
        assert!(boot.setup_root_generation.is_empty());
        assert_eq!(boot.setup_total_bytes, 0);
        assert!(boot.setup_header_sha256.is_empty());
        assert!(!engine.path().join("content").exists());
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
            prepare_workspace_boot(engine.path(), &environment),
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
        let state = SupervisorState::default();
        state.validate().unwrap();
        let encoded = serde_json::to_string(&state).unwrap().to_ascii_lowercase();
        assert!(!encoded.contains("token"));
        assert!(!encoded.contains("credential"));
        assert!(!encoded.contains("capability"));
    }

    #[test]
    fn canonical_project_intent_is_digest_and_resource_bound() {
        let (bytes, digest) = project_intent(2, 16 * 1024, 20);
        let disk_bytes = 20 * 1024 * 1024 * 1024;
        validate_project_intent(&bytes, &digest, Some((2, 16 * 1024, disk_bytes))).unwrap();

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
        let (project_spec_json, project_spec_sha256) = project_intent(2, 16 * 1024, 20);
        let request = v1::CreateEnvironmentRequest {
            name: "dev".to_owned(),
            source_path: "/workspace/source".to_owned(),
            vcpus: 2,
            memory_mib: 16 * 1024,
            disk_bytes: 20 * 1024 * 1024 * 1024,
            request_id: Uuid::new_v4().to_string(),
            project_spec_json,
            project_spec_sha256,
        };
        validate_create(&request).unwrap();
        let operation = OperationRecord {
            operation_id: Uuid::new_v4(),
            request_id: Uuid::parse_str(&request.request_id).unwrap(),
            environment_id: Some(Uuid::new_v4()),
            kind: OperationKind::Create,
            phase: OperationPhase::Intent,
            checkpoint: 0,
            payload: create_operation_payload(&request),
            result: None,
            error_code: None,
        };

        assert_eq!(create_request_from_operation(&operation).unwrap(), request);
    }

    #[test]
    fn vsock_cid_is_stable_and_not_reserved() {
        let id = Uuid::parse_str("12345678-1234-5678-9abc-def012345678").unwrap();
        assert_eq!(allocate_vsock_cid(id), allocate_vsock_cid(id));
        assert!((3..u32::MAX).contains(&allocate_vsock_cid(id)));
    }

    #[test]
    fn foundation_root_generation_is_stable_and_artifact_bound() {
        let mut environment = EnvironmentRecord {
            id: Uuid::new_v4(),
            name: "dev".to_owned(),
            state: StoredEnvironmentState::Stopped,
            vcpus: 2,
            memory_mib: 16 * 1024,
            disk_bytes: crate::linux::state::MINIMUM_STATE_DISK_BYTES,
            generation: 1,
            workspace_commit: "a".repeat(40),
            source_path: PathBuf::from("/workspace/source"),
            project_spec_json: None,
            project_spec_sha256: None,
            runner: None,
            active_artifact_generation: Some("b".repeat(64)),
            staging_artifact_generation: None,
            active_workspace_generation: None,
            staging_workspace_generation: None,
            rollback_workspace_generation: None,
        };
        let first = foundation_root_generation(&environment).unwrap();
        assert!(valid_sha256(&first));
        assert_eq!(foundation_root_generation(&environment).unwrap(), first);

        environment.active_artifact_generation = Some("c".repeat(64));
        assert_ne!(foundation_root_generation(&environment).unwrap(), first);

        environment.active_artifact_generation = None;
        assert!(matches!(
            foundation_root_generation(&environment),
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
        assert_eq!(
            artifact_generation_for_boot(&environment, true).unwrap(),
            "b".repeat(64)
        );
        environment.staging_artifact_generation = Some("c".repeat(64));
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

        let first = begin_create_operation(&store, request_id, &payload).unwrap();
        let retried = begin_create_operation(&store, request_id, &payload).unwrap();

        assert_eq!(retried, first);
        assert!(first.environment_id.is_some());
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
                executable: PathBuf::from("/usr/bin/true"),
            },
            root,
            store,
            state,
            children: HashMap::new(),
            live_runners: HashMap::new(),
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
        let existing = EnvironmentRecord {
            id: existing_id,
            name: "dev".to_owned(),
            state: StoredEnvironmentState::Running,
            vcpus: 2,
            memory_mib: 16 * 1024,
            disk_bytes: crate::linux::state::MINIMUM_STATE_DISK_BYTES,
            generation: 1,
            workspace_commit: "a".repeat(40),
            source_path: PathBuf::from("/workspace/source"),
            project_spec_json: None,
            project_spec_sha256: None,
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
                executable: PathBuf::from("/usr/bin/true"),
            },
            root,
            store,
            state,
            children: HashMap::new(),
            live_runners: HashMap::new(),
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
                executable: PathBuf::from("/usr/bin/true"),
            },
            root,
            store,
            state,
            children: HashMap::new(),
            live_runners: HashMap::new(),
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
