//! Per-user native local-environment supervisor.
//!
//! SQLite WAL and its operation journal own durable lifecycle state. Process
//! and socket identities are persisted, but daemon capabilities and workload
//! credentials never are.

mod bootstrap;
mod checkpoints;
mod collection_roots;
mod metadata;
mod network_policies;
mod retained_images;
mod runtime;
mod snapshots;
mod sources;
mod ssh;
#[cfg(test)]
pub(crate) use crate::supervisor_metadata::SUPERVISOR_STATE_SCHEMA;
pub(crate) use crate::supervisor_metadata::{
    EnvironmentRecord, PlatformSourceAuthority, RunnerRecord, StoredEnvironmentState,
    SupervisorState,
};

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
#[cfg(test)]
use std::sync::atomic::Ordering;
use std::time::Duration;

use codewire_access::{
    AccessProfileId, AccessProfileReference, AccessProfileScope, EnvironmentAccessBinding,
    EnvironmentId,
};
use codewire_local_credentials::{
    AuthorityFeature, AuthorityRuntimeConfig, EnvironmentBrokerRuntime as AuthorityBrokerRuntime,
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
use crate::control::v1::local_supervisor_service_server::{
    LocalSupervisorService, LocalSupervisorServiceServer,
};
use crate::cw_runtime::{CwRuntimeError, CwRuntimeStore};
use crate::diagnostic_log::{self, DiagnosticLog, LogField};
use crate::generation::{GenerationError, ensure_root_generation};
use crate::host::path::{PathError, PrivateRoot, SocketIdentity};
use crate::host::process::{LiveProcess, ProcessIdentity, RecoveryError, signal_unreaped_child};
use crate::host_port::{
    HostPortBinding, canonical_host_port_bindings, validate_canonical_host_port_bindings,
};
use crate::lifecycle::{EffectDurability, LifecycleEffect, next_effect};
use crate::mesh_ingress::{MeshAttachment, MeshEnrollmentAuthSource};
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
use crate::state::{
    DeletionTreeLocation, StateError, VmPaths, cleanup_trashed_vm,
    cleanup_unreferenced_root_generations, deletion_tree_location, move_stopped_vm_to_trash,
};
pub use crate::supervisor_client::NativeSupervisorClient;
use crate::supervisor_client::{SupervisorClientError, operation_watch_failure};
#[cfg(test)]
use crate::supervisor_client::{operation_outcome, operation_terminal, read_selector};
use crate::supervisor_config::NATIVE_SUPERVISOR_PROTOCOL_VERSION;
pub use crate::supervisor_config::NativeRuntimeConfig;
use crate::supervisor_config::{SupervisorConfigError, supervisor_info};
#[cfg(test)]
use crate::supervisor_metadata::oci_storage_generation;
use crate::supervisor_metadata::{
    CwRuntimeBinding, environment_access_metadata_valid, host_ports_to_proto,
    mesh_attachment_to_proto, runner_event_error_code_valid, valid_environment_name, valid_sha256,
    validate_host_ports_for_project, validate_mesh_for_project, validate_project_intent,
    workspace_storage_generation,
};
pub use crate::supervisor_store::{IndexedEnvironment, read_environment_index};
use crate::supervisor_store::{
    OperationKind, OperationPhase, OperationRecord, SupervisorOperationReader, SupervisorStore,
    SupervisorStoreError,
};
use crate::uds::{UdsError, bind_owner_only_listener, remove_bound_socket};
use crate::workspace::{
    WorkspaceError, WorkspaceSelection, WorkspaceSourceMode,
    cleanup_interrupted_workspace_provisioning, ensure_docker_data_disk, ensure_workspace_plan,
    inspect_workspace_skipping, workspace_content_limit,
};
use crate::workspace_generation::{WorkspaceGenerationError, WorkspaceGenerationRecord};
use crate::workspace_plan::{
    CheckedDirectShares, DirectShareDiscriminators, RepositoryCredentialAccess, WorkspaceInput,
    WorkspacePlan, WorkspacePlanError, prepare_direct_input, prepare_repository_plan,
    validate_local_mount_destination,
};
use codewire_project::valid_vm_only_patterns;

const RUNNER_START_TIMEOUT: Duration = Duration::from_secs(15);
const RUNNER_EXIT_TIMEOUT: Duration = Duration::from_secs(5);
/// How long a stopped environment keeps its runner for a restart to reuse
/// (#3270). A start within it skips spawning one; after it the reaper retires
/// the runner, so a stopped VM holds no process, memory or open runtime
/// artifacts for long.
const IDLE_RUNNER_WINDOW: Duration = Duration::from_secs(10 * 60);
/// How often the reaper looks for runners past their window.
const IDLE_RUNNER_SWEEP: Duration = Duration::from_secs(30);
/// An environment's runner is gone while the environment should be running;
/// `cw --local daemon repair` or a restart recovers it.
const RUNNER_EXIT_ERROR_CODE: &str = "runner_exit";
/// The profile slot that holds an SSH key, on both placements.
const SSH_PROFILE_SLOT: &str = "ssh";
/// How long a client keeps connecting after its replacement supervisor exited
/// without taking the lock, in case a concurrently started one is binding.
const STALE_ENDPOINT_GRACE: Duration = Duration::from_secs(2);
/// How long a new supervisor waits for a previous supervisor's runner, which
/// exits as soon as it sees its parent exit.
#[cfg(target_os = "macos")]
const PREVIOUS_RUNNER_EXIT_TIMEOUT: Duration = Duration::from_secs(10);
const _: () = assert!(
    RUNNER_EXIT_TIMEOUT.as_nanos() > crate::runner_service::RUNNER_SERVER_DRAIN_TIMEOUT.as_nanos()
);
const OPERATION_WATCH_BUFFER: usize = 8;
const OPERATION_PROGRESS_CAPACITY: usize = 256;
const RUNNER_EVENT_DRAIN_TIMEOUT: Duration = Duration::from_secs(1);
/// A start's GitHub question to the credential authority: the authority's
/// own 15-second bound plus a margin, so a stalled authority cannot hold a
/// start; past it the start omits GitHub.
const PLATFORM_GITHUB_STATE_CALL_BOUND: Duration = Duration::from_secs(20);
const MAXIMUM_RUNNER_EVENTS: usize = 128;
const DAEMON_VSOCK_PORT: u32 = 7777;
const DEFAULT_OCI_ROOT_DISK_BYTES: u64 = 32 * 1024 * 1024 * 1024;

/// An authority older than the GitHub question still serves the VMs that ran
/// across a cw update. It would ignore the question's `platform` and evaluate
/// a local binding instead, so it is not asked and the start omits GitHub.
fn platform_github_askable(authority_protocol: u32) -> Result<(), &'static str> {
    if AuthorityFeature::PlatformGithub.served_by(authority_protocol) {
        Ok(())
    } else {
        Err("authority_older")
    }
}

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
#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
#[repr(C)]
struct LinuxCapabilityHeader {
    version: u32,
    pid: i32,
}

#[cfg(target_os = "linux")]
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

    /// Each runtime artifact store directory that is not this user's own with
    /// mode 0700, one line each naming its path, mode and owner (#3271).
    pub fn unsafe_runtime_artifact_store_directories(&self) -> Vec<String> {
        crate::artifact_store::unsafe_runtime_artifact_store_directories(&self.engine_root())
    }

    fn credential_authority_config(&self) -> AuthorityRuntimeConfig {
        AuthorityRuntimeConfig {
            root: self.credential_authority_root.clone(),
            executable: self.executable.clone(),
            socket_dir: crate::socket_dir::predicted(&self.credential_authority_root),
        }
    }

    fn direct_share_forbidden_roots(&self) -> Result<Vec<PathBuf>, SupervisorError> {
        // The per-user directories that hold the supervisor's, runners', VMs'
        // and credential authority's sockets (#2735, #2745) are never shared.
        let socket_bases = [
            &self.root,
            &self.engine_root(),
            &self.credential_authority_root,
        ]
        .into_iter()
        .filter_map(|root| {
            crate::socket_dir::predicted(root)
                .parent()
                .map(Path::to_path_buf)
        })
        .collect::<Vec<_>>();
        [
            &self.root,
            &self.artifact_root,
            &self.credential_authority_root,
            &self.mesh_data_dir,
            &self.platform_config_dir,
        ]
        .into_iter()
        .chain(&socket_bases)
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

impl NativeSupervisorClient {
    /// Connect-only; no runtime action starts or replaces any service or VM.
    pub async fn connect_runtime(config: &NativeRuntimeConfig) -> Result<Self, SupervisorError> {
        config.validate()?;
        Self::connect_for_config(&config.supervisor_socket(), config).await
    }

    /// Connect to the supervisor, starting one when no endpoint exists or when
    /// the existing endpoint refuses connections.
    ///
    /// A refused endpoint is only replaced by a new supervisor that holds
    /// `supervisor.lock`. Every supervisor holds that lock for its whole life
    /// and binds its socket only after taking it, so a supervisor that is alive
    /// (even one not accepting) keeps its socket: the new one fails to take the
    /// lock and exits without touching the endpoint. The client never unlinks
    /// anything itself.
    pub async fn connect_or_start(config: &NativeRuntimeConfig) -> Result<Self, SupervisorError> {
        config.validate()?;
        let mut socket = config.supervisor_socket();
        match fs::symlink_metadata(&socket) {
            Ok(_) => match Self::connect_for_config(&socket, config).await {
                Err(error) if error.refused_connection() => {}
                result => return result,
            },
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(SupervisorError::Io {
                    path: socket,
                    source,
                });
            }
        }
        // A supervisor from before #2735 (protocol 10) listens in the root
        // itself and holds its lock until it exits: it keeps serving.
        let legacy = config.legacy_supervisor_socket();
        if std::os::unix::net::UnixStream::connect(&legacy).is_ok() {
            return Self::connect_for_config(&legacy, config).await;
        }
        let root = prepare_runtime_root(&config.root)?;
        let mut child = spawn_supervisor(config, &root)?;
        let deadline = tokio::time::Instant::now() + RUNNER_START_TIMEOUT;
        let mut exited_at = None;
        loop {
            // A supervisor that had to fall back records a new socket
            // directory, so the endpoint is looked up afresh (#2735).
            socket = config.supervisor_socket();
            if fs::symlink_metadata(&socket).is_ok() {
                match Self::connect_for_config(&socket, config).await {
                    Ok(client) => return Ok(client),
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
            if exited_at.is_none()
                && child
                    .try_wait()
                    .map_err(|_| SupervisorError::SpawnSupervisor)?
                    .is_some()
            {
                if fs::symlink_metadata(&socket).is_err() {
                    return Err(SupervisorError::SupervisorNotReachable {
                        socket,
                        log: config.root.join("logs").join("supervisor.log"),
                    });
                }
                exited_at = Some(tokio::time::Instant::now());
            }
            // A supervisor that exits while the old endpoint still refuses did
            // not get the lock. Allow a concurrent winner a moment to bind.
            if exited_at.is_some_and(|exited| exited.elapsed() >= STALE_ENDPOINT_GRACE) {
                return Err(SupervisorError::EndpointNotReplaced(socket));
            }
            if tokio::time::Instant::now() >= deadline {
                terminate_unadmitted_child(&mut child);
                return Err(SupervisorError::SupervisorStartTimeout);
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    pub async fn connect(socket: &Path) -> Result<Self, SupervisorError> {
        Self::connect_admitted(socket, None)
            .await
            .map_err(Into::into)
    }

    async fn connect_for_config(
        socket: &Path,
        config: &NativeRuntimeConfig,
    ) -> Result<Self, SupervisorError> {
        if socket != config.supervisor_socket() && socket != config.legacy_supervisor_socket() {
            return Err(SupervisorError::InvalidConfiguration);
        }
        Self::connect_configured_at(socket, config)
            .await
            .map_err(Into::into)
    }

    pub(crate) async fn reconnect_after_watch_failure(
        &mut self,
        operation_id: &str,
    ) -> Result<(), Status> {
        if !self.reconnect_enabled {
            return Err(operation_watch_failure(
                operation_id,
                Status::unavailable("local supervisor reconnect is unavailable"),
            ));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        let replacement = Self::connect_pinned(
            self.peer_pin.clone(),
            Some(self.expected_configuration_digest),
            true,
        )
        .await
        .map_err(|_| {
            operation_watch_failure(
                operation_id,
                Status::unavailable("reconnect to local supervisor failed"),
            )
        })?;
        *self = replacement;
        Ok(())
    }
}

#[cfg(test)]
fn admit_supervisor_info(
    info: &v1::SupervisorInfo,
    expected_configuration_digest: Option<&[u8; 32]>,
) -> Result<(), SupervisorError> {
    crate::supervisor_config::admit_supervisor_info(info, expected_configuration_digest)
        .map_err(Into::into)
}

pub async fn serve_supervisor(config: NativeRuntimeConfig) -> Result<(), SupervisorError> {
    config.validate()?;
    let root = prepare_runtime_root(&config.root)?;
    let lock = SupervisorLock::acquire(&root)?;
    // Releases before #2735 kept runner sockets here, and their supervisor
    // opens this directory for every runner it starts. Only the lock holder
    // may remove it, as an empty leftover (one still holding a live runner's
    // socket stays): a CLI or a losing supervisor never touches it while an
    // older supervisor may still serve this root.
    let _ = root.remove_empty_private_directory(Path::new("runners"));
    // Only the lock holder logs; a losing supervisor's exit error still
    // reaches the same file through stderr.
    let log = DiagnosticLog::inherited();
    diagnostic_log::record(
        log.as_ref(),
        "supervisor_started",
        &[
            ("pid", LogField::Count(u64::from(std::process::id()))),
            (
                "protocol",
                LogField::Count(u64::from(NATIVE_SUPERVISOR_PROTOCOL_VERSION)),
            ),
        ],
    );
    let (store, state) = SupervisorStore::open(&root)?;
    let retained_images = retained_images::load(&store, log.as_ref())?;
    let network_policies = Arc::new(
        crate::network_policy_store::NetworkPolicyStore::open(&root)
            .map_err(|error| SupervisorError::NetworkPolicyStore(error.to_string()))?,
    );
    let operation_events = store.operation_events();
    let operation_reader = SupervisorOperationReader::open(&root)?;
    let operation_progress = broadcast::channel(OPERATION_PROGRESS_CAPACITY).0;
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    let mut core = SupervisorCore {
        config: config.clone(),
        root: Arc::new(root),
        store,
        state,
        children: HashMap::new(),
        live_runners: HashMap::new(),
        idle_runners: HashMap::new(),
        runtime_operations: BTreeSet::new(),
        incompatible_runners: BTreeSet::new(),
        download_cache: BTreeMap::new(),
        retained_images,
        content_writers: 0,
        collection_wanted: false,
        collecting: false,
        retiring: false,
        admitted_here: HashMap::new(),
        selections: 0,
        operation_progress: operation_progress.clone(),
        log: log.map(Arc::new),
        network_policies: Arc::clone(&network_policies),
        _lock: lock,
    };
    #[cfg(all(target_os = "linux", feature = "synthetic-oci-input-smoke"))]
    core.admit_synthetic_workspace_image_pin()?;
    core.recover_host_reboot_workspace_transitions()?;
    let supervisor = Supervisor::new(core, shutdown_tx);
    supervisor.reconcile_exposing_runners_for_startup().await?;
    supervisor
        .record_direct_share_discriminators_for_startup()
        .await?;
    supervisor.core().begin_rollback_of_failed_creates()?;
    let service = SupervisorRpc {
        info: supervisor_info(&config),
        supervisor,
        operation_reader: Arc::new(Mutex::new(operation_reader)),
        operation_events,
        operation_progress,
        host_keys: Arc::new(ssh::HostKeys::new(&config.root)),
        ssh_streams: Arc::default(),
        network_policies,
        #[cfg(test)]
        hold_drains: Arc::default(),
    };
    let socket = config.supervisor_socket();
    let (listener, socket_identity) = bind_owner_only_listener(&socket)?;
    let connections = crate::uds::Connections::new();
    let listener = listener.tracked(Arc::clone(&connections));
    // One collection before any drain runs recovers what a crash left
    // behind; later ones run in the collector task (#2978).
    if service.supervisor.collect_if_idle().await.is_err() {
        diagnostic_log::record(
            service.supervisor.log.as_deref(),
            "content_collection_failed",
            &[],
        );
    }
    drop(tokio::spawn(
        Arc::clone(&service.supervisor).run_collector(),
    ));
    drop(tokio::spawn(
        Arc::clone(&service.supervisor).run_idle_runner_reaper(),
    ));
    drop(tokio::spawn(
        Arc::clone(&service.supervisor).run_idle_exit(connections),
    ));
    // Nothing pending was admitted by this process, so every drain recovers.
    for name in service.supervisor.names_with_pending_work()? {
        service.spawn_drain(&name);
    }
    service.spawn_unheld_runtime_recovery();
    // tmpfiles ages /tmp entries by their timestamps; keep this root's and its
    // engine's sockets current for as long as the supervisor lives (#2735).
    let refreshed = [
        config.socket_dir(),
        crate::socket_dir::predicted(&config.root.join("engine")),
    ];
    let refresher = tokio::spawn(async move {
        let mut interval = tokio::time::interval(crate::socket_dir::REFRESH_INTERVAL);
        loop {
            interval.tick().await;
            for directory in &refreshed {
                crate::socket_dir::refresh(directory);
            }
        }
    });
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
    refresher.abort();
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
    #[cfg(all(target_os = "linux", feature = "synthetic-oci-input-smoke"))]
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

/// The supervisor's state: its store, the in-memory copy of its durable state
/// and the runner processes it owns. Only short synchronous sections of
/// [`Supervisor::core`]'s lock touch it, never across an await (#2978).
/// A stopped environment's runner and since when it has had no VM.
#[derive(Debug, Clone, PartialEq, Eq)]
struct IdleRunner {
    process: ProcessIdentity,
    since: tokio::time::Instant,
}

struct SupervisorCore {
    config: NativeRuntimeConfig,
    root: Arc<PrivateRoot>,
    store: SupervisorStore,
    state: SupervisorState,
    children: HashMap<Uuid, Child>,
    live_runners: HashMap<Uuid, Arc<LiveProcess>>,
    /// Since when each stopped environment's runner has been idle, by
    /// environment, for the reaper (#3270). Memory only: a new supervisor
    /// starts every window again.
    idle_runners: HashMap<Uuid, IdleRunner>,
    runtime_operations: BTreeSet<Uuid>,
    // Observation only: an unsupported protocol never grants runner RPC or
    // retirement authority, and does not rewrite the durable lifecycle state.
    incompatible_runners: BTreeSet<Uuid>,
    // Set once RetireSupervisor admits a handoff: every later request and
    // pending-operation run is refused while this supervisor exits.
    retiring: bool,
    // Operations an RPC in this process admitted, each with `selections` at
    // its admission. Every other pending operation runs as recovering
    // (#2978).
    admitted_here: HashMap<Uuid, u64>,
    // Bumped by every select, one of the current environment included, so a
    // create admitted before it does not select itself (#2978).
    selections: u64,
    operation_progress: broadcast::Sender<OperationProgress>,
    // The image blobs each environment name's latest registry pull verified.
    // Content collection keeps them while no environment references them, so
    // a failed create's retry resumes its downloads (#2952). Only image blobs,
    // never a repository bundle; the name's next pull replaces them, a
    // requested delete of that name frees them, another name's pull frees
    // them once the name has no environment and no pending create, and a new
    // supervisor starts without them.
    download_cache: BTreeMap<String, BTreeMap<Sha256Digest, u64>>,
    // The newest pulled image of each repository, kept after its last
    // environment is removed (#4262; see `retained_images`).
    retained_images: retained_images::RetainedImages,
    // Content and artifact writers in flight, and whether a collection is
    // wanted or running (#2978). A collection runs only with no writer in
    // flight, and a writer waits only while one runs.
    content_writers: usize,
    collection_wanted: bool,
    collecting: bool,
    // The bounded owner-only log its spawner gave this supervisor, if any.
    log: Option<Arc<DiagnosticLog>>,
    /// The host's network policies and each environment's selection (#2537).
    network_policies: Arc<crate::network_policy_store::NetworkPolicyStore>,
    _lock: SupervisorLock,
}

/// What one collection keeps.
struct CollectionRetained {
    content: BTreeMap<Sha256Digest, u64>,
    artifacts: BTreeSet<String>,
}

/// Remove from the content and runtime-artifact stores what `retained` does
/// not keep. Only with no writer in flight: it removes temporary ingest files
/// too.
fn collect_stores(
    engine_root: &Path,
    retained: &CollectionRetained,
) -> Result<(), SupervisorError> {
    let engine = PrivateRoot::open(engine_root)?;
    collect_content(&engine, &retained.content)?;
    let artifacts = RuntimeArtifactStore::create(&engine).map_err(artifact_store_error)?;
    let _collected = artifacts
        .collect_unreferenced(&retained.artifacts)
        .map_err(artifact_store_error)?;
    Ok(())
}

fn collect_content(
    engine: &PrivateRoot,
    retained: &BTreeMap<Sha256Digest, u64>,
) -> Result<(), SupervisorError> {
    let _collected = ContentStore::create(engine)?.collect_unreferenced(retained)?;
    Ok(())
}

/// A content or artifact writer in flight (#2978): while one is, no
/// collection runs, so nothing it wrote and has not yet recorded is taken.
struct ContentWriter<'a> {
    supervisor: &'a Supervisor,
}

impl Drop for ContentWriter<'_> {
    fn drop(&mut self) {
        let wanted = {
            let mut core = self.supervisor.core();
            core.content_writers -= 1;
            core.content_writers == 0 && core.collection_wanted
        };
        if wanted {
            self.supervisor.collection.notify_one();
        }
    }
}

#[cfg(test)]
impl SupervisorCore {
    /// The content half of a collection, run here and now, as one with no
    /// writer in flight does.
    fn collect_content_now(&self) -> Result<(), SupervisorError> {
        let engine = PrivateRoot::open(&self.config.engine_root())?;
        collect_content(&engine, &self.collection_retained()?.content)
    }
}

#[cfg(test)]
impl Supervisor {
    /// Tests' entry to the drains: every name with pending work, in name
    /// order, then cw-runtime work no name holds. With `recovering` false the
    /// pending operations count as admitted here, as an RPC's would.
    async fn drain_pending(&self, recovering: bool) -> Result<(), SupervisorError> {
        if !recovering {
            let pending = self.core().store.pending_operations()?;
            for operation in &pending {
                self.admit(operation);
            }
        }
        for name in self.names_with_pending_work()? {
            self.drain(&name).await?;
        }
        let held = self
            .core()
            .state
            .environments
            .values()
            .map(|environment| environment.id)
            .collect::<BTreeSet<_>>();
        self.recover_runtime_operations(|id| !held.contains(&id))
            .await
    }
}

/// The supervisor (#2978). Lifecycle operations are its async methods: they
/// await runners, the credential authority, registries and disks with no lock
/// held, and read or change [`SupervisorCore`] only in short synchronous
/// sections.
struct Supervisor {
    /// This supervisor's own `Arc`, for work a dropped request must not cut
    /// short (see [`Self::detached`]).
    this: std::sync::Weak<Supervisor>,
    config: NativeRuntimeConfig,
    root: Arc<PrivateRoot>,
    log: Option<Arc<DiagnosticLog>>,
    operation_progress: broadcast::Sender<OperationProgress>,
    shutdown: watch::Sender<bool>,
    core: std::sync::Mutex<SupervisorCore>,
    /// One lease per environment name: it orders that name's operations and
    /// lets other names' run alongside (#2978). Entries are never removed: a
    /// waiter may already hold a clone, and there are only as many as the
    /// names this process has seen.
    leases: std::sync::Mutex<HashMap<String, Arc<Mutex<()>>>>,
    /// Wakes the collector task when a collection may run.
    collection: tokio::sync::Notify,
    /// Wakes content writers waiting for a running collection to end.
    collection_ended: tokio::sync::Notify,
}

impl Supervisor {
    fn new(core: SupervisorCore, shutdown: watch::Sender<bool>) -> Arc<Self> {
        Arc::new_cyclic(|this| Self {
            this: this.clone(),
            config: core.config.clone(),
            root: Arc::clone(&core.root),
            log: core.log.clone(),
            operation_progress: core.operation_progress.clone(),
            shutdown,
            core: std::sync::Mutex::new(core),
            leases: std::sync::Mutex::default(),
            collection: tokio::sync::Notify::new(),
            collection_ended: tokio::sync::Notify::new(),
        })
    }

    /// The state lock. A panic while it was held may have left memory ahead
    /// of the store, so a poisoned lock stops this supervisor, and nothing
    /// more is written; the next one starts from the store.
    fn core(&self) -> std::sync::MutexGuard<'_, SupervisorCore> {
        self.core.lock().unwrap_or_else(|poisoned| {
            let core = poisoned.into_inner();
            core.store.stop();
            let _ = self.shutdown.send(true);
            core
        })
    }

    /// Stop after a fatal error (#2978): no later commit or drain proceeds
    /// in any environment, and the supervisor shuts down.
    fn halt(&self) {
        self.core().store.stop();
        let _ = self.shutdown.send(true);
    }

    /// Run `work` in a task of its own and wait for it (#2978): a request
    /// dropped meanwhile cuts no drain, collection or retirement short, so
    /// none leaves an admission, a running collection or `retiring` behind.
    /// A panic in it stops the supervisor.
    async fn detached<T, F>(&self, work: impl FnOnce(Arc<Self>) -> F) -> Result<T, SupervisorError>
    where
        F: Future<Output = Result<T, SupervisorError>> + Send + 'static,
        T: Send + 'static,
    {
        let supervisor = self
            .this
            .upgrade()
            .expect("a supervisor is borrowed only through its Arc");
        match tokio::spawn(work(supervisor)).await {
            Ok(result) => result,
            Err(_) => {
                self.halt();
                Err(SupervisorStoreError::Stopping.into())
            }
        }
    }

    /// A copy of one environment's record as it is now.
    fn environment(&self, name: &str) -> Result<EnvironmentRecord, SupervisorError> {
        self.core().environment(name).cloned()
    }

    fn leases(&self) -> std::sync::MutexGuard<'_, HashMap<String, Arc<Mutex<()>>>> {
        self.leases.lock().unwrap_or_else(|poisoned| {
            self.halt();
            poisoned.into_inner()
        })
    }

    /// The lease of one environment name.
    fn lease(&self, name: &str) -> Arc<Mutex<()>> {
        Arc::clone(self.leases().entry(name.to_owned()).or_default())
    }

    /// Register a content or artifact writer, waiting only while a
    /// collection runs (#2978).
    async fn content_writer(&self) -> ContentWriter<'_> {
        loop {
            let ended = self.collection_ended.notified();
            {
                let mut core = self.core();
                if !core.collecting {
                    core.content_writers += 1;
                    return ContentWriter { supervisor: self };
                }
            }
            ended.await;
        }
    }

    /// Before a stage writes content: remove the environment's own
    /// unreferenced roots, collect the shared stores unless another writer is
    /// in flight, then count as a writer until the stage's record commits.
    async fn begin_staging(&self, name: &str) -> Result<ContentWriter<'_>, SupervisorError> {
        self.collect_unreferenced_workspace_roots(name).await?;
        self.collect_if_idle().await?;
        Ok(self.content_writer().await)
    }

    /// Remove `name`'s root generations its record no longer references.
    /// Its caller holds the name's lease; the walk holds no lock.
    async fn collect_unreferenced_workspace_roots(
        &self,
        name: &str,
    ) -> Result<Vec<String>, SupervisorError> {
        let environment = self.environment(name)?;
        let retained = referenced_root_storage_generations(&environment)?;
        let engine_root = self.config.engine_root();
        tokio::task::spawn_blocking(move || {
            let engine = PrivateRoot::open(&engine_root)?;
            let paths = VmPaths::create(&engine, environment.id)?;
            cleanup_unreferenced_root_generations(&paths, &retained).map_err(Into::into)
        })
        .await
        .map_err(|_| SupervisorError::WorkspaceGenerationProvisionTask)?
    }

    /// Collect now if no writer is in flight, as a stage, a create's cleanup
    /// and a delete do; otherwise the collector runs it once the writers
    /// finish. `Ok(false)` when it was left to the collector: a delete then
    /// reports nothing pending, because nothing failed.
    async fn collect_if_idle(&self) -> Result<bool, SupervisorError> {
        let retained = {
            let mut core = self.core();
            if core.content_writers > 0 || core.collecting {
                core.collection_wanted = true;
                None
            } else {
                core.collection_wanted = false;
                core.collecting = true;
                Some(core.collection_retained())
            }
        };
        let Some(retained) = retained else {
            self.collection.notify_one();
            return Ok(false);
        };
        // The walk and its end run in a task of their own, so a caller
        // dropped meanwhile never leaves `collecting` set.
        self.detached(|supervisor| async move {
            let result = match retained {
                Ok(retained) => supervisor.collect(retained).await,
                Err(error) => Err(error),
            };
            supervisor.end_collection();
            result.map(|()| true)
        })
        .await
    }

    fn end_collection(&self) {
        self.core().collecting = false;
        self.collection_ended.notify_waiters();
        // One wanted meanwhile runs once the writers allow it.
        self.collection.notify_one();
    }

    /// One collection's filesystem walk, with no lock held: it removes what
    /// `retained` does not keep, temporary ingest files included, which is
    /// safe because no writer is in flight while it runs.
    async fn collect(&self, retained: CollectionRetained) -> Result<(), SupervisorError> {
        let engine_root = self.config.engine_root();
        tokio::task::spawn_blocking(move || collect_stores(&engine_root, &retained))
            .await
            .map_err(|_| SupervisorError::WorkspaceGenerationProvisionTask)?
    }

    /// The collector task: it runs a wanted collection once no writer is in
    /// flight, so a collection never runs inside a request or a drop.
    async fn run_collector(self: Arc<Self>) {
        loop {
            let woken = self.collection.notified();
            let retained = {
                let mut core = self.core();
                if core.collection_wanted && core.content_writers == 0 && !core.collecting {
                    core.collection_wanted = false;
                    core.collecting = true;
                    Some(core.collection_retained())
                } else {
                    None
                }
            };
            let Some(retained) = retained else {
                woken.await;
                continue;
            };
            let result = match retained {
                Ok(retained) => self.collect(retained).await,
                Err(error) => Err(error),
            };
            self.end_collection();
            if result.is_err() {
                // An object the collector does not recognise stays where it
                // is, for the orphan inventory, as after any failed cleanup.
                diagnostic_log::record(self.log.as_deref(), "content_collection_failed", &[]);
            }
        }
    }

    /// The idle-runner reaper (#3270): every sweep it retires the runner of
    /// each stopped environment idle for [`IDLE_RUNNER_WINDOW`].
    async fn run_idle_runner_reaper(self: Arc<Self>) {
        let mut sweeps = tokio::time::interval(IDLE_RUNNER_SWEEP);
        sweeps.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            sweeps.tick().await;
            for name in self.expired_idle_runners(tokio::time::Instant::now()) {
                if self.retire_expired_idle_runner(&name).await.is_err() {
                    diagnostic_log::record(self.log.as_deref(), "idle_runner_retire_failed", &[]);
                }
            }
        }
    }

    /// The idle exit (#3793): a supervisor that holds nothing and has had no
    /// client connected for [`IDLE_RUNNER_WINDOW`] shuts down, as on a
    /// handoff. One started by a cw with another configuration, or by a cw
    /// since deleted, would otherwise refuse the user's cw forever; the next
    /// cw command starts its own.
    async fn run_idle_exit(self: Arc<Self>, connections: Arc<crate::uds::Connections>) {
        let mut sweeps = tokio::time::interval(IDLE_RUNNER_SWEEP);
        sweeps.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut quiet_since = None;
        loop {
            sweeps.tick().await;
            if self.idle_exit_due(&mut quiet_since, &connections, tokio::time::Instant::now()) {
                diagnostic_log::record(self.log.as_deref(), "supervisor_idle_exit", &[]);
                let _ = self.shutdown.send(true);
                return;
            }
        }
    }

    /// Whether this supervisor has held nothing at every sweep since
    /// `quiet_since`, and no client has been connected, for a whole window at
    /// `now`. Anything held restarts the window.
    fn idle_exit_due(
        &self,
        quiet_since: &mut Option<tokio::time::Instant>,
        connections: &crate::uds::Connections,
        now: tokio::time::Instant,
    ) -> bool {
        let Some(unconnected) = connections.idle_for(now).filter(|_| self.holds_nothing()) else {
            *quiet_since = None;
            return false;
        };
        let quiet = now.saturating_duration_since(*quiet_since.get_or_insert(now));
        quiet.min(unconnected) >= IDLE_RUNNER_WINDOW
    }

    /// No environment, process, operation, content work or handoff: exiting
    /// loses nothing a new supervisor would not recover.
    fn holds_nothing(&self) -> bool {
        let core = self.core();
        core.state.environments.is_empty()
            && core.children.is_empty()
            && core.live_runners.is_empty()
            && core.runtime_operations.is_empty()
            && core.content_writers == 0
            && !core.collecting
            && !core.retiring
            && core
                .store
                .pending_operations()
                .is_ok_and(|pending| pending.is_empty())
    }

    /// Notes when each stopped environment's runner became idle, forgets the
    /// rest, and names those idle for the whole window at `now`.
    fn expired_idle_runners(&self, now: tokio::time::Instant) -> Vec<String> {
        let mut core = self.core();
        let idle = core
            .state
            .environments
            .values()
            .filter(|environment| environment.state == StoredEnvironmentState::Stopped)
            .filter_map(|environment| {
                let runner = environment.runner.as_ref()?;
                Some((
                    environment.id,
                    environment.name.clone(),
                    runner.process.clone(),
                ))
            })
            .collect::<Vec<_>>();
        let mut expired = Vec::new();
        let mut tracked = HashMap::new();
        for (environment_id, name, process) in idle {
            let since = match core.idle_runners.get(&environment_id) {
                Some(idle) if idle.process == process => idle.since,
                _ => now,
            };
            if now.duration_since(since) >= IDLE_RUNNER_WINDOW {
                expired.push(name);
            }
            tracked.insert(environment_id, IdleRunner { process, since });
        }
        core.idle_runners = tracked;
        expired
    }

    /// Retire `name`'s idle runner if it is still idle past its window. An
    /// environment with an operation pending or holding its lease is left to
    /// the next sweep, so a start never races its runner's retirement.
    async fn retire_expired_idle_runner(&self, name: &str) -> Result<(), SupervisorError> {
        if !self.pending_for(name)?.is_empty() {
            return Ok(());
        }
        let Ok(_lease) = self.lease(name).try_lock_owned() else {
            return Ok(());
        };
        if !self.core().state.environments.contains_key(name) || !self.pending_for(name)?.is_empty()
        {
            return Ok(());
        }
        // A runner recovered from the store is checked before it is acted on;
        // one this supervisor holds is already tracked and needs no RPC.
        let environment_id = self.environment(name)?.id;
        if !self.core().live_runners.contains_key(&environment_id) {
            self.reconcile(name).await?;
        }
        let environment = self.environment(name)?;
        let Some(runner) = environment.runner.clone() else {
            return Ok(());
        };
        let expired = self
            .core()
            .idle_runners
            .get(&environment.id)
            .is_some_and(|idle| {
                idle.process == runner.process && idle.since.elapsed() >= IDLE_RUNNER_WINDOW
            });
        if environment.state != StoredEnvironmentState::Stopped || !expired {
            return Ok(());
        }
        self.retire_idle_runner(name, &runner).await?;
        self.core().idle_runners.remove(&environment.id);
        Ok(())
    }

    /// The lease for cw-runtime work on environment `id`: that of the name
    /// holding it, or, while none does, one for the id alone. A name never
    /// contains a NUL, so that key names no environment.
    fn runtime_lease(&self, id: Uuid) -> Arc<Mutex<()>> {
        let holder = self
            .core()
            .state
            .environments
            .values()
            .find(|environment| environment.id == id)
            .map(|environment| environment.name.clone());
        self.lease(&holder.unwrap_or_else(|| format!("\0{id}")))
    }

    /// The name's pending lifecycle operations, in order. cw-runtime
    /// operations have no name and never count, so one awaiting an explicit
    /// observe or cancel cannot block its environment's lifecycle.
    fn pending_for(&self, name: &str) -> Result<Vec<OperationRecord>, SupervisorError> {
        let pending = self.core().store.pending_operations()?;
        Ok(pending
            .into_iter()
            .filter(|operation| {
                !operation.kind.cw_runtime() && operation_name(operation) == Some(name)
            })
            .collect())
    }

    /// Run `name`'s pending operations in order, under its lease.
    async fn drain(&self, name: &str) -> Result<(), SupervisorError> {
        let lease = self.lease(name);
        let _lease = lease.lock().await;
        self.drain_held(name).await
    }

    /// As [`Self::drain`], for a caller that already holds `name`'s lease.
    /// It also recovers the cw-runtime operations of the environment the
    /// name holds, and checks that name's workspace staging.
    async fn drain_held(&self, name: &str) -> Result<(), SupervisorError> {
        self.drainable()?;
        for operation in self.pending_for(name)? {
            // Another environment's drain may have stopped the supervisor.
            self.drainable()?;
            let operation_id = operation.operation_id;
            let recovering = !self.core().admitted_here.contains_key(&operation_id);
            let result = self.run_operation(operation, recovering).await;
            self.core().admitted_here.remove(&operation_id);
            result?;
        }
        let environment_id = self
            .core()
            .state
            .environments
            .get(name)
            .map(|environment| environment.id);
        if let Some(environment_id) = environment_id {
            self.recover_runtime_operations(|id| id == environment_id)
                .await?;
        }
        self.core().ensure_no_unowned_workspace_staging(name)
    }

    /// Whether a drain may run an operation: not while retiring, nor once a
    /// fatal error stopped the supervisor.
    fn drainable(&self) -> Result<(), SupervisorError> {
        let core = self.core();
        if core.retiring {
            return Err(SupervisorError::Retiring);
        }
        if core.store.stopping() {
            return Err(SupervisorStoreError::Stopping.into());
        }
        Ok(())
    }

    /// Recover pending cw-runtime operations whose environment `matches`,
    /// except those an RPC in this process is still running.
    async fn recover_runtime_operations(
        &self,
        matches: impl Fn(Uuid) -> bool,
    ) -> Result<(), SupervisorError> {
        let pending = self.core().store.pending_operations()?;
        for operation in pending {
            let running = self
                .core()
                .runtime_operations
                .contains(&operation.operation_id);
            if operation.kind.cw_runtime()
                && !running
                && operation.environment_id.is_some_and(&matches)
            {
                runtime::recover(self, &operation).await?;
            }
        }
        Ok(())
    }

    /// `name`'s lease, once its own pending operations have run here: a
    /// mutation or a per-environment read waits for its own environment only
    /// (#2978).
    async fn quiet_lease(
        &self,
        name: &str,
    ) -> Result<tokio::sync::OwnedMutexGuard<()>, SupervisorError> {
        let lease = self.lease(name).lock_owned().await;
        self.drain_under(lease, name).await
    }

    /// Run `name`'s pending operations under `lease`, which its caller holds,
    /// in a task of their own, and hand the lease back: a request dropped
    /// meanwhile cuts no operation short (#2978). A fatal error stops the
    /// supervisor here too, not only in the request's answer (#3143).
    async fn drain_under(
        &self,
        lease: tokio::sync::OwnedMutexGuard<()>,
        name: &str,
    ) -> Result<tokio::sync::OwnedMutexGuard<()>, SupervisorError> {
        let name = name.to_owned();
        self.detached(|supervisor| async move {
            if let Err(error) = supervisor.drain_held(&name).await {
                if fatal_drain_error(&error) {
                    supervisor.halt();
                }
                return Err(error);
            }
            Ok(lease)
        })
        .await
    }

    /// Reconcile `name` only if no operation holds it or waits for it: a
    /// busy environment's own operation owns its reconciliation, and a read
    /// never waits for it (#2978).
    async fn reconcile_if_idle(&self, name: &str) -> Result<(), SupervisorError> {
        if !self.pending_for(name)?.is_empty() {
            return Ok(());
        }
        let Ok(_lease) = self.lease(name).try_lock_owned() else {
            return Ok(());
        };
        // Under the lease nothing can remove it, but a delete may have run
        // before, and an operation may have been admitted since the check.
        if !self.core().state.environments.contains_key(name) || !self.pending_for(name)?.is_empty()
        {
            return Ok(());
        }
        self.reconcile(name).await
    }

    /// Record that an RPC in this process admitted `operation`, with the
    /// selections so far, so its drain runs it as new work rather than as a
    /// recovery.
    fn admit(&self, operation: &OperationRecord) {
        self.core().admit(operation);
    }

    /// Names with pending lifecycle work, and those holding environments with
    /// pending cw-runtime work, for drains to start.
    fn names_with_pending_work(&self) -> Result<BTreeSet<String>, SupervisorError> {
        let core = self.core();
        let pending = core.store.pending_operations()?;
        let mut names = BTreeSet::new();
        for operation in &pending {
            if operation.kind.cw_runtime() {
                if let Some(environment) = core
                    .state
                    .environments
                    .values()
                    .find(|environment| Some(environment.id) == operation.environment_id)
                {
                    names.insert(environment.name.clone());
                }
            } else if let Some(name) = operation_name(operation) {
                names.insert(name.to_owned());
            }
        }
        Ok(names)
    }

    /// Applies `change` to the current state and records it with the
    /// operation's transactional checkpoint, in one section of the lock, so a
    /// change is never made to a copy older than another commit.
    fn commit_operation(
        &self,
        operation: &OperationRecord,
        change: impl FnOnce(&mut SupervisorState) -> Result<(), SupervisorError>,
    ) -> Result<OperationRecord, SupervisorError> {
        let mut core = self.core();
        let mut next_state = core.state.clone();
        change(&mut next_state)?;
        core.checkpoint_state_operation(operation, next_state)
    }

    /// Applies `change` to the current state and fails the operation with
    /// `error_code`, in one section of the lock.
    fn fail_operation_with(
        &self,
        operation: &OperationRecord,
        error_code: &str,
        change: impl FnOnce(&mut SupervisorState) -> Result<(), SupervisorError>,
    ) -> Result<OperationRecord, SupervisorError> {
        let mut core = self.core();
        let mut next_state = core.state.clone();
        change(&mut next_state)?;
        let updated = core.store.replace_state_and_advance_operation(
            &next_state,
            operation.operation_id,
            operation.checkpoint,
            OperationPhase::Failed,
            None,
            Some(error_code),
        )?;
        core.state = next_state;
        Ok(updated)
    }

    /// Applies `change` to one environment's current record and saves the
    /// state, in one section of the lock; a failed save changes nothing.
    fn update_environment(
        &self,
        name: &str,
        change: impl FnOnce(&mut EnvironmentRecord) -> Result<(), SupervisorError>,
    ) -> Result<(), SupervisorError> {
        let mut core = self.core();
        let mut next_state = core.state.clone();
        change(
            next_state
                .environments
                .get_mut(name)
                .ok_or_else(|| SupervisorError::NotFound(name.to_owned()))?,
        )?;
        core.store.replace_state(&next_state)?;
        core.state = next_state;
        Ok(())
    }
}

/// Records a first boot's staged workspace generation; `None` (one already
/// staged) changes nothing.
fn record_staged_workspace_generation(
    state: &mut SupervisorState,
    name: &str,
    generation: Option<WorkspaceGenerationRecord>,
) -> Result<(), SupervisorError> {
    let Some(generation) = generation else {
        return Ok(());
    };
    let environment = state
        .environments
        .get_mut(name)
        .ok_or_else(|| SupervisorError::NotFound(name.to_owned()))?;
    if environment.active_workspace_generation.is_some()
        || environment.staging_workspace_generation.is_some()
    {
        return Err(SupervisorError::InvalidState);
    }
    environment.staging_workspace_generation = Some(generation);
    Ok(())
}

/// Records an update's staged runtime artifacts and workspace generation;
/// `None` (already staged) changes nothing.
fn record_staged_workspace_update(
    state: &mut SupervisorState,
    name: &str,
    parameters: &WorkspaceTransitionParameters,
    staged: Option<(String, WorkspaceGenerationRecord)>,
) -> Result<(), SupervisorError> {
    let Some((artifact_generation, generation)) = staged else {
        return Ok(());
    };
    let environment = state
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
    Ok(())
}

fn record_staged_workspace_rollback(
    state: &mut SupervisorState,
    name: &str,
    parameters: &WorkspaceTransitionParameters,
) -> Result<(), SupervisorError> {
    let WorkspaceTransitionIntent::Rollback {
        rollback_storage_generation,
    } = &parameters.intent
    else {
        return Err(SupervisorError::InvalidState);
    };
    state
        .environments
        .get_mut(name)
        .ok_or_else(|| SupervisorError::NotFound(name.to_owned()))?
        .stage_rollback_workspace_generation(
            &parameters.prior_storage_generation,
            rollback_storage_generation,
        )
}

impl Supervisor {
    async fn resolve_workspace_image(
        &self,
        name: &str,
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
        let resolver = RegistryResolver::new(content)?;
        let resolved = resolver.resolve_anonymous(reference).await;
        self.core()
            .record_pull(name, reference, resolver.verified_blobs(), resolved)
    }
}

impl SupervisorCore {
    /// As [`Supervisor::admit`], within a section of the lock its caller
    /// already holds.
    fn admit(&mut self, operation: &OperationRecord) {
        self.admitted_here
            .insert(operation.operation_id, self.selections);
    }
}

impl SupervisorCore {
    fn environment_proto(&self, name: &str) -> Result<v1::Environment, SupervisorError> {
        let environment = self.environment(name)?;
        let mut projected = environment.proto(self.selected(name));
        projected.network_policy = Some(
            network_policies::status_proto(
                &self.network_policies,
                environment.id,
                environment.state == StoredEnvironmentState::Running,
            )
            .map_err(|status| SupervisorError::NetworkPolicyStore(status.message().to_owned()))?,
        );
        if self.incompatible_runners.contains(&environment.id) {
            projected.error_code = "runner_protocol_unsupported".to_owned();
        } else if projected.error_code.is_empty()
            && matches!(
                environment.state,
                StoredEnvironmentState::Error | StoredEnvironmentState::Stopped
            )
            && let Some(error_code) = self.error_transition_code(environment.id)?
        {
            projected.error_code = error_code;
        }
        Ok(projected)
    }

    /// Why an environment without a runner's own code is in Error, or stopped
    /// after a failure: the error code of the reconcile that moved it into
    /// Error (#2568). Operations recorded since, while it stayed in Error, do
    /// not replace that code, nor does a runner reporting the VM stopped after
    /// the failure (#2626). A runner that reported its start failure first
    /// moved it into Error unrecorded, so the failed operation's own record is
    /// then the oldest code. A completed operation that left it in another
    /// state, or an observation that it runs again, means no code applies.
    fn error_transition_code(
        &self,
        environment_id: Uuid,
    ) -> Result<Option<String>, SupervisorError> {
        let operations = self.store.recent_environment_operations(environment_id)?;
        let mut recorded = None;
        for operation in operations.into_iter().rev() {
            if operation.phase != OperationPhase::Completed {
                continue;
            }
            if operation.kind == OperationKind::Reconcile
                && let Ok(parameters) = reconcile_operation_parameters(&operation)
            {
                match parameters.state {
                    StoredEnvironmentState::Error => {
                        if parameters.runner_error_code.is_some() {
                            recorded = parameters.runner_error_code;
                        }
                        if parameters.precondition.state != StoredEnvironmentState::Error {
                            return Ok(recorded);
                        }
                        continue;
                    }
                    StoredEnvironmentState::Stopped => continue,
                    _ => return Ok(recorded),
                }
            }
            let state = operation
                .result
                .as_ref()
                .and_then(|result: &serde_json::Value| result.get("state"))
                .and_then(serde_json::Value::as_str);
            if state.is_some_and(|state| state != StoredEnvironmentState::Error.as_str()) {
                return Ok(recorded);
            }
        }
        Ok(recorded)
    }

    fn save(&self) -> Result<(), SupervisorError> {
        self.store.replace_state(&self.state)?;
        Ok(())
    }

    #[cfg(all(target_os = "linux", feature = "synthetic-oci-input-smoke"))]
    fn synthetic_workspace_image_pin(&self) -> Result<Option<ResolvedImage>, SupervisorError> {
        let engine = PrivateRoot::open(&self.config.engine_root())?;
        let content = ContentStore::create(&engine)?;
        crate::oci::load_synthetic_image_pin(&engine, &content)
            .map_err(|_| SupervisorError::InvalidState)
    }

    #[cfg(all(target_os = "linux", feature = "synthetic-oci-input-smoke"))]
    fn admit_synthetic_workspace_image_pin(&mut self) -> Result<(), SupervisorError> {
        let _ = self.synthetic_workspace_image_pin()?;
        Ok(())
    }

    fn matching_synthetic_workspace_image(
        &self,
        reference: &RegistryReference,
    ) -> Result<Option<ResolvedImage>, SupervisorError> {
        #[cfg(all(target_os = "linux", feature = "synthetic-oci-input-smoke"))]
        {
            Ok(self
                .synthetic_workspace_image_pin()?
                .filter(|image| image.source_reference == reference.original()))
        }
        #[cfg(not(all(target_os = "linux", feature = "synthetic-oci-input-smoke")))]
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
}

impl Supervisor {
    async fn access_control_client(&self) -> Result<LocalCredentialControlClient, SupervisorError> {
        LocalCredentialControlClient::connect(&self.config.credential_authority_config())
            .await
            .map_err(|_| SupervisorError::CredentialAuthorityUnavailable)
    }

    /// Whether a create's selected profile has an SSH key, asked only when a
    /// github.com repository in SSH form would otherwise use the GitHub
    /// connection (#2723): a platform profile's slots say so; a local
    /// profile's exact revision is read from the authority, material-free.
    async fn profile_has_ssh_key(
        &self,
        request: &v1::CreateEnvironmentRequest,
        project: &codewire_project::ProjectSpec,
        platform: bool,
        profile_id: &AccessProfileId,
        profile_revision: u64,
    ) -> Result<bool, SupervisorError> {
        if !project.repositories.iter().any(|repository| {
            matches!(
                codewire_project::github_repository_path(&repository.source),
                Some((_, codewire_project::GitHubSourceForm::Ssh))
            )
        }) {
            return Ok(false);
        }
        if platform {
            return Ok(request
                .platform_source_authority
                .as_ref()
                .is_some_and(|authority| {
                    authority
                        .profile_slots
                        .iter()
                        .any(|slot| slot == SSH_PROFILE_SLOT)
                }));
        }
        let revision = self
            .access_control_client()
            .await?
            .get_profile_revision(profile_id, profile_revision)
            .await
            .map_err(credential_control_error)?;
        Ok(revision
            .profile
            .entries
            .keys()
            .any(|slot| slot.as_str() == SSH_PROFILE_SLOT))
    }

    async fn bind_environment_access(
        &self,
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

    async fn require_environment_access(&self, name: &str) -> Result<(), SupervisorError> {
        let environment = self.environment(name)?;
        let Some(expected) = environment.access_binding.clone() else {
            return Ok(());
        };
        let project: codewire_project::ProjectSpec = serde_json::from_slice(
            environment
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
            sources::platform::managed_clients(&environment)?
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

    /// Ask the credential authority, which asks the platform as the pinned
    /// creator, whether that account's GitHub connection is usable now.
    /// Material-free. `None` when it cannot answer at this start; the
    /// supervisor's log then records why, as a closed reason only.
    async fn platform_github_connected(
        &self,
        environment: &EnvironmentRecord,
        generation: u64,
    ) -> Option<bool> {
        match self.ask_platform_github(environment, generation).await {
            Ok(connected) => Some(connected),
            Err(reason) => {
                if let Some(log) = &self.log {
                    log.record(
                        "platform_github_unanswered",
                        &[
                            ("environment", LogField::Id(environment.id)),
                            ("reason", LogField::Name(reason)),
                        ],
                    );
                }
                None
            }
        }
    }

    /// [`Self::platform_github_connected`]'s question, or the closed reason
    /// it went unanswered: no platform binding, the pinned configuration,
    /// the authority unreachable, older than the question or past its bound,
    /// the platform refusing the saved login (not the creator's, an API key,
    /// another server), or the platform unavailable.
    async fn ask_platform_github(
        &self,
        environment: &EnvironmentRecord,
        generation: u64,
    ) -> Result<bool, &'static str> {
        let mut binding =
            sources::platform::broker_binding(environment, &self.config.platform_config_dir)
                .map_err(|_| "binding_invalid")?
                .ok_or("no_platform_binding")?;
        sources::platform::resolve_config_directory(&mut binding)
            .map_err(|_| "config_directory")?;
        let environment_id = access_environment_id(environment.id).map_err(|_| "environment")?;
        let mut client = self
            .access_control_client()
            .await
            .map_err(|_| "authority_unreachable")?;
        platform_github_askable(client.info().protocol_version)?;
        tokio::time::timeout(
            PLATFORM_GITHUB_STATE_CALL_BOUND,
            client.platform_github_connected(&environment_id, generation, binding),
        )
        .await
        .map_err(|_| "timed_out")?
        .map_err(|status| match status.code() {
            tonic::Code::DeadlineExceeded => "timed_out",
            tonic::Code::PermissionDenied | tonic::Code::Unauthenticated => "login_refused",
            tonic::Code::Unavailable => "unavailable",
            _ => "failed",
        })
    }

    /// Capture only client-slot metadata from the exact selected revision.
    /// This configures clients; each broker request still evaluates live grants.
    async fn managed_credential_clients_for_boot(
        &self,
        environment: &EnvironmentRecord,
        generation: u64,
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
        if let Some(pinned) = sources::platform::managed_clients(environment)? {
            return Ok(sources::platform::clients_for_start(pinned, || {
                self.platform_github_connected(environment, generation)
            })
            .await);
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
        // The store's one GitHub connection is never a profile entry: the
        // authority grants it to profiles that include GitHub while it is
        // active. Configure git for it exactly then, so a missing connection
        // never routes GitHub remotes to a route that cannot serve them.
        let github = authority
            .environment_grant_slots(&expected.environment_id, generation)
            .await
            .map_err(credential_control_error)?
            .contains("github");
        // Local profiles never hold a Claude subscription token or sign-in:
        // the local authority refuses Anthropic OAuth, so slot names fix every
        // form here. A platform profile pins its form with its slots
        // (sources::platform::managed_clients).
        let clients = codewire_access::ManagedCredentialClients::from_profile_slots(
            revision
                .profile
                .entries
                .keys()
                .map(|slot| slot.as_str())
                .chain(github.then_some("github")),
        )
        .map_err(|_| SupervisorError::EnvironmentAccessUnavailable)?;
        clients
            .check_collisions(project.environment.keys().map(String::as_str))
            .map_err(|_| SupervisorError::EnvironmentAccessUnavailable)?;
        Ok(clients)
    }

    async fn stop_environment_broker_if_present(
        &self,
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

    async fn revoke_environment_access_best_effort(&self, environment_id: Uuid) -> bool {
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

    async fn environment_access_cleanup_pending(&self, environment_id: Uuid) -> bool {
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
}

impl SupervisorCore {
    fn orphan_inventory(&self) -> Result<v1::ListOrphansResponse, SupervisorError> {
        let deletion_trash_names = self.store.deletion_trash_names()?;
        orphan_inventory_response(&self.root, &self.state, &deletion_trash_names)
    }
}

impl Supervisor {
    async fn admit_current_artifact_generation(&self) -> Result<String, SupervisorError> {
        let engine = PrivateRoot::open(&self.config.engine_root())?;
        RuntimeArtifactStore::create(&engine)
            .map_err(artifact_store_error)?
            .admit_source(&self.config.artifact_lock, &self.config.artifact_root)
            .await
            .map_err(artifact_store_error)
    }
}

impl SupervisorCore {
    #[cfg(target_os = "macos")]
    fn require_vz_helper(&self) -> Result<(), SupervisorError> {
        let lock = crate::artifact::ArtifactLock::read(&self.config.artifact_lock)?;
        let helper = self.config.artifact_root.join(&lock.vz_runner.path);
        match crate::host::vz_helper_problem(&helper) {
            None => Ok(()),
            Some(crate::host::VzHelperProblem::Missing) => {
                Err(SupervisorError::VzHelperMissing(helper))
            }
            Some(crate::host::VzHelperProblem::Unentitled) => {
                Err(SupervisorError::VzHelperUnentitled(helper))
            }
        }
    }
}

impl Supervisor {
    async fn admit_cached_artifact_generation(
        &self,
        artifact_generation: &str,
    ) -> Result<(), SupervisorError> {
        let engine = PrivateRoot::open(&self.config.engine_root())?;
        let _ = RuntimeArtifactStore::create(&engine)
            .map_err(artifact_store_error)?
            .open_generation(artifact_generation)
            .await
            .map_err(artifact_store_error)?;
        Ok(())
    }

    async fn preflight(&self) -> Result<String, SupervisorError> {
        #[cfg(target_os = "macos")]
        self.core().require_vz_helper()?;
        let artifact_generation = self.admit_current_artifact_generation().await?;
        let engine = PrivateRoot::open(&self.config.engine_root())?;
        RuntimeArtifactStore::create(&engine)
            .map_err(artifact_store_error)?
            .open_generation(&artifact_generation)
            .await
            .map_err(artifact_store_error)?
            .require_current_guest_seed_abi()?;
        if fs::symlink_metadata(self.config.cw_runtime_lock()).is_ok() {
            RuntimeArtifactStore::create(&engine)
                .map_err(artifact_store_error)?
                .open_generation(&artifact_generation)
                .await
                .map_err(artifact_store_error)?
                .require_live_cw_runtime_publisher()?;
        }
        #[cfg(target_os = "linux")]
        crate::linux::preflight::preflight().map_err(RunnerError::from)?;
        Ok(artifact_generation)
    }

    async fn prepare_create_workspace_plan(
        &self,
        request: &v1::CreateEnvironmentRequest,
        environment_id: Uuid,
    ) -> Result<(WorkspacePlan, DirectShareDiscriminators), SupervisorError> {
        // Repository preparation runs the runtime's git before preflight
        // admits the VM inputs. Without an admissible runtime, git-backed
        // preparation reports the reinstall guidance and preflight the rest.
        #[cfg(target_os = "macos")]
        if let Ok(lock) = crate::artifact::ArtifactLock::read(&self.config.artifact_lock) {
            let _ = lock.admit_host_tools(&self.config.artifact_root);
        }
        let project: codewire_project::ProjectSpec =
            serde_json::from_slice(&request.project_spec_json)
                .map_err(|_| SupervisorError::InvalidRequest)?;
        if project.repositories.is_empty() && request.local_mounts.is_empty() {
            let requested_source = PathBuf::from(&request.source_path);
            let path_mode = parse_implicit_path_mode(&request.implicit_path_mode)?;
            let maximum_copy_bytes = workspace_content_limit(request.disk_bytes);
            let vm_only = request.implicit_vm_only.clone();
            let source = tokio::task::spawn_blocking(move || {
                inspect_workspace_skipping(
                    &requested_source,
                    workspace_selection(path_mode),
                    maximum_copy_bytes,
                    &vm_only,
                )
            })
            .await
            .map_err(|_| SupervisorError::WorkspaceProvisionTask)??;
            let plan = WorkspacePlan::local(&source)?;
            validate_request_workspace_plan(request, &project, &plan)?;
            return Ok((plan, DirectShareDiscriminators::default()));
        }
        let mut discriminators = DirectShareDiscriminators::default();
        let mut inputs = if project.repositories.is_empty() {
            Vec::new()
        } else {
            let platform = sources::platform::repository_binding(
                request,
                &project,
                environment_id,
                &self.config.platform_config_dir,
            )?;
            let credential_access = match create_request_access_selection(request, &project)? {
                Some((profile_id, profile_revision, _)) => {
                    let ssh_key = self
                        .profile_has_ssh_key(
                            request,
                            &project,
                            platform.is_some(),
                            &profile_id,
                            profile_revision,
                        )
                        .await?;
                    Some(RepositoryCredentialAccess {
                        request_id: Uuid::parse_str(&request.request_id)
                            .expect("validated create request ID"),
                        profile_id,
                        profile_revision,
                        platform,
                        ssh_key,
                    })
                }
                None => None,
            };
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
                                mount.vm_only.clone(),
                                &forbidden_roots,
                            )
                            .map(|(input, discriminator)| (input, Some(discriminator)))
                            .map_err(SupervisorError::from);
                        }
                        let source = inspect_workspace_skipping(
                            &requested_source,
                            WorkspaceSelection::Copy,
                            maximum_copy_bytes,
                            &mount.vm_only,
                        )
                        .map_err(SupervisorError::from)?;
                        if source.source_path.as_os_str().as_bytes() != mount.source_path {
                            return Err(SupervisorError::from(WorkspaceError::SourceChanged));
                        }
                        Ok((WorkspaceInput::local(&source, &mount.destination), None))
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .await
            .map_err(|_| SupervisorError::WorkspaceProvisionTask)??;
            for (input, discriminator) in local_inputs {
                if let (Some(identity_sha256), Some(discriminator)) =
                    (input.direct_identity_sha256(), discriminator)
                {
                    discriminators.insert(identity_sha256, discriminator);
                }
                inputs.push(input);
            }
        }
        let plan = WorkspacePlan::from_inputs(inputs)?;
        validate_request_workspace_plan(request, &project, &plan)?;
        Ok((plan, discriminators))
    }

    /// The workspace generation a first boot stages, or `None` when one is
    /// already active or staged. [`record_staged_workspace_generation`]
    /// records it.
    async fn stage_workspace_generation(
        &self,
        name: &str,
    ) -> Result<Option<WorkspaceGenerationRecord>, SupervisorError> {
        let (project_json, project_sha256, artifact_generation) = {
            let environment = self.environment(name)?;
            if environment.active_workspace_generation.is_some()
                || environment.staging_workspace_generation.is_some()
            {
                return Ok(None);
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
        let pinned = self.core().matching_synthetic_workspace_image(&reference)?;
        let image = self
            .resolve_workspace_image(name, &reference, &content, pinned)
            .await?;
        let resolution = self.core().spawn_skill_snapshot_resolution(
            name,
            &project,
            &project_sha256,
            1,
            None,
        )?;
        let skill_snapshot = resolution
            .await
            .map_err(|_| SupervisorError::WorkspaceGenerationProvisionTask)??;
        WorkspaceGenerationRecord::new_with_skill_snapshot(
            &project_json,
            project_sha256.to_owned(),
            artifact_generation,
            image,
            DEFAULT_OCI_ROOT_DISK_BYTES,
            skill_snapshot,
        )
        .map(Some)
        .map_err(Into::into)
    }

    /// The runtime artifacts and workspace generation an update stages, or
    /// `None` when they are already staged. [`record_staged_workspace_update`]
    /// records them.
    async fn stage_workspace_update(
        &self,
        name: &str,
        parameters: &WorkspaceTransitionParameters,
    ) -> Result<Option<(String, WorkspaceGenerationRecord)>, SupervisorError> {
        let WorkspaceTransitionIntent::Update {
            project_spec_json,
            project_spec_sha256,
        } = &parameters.intent
        else {
            return Err(SupervisorError::InvalidState);
        };
        let environment = self.environment(name)?;
        let active = environment
            .active_workspace_generation
            .as_ref()
            .ok_or(SupervisorError::InvalidState)?;
        if workspace_storage_generation(active)? != parameters.prior_storage_generation {
            return Err(SupervisorError::InvalidState);
        }
        if environment.staging_workspace_generation.is_some() {
            workspace_transition_requires_boot(&environment, parameters)?;
            return Ok(None);
        }

        let project: codewire_project::ProjectSpec =
            serde_json::from_slice(project_spec_json).map_err(|_| SupervisorError::InvalidState)?;
        let (artifact_generation, image, root_disk_bytes) = if parameters.refresh_skills {
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
            let pinned = self.core().matching_synthetic_workspace_image(&reference)?;
            let image = self
                .resolve_workspace_image(name, &reference, &content, pinned)
                .await?;
            (artifact_generation, image, DEFAULT_OCI_ROOT_DISK_BYTES)
        };
        let plan_generation = match active.skill_snapshot.as_ref() {
            Some(snapshot) => snapshot
                .plan_generation()
                .checked_add(1)
                .ok_or(SupervisorError::InvalidState)?,
            None => 1,
        };
        let resolution = self.core().spawn_skill_snapshot_resolution(
            name,
            &project,
            project_spec_sha256,
            plan_generation,
            None,
        )?;
        let skill_snapshot = resolution
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
        Ok(Some((artifact_generation, generation)))
    }
}

impl SupervisorCore {
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
}

impl Supervisor {
    /// Admit `plan`'s direct shares again under the discriminators recorded
    /// for `environment_id`, and record any that change (#3209). The result
    /// holds every share open; see [`WorkspacePlan::check_direct_shares`].
    /// A store failure fails it as `SupervisorError::Store`, after the
    /// shares were checked as if nothing were recorded, so it never stands
    /// for a changed share and never quarantines a runner (see
    /// [`revalidation_requires_quarantine`]).
    async fn revalidate_workspace_plan_for_boot(
        &self,
        environment_id: Uuid,
        plan: &WorkspacePlan,
    ) -> Result<CheckedDirectShares, SupervisorError> {
        let plan = plan.clone();
        let forbidden_roots = self.config.direct_share_forbidden_roots()?;
        let (recorded, read_failure) = match self
            .core()
            .store
            .direct_share_discriminators(environment_id)
        {
            Ok(recorded) => (recorded, None),
            Err(error) => (DirectShareDiscriminators::default(), Some(error)),
        };
        let check_recorded = recorded.clone();
        let checked = tokio::task::spawn_blocking(move || {
            revalidate_direct_shares_for_boot(&plan, &forbidden_roots, &check_recorded)
        })
        .await
        .map_err(|_| SupervisorError::WorkspaceGenerationProvisionTask)??;
        if let Some(error) = read_failure {
            return Err(error.into());
        }
        if checked.discriminators != recorded {
            self.core()
                .store
                .record_direct_share_discriminators(environment_id, &checked.discriminators)?;
        }
        Ok(checked)
    }

    async fn revalidate_environment_workspace_plan_for_boot(
        &self,
        name: &str,
    ) -> Result<CheckedDirectShares, SupervisorError> {
        let environment = self.environment(name)?;
        let plan = environment.workspace_plan.clone();
        let exposes_direct_shares =
            environment.runner.is_some() && environment_may_expose_direct_shares(&environment);
        let validation = self
            .revalidate_workspace_plan_for_boot(environment.id, &plan)
            .await;
        if exposes_direct_shares
            && validation
                .as_ref()
                .is_err_and(revalidation_requires_quarantine)
        {
            // A replay can resume after StartVm. Reconciliation terminates an
            // exact live runner before an invalid or unresolved current
            // exclusion boundary is returned to the lifecycle worker.
            self.reconcile_runner(name, true).await?;
        }
        validation
    }

    async fn reconcile_active_environment_before_protected_effect(
        &self,
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
        if !environment_may_expose_direct_shares(&environment) {
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

    /// Record a discriminator for each direct share that has none yet and
    /// still matches its recorded identity (#3209). A database written
    /// before #3209 records none, so this records them at the first start
    /// after the upgrade, and a share replaced from then on is refused at
    /// its next boot even where inode numbers are reused. Nothing is
    /// refused here: a share that does not match is left for its boot.
    async fn record_direct_share_discriminators_for_startup(&self) -> Result<(), SupervisorError> {
        let environments = self
            .core()
            .state
            .environments
            .values()
            .filter(|environment| {
                environment
                    .workspace_plan
                    .inputs
                    .iter()
                    .any(|input| matches!(input, WorkspaceInput::Direct { .. }))
            })
            .map(|environment| (environment.id, environment.workspace_plan.clone()))
            .collect::<Vec<_>>();
        if environments.is_empty() {
            return Ok(());
        }
        let forbidden_roots = self.config.direct_share_forbidden_roots()?;
        for (environment_id, plan) in environments {
            let recorded = self
                .core()
                .store
                .direct_share_discriminators(environment_id)?;
            let sweep_recorded = recorded.clone();
            let sweep_roots = forbidden_roots.clone();
            let swept = tokio::task::spawn_blocking(move || {
                plan.sweep_direct_share_discriminators(&sweep_roots, &sweep_recorded)
            })
            .await
            .map_err(|_| SupervisorError::WorkspaceGenerationProvisionTask)?;
            if swept != recorded {
                self.core()
                    .store
                    .record_direct_share_discriminators(environment_id, &swept)?;
            }
        }
        Ok(())
    }

    async fn reconcile_exposing_runners_for_startup(&self) -> Result<(), SupervisorError> {
        let names = self
            .core()
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
                Ok(_) => valid_names.push(name),
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
        &self,
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
            .revalidate_workspace_plan_for_boot(environment_id, workspace_plan)
            .await;
        if validation
            .as_ref()
            .is_err_and(revalidation_requires_quarantine)
            && self
                .core()
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
            let effect_name = effect.name();
            let effect_started = std::time::Instant::now();
            match effect {
                LifecycleEffect::RecordEnvironment => {
                    // A restore records its snapshot's pinned artifact
                    // generation and disk sizes, and its requested vCPUs and
                    // memory (#3046).
                    let restore = snapshots::record_inputs(self, request).await?;
                    let (vcpus, memory_mib, disk_bytes, docker_disk_bytes) =
                        snapshots::RestoreRecord::resources(restore.as_ref(), request)?;
                    // The selection is recorded first, so the first boot
                    // enforces it; a failed create's rollback clears it.
                    let selection =
                        network_policies::selection_from_reference(&request.network_policy)
                            .map_err(|status| {
                                SupervisorError::NetworkPolicySelection(status.message().to_owned())
                            })?;
                    self.core()
                        .network_policies
                        .select(environment_id, selection.as_ref())
                        .map_err(|error| {
                            SupervisorError::NetworkPolicySelection(error.to_string())
                        })?;
                    let recorded = |environment: &EnvironmentRecord| {
                        Ok::<_, SupervisorError>(
                            environment.id == environment_id
                                && environment.vcpus == vcpus
                                && environment.memory_mib == memory_mib
                                && environment.disk_bytes == disk_bytes
                                && environment.docker_disk_bytes == docker_disk_bytes
                                && environment.host_ports
                                    == host_ports_from_proto(&request.host_ports)?
                                && environment.mesh
                                    == mesh_attachment_from_proto(request.mesh.as_ref())?
                                && environment.project_spec_json.as_deref()
                                    == Some(request.project_spec_json.as_slice())
                                && environment.project_spec_sha256.as_deref()
                                    == Some(request.project_spec_sha256.as_str())
                                && environment.access_profile == expected_access_profile
                                && environment.access_binding == expected_access_binding
                                && environment.platform_source_authority
                                    == request
                                        .platform_source_authority
                                        .as_ref()
                                        .map(PlatformSourceAuthority::from_proto)
                                        .transpose()?
                                && &environment.workspace_plan == workspace_plan,
                        )
                    };
                    // Admission awaits the runtime's artifacts with no lock
                    // held, as a writer until the record that references them
                    // commits; the record is inserted only if the name is
                    // still free then.
                    let _writer = self.content_writer().await;
                    let admitted = if self.environment(&request.name).is_ok() {
                        None
                    } else {
                        let artifact_generation = match restore.as_ref() {
                            Some(restore) => restore.artifact_generation.clone(),
                            None => self.preflight().await?,
                        };
                        self.require_vm_only_guest_for_plan(&artifact_generation, workspace_plan)
                            .await?;
                        // A VM checkpoint fork boots its recorded catalog,
                        // never the installed runtime (#3046).
                        let cw_runtime = match restore
                            .as_ref()
                            .and_then(|restore| restore.checkpoint_cw_runtime.clone())
                        {
                            Some(Some(generation)) => {
                                let config = self.config.clone();
                                Some(
                                    tokio::task::spawn_blocking(move || {
                                        snapshots::open_recorded_cw_runtime_catalog(
                                            &config,
                                            &generation,
                                        )
                                    })
                                    .await
                                    .map_err(|_| SupervisorError::CwRuntimeProvisionTask)??,
                                )
                            }
                            Some(None) => None,
                            None => self.admit_installed_cw_runtime().await?,
                        }
                        .map(|generation| CwRuntimeBinding {
                            schema_version: 1,
                            active_catalog_generation: generation,
                            staging_catalog_generation: None,
                            rollback_catalog_generation: None,
                        });
                        Some(EnvironmentRecord {
                            cw_runtime,
                            id: environment_id,
                            name: request.name.clone(),
                            state: StoredEnvironmentState::Starting,
                            vcpus,
                            memory_mib,
                            disk_bytes,
                            docker_disk_bytes,
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
                        })
                    };
                    // Whether it selects itself is decided in the same
                    // section of the lock as its commit, so no select falls
                    // between them.
                    let mut core = self.core();
                    let selects_itself = create_selects_itself(
                        core.admitted_here.get(&operation.operation_id).copied(),
                        core.selections,
                    );
                    let mut next_state = core.state.clone();
                    if let Some(environment) = next_state.environments.get(&request.name) {
                        if !recorded(environment)? {
                            return Err(SupervisorError::AlreadyExists(request.name.clone()));
                        }
                    } else {
                        let environment = admitted.ok_or(SupervisorError::InvalidState)?;
                        next_state
                            .environments
                            .insert(request.name.clone(), environment);
                        if selects_itself {
                            next_state.current = Some(request.name.clone());
                        }
                    }
                    operation = core.checkpoint_state_operation(&operation, next_state)?;
                }
                LifecycleEffect::BindEnvironmentAccess => {
                    self.bind_environment_access(request, environment_id)
                        .await?;
                    operation = self.core().checkpoint_operation(&operation)?;
                }
                LifecycleEffect::ProvisionWorkspace if request.snapshot.is_some() => {
                    // A restore places its snapshot's disks and records their
                    // root generation (#3046).
                    operation =
                        snapshots::place_disks(self, request, environment_id, &operation).await?;
                }
                LifecycleEffect::ProvisionWorkspace => {
                    let environment = self.environment(&request.name)?;
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
                    operation = self.core().checkpoint_operation(&operation)?;
                }
                LifecycleEffect::StageWorkspaceGeneration => {
                    let _writer = self.begin_staging(&request.name).await?;
                    let generation = self.stage_workspace_generation(&request.name).await?;
                    operation = self.commit_operation(&operation, |next_state| {
                        record_staged_workspace_generation(next_state, &request.name, generation)
                    })?;
                }
                LifecycleEffect::RecordStarting => {
                    operation = self.commit_operation(&operation, |next_state| {
                        let environment = next_state
                            .environments
                            .get_mut(&request.name)
                            .ok_or_else(|| SupervisorError::NotFound(request.name.clone()))?;
                        reserve_boot_generation(environment, 1)?;
                        Ok(())
                    })?;
                }
                LifecycleEffect::EnsureRunner => {
                    let staging = self
                        .environment(&request.name)?
                        .staging_workspace_generation
                        .is_some();
                    validate_environment_workload_secret_delivery(
                        &self.environment(&request.name)?,
                        staging,
                    )?;
                    let artifact_generation =
                        artifact_generation_for_boot(&self.environment(&request.name)?, staging)?
                            .to_owned();
                    let _ = self
                        .runner_client_for_artifact(&request.name, &artifact_generation)
                        .await?;
                    operation = self.core().checkpoint_operation(&operation)?;
                }
                LifecycleEffect::StartVm => {
                    self.ensure_vm_started(&request.name, 1, operation.operation_id)
                        .await?;
                    operation = self.core().checkpoint_operation(&operation)?;
                }
                LifecycleEffect::RecordRunning => {
                    operation = self.commit_operation(&operation, |next_state| {
                        let environment = next_state
                            .environments
                            .get_mut(&request.name)
                            .ok_or_else(|| SupervisorError::NotFound(request.name.clone()))?;
                        let _displaced = environment.promote_staging_workspace_generation()?;
                        environment.generation = 1;
                        environment.state = StoredEnvironmentState::Running;
                        Ok(())
                    })?;
                }
                _ => return Err(SupervisorError::InvalidState),
            }
            log_effect_timing(self.log.as_deref(), &operation, effect_name, effect_started);
        }
        Ok((
            self.environment(&request.name)?
                .proto(self.core().selected(&request.name)),
            operation,
        ))
    }

    /// Run one pending operation (#2978): its name's drain calls it under
    /// that name's lease. `recovering` is false only for an operation an RPC in
    /// this process admitted.
    async fn run_operation(
        &self,
        operation: OperationRecord,
        recovering: bool,
    ) -> Result<(), SupervisorError> {
        let Some(name) = operation
            .payload
            .get("name")
            .and_then(|value| value.as_str())
        else {
            self.core()
                .interrupt_operation(&operation, "invalid_replay_payload")?;
            return Ok(());
        };
        if operation.kind == OperationKind::Create {
            let (request, workspace_plan) = match create_request_from_operation(&operation) {
                Ok(prepared) => prepared,
                Err(_) => {
                    self.core()
                        .interrupt_operation(&operation, "invalid_replay_payload")?;
                    return Ok(());
                }
            };
            let (_, operation) = match self.create(&request, &workspace_plan, &operation).await {
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
                    self.core()
                        .log_operation_failure(&operation, name, &error, error_code);
                    self.roll_back_failed_create(&operation, name, error_code, recovering)
                        .await?;
                    // If failure happened before RecordEnvironment, the
                    // prepared repository bundles have no durable owner.
                    // If it happened later, the recorded plan retains
                    // them. Re-derive reachability in either case.
                    let _ = self.collect_if_idle().await;
                    return Ok(());
                }
            };
            let result = self
                .core()
                .state
                .environments
                .get(name)
                .map(environment_operation_result)
                .ok_or(SupervisorError::InvalidState)?;
            self.core().complete_operation(&operation, &result)?;
            return Ok(());
        }
        if operation.kind == OperationKind::Start {
            let (_, operation) = match self.start(name, &operation).await {
                Ok(result) => result,
                Err(SupervisorError::CredentialAuthorityUnavailable) if recovering => {
                    return Err(SupervisorError::CredentialAuthorityUnavailable);
                }
                Err(error) => {
                    let error_code =
                        match error {
                            SupervisorError::WorkspacePlan(
                                WorkspacePlanError::DirectShareChanged,
                            ) if !recovering => "start_direct_share_changed".to_owned(),
                            _ if recovering => "start_interrupted".to_owned(),
                            _ => lifecycle_failure_code(
                                "start",
                                &error,
                                self.core().recorded_runner_error_code(name),
                            ),
                        };
                    self.core()
                        .log_operation_failure(&operation, name, &error, &error_code);
                    self.core()
                        .fail_replayed_operation(&operation, name, &error_code)?;
                    return Ok(());
                }
            };
            let result = self
                .core()
                .state
                .environments
                .get(name)
                .map(environment_operation_result)
                .ok_or(SupervisorError::InvalidState)?;
            self.core().complete_operation(&operation, &result)?;
            return Ok(());
        }
        if operation.kind == OperationKind::Stop {
            let (_, operation) = match self.stop(name, &operation).await {
                Ok(result) => result,
                Err(error) => {
                    let error_code = lifecycle_failure_code("stop", &error, None);
                    self.core()
                        .log_operation_failure(&operation, name, &error, &error_code);
                    self.core()
                        .fail_pending_operation(&operation, &error_code)?;
                    return Ok(());
                }
            };
            let result = self
                .core()
                .state
                .environments
                .get(name)
                .map(environment_operation_result)
                .ok_or(SupervisorError::InvalidState)?;
            self.core().complete_operation(&operation, &result)?;
            return Ok(());
        }
        if operation.kind == OperationKind::Delete {
            self.run_delete_operation(name, &operation, recovering)
                .await?;
            return Ok(());
        }
        if matches!(
            operation.kind,
            OperationKind::Restart | OperationKind::GrowDisk
        ) {
            let operation = match self.resize(name, &operation).await {
                Ok(operation) => operation,
                Err(error @ SupervisorError::ReplacementPreflight(_)) => {
                    self.core().log_operation_failure(
                        &operation,
                        name,
                        &error,
                        "restart_preflight",
                    );
                    self.core()
                        .fail_pending_operation(&operation, "restart_preflight")?;
                    return Ok(());
                }
                Err(SupervisorError::CredentialAuthorityUnavailable) if recovering => {
                    return Err(SupervisorError::CredentialAuthorityUnavailable);
                }
                Err(error) => {
                    let error_code = if recovering {
                        "resize_interrupted".to_owned()
                    } else {
                        lifecycle_failure_code(
                            "resize",
                            &error,
                            self.core().recorded_runner_error_code(name),
                        )
                    };
                    self.core()
                        .log_operation_failure(&operation, name, &error, &error_code);
                    self.core()
                        .fail_replayed_operation(&operation, name, &error_code)?;
                    return Ok(());
                }
            };
            let result = self
                .core()
                .state
                .environments
                .get(name)
                .map(environment_operation_result)
                .ok_or(SupervisorError::InvalidState)?;
            self.core().complete_operation(&operation, &result)?;
            return Ok(());
        }
        if matches!(
            operation.kind,
            OperationKind::UpdateWorkspace | OperationKind::RollbackWorkspace
        ) {
            let operation = match self.workspace_transition(name, &operation).await {
                Ok(operation) => operation,
                Err(error @ SupervisorError::ReplacementPreflight(_)) => {
                    let current = self
                        .core()
                        .store
                        .operation_by_request(operation.request_id)?
                        .ok_or(SupervisorError::InvalidState)?;
                    let error_code = if operation.kind == OperationKind::UpdateWorkspace {
                        "workspace_update_preflight"
                    } else {
                        "workspace_rollback_preflight"
                    };
                    self.core()
                        .log_operation_failure(&operation, name, &error, error_code);
                    self.abort_workspace_transition_with_stop(&current, name, error_code, false)
                        .await?;
                    return Ok(());
                }
                Err(SupervisorError::CredentialAuthorityUnavailable) if recovering => {
                    return Err(SupervisorError::CredentialAuthorityUnavailable);
                }
                Err(error) => {
                    let prefix = match operation.kind {
                        OperationKind::UpdateWorkspace => "workspace_update",
                        OperationKind::RollbackWorkspace => "workspace_rollback",
                        _ => return Err(SupervisorError::InvalidState),
                    };
                    let error_code = if recovering {
                        format!("{prefix}_interrupted")
                    } else {
                        lifecycle_failure_code(
                            prefix,
                            &error,
                            self.core().recorded_runner_error_code(name),
                        )
                    };
                    self.core()
                        .log_operation_failure(&operation, name, &error, &error_code);
                    self.abort_replayed_workspace_transition(&operation, name, &error_code)
                        .await?;
                    return Ok(());
                }
            };
            let result = self
                .core()
                .state
                .environments
                .get(name)
                .map(environment_operation_result)
                .ok_or(SupervisorError::InvalidState)?;
            self.core().complete_operation(&operation, &result)?;
            return Ok(());
        }
        if operation.kind == OperationKind::UpdateEnvironmentSources {
            self.execute_source_operation(&operation).await?;
            return Ok(());
        }
        if operation.kind == OperationKind::UpdateHostPorts {
            // A failed update changes nothing recorded and leaves the
            // environment as it was.
            let operation = match self.update_host_ports(name, &operation).await {
                Ok(operation) => operation,
                Err(error) => {
                    let error_code = match error {
                        SupervisorError::HostPortUnavailable => "host_port_unavailable".to_owned(),
                        _ if recovering => "host_ports_interrupted".to_owned(),
                        _ => lifecycle_failure_code("host_ports", &error, None),
                    };
                    self.core()
                        .log_operation_failure(&operation, name, &error, &error_code);
                    self.core()
                        .fail_pending_operation(&operation, &error_code)?;
                    return Ok(());
                }
            };
            let result = self
                .core()
                .state
                .environments
                .get(name)
                .map(environment_operation_result)
                .ok_or(SupervisorError::InvalidState)?;
            self.core().complete_operation(&operation, &result)?;
            return Ok(());
        }
        if operation.kind == OperationKind::Reconcile {
            let operation = self.core().apply_reconcile_operation(&operation)?;
            let result = self
                .core()
                .state
                .environments
                .get(name)
                .map(environment_operation_result)
                .ok_or(SupervisorError::InvalidState)?;
            self.core().complete_operation(&operation, &result)?;
            return Ok(());
        }
        Err(SupervisorError::InvalidState)
    }
}

impl SupervisorCore {
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

    /// After `name`'s drain, nothing of it stays staged beside an active
    /// workspace. Only that name: another environment may be mid-update
    /// (#2978).
    fn ensure_no_unowned_workspace_staging(&self, name: &str) -> Result<(), SupervisorError> {
        if self
            .state
            .environments
            .get(name)
            .is_some_and(|environment| {
                environment.active_workspace_generation.is_some()
                    && environment.staging_workspace_generation.is_some()
            })
        {
            return Err(SupervisorError::InvalidState);
        }
        Ok(())
    }
}

/// Whether a drain's error stops the supervisor, as an operation error always
/// has (#3143). A recovery waiting for the credential authority stops only its
/// name's drain until a later request retries it, and a retiring or stopping
/// supervisor is already ending.
fn fatal_drain_error(error: &SupervisorError) -> bool {
    !matches!(
        error,
        SupervisorError::CredentialAuthorityUnavailable
            | SupervisorError::Retiring
            | SupervisorError::Store(SupervisorStoreError::Stopping)
    )
}

/// Whether a create that commits its record selects itself (#2978). A
/// recovered create, with no admission here, always does, as before; one an
/// RPC here admitted does only if no select came since, so a `cw select`
/// during the create stands, even of the VM selected already.
fn create_selects_itself(selections_at_admission: Option<u64>, selections: u64) -> bool {
    selections_at_admission.is_none_or(|admitted| admitted == selections)
}

/// The environment name a lifecycle operation's payload names.
fn operation_name(operation: &OperationRecord) -> Option<&str> {
    operation
        .payload
        .get("name")
        .and_then(|value| value.as_str())
}

impl Supervisor {
    /// Runs one delete to its end. A delete that fails before its tree
    /// reaches trash keeps the environment and records why; later failures
    /// stop the worker, because only finishing the same delete is safe.
    async fn run_delete_operation(
        &self,
        name: &str,
        operation: &OperationRecord,
        recovering: bool,
    ) -> Result<(), SupervisorError> {
        let (operation, cleanup_pending) = match self.delete(name, operation).await {
            Ok(result) => result,
            Err(error) => {
                let error_code = if recovering {
                    "delete_interrupted"
                } else {
                    "delete_failed"
                };
                self.core()
                    .log_operation_failure(operation, name, &error, error_code);
                if self
                    .core()
                    .retain_failed_delete(operation, name, error_code)?
                {
                    return Ok(());
                }
                return Err(error);
            }
        };
        let result = serde_json::json!({
            "name": name,
            "removed": true,
            "cleanup_pending": cleanup_pending,
        });
        self.core().complete_operation(&operation, &result)?;
        if let Some(environment_id) = operation.environment_id {
            diagnostic_log::remove_log(
                &self.root,
                &diagnostic_log::runner_log_name(environment_id),
            );
            ssh::remove_host_key(&self.config.root, environment_id);
            // A deleted environment selects nothing, so its policy can go too.
            self.core()
                .network_policies
                .clear_environment(environment_id)
                .map_err(|error| SupervisorError::NetworkPolicyStore(error.to_string()))?;
        }
        Ok(())
    }
}

impl SupervisorCore {
    /// Environments that an earlier failed create left in `error` (never run:
    /// generation 0 and no active workspace generation) get the ordinary
    /// delete, which the startup worker then runs like any pending delete.
    fn begin_rollback_of_failed_creates(&mut self) -> Result<(), SupervisorError> {
        let stranded = self
            .state
            .environments
            .values()
            .filter(|environment| {
                environment.state == StoredEnvironmentState::Error
                    && environment.generation == 0
                    && environment.active_workspace_generation.is_none()
            })
            // Store validation at load already rejects invalid access
            // metadata; a cleanup scan never stops the supervisor starting.
            .filter_map(|environment| {
                let revoke_access = environment_uses_access_profile(environment).ok()?;
                Some((environment.name.clone(), environment.id, revoke_access))
            })
            .collect::<Vec<_>>();
        for (name, environment_id, revoke_access) in stranded {
            if self.store.has_pending_lifecycle_operation(environment_id)? {
                continue;
            }
            self.store.begin_operation(
                Uuid::new_v4(),
                Some(environment_id),
                OperationKind::Delete,
                &serde_json::json!({ "name": name, "revoke_access": revoke_access }),
            )?;
        }
        Ok(())
    }
}

impl Supervisor {
    /// A failed create leaves nothing behind (#2491). Once the environment
    /// is recorded, the create fails in the same transaction that begins the
    /// ordinary delete of that environment, which then runs at once. The
    /// create keeps its own error code; the delete records its own outcome,
    /// so a delete that cannot finish leaves a visible `error` environment
    /// and a failed delete, never a silent record or a false "removed".
    async fn roll_back_failed_create(
        &self,
        failed: &OperationRecord,
        name: &str,
        error_code: &str,
        recovering: bool,
    ) -> Result<(), SupervisorError> {
        let rollback = self
            .core()
            .fail_create_and_begin_rollback(failed, name, error_code)?;
        match rollback {
            Some(rollback) => self.run_delete_operation(name, &rollback, recovering).await,
            None => Ok(()),
        }
    }
}

impl SupervisorCore {
    /// Fails a create and, in the same transaction, begins the delete of the
    /// environment it recorded; `None` when it recorded nothing to remove.
    fn fail_create_and_begin_rollback(
        &mut self,
        failed: &OperationRecord,
        name: &str,
        error_code: &str,
    ) -> Result<Option<OperationRecord>, SupervisorError> {
        let current = self
            .store
            .operation_by_request(failed.request_id)?
            .ok_or(SupervisorError::InvalidState)?;
        let environment_id = current
            .environment_id
            .ok_or(SupervisorError::InvalidState)?;
        let Some(environment) = self
            .state
            .environments
            .get(name)
            .filter(|environment| environment.id == environment_id)
        else {
            // Nothing was recorded; there is nothing to remove.
            self.fail_operation(&current, error_code)?;
            return Ok(None);
        };
        let payload = serde_json::json!({
            "name": name,
            "revoke_access": environment_uses_access_profile(environment)?,
        });
        // Marked `error` as any failed create is, which is how the delete
        // recognizes a never-started environment and removes it without
        // booting a runner.
        let mut next_state = self.state.clone();
        next_state
            .environments
            .get_mut(name)
            .ok_or_else(|| SupervisorError::NotFound(name.to_owned()))?
            .state = StoredEnvironmentState::Error;
        let (_, rollback) = self.store.fail_operation_and_begin(
            &next_state,
            current.operation_id,
            current.checkpoint,
            error_code,
            Uuid::new_v4(),
            environment_id,
            OperationKind::Delete,
            &payload,
        )?;
        self.state = next_state;
        Ok(Some(rollback))
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

    /// Nothing is removed until the environment tree moves to trash. A delete
    /// that fails before then keeps the environment, marks it `error` and
    /// records why, so a retry starts over and later supervisors do not stop
    /// at replay. Returns false once the tree is in trash: only finishing the
    /// same delete is safe then.
    fn retain_failed_delete(
        &mut self,
        failed: &OperationRecord,
        name: &str,
        error_code: &str,
    ) -> Result<bool, SupervisorError> {
        let current = self
            .store
            .operation_by_request(failed.request_id)?
            .ok_or(SupervisorError::InvalidState)?;
        let environment_id = current
            .environment_id
            .ok_or(SupervisorError::InvalidState)?;
        let trashed = matches!(
            deletion_tree_location(
                &self.config.engine_root(),
                environment_id,
                current.operation_id
            ),
            Ok(DeletionTreeLocation::Trash(_))
        );
        if trashed
            || supervisor_effect(current.kind, current.checkpoint)?.is_none_or(|effect| {
                !matches!(
                    effect,
                    LifecycleEffect::PrepareDelete | LifecycleEffect::MoveToTrash
                )
            })
        {
            return Ok(false);
        }
        self.fail_operation_with_environment_error(&current, name, error_code)?;
        Ok(true)
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
}

impl Supervisor {
    async fn abort_replayed_workspace_transition(
        &self,
        replayed: &OperationRecord,
        name: &str,
        error_code: &str,
    ) -> Result<(), SupervisorError> {
        let current = self
            .core()
            .store
            .operation_by_request(replayed.request_id)?
            .ok_or(SupervisorError::InvalidState)?;
        self.abort_workspace_transition(&current, name, error_code)
            .await?;
        Ok(())
    }
}

impl SupervisorCore {
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

    /// The closed code a runner recorded for its failed start, while the
    /// environment still records that runner.
    fn recorded_runner_error_code(&self, name: &str) -> Option<&str> {
        self.state
            .environments
            .get(name)?
            .runner
            .as_ref()?
            .error_code
            .as_deref()
            .filter(|code| runner_event_error_code_valid(code))
    }

    /// Logs why a lifecycle operation failed, before its failure is
    /// journaled: the effect it was running and the closed cause. Never the
    /// error's text.
    fn log_operation_failure(
        &self,
        operation: &OperationRecord,
        name: &str,
        error: &SupervisorError,
        error_code: &str,
    ) {
        let Some(log) = self.log.as_ref() else {
            return;
        };
        let current = self
            .store
            .operation_by_request(operation.request_id)
            .ok()
            .flatten();
        let current = current.as_ref().unwrap_or(operation);
        let effect = supervisor_effect(current.kind, current.checkpoint)
            .ok()
            .flatten()
            .map_or("none", LifecycleEffect::name);
        let mut fields = vec![
            ("kind", LogField::Name(current.kind.as_str())),
            ("operation", LogField::Id(current.operation_id)),
            ("effect", LogField::Name(effect)),
            ("cause", LogField::Name(lifecycle_failure_cause(error))),
        ];
        if let Some(environment_id) = current.environment_id {
            fields.push(("environment", LogField::Id(environment_id)));
        }
        if let Some(code) = self.recorded_runner_error_code(name) {
            fields.push(("runner_error", LogField::Code(code)));
        }
        if let SupervisorError::UnsafeRuntimeArtifactStore { location } = error {
            fields.push(("location", LogField::Name(location)));
        }
        fields.push(("error_code", LogField::Code(error_code)));
        log.record("operation_failed", &fields);
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
        // A failed operation's record cannot say whether it changed the
        // environment's state, so the move into Error is recorded as a
        // reconcile carrying the operation's code, the record an environment
        // without a runner reports its error from (#2572).
        let generation = self.environment(name)?.generation;
        self.record_reconcile_observation(
            name,
            StoredEnvironmentState::Error,
            generation,
            false,
            Some(error_code),
        )?;
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
}

impl Supervisor {
    async fn reconcile(&self, name: &str) -> Result<(), SupervisorError> {
        self.reconcile_runner(name, false).await
    }

    async fn reconcile_runner(
        &self,
        name: &str,
        force_direct_share_quarantine: bool,
    ) -> Result<(), SupervisorError> {
        let environment_id = self.environment(name)?.id;
        self.core().incompatible_runners.remove(&environment_id);
        let environment = self.environment(name)?;
        let Some(mut record) = environment.runner.clone() else {
            if environment.state == StoredEnvironmentState::Running {
                self.core().mark_runner_dead(name)?;
            }
            return Ok(());
        };
        let environment_id = environment.id;
        let workspace_plan = environment.workspace_plan.clone();
        let direct_share_validation = if force_direct_share_quarantine {
            None
        } else {
            Some(
                self.revalidate_workspace_plan_for_boot(environment_id, &workspace_plan)
                    .await
                    .map(drop),
            )
        };
        let expected_socket = self.config.runner_socket(environment_id);
        let live = self.core().live_runners.get(&environment_id).cloned();
        let exited = if let Some(live) = live {
            if live.identity() != &record.process {
                self.core().mark_orphaned(name)?;
                return Ok(());
            }
            live.is_exited()?
        } else {
            let live = match LiveProcess::recover(&record.process) {
                Ok(live) => live,
                Err(RecoveryError::ReadProcess(error))
                    if error.kind() == io::ErrorKind::NotFound =>
                {
                    self.core().mark_runner_dead(name)?;
                    return Ok(());
                }
                Err(RecoveryError::ProcessExited) => {
                    self.core().mark_runner_dead(name)?;
                    return Ok(());
                }
                // A recorded process this supervisor cannot prove is its
                // runner is never adopted. Its environment alone is marked;
                // the supervisor serves the rest of the root (#3355).
                Err(RecoveryError::IdentityMismatch | RecoveryError::MalformedProcess) => {
                    self.core().mark_orphaned(name)?;
                    return Ok(());
                }
                // The recorded runner still runs from an executable file that
                // was since replaced, such as a cw rebuilt in place. That
                // exact birth is retired, never adopted: its identity can no
                // longer be admitted from its path (#3355).
                #[cfg(target_os = "linux")]
                Err(RecoveryError::ExecutableReplaced) => {
                    let live = LiveProcess::recover_replaced(&record.process)?;
                    self.core()
                        .live_runners
                        .insert(environment_id, Arc::new(live));
                    return self.retire_idle_runner(name, &record).await;
                }
                // A runner exits with its supervisor on Darwin. One still
                // alive belongs to the previous supervisor; wait for it to
                // finish exiting, and never adopt it.
                #[cfg(target_os = "macos")]
                Err(RecoveryError::Unowned) => {
                    if LiveProcess::wait_recorded_exit(
                        &record.process,
                        PREVIOUS_RUNNER_EXIT_TIMEOUT,
                    )
                    .await?
                    {
                        self.core().mark_runner_dead(name)?;
                    } else {
                        self.core().mark_orphaned(name)?;
                    }
                    return Ok(());
                }
                Err(error) => return Err(error.into()),
            };
            let exited = live.is_exited()?;
            if !exited {
                self.core()
                    .live_runners
                    .insert(environment_id, Arc::new(live));
            }
            exited
        };
        if exited {
            self.core().mark_runner_dead(name)?;
            return Ok(());
        }
        self.pin_recovered_runner_socket(name, &mut record);
        // A runner that exited while its socket was being pinned may have
        // freed that inode first: act on nothing pinned after its exit.
        let live = self.core().live_runners.get(&environment_id).cloned();
        if let Some(live) = live
            && live.is_exited()?
        {
            self.core().mark_runner_dead(name)?;
            return Ok(());
        }
        // A stopped environment's runner from another cw (an older supervisor
        // started it, and on Linux it outlives that supervisor) holds no VM:
        // end it and clear its record, so the next start runs this cw's
        // runner. It is never adopted.
        if self.environment(name)?.state == StoredEnvironmentState::Stopped
            && record.process.executable != self.config.executable
        {
            return self.retire_idle_runner(name, &record).await;
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
            Some(Err(error)) if !revalidation_requires_quarantine(&error) => {
                return Err(error);
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
            self.core().mark_orphaned(name)?;
            return Ok(());
        }
        let mut client = match RunnerClient::connect(&expected_socket).await {
            Ok(client) => client,
            Err(error) if error.incompatible_protocol() => {
                // Metadata inspection must not stop an existing VM before a
                // replacement has been admitted. Keep its exact custody;
                // every useful RPC still requires current protocol admission.
                self.core().incompatible_runners.insert(environment_id);
                return Ok(());
            }
            Err(error) => return Err(error.into()),
        };
        let info = client
            .info()
            .await
            .map_err(|_| SupervisorError::RunnerUnavailable)?;
        if info.environment_id != environment_id.to_string() {
            self.core().mark_orphaned(name)?;
            return Ok(());
        }
        if !runner_artifact_identity_matches(&record.artifact_generation, &info.artifact_generation)
        {
            self.core().mark_orphaned(name)?;
            return Ok(());
        }
        let state = match StoredEnvironmentState::from_proto(info.state) {
            Ok(state) => state,
            Err(_) => {
                self.core().mark_orphaned(name)?;
                return Ok(());
            }
        };
        let attached_runtime = (!info.cw_runtime_catalog_generation.is_empty())
            .then_some(info.cw_runtime_catalog_generation.as_str());
        if !runner_cw_runtime_identity_matches(&self.environment(name)?, &record, &info, state) {
            self.core().mark_orphaned(name)?;
            return Ok(());
        }
        let runner_error_code = (!info.error_code.is_empty()).then_some(info.error_code.as_str());
        let runner_error_valid = runner_error_code.is_some_and(runner_event_error_code_valid);
        if (state == StoredEnvironmentState::Error) != runner_error_valid
            || (runner_error_code.is_some() && !runner_error_valid)
        {
            self.core().mark_orphaned(name)?;
            return Ok(());
        }
        let generation = self.environment(name)?.generation.max(info.generation);
        self.core().record_reconcile_observation(
            name,
            state,
            generation,
            false,
            runner_error_code,
        )?;
        let attached_runtime = attached_runtime.map(str::to_owned);
        if self
            .environment(name)?
            .runner
            .as_ref()
            .is_some_and(|runner| runner.cw_runtime_catalog_generation != attached_runtime)
        {
            self.update_environment(name, |environment| {
                environment
                    .runner
                    .as_mut()
                    .ok_or(SupervisorError::InvalidState)?
                    .cw_runtime_catalog_generation = attached_runtime;
                Ok(())
            })?;
        }
        Ok(())
    }
}

impl SupervisorCore {
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
        // An operation of its own that boots the environment owns its state
        // until it ends: the runner it has just started reports `stopped`
        // until the VM boots, which must not read as stopped meanwhile
        // (#3143). The operation's end, or its failure, records the outcome.
        let state = if environment.state == StoredEnvironmentState::Starting
            && state == StoredEnvironmentState::Stopped
            && self.store.has_pending_lifecycle_operation(environment.id)?
        {
            StoredEnvironmentState::Starting
        } else {
            state
        };
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
        self.incompatible_runners.remove(&environment_id);
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
        // The runner record that carries error codes is cleared here, so the
        // reconcile itself records why the environment failed (#2568).
        let error_code = (state == StoredEnvironmentState::Error
            && environment.state != StoredEnvironmentState::Error)
            .then_some(RUNNER_EXIT_ERROR_CODE);
        self.record_reconcile_observation(name, state, generation, true, error_code)
    }
}

impl Supervisor {
    async fn runner_client_for_artifact(
        &self,
        name: &str,
        artifact_generation: &str,
    ) -> Result<RunnerClient, SupervisorError> {
        if !valid_sha256(artifact_generation) {
            return Err(SupervisorError::InvalidState);
        }
        self.reconcile(name).await?;
        let environment = self.environment(name)?;
        if self.core().incompatible_runners.contains(&environment.id) {
            return Err(SupervisorError::RunnerProtocolUnsupported);
        }
        if environment.state == StoredEnvironmentState::Orphaned {
            return Err(SupervisorError::Orphaned);
        }
        if environment.runner.is_none() {
            self.admit_cached_artifact_generation(artifact_generation)
                .await?;
            return self.spawn_runner(name, artifact_generation).await;
        }
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
        &self,
        name: &str,
        artifact_generation: &str,
    ) -> Result<RunnerClient, SupervisorError> {
        let environment_id = self.environment(name)?.id;
        let socket = self.config.runner_socket(environment_id);
        // tmpfiles may have removed the socket directory since startup.
        let runners = PrivateRoot::open(&prepare_runner_socket_dir(self.root.path())?)?;
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
        // The runner's own bounded owner-only log, not /dev/null (#2595). Its
        // isolated children keep their null stdio.
        let (stdout, stderr) = diagnostic_log::child_stdio(
            &self.root,
            &diagnostic_log::runner_log_name(environment_id),
        );
        command
            .current_dir(&self.config.root)
            .stdin(Stdio::null())
            .stdout(stdout)
            .stderr(stderr);
        // SAFETY: these libc calls use only scalar arguments between fork and
        // exec. PDEATHSIG closes the spawn-to-manifest orphan window; the
        // runner clears it only after its exact identity is durable.
        #[cfg(target_os = "linux")]
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
        // SAFETY: as above. Darwin has no parent-death signal: the runner
        // watches this process and exits with it.
        #[cfg(target_os = "macos")]
        unsafe {
            command.pre_exec(move || {
                if libc::getppid() != expected_parent || libc::setsid() < 0 {
                    return Err(io::Error::last_os_error());
                }
                crate::darwin::process::mark_inherited_descriptors_close_on_exec();
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
            cw_runtime_catalog_generation: None,
            process: live.identity().clone(),
            socket: socket_identity.clone(),
            artifact_generation: artifact_generation.to_owned(),
            error_code: None,
        };
        let recorded = self.update_environment(name, |environment| {
            environment.runner = Some(runner_record);
            Ok(())
        });
        if let Err(error) = recorded {
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
                self.update_environment(name, |environment| {
                    environment.runner = None;
                    Ok(())
                })?;
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
            self.update_environment(name, |environment| {
                environment.runner = None;
                Ok(())
            })?;
            let _ = remove_bound_socket(&socket, &socket_identity);
            return Err(SupervisorError::RunnerAdoption);
        }
        let mut core = self.core();
        core.live_runners.insert(environment_id, Arc::new(live));
        core.children.insert(environment_id, child);
        Ok(client)
    }

    async fn require_environment_guest_seed_abi(
        &self,
        name: &str,
        staging: bool,
    ) -> Result<(), SupervisorError> {
        let generation =
            artifact_generation_for_boot(&self.environment(name)?, staging)?.to_owned();
        self.require_guest_seed_abi_for_generation(&generation)
            .await
    }

    /// A plan that keeps paths on the VM's disk boots only a guest that binds
    /// them; checked before a create or start rather than failing at boot.
    async fn require_vm_only_guest_for_plan(
        &self,
        generation: &str,
        workspace_plan: &WorkspacePlan,
    ) -> Result<(), SupervisorError> {
        let keeps_paths = workspace_plan.inputs.iter().any(
            |input| matches!(input, WorkspaceInput::Direct { vm_only, .. } if !vm_only.is_empty()),
        );
        let root_share = workspace_plan.inputs.iter().any(|input| {
            matches!(input, WorkspaceInput::Direct { destination, .. }
                if destination == codewire_vmm_guest_probe::WORKSPACE_ROOT)
        });
        if !keeps_paths && !root_share {
            return Ok(());
        }
        let engine = PrivateRoot::open(&self.config.engine_root())?;
        let artifacts = RuntimeArtifactStore::create(&engine)
            .map_err(artifact_store_error)?
            .open_generation(generation)
            .await
            .map_err(artifact_store_error)?;
        if keeps_paths {
            artifacts.require_vm_only_guest()?;
        }
        if root_share {
            artifacts.require_workspace_root_share_guest()?;
        }
        Ok(())
    }

    async fn require_guest_seed_abi_for_generation(
        &self,
        generation: &str,
    ) -> Result<(), SupervisorError> {
        let engine = PrivateRoot::open(&self.config.engine_root())?;
        RuntimeArtifactStore::create(&engine)
            .map_err(artifact_store_error)?
            .open_generation(generation)
            .await
            .map_err(artifact_store_error)?
            .require_current_guest_seed_abi()?;
        Ok(())
    }

    async fn admit_start_boot_inputs(&self, name: &str) -> Result<(), SupervisorError> {
        let environment = self.environment(name)?;
        let staging = environment.staging_workspace_generation.is_some();
        let generation = if !staging
            && environment.active_workspace_generation.is_none()
            && environment.staging_workspace_generation.is_none()
            && environment.staging_artifact_generation.is_none()
        {
            // A first Start has retained boot assets before its workspace is
            // staged. Admit those exact assets, never a new installed default.
            environment
                .active_artifact_generation
                .as_deref()
                .filter(|generation| valid_sha256(generation))
                .ok_or(SupervisorError::InvalidState)?
        } else {
            artifact_generation_for_boot(&environment, staging)?
        }
        .to_owned();
        self.require_guest_seed_abi_for_generation(&generation)
            .await?;
        let workspace_plan = self.environment(name)?.workspace_plan.clone();
        self.require_vm_only_guest_for_plan(&generation, &workspace_plan)
            .await?;
        if self.environment(name)?.cw_runtime.is_some() {
            let engine = PrivateRoot::open(&self.config.engine_root())?;
            RuntimeArtifactStore::create(&engine)
                .map_err(artifact_store_error)?
                .open_generation(&generation)
                .await
                .map_err(artifact_store_error)?
                .require_live_cw_runtime_publisher()?;
        }
        self.admit_environment_cw_runtime(name).await?;
        Ok(())
    }

    /// Admit the installed cw runtime source and return its catalog generation.
    async fn admit_installed_cw_runtime(&self) -> Result<Option<String>, SupervisorError> {
        let engine_root = self.config.engine_root();
        let source = self.config.cw_runtime_lock();
        tokio::task::spawn_blocking(move || {
            match fs::symlink_metadata(&source) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
                Err(error) => return Err(CwRuntimeError::Io(error)),
                Ok(_) => {}
            }
            let engine = PrivateRoot::open(&engine_root)?;
            let store = CwRuntimeStore::create(&engine)?;
            let asset = store.admit_source(&source)?;
            store
                .prepare_catalog(&asset.provenance, &BTreeMap::new())
                .map(|disk| Some(disk.generation))
        })
        .await
        .map_err(|_| SupervisorError::CwRuntimeProvisionTask)?
        .map_err(Into::into)
    }

    /// Revalidate an environment's bound cw runtime catalog and return its
    /// generation.
    async fn admit_environment_cw_runtime(
        &self,
        name: &str,
    ) -> Result<Option<String>, SupervisorError> {
        // Unbound legacy/raw environments remain unbound across an ordinary
        // start or restart. Only creation or explicit update selects a source.
        let Some(binding) = self.environment(name)?.cw_runtime.clone() else {
            return Ok(None);
        };
        binding.validate()?;
        let engine_root = self.config.engine_root();
        tokio::task::spawn_blocking(move || {
            let engine = PrivateRoot::open(&engine_root)?;
            let selected = binding
                .staging_catalog_generation
                .as_deref()
                .unwrap_or(&binding.active_catalog_generation);
            CwRuntimeStore::create(&engine)?
                .open_catalog(selected)
                .map(|disk| Some(disk.generation))
        })
        .await
        .map_err(|_| SupervisorError::CwRuntimeProvisionTask)?
        .map_err(Into::into)
    }

    async fn ensure_vm_started(
        &self,
        name: &str,
        generation: u64,
        operation_id: Uuid,
    ) -> Result<(), SupervisorError> {
        // Every checked share stays open until the runner's StartVm returns
        // (`while_holding_direct_shares`): the runner reopens each by path
        // and compares (device, inode), which is exact only while the
        // admitted inode cannot be freed (#3209).
        let checked_direct_shares = self
            .revalidate_environment_workspace_plan_for_boot(name)
            .await?;
        let environment = self.environment(name)?;
        let staging = environment.staging_workspace_generation.is_some();
        let expected_artifact_generation =
            artifact_generation_for_boot(&environment, staging)?.to_owned();
        self.require_environment_guest_seed_abi(name, staging)
            .await?;
        let cw_runtime = self.admit_environment_cw_runtime(name).await?;
        let expected_cw_runtime_generation = cw_runtime.clone().unwrap_or_default();
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
            if current.generation != generation
                || current.cw_runtime_catalog_generation != expected_cw_runtime_generation
            {
                return Err(SupervisorError::InvalidRunnerResponse);
            }
            if cw_runtime.is_some() {
                let access = client
                    .daemon_access()
                    .await
                    .map_err(|_| SupervisorError::RunnerUnavailable)?;
                runtime::confirm_boot(self, name, generation, access)
                    .await
                    .map_err(|status| SupervisorError::VmStart(status.message().to_owned()))?;
            }
            return Ok(());
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
            .managed_credential_clients_for_boot(&projection_environment, generation)
            .await?;
        let broker_request = self
            .core()
            .credential_broker_request_for_environment(&projection_environment, generation)?;
        let environment_projection_sha256 =
            if broker_request.projection.is_some() || broker_request.platform.is_some() {
                projection_environment
                    .project_spec_sha256
                    .clone()
                    .ok_or(SupervisorError::InvalidState)?
            } else {
                String::new()
            };
        // The selected network policy at its current revision (#2537): the
        // egress broker of this boot enforces exactly this document.
        let network_policy = self
            .core()
            .network_policies
            .environment_policy(environment.id)
            .map_err(|error| SupervisorError::NetworkPolicyStore(error.to_string()))?
            .selected;
        let network_policy_document = match &network_policy {
            crate::network_policy_store::SelectedPolicy::Open => Vec::new(),
            selected => selected
                .compile()
                .canonical_json()
                .map_err(|error| SupervisorError::NetworkPolicyStore(error.to_string()))?,
        };
        let start_request = v1::StartVmRequest {
            network_policy_document,
            cw_runtime_catalog_generation: expected_cw_runtime_generation.clone(),
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
            checkpoint: None,
        };
        let start_request = checkpoints::attach_boot(self, operation_id, start_request)?;
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
        let (start, broker) = while_holding_direct_shares(checked_direct_shares, async {
            tokio::join!(client.start(start_request), async {
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
            },)
        })
        .await;
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
                self.core().record_runner_start_failure(name, &error_code)?;
                if error_code == crate::runner_service::GUEST_DOCKER_TOOLING_MISSING {
                    return Err(SupervisorError::GuestDockerToolingMissing);
                }
                if error_code == crate::runner_service::GUEST_SETUP_FAILED {
                    return Err(SupervisorError::GuestSetupFailed);
                }
                if error_code == crate::runner_service::GUEST_WORKSPACE_FAILED {
                    return Err(SupervisorError::GuestWorkspaceFailed);
                }
                if error_code == crate::runner_service::HOST_PORT_UNAVAILABLE {
                    return Err(SupervisorError::HostPortUnavailable);
                }
                #[cfg(target_os = "macos")]
                if error_code == crate::runner_service::VM_START_REFUSED {
                    return Err(SupervisorError::VmStartRefused);
                }
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
            || info.cw_runtime_catalog_generation != expected_cw_runtime_generation
            || !info.error_code.is_empty()
        {
            let _ = client.stop().await;
            return Err(SupervisorError::InvalidRunnerResponse);
        }
        self.core()
            .network_policies
            .record_enforced(environment.id, &network_policy)
            .map_err(|error| SupervisorError::NetworkPolicyStore(error.to_string()))?;
        if cw_runtime.is_some() {
            let confirmation = match client.daemon_access().await {
                Ok(access) => runtime::confirm_boot(self, name, generation, access).await,
                Err(_) => Err(Status::unavailable("runtime startup endpoint unavailable")),
            };
            if let Err(status) = confirmation {
                let _ = client.stop().await;
                let mut failed_generation = environment.clone();
                failed_generation.generation = generation;
                self.stop_environment_broker_if_present(&failed_generation)
                    .await?;
                return Err(SupervisorError::VmStart(status.message().to_owned()));
            }
        }
        self.update_environment(name, |environment| {
            environment
                .runner
                .as_mut()
                .ok_or(SupervisorError::InvalidState)?
                .cw_runtime_catalog_generation = cw_runtime;
            Ok(())
        })
    }
}

impl SupervisorCore {
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
}

impl Supervisor {
    async fn ensure_vm_stopped(&self, name: &str) -> Result<(), SupervisorError> {
        self.ensure_vm_stopped_with(name, false).await
    }

    /// `discard_guest_state` skips the guest's graceful poweroff; only a Stop
    /// admitted for a VM checkpoint restore sets it (#3046).
    async fn ensure_vm_stopped_with(
        &self,
        name: &str,
        discard_guest_state: bool,
    ) -> Result<(), SupervisorError> {
        self.reconcile(name).await?;
        if self.environment(name)?.state == StoredEnvironmentState::Orphaned {
            return Err(SupervisorError::Orphaned);
        }
        let environment = self.environment(name)?;
        self.stop_environment_broker_if_present(&environment)
            .await?;
        if self.core().incompatible_runners.contains(&environment.id) {
            self.terminate_recorded_runner(name).await?;
            self.core().mark_runner_dead(name)?;
            return Ok(());
        }
        if environment.runner.is_none() {
            return Ok(());
        }
        let socket = self.config.runner_socket(environment.id);
        let mut client = RunnerClient::connect(&socket).await?;
        let info = if discard_guest_state {
            client.stop_discarding_guest_state().await
        } else {
            client.stop().await
        }
        .map_err(|_| SupervisorError::VmStop)?;
        if info.environment_id != environment.id.to_string()
            || info.state != v1::EnvironmentState::Stopped as i32
        {
            return Err(SupervisorError::InvalidRunnerResponse);
        }
        Ok(())
    }

    async fn start(
        &self,
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
        if operation.checkpoint > 0 {
            // Recovery past authority admission must still validate retained
            // assets before recording state or touching an existing runner.
            self.admit_start_boot_inputs(name).await?;
        }
        let mut operation = operation.clone();
        while let Some(effect) = supervisor_effect(operation.kind, operation.checkpoint)? {
            let effect_name = effect.name();
            let effect_started = std::time::Instant::now();
            match effect {
                LifecycleEffect::RequireEnvironmentAccess => {
                    self.require_environment_access(name).await?;
                    self.admit_start_boot_inputs(name).await?;
                    operation = self.core().checkpoint_operation(&operation)?;
                }
                LifecycleEffect::RecordStarting => {
                    operation = self.commit_operation(&operation, |next_state| {
                        let environment = next_state
                            .environments
                            .get_mut(name)
                            .ok_or_else(|| SupervisorError::NotFound(name.to_owned()))?;
                        reserve_boot_generation(environment, target_generation)?;
                        Ok(())
                    })?;
                }
                LifecycleEffect::StageWorkspaceGeneration => {
                    let _writer = self.begin_staging(name).await?;
                    let restore = operation
                        .payload
                        .as_object()
                        .map(checkpoints::start_payload_checkpoint)
                        .transpose()?
                        .flatten();
                    let generation = match restore {
                        Some(checkpoint) => {
                            checkpoints::place_in_place(
                                self,
                                name,
                                checkpoint,
                                operation.operation_id,
                            )
                            .await?
                        }
                        None => self.stage_workspace_generation(name).await?,
                    };
                    operation = self.commit_operation(&operation, |next_state| {
                        record_staged_workspace_generation(next_state, name, generation)
                    })?;
                }
                LifecycleEffect::EnsureRunner => {
                    let staging = self
                        .environment(name)?
                        .staging_workspace_generation
                        .is_some();
                    validate_environment_workload_secret_delivery(
                        &self.environment(name)?,
                        staging,
                    )?;
                    let artifact_generation =
                        artifact_generation_for_boot(&self.environment(name)?, staging)?.to_owned();
                    let _ = self
                        .runner_client_for_artifact(name, &artifact_generation)
                        .await?;
                    operation = self.core().checkpoint_operation(&operation)?;
                }
                LifecycleEffect::StartVm => {
                    self.ensure_vm_started(name, target_generation, operation.operation_id)
                        .await?;
                    operation = self.core().checkpoint_operation(&operation)?;
                }
                LifecycleEffect::RecordRunning => {
                    operation = self.commit_operation(&operation, |next_state| {
                        let environment = next_state
                            .environments
                            .get_mut(name)
                            .ok_or_else(|| SupervisorError::NotFound(name.to_owned()))?;
                        let _displaced = environment.promote_staging_workspace_generation()?;
                        environment.generation = target_generation;
                        environment.state = StoredEnvironmentState::Running;
                        Ok(())
                    })?;
                }
                _ => return Err(SupervisorError::InvalidState),
            }
            log_effect_timing(self.log.as_deref(), &operation, effect_name, effect_started);
        }
        Ok((
            self.environment(name)?.proto(self.core().selected(name)),
            operation,
        ))
    }

    async fn stop(
        &self,
        name: &str,
        operation: &OperationRecord,
    ) -> Result<(v1::Environment, OperationRecord), SupervisorError> {
        let environment_id = operation
            .environment_id
            .ok_or(SupervisorError::InvalidState)?;
        // A Stop for a VM checkpoint restore records the checkpoint it was
        // admitted for, so a replay stops the same way (#3046).
        let discard_guest_state = match stop_payload_checkpoint(&operation.payload, name) {
            Some(discard) => discard,
            None => return Err(SupervisorError::InvalidState),
        };
        if operation.kind != OperationKind::Stop || self.environment(name)?.id != environment_id {
            return Err(SupervisorError::InvalidState);
        }
        let mut operation = operation.clone();
        while let Some(effect) = supervisor_effect(operation.kind, operation.checkpoint)? {
            let effect_name = effect.name();
            let effect_started = std::time::Instant::now();
            match effect {
                LifecycleEffect::StopVm => {
                    self.ensure_vm_stopped_with(name, discard_guest_state)
                        .await?;
                    operation = self.core().checkpoint_operation(&operation)?;
                }
                LifecycleEffect::RecordStopped => {
                    operation = self.commit_operation(&operation, |next_state| {
                        next_state
                            .environments
                            .get_mut(name)
                            .ok_or_else(|| SupervisorError::NotFound(name.to_owned()))?
                            .state = StoredEnvironmentState::Stopped;
                        Ok(())
                    })?;
                }
                _ => return Err(SupervisorError::InvalidState),
            }
            log_effect_timing(self.log.as_deref(), &operation, effect_name, effect_started);
        }
        Ok((
            self.environment(name)?.proto(self.core().selected(name)),
            operation,
        ))
    }

    async fn retire_existing_runner(&self, name: &str) -> Result<(), SupervisorError> {
        self.reconcile(name).await?;
        if self.environment(name)?.state == StoredEnvironmentState::Orphaned {
            return Err(SupervisorError::Orphaned);
        }
        let environment = self.environment(name)?;
        let environment_id = environment.id;
        if environment.runner.is_none() {
            return Ok(());
        }
        if self.core().incompatible_runners.contains(&environment_id) {
            self.terminate_recorded_runner(name).await?;
            self.core().mark_runner_dead(name)?;
            return self.update_environment(name, |environment| {
                environment.state = StoredEnvironmentState::Stopped;
                Ok(())
            });
        }
        let socket = self.config.runner_socket(environment_id);
        let mut client = RunnerClient::connect(&socket).await?;
        client
            .prepare_retire()
            .await
            .map_err(|_| SupervisorError::RunnerRetirement)?;
        let generation = self.environment(name)?.generation;
        let live = self
            .core()
            .live_runners
            .get(&environment_id)
            .cloned()
            .ok_or(SupervisorError::InvalidState)?;
        let _ = request_runner_shutdown_and_observe(&mut client, environment_id, generation, &live)
            .await?;
        drop(client);
        self.terminate_recorded_runner(name).await?;
        self.update_environment(name, |environment| {
            environment.runner = None;
            environment.state = StoredEnvironmentState::Stopped;
            Ok(())
        })
    }

    /// Pin the socket of a runner record read back from the store, which
    /// holds no pin, while its runner is verified alive and so still holds
    /// the socket (#3209). Only the socket the record names is pinned, at
    /// this root's runner path or the pre-#2735 one. Every later removal
    /// after a kill (`terminate_recorded_runner`, `quarantine_recorded_runner`,
    /// `retire_idle_runner`) compares with the record, and against a pinned
    /// one that is exact even where inode numbers are reused. A runner this
    /// supervisor started was pinned when its socket was captured. Darwin
    /// never adopts a runner that outlived its supervisor, and pins nothing.
    fn pin_recovered_runner_socket(&self, name: &str, record: &mut RunnerRecord) {
        if !cfg!(target_os = "linux") || record.socket.pin.is_pinned() {
            return;
        }
        let Ok(environment_id) = self.environment(name).map(|environment| environment.id) else {
            return;
        };
        let pinned = [
            self.config.runner_socket(environment_id),
            self.config.legacy_runner_socket(environment_id),
        ]
        .iter()
        .find_map(|socket| {
            SocketIdentity::capture(socket)
                .ok()
                .filter(|captured| captured == &record.socket)
        });
        let Some(pinned) = pinned else {
            return;
        };
        if let Ok(environment) = self.core().environment_mut(name)
            && let Some(runner) = environment.runner.as_mut()
            && runner.process == record.process
            && runner.socket == pinned
        {
            runner.socket = pinned.clone();
        }
        record.socket = pinned;
    }

    /// Terminate the exact process and remove the exact socket recorded for a
    /// runner without trusting the runner protocol. Every caller must first
    /// reconcile process and socket identity; identity mismatches remain
    /// orphaned and never reach this helper. Runner-owned VMM and auxiliary
    /// processes carry a parent-death signal, so killing this exact runner
    /// also closes its pre-upgrade guest boundary; a replacement runner still
    /// performs tracked-process cleanup before accepting lifecycle work.
    async fn terminate_recorded_runner(&self, name: &str) -> Result<(), SupervisorError> {
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
        &self,
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
        self.core().mark_runner_dead(name)?;
        socket_cleanup
    }

    /// End a stopped environment's idle runner, which holds no VM: one from
    /// another cw (see `reconcile_runner`), this cw's own before it hands the
    /// root over (`retire_supervisor`), or one idle past its window (#3270). Its exact recorded process, then
    /// its socket, at this root's runner path or the pre-#2735 one, removed
    /// only while it is still the recorded socket; the record is cleared, so
    /// the next start runs the runner of whichever cw starts it.
    async fn retire_idle_runner(
        &self,
        name: &str,
        record: &RunnerRecord,
    ) -> Result<(), SupervisorError> {
        let environment_id = self.environment(name)?.id;
        self.terminate_recorded_runner_process(name).await?;
        let socket = [
            self.config.runner_socket(environment_id),
            self.config.legacy_runner_socket(environment_id),
        ]
        .into_iter()
        .find(|socket| record.socket.revalidate(socket).is_ok());
        let socket_cleanup = match socket {
            Some(socket) => remove_bound_socket(&socket, &record.socket).map_err(Into::into),
            None => Ok(()),
        };
        self.core().mark_runner_dead(name)?;
        socket_cleanup
    }

    async fn terminate_recorded_runner_process(&self, name: &str) -> Result<(), SupervisorError> {
        let environment = self.environment(name)?;
        let environment_id = environment.id;
        let runner = environment
            .runner
            .clone()
            .ok_or(SupervisorError::InvalidState)?;
        let live = self
            .core()
            .live_runners
            .get(&environment_id)
            .cloned()
            .ok_or(SupervisorError::InvalidState)?;
        if live.identity() != &runner.process {
            return Err(SupervisorError::InvalidState);
        }
        if !live.is_exited()? {
            live.signal(Signal::KILL)?;
        }
        let mut child = self.core().children.remove(&environment_id);
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
        self.core().live_runners.remove(&environment_id);
        Ok(())
    }

    /// Apply `name`'s selected network policy to its running VM's egress
    /// broker unless the broker already enforces it, and record what the
    /// broker acknowledged (#2537). The caller holds `name`'s lease. It is
    /// `false` when the environment is not running: it takes its selection
    /// at its next start. A broker that cannot take it fails closed, and the
    /// environment reports the earlier revision until it restarts.
    async fn apply_network_policy(&self, name: &str) -> Result<bool, SupervisorError> {
        let environment = self.environment(name)?;
        if environment.state != StoredEnvironmentState::Running {
            return Ok(false);
        }
        let store = Arc::clone(&self.core().network_policies);
        let store_error = |error: crate::network_policy_store::NetworkPolicyStoreError| {
            SupervisorError::NetworkPolicyStore(error.to_string())
        };
        let current = store
            .environment_policy(environment.id)
            .map_err(store_error)?;
        if !current.enforcement_is_stale() {
            return Ok(true);
        }
        let policy = current.selected.compile();
        let artifact_generation = artifact_generation_for_boot(&environment, false)?.to_owned();
        let mut runner = self
            .runner_client_for_artifact(name, &artifact_generation)
            .await?;
        let enforced = runner
            .replace_network_policy(environment.id, environment.generation, &policy)
            .await
            .map_err(|_| SupervisorError::InvalidRunnerResponse)?;
        if enforced != policy.digest() {
            return Err(SupervisorError::InvalidRunnerResponse);
        }
        store
            .record_enforced(environment.id, &current.selected)
            .map_err(store_error)?;
        Ok(true)
    }

    /// Apply every running selection of `policy` (#2537): the names that now
    /// enforce its current revision, and those that take it at their next
    /// start.
    pub(crate) async fn apply_network_policy_everywhere(
        &self,
        policy: &codewire_egress_policy::reference::PolicyId,
    ) -> Result<(Vec<String>, Vec<String>), SupervisorError> {
        let store = Arc::clone(&self.core().network_policies);
        let selecting = store
            .environments_selecting(policy)
            .map_err(|error| SupervisorError::NetworkPolicyStore(error.to_string()))?;
        let names: Vec<String> = {
            let core = self.core();
            core.state
                .environments
                .iter()
                .filter(|(_, environment)| selecting.contains(&environment.id))
                .map(|(name, _)| name.clone())
                .collect()
        };
        let (mut enforced, mut restart_required) = (Vec::new(), Vec::new());
        for name in names {
            let lease = self.quiet_lease(&name).await?;
            match self.apply_network_policy(&name).await {
                Ok(true) => enforced.push(name),
                Ok(false) => {}
                Err(SupervisorError::NotFound(_)) => {}
                Err(_) => restart_required.push(name),
            }
            drop(lease);
        }
        Ok((enforced, restart_required))
    }

    async fn update_host_ports(
        &self,
        name: &str,
        operation: &OperationRecord,
    ) -> Result<OperationRecord, SupervisorError> {
        let target = operation
            .payload
            .get("target")
            .cloned()
            .and_then(|target| serde_json::from_value::<Vec<HostPortBinding>>(target).ok())
            .ok_or(SupervisorError::InvalidState)?;
        validate_canonical_host_port_bindings(&target)
            .map_err(|_| SupervisorError::InvalidState)?;
        let environment_id = operation
            .environment_id
            .ok_or(SupervisorError::InvalidState)?;
        let mut operation = operation.clone();
        loop {
            let Some(effect) = supervisor_effect(operation.kind, operation.checkpoint)? else {
                return Ok(operation);
            };
            match effect {
                LifecycleEffect::ApplyHostPorts => {
                    let environment = self.environment(name)?;
                    if environment.id != environment_id {
                        return Err(SupervisorError::InvalidState);
                    }
                    if environment.state == StoredEnvironmentState::Running {
                        let generation = environment.generation;
                        let artifact_generation =
                            artifact_generation_for_boot(&environment, false)?.to_owned();
                        let mut runner = self
                            .runner_client_for_artifact(name, &artifact_generation)
                            .await?;
                        runner
                            .set_host_ports(environment_id, generation, &target)
                            .await
                            .map_err(|status| {
                                if status
                                    .message()
                                    .starts_with(crate::runner_service::HOST_PORT_UNAVAILABLE)
                                {
                                    SupervisorError::HostPortUnavailable
                                } else {
                                    SupervisorError::InvalidRunnerResponse
                                }
                            })?;
                    }
                    operation = self.core().checkpoint_operation(&operation)?;
                }
                LifecycleEffect::RecordHostPorts => {
                    operation = self.commit_operation(&operation, |next_state| {
                        next_state
                            .environments
                            .get_mut(name)
                            .ok_or_else(|| SupervisorError::NotFound(name.to_owned()))?
                            .host_ports = target.clone();
                        Ok(())
                    })?;
                }
                _ => return Err(SupervisorError::InvalidState),
            }
        }
    }

    async fn prepare_environment_for_delete(&self, name: &str) -> Result<(), SupervisorError> {
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
        // Removal ends the broker's supervision, as a stop does: the authority
        // drains the exact generation before its runner goes. Access
        // revocation cannot do it for a platform profile or a projection,
        // which hold no local binding, and the authority would otherwise keep
        // restarting a broker whose runner is gone (#2924).
        let environment = self.environment(name)?;
        self.stop_environment_broker_if_present(&environment)
            .await?;
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
                delete_cleanup_artifact_generation(&self.environment(name)?)?.to_owned();
            let _ = self
                .runner_client_for_artifact(name, &artifact_generation)
                .await?;
        }
        self.retire_existing_runner(name).await
    }

    async fn resize(
        &self,
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
                    operation = self.core().checkpoint_operation(&operation)?;
                }
                LifecycleEffect::StopVm => {
                    if was_running {
                        self.require_environment_guest_seed_abi(name, false)
                            .await
                            .map_err(|error| {
                                SupervisorError::ReplacementPreflight(Box::new(error))
                            })?;
                        self.admit_environment_cw_runtime(name)
                            .await
                            .map_err(|error| {
                                SupervisorError::ReplacementPreflight(Box::new(error))
                            })?;
                    }
                    self.ensure_vm_stopped(name).await?;
                    operation = self.core().checkpoint_operation(&operation)?;
                }
                LifecycleEffect::RecordStopped => {
                    operation = self.commit_operation(&operation, |next_state| {
                        next_state
                            .environments
                            .get_mut(name)
                            .ok_or_else(|| SupervisorError::NotFound(name.to_owned()))?
                            .state = StoredEnvironmentState::Stopped;
                        Ok(())
                    })?;
                }
                LifecycleEffect::GrowDisk => {
                    let current_disk_bytes = self.environment(name)?.disk_bytes;
                    if disk_bytes < current_disk_bytes {
                        return Err(SupervisorError::InvalidRequest);
                    }
                    if disk_bytes > current_disk_bytes {
                        validate_environment_workload_secret_delivery(
                            &self.environment(name)?,
                            false,
                        )?;
                        let artifact_generation =
                            artifact_generation_for_boot(&self.environment(name)?, false)?
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
                    operation = self.core().checkpoint_operation(&operation)?;
                }
                LifecycleEffect::RecordResources => {
                    operation = self.commit_operation(&operation, |next_state| {
                        let environment = next_state
                            .environments
                            .get_mut(name)
                            .ok_or_else(|| SupervisorError::NotFound(name.to_owned()))?;
                        environment.vcpus = vcpus;
                        environment.memory_mib = memory_mib;
                        environment.disk_bytes = disk_bytes;
                        Ok(())
                    })?;
                }
                LifecycleEffect::RecordStarting => {
                    operation = self.commit_operation(&operation, |next_state| {
                        let environment = next_state
                            .environments
                            .get_mut(name)
                            .ok_or_else(|| SupervisorError::NotFound(name.to_owned()))?;
                        if was_running {
                            reserve_boot_generation(environment, target_generation)?;
                        } else if environment.generation != target_generation {
                            return Err(SupervisorError::InvalidState);
                        }
                        Ok(())
                    })?;
                }
                LifecycleEffect::RestartVm => {
                    if was_running {
                        self.ensure_vm_started(name, target_generation, operation.operation_id)
                            .await?;
                    }
                    operation = self.core().checkpoint_operation(&operation)?;
                }
                LifecycleEffect::RecordResizeOutcome => {
                    operation = self.commit_operation(&operation, |next_state| {
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
                        Ok(())
                    })?;
                }
                _ => return Err(SupervisorError::InvalidState),
            }
        }
        Ok(operation)
    }

    async fn workspace_transition(
        &self,
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
        let parameters = workspace_transition_parameters(operation, &self.environment(name)?)?;
        reject_workspace_transition_workload_secrets(&self.environment(name)?, &parameters)?;
        self.revalidate_environment_workspace_plan_for_boot(name)
            .await?;
        let mut operation = operation.clone();
        while let Some(effect) = supervisor_effect(operation.kind, operation.checkpoint)? {
            match effect {
                LifecycleEffect::RequireEnvironmentAccess => {
                    if parameters.was_running {
                        self.require_environment_access(name).await?;
                    }
                    operation = self.core().checkpoint_operation(&operation)?;
                }
                LifecycleEffect::StageWorkspaceGeneration
                    if operation.kind == OperationKind::UpdateWorkspace =>
                {
                    validate_workspace_transition_start(&self.environment(name)?, &parameters)?;
                    let _writer = self.begin_staging(name).await?;
                    let staged = self.stage_workspace_update(name, &parameters).await?;
                    operation = self.commit_operation(&operation, |next_state| {
                        record_staged_workspace_update(next_state, name, &parameters, staged)
                    })?;
                }
                LifecycleEffect::StageRollbackGeneration
                    if operation.kind == OperationKind::RollbackWorkspace =>
                {
                    validate_workspace_transition_start(&self.environment(name)?, &parameters)?;
                    operation = self.commit_operation(&operation, |next_state| {
                        record_staged_workspace_rollback(next_state, name, &parameters)
                    })?;
                }
                LifecycleEffect::StopVm => {
                    if workspace_transition_requires_boot(&self.environment(name)?, &parameters)? {
                        self.require_environment_guest_seed_abi(name, true)
                            .await
                            .map_err(|error| {
                                SupervisorError::ReplacementPreflight(Box::new(error))
                            })?;
                        self.admit_environment_cw_runtime(name)
                            .await
                            .map_err(|error| {
                                SupervisorError::ReplacementPreflight(Box::new(error))
                            })?;
                        self.ensure_vm_stopped(name).await?;
                    }
                    operation = self.core().checkpoint_operation(&operation)?;
                }
                LifecycleEffect::RecordStopped => {
                    operation = self.commit_operation(&operation, |next_state| {
                        let environment = next_state
                            .environments
                            .get_mut(name)
                            .ok_or_else(|| SupervisorError::NotFound(name.to_owned()))?;
                        if workspace_transition_requires_boot(environment, &parameters)? {
                            environment.state = StoredEnvironmentState::Stopped;
                        }
                        Ok(())
                    })?;
                }
                LifecycleEffect::RecordStarting => {
                    operation = self.commit_operation(&operation, |next_state| {
                        let environment = next_state
                            .environments
                            .get_mut(name)
                            .ok_or_else(|| SupervisorError::NotFound(name.to_owned()))?;
                        if workspace_transition_requires_boot(environment, &parameters)? {
                            reserve_boot_generation(environment, parameters.target_generation)?;
                        }
                        Ok(())
                    })?;
                }
                LifecycleEffect::EnsureRunner => {
                    if workspace_transition_requires_boot(&self.environment(name)?, &parameters)? {
                        let staging = self
                            .environment(name)?
                            .staging_workspace_generation
                            .is_some();
                        validate_environment_workload_secret_delivery(
                            &self.environment(name)?,
                            staging,
                        )?;
                        let artifact_generation =
                            artifact_generation_for_boot(&self.environment(name)?, staging)?
                                .to_owned();
                        let _ = self
                            .runner_client_for_artifact(name, &artifact_generation)
                            .await?;
                    }
                    operation = self.core().checkpoint_operation(&operation)?;
                }
                LifecycleEffect::StartVm => {
                    if workspace_transition_requires_boot(&self.environment(name)?, &parameters)? {
                        self.ensure_vm_started(
                            name,
                            parameters.target_generation,
                            operation.operation_id,
                        )
                        .await?;
                    }
                    operation = self.core().checkpoint_operation(&operation)?;
                }
                LifecycleEffect::RestoreDesiredPower => {
                    if !parameters.was_running
                        && workspace_transition_requires_boot(
                            &self.environment(name)?,
                            &parameters,
                        )?
                    {
                        self.ensure_vm_stopped(name).await?;
                    }
                    operation = self.core().checkpoint_operation(&operation)?;
                }
                LifecycleEffect::RecordWorkspaceTransition => {
                    operation = self.commit_operation(&operation, |next_state| {
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
                        Ok(())
                    })?;
                }
                _ => return Err(SupervisorError::InvalidState),
            }
        }
        Ok(operation)
    }

    async fn abort_workspace_transition(
        &self,
        operation: &OperationRecord,
        name: &str,
        error_code: &str,
    ) -> Result<OperationRecord, SupervisorError> {
        self.abort_workspace_transition_with_stop(operation, name, error_code, true)
            .await
    }

    async fn abort_workspace_transition_with_stop(
        &self,
        operation: &OperationRecord,
        name: &str,
        error_code: &str,
        may_stop: bool,
    ) -> Result<OperationRecord, SupervisorError> {
        if !may_stop
            && supervisor_effect(operation.kind, operation.checkpoint)?
                != Some(LifecycleEffect::StopVm)
        {
            return Err(SupervisorError::InvalidState);
        }
        if operation.phase != OperationPhase::Intent
            && operation.phase != OperationPhase::EffectApplied
        {
            return Err(SupervisorError::OperationTerminal);
        }
        let environment = self.environment(name)?;
        if operation.environment_id != Some(environment.id) {
            return Err(SupervisorError::InvalidState);
        }
        let parameters = workspace_transition_parameters(operation, &environment)?;
        cleanup_interrupted_skill_snapshot(&self.config.engine_root(), environment.id)?;
        if operation.checkpoint == 0 {
            return self.core().fail_operation(operation, error_code);
        }

        let requires_boot = workspace_transition_requires_boot(&environment, &parameters)?;
        if requires_boot && may_stop {
            self.ensure_vm_stopped(name).await?;
        }
        self.fail_operation_with(operation, error_code, |next_state| {
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
            if requires_boot && may_stop {
                environment.state = StoredEnvironmentState::Stopped;
            }
            Ok(())
        })
    }

    async fn delete(
        &self,
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
        if self
            .environment(name)
            .is_ok_and(|environment| environment.id != environment_id)
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
                            if !self.core().state.environments.contains_key(name) {
                                return Err(SupervisorError::InvalidState);
                            }
                            self.prepare_environment_for_delete(name).await?;
                        }
                        DeletionTreeLocation::Trash(_) | DeletionTreeLocation::Missing => {}
                    }
                    checkpoints::retire_for_environment(self, environment_id).await?;
                    operation = self.core().checkpoint_operation(&operation)?;
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
                            // A create that failed before provisioning (for
                            // example at access binding) recorded the
                            // environment but never made its tree; there is
                            // nothing to trash. Any other recorded
                            // environment must still have one.
                            if self
                                .core()
                                .state
                                .environments
                                .get(name)
                                .is_some_and(|environment| {
                                    !environment_never_provisioned(environment)
                                })
                            {
                                return Err(SupervisorError::State(
                                    StateError::MissingTrashSource(
                                        engine_root.join("vms").join(environment_id.to_string()),
                                    ),
                                ));
                            }
                        }
                    }
                    operation = self.core().checkpoint_operation(&operation)?;
                }
                LifecycleEffect::RevokeEnvironmentAccess => {
                    if revoke_access {
                        cleanup_pending |= self
                            .revoke_environment_access_best_effort(environment_id)
                            .await;
                    }
                    operation = self.core().checkpoint_operation(&operation)?;
                }
                LifecycleEffect::RemoveEnvironment => {
                    operation = self.commit_operation(&operation, |next_state| {
                        next_state.environments.remove(name);
                        if next_state.current.as_deref() == Some(name) {
                            next_state.current = next_state.environments.keys().next().cloned();
                        }
                        Ok(())
                    })?;
                }
                LifecycleEffect::CleanupTrash => {
                    let trash_pending =
                        cleanup_trashed_vm(&engine_root, environment_id, operation.operation_id)
                            .is_err();
                    let collection_pending = self.collect_if_idle().await.is_err();
                    if trash_pending || collection_pending {
                        // Deletion is already durable. Any object that cannot
                        // pass the exact allowlist remains quarantined for
                        // orphan inventory; it is never recursively removed or
                        // silently adopted.
                        cleanup_pending = true;
                    }
                    operation = self.core().checkpoint_operation(&operation)?;
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
        cleanup_pending |= self.collect_if_idle().await.is_err();
        if revoke_access {
            cleanup_pending |= self
                .environment_access_cleanup_pending(environment_id)
                .await;
        }
        Ok((operation, cleanup_pending))
    }

    async fn daemon_access(&self, name: &str) -> Result<v1::DaemonAccess, SupervisorError> {
        self.reconcile(name).await?;
        if self.environment(name)?.state != StoredEnvironmentState::Running {
            return Err(SupervisorError::NotRunning);
        }
        let artifact_generation =
            artifact_generation_for_boot(&self.environment(name)?, false)?.to_owned();
        let mut client = self
            .runner_client_for_artifact(name, &artifact_generation)
            .await?;
        client
            .daemon_access()
            .await
            .map_err(|_| SupervisorError::RunnerUnavailable)
    }
}

impl SupervisorCore {
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
    supervisor: Arc<Supervisor>,
    operation_reader: Arc<Mutex<SupervisorOperationReader>>,
    operation_events: broadcast::Sender<OperationRecord>,
    operation_progress: broadcast::Sender<OperationProgress>,
    host_keys: Arc<ssh::HostKeys>,
    ssh_streams: Arc<ssh::SshStreams>,
    /// The host's network policies (#2537).
    network_policies: Arc<crate::network_policy_store::NetworkPolicyStore>,
    /// Tests only: admitted operations wait instead of draining, so a test
    /// observes them as admitted.
    #[cfg(test)]
    hold_drains: Arc<std::sync::atomic::AtomicBool>,
}

impl SupervisorRpc {
    /// Start a drain of `name` (#2978). Every admission starts one; a drain
    /// with nothing pending just exits, so no wakeup is lost and nothing
    /// tracks whether one runs. An operation error stops the supervisor, as
    /// it always has, except a recovery waiting for the credential
    /// authority, which stops only this name's drain until a later request.
    fn spawn_drain(&self, name: &str) {
        #[cfg(test)]
        if self.hold_drains.load(std::sync::atomic::Ordering::Acquire) {
            return;
        }
        let supervisor = Arc::clone(&self.supervisor);
        let name = name.to_owned();
        drop(tokio::spawn(async move {
            if let Err(error) = supervisor.drain(&name).await
                && fatal_drain_error(&error)
            {
                supervisor.halt();
            }
        }));
    }

    /// Recover the cw-runtime operations of environments no name holds any
    /// more; each one held by a name recovers in that name's drain.
    fn spawn_unheld_runtime_recovery(&self) {
        let supervisor = Arc::clone(&self.supervisor);
        drop(tokio::spawn(async move {
            let held = supervisor
                .core()
                .state
                .environments
                .values()
                .map(|environment| environment.id)
                .collect::<BTreeSet<_>>();
            if supervisor
                .recover_runtime_operations(|id| !held.contains(&id))
                .await
                .is_err()
            {
                supervisor.halt();
            }
        }));
    }

    /// Every request's entry (#2978): refuse while retiring, then start a
    /// drain, without waiting, for every name with pending work, so a request
    /// retries a recovery deferred for the credential authority.
    fn start_drains(&self) -> Result<(), Status> {
        if self.supervisor.core().retiring {
            return Err(Status::from(SupervisorError::Retiring));
        }
        let names = self
            .supervisor
            .names_with_pending_work()
            .map_err(Status::from)?;
        for name in names {
            self.spawn_drain(&name);
        }
        Ok(())
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

    async fn operation_for_request(&self, request_id: Uuid) -> Result<OperationRecord, Status> {
        self.operation_reader
            .lock()
            .await
            .operation_by_request(request_id)
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
        network_policies::check_selectable(&self.network_policies, &request.network_policy)?;
        self.start_drains()?;
        let lease = self
            .supervisor
            .quiet_lease(&request.name)
            .await
            .map_err(Status::from)?;
        let existing = self
            .supervisor
            .core()
            .store
            .operation_by_request(request_id)
            .map_err(SupervisorError::from)
            .map_err(Status::from)?;
        let (operation, admitted) = match existing {
            Some(operation) => {
                let (recorded, _) =
                    create_request_from_operation(&operation).map_err(Status::from)?;
                if recorded != request {
                    return Err(Status::aborted("local lifecycle request ID collision"));
                }
                (operation, false)
            }
            None => {
                // A new create for a taken name fails here, before anything
                // is recorded. Replay above has already finished any rollback
                // of a failed create, so its name is free again.
                if self
                    .supervisor
                    .core()
                    .state
                    .environments
                    .contains_key(&request.name)
                {
                    return Err(Status::from(SupervisorError::AlreadyExists(
                        request.name.clone(),
                    )));
                }
                // Allocate the eventual environment identity before repository
                // preparation. Successful preparation journals this SAME ID;
                // failure abandons it and keeps offline replay unchanged.
                let environment_id = Uuid::new_v4();
                // Preparation writes repository bundles that only the
                // journaled create will reference: a writer until then.
                let writer = self.supervisor.content_writer().await;
                // A restore takes its snapshot's plan, after every refusal
                // checked there (#3046); nothing is prepared.
                let prepared = match request.snapshot.as_ref() {
                    Some(_) => snapshots::restore_plan(&self.supervisor, &request).await,
                    None => self
                        .supervisor
                        .prepare_create_workspace_plan(&request, environment_id)
                        .await
                        .map_err(Status::from),
                };
                let (workspace_plan, discriminators) = match prepared {
                    Ok(prepared) => prepared,
                    Err(error) => {
                        // A multi-repository preparation can admit an earlier
                        // bundle before a later repository fails: collect what
                        // nothing references, once no writer is in flight.
                        drop(writer);
                        let _ = self.supervisor.collect_if_idle().await;
                        return Err(error);
                    }
                };
                let payload =
                    create_operation_payload(&request, &workspace_plan).map_err(Status::from)?;
                // One section of the lock journals and admits it (#3143): no
                // select falls between them, and a retire either sees this
                // create pending or is seen here. Any other admission is of a
                // recorded name, whose lease a retire holds.
                let operation = {
                    let mut core = self.supervisor.core();
                    if core.retiring {
                        return Err(Status::from(SupervisorError::Retiring));
                    }
                    let operation = begin_create_operation(
                        &core.store,
                        request_id,
                        environment_id,
                        &payload,
                        &discriminators,
                    )
                    .map_err(Status::from)?;
                    if !operation.phase.terminal() {
                        core.admit(&operation);
                    }
                    operation
                };
                drop(writer);
                (operation, true)
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
        if !admitted && !operation.phase.terminal() {
            self.supervisor.admit(&operation);
        }
        drop(lease);
        if !operation.phase.terminal() {
            self.spawn_drain(&request.name);
        }
        Ok(Response::new(response))
    }

    async fn list_environments(
        &self,
        _request: Request<v1::ListEnvironmentsRequest>,
    ) -> Result<Response<v1::ListEnvironmentsResponse>, Status> {
        // A read never waits on another environment's operation (#2978). It
        // lists what is recorded now, so an environment a concurrent delete
        // removed is simply absent.
        self.start_drains()?;
        let names = self
            .supervisor
            .core()
            .state
            .environments
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        for name in &names {
            self.supervisor
                .reconcile_if_idle(name)
                .await
                .map_err(Status::from)?;
        }
        let core = self.supervisor.core();
        let environments = core
            .state
            .environments
            .keys()
            .map(|name| core.environment_proto(name))
            .collect::<Result<Vec<_>, _>>()
            .map_err(Status::from)?;
        Ok(Response::new(v1::ListEnvironmentsResponse { environments }))
    }

    async fn get_environment(
        &self,
        request: Request<v1::EnvironmentSelector>,
    ) -> Result<Response<v1::Environment>, Status> {
        let name = selected_name(request.into_inner())?;
        self.start_drains()?;
        self.supervisor
            .reconcile_if_idle(&name)
            .await
            .map_err(Status::from)?;
        Ok(Response::new(
            self.supervisor
                .core()
                .environment_proto(&name)
                .map_err(Status::from)?,
        ))
    }

    async fn select_environment(
        &self,
        request: Request<v1::EnvironmentSelector>,
    ) -> Result<Response<v1::Environment>, Status> {
        let (name, _request_id, expected_environment_id) =
            mutation_selection(request.into_inner())?;
        self.start_drains()?;
        let _lease = self
            .supervisor
            .quiet_lease(&name)
            .await
            .map_err(Status::from)?;
        self.supervisor
            .reconcile(&name)
            .await
            .map_err(Status::from)?;
        let environment = self.supervisor.environment(&name).map_err(Status::from)?;
        require_expected_environment(&environment, expected_environment_id)?;
        let mut core = self.supervisor.core();
        core.selections += 1;
        if core.state.current.as_deref() != Some(name.as_str()) {
            core.state.current = Some(name.clone());
            core.save().map_err(Status::from)?;
        }
        Ok(Response::new(
            core.environment_proto(&name).map_err(Status::from)?,
        ))
    }

    async fn list_orphans(
        &self,
        _request: Request<v1::ListOrphansRequest>,
    ) -> Result<Response<v1::ListOrphansResponse>, Status> {
        self.supervisor
            .core()
            .orphan_inventory()
            .map(Response::new)
            .map_err(Status::from)
    }

    async fn start_environment(
        &self,
        request: Request<v1::EnvironmentSelector>,
    ) -> Result<Response<v1::Operation>, Status> {
        let (name, request_id, expected_environment_id) = mutation_selection(request.into_inner())?;
        self.start_drains()?;
        let lease = self
            .supervisor
            .quiet_lease(&name)
            .await
            .map_err(Status::from)?;
        self.supervisor
            .reconcile(&name)
            .await
            .map_err(Status::from)?;
        let environment = self.supervisor.environment(&name).map_err(Status::from)?;
        require_expected_environment(&environment, expected_environment_id)?;
        reject_environment_workload_secrets(&environment).map_err(Status::from)?;
        let existing = self
            .supervisor
            .core()
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
            self.supervisor
                .core()
                .store
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
        if !operation.phase.terminal() {
            self.supervisor.admit(&operation);
        }
        drop(lease);
        if !operation.phase.terminal() {
            self.spawn_drain(&name);
        }
        Ok(Response::new(response))
    }

    async fn stop_environment(
        &self,
        request: Request<v1::EnvironmentSelector>,
    ) -> Result<Response<v1::Operation>, Status> {
        let (name, request_id, expected_environment_id) = mutation_selection(request.into_inner())?;
        self.start_drains()?;
        let lease = self
            .supervisor
            .quiet_lease(&name)
            .await
            .map_err(Status::from)?;
        let environment = self.supervisor.environment(&name).map_err(Status::from)?;
        require_expected_environment(&environment, expected_environment_id)?;
        let environment_id = environment.id;
        let payload = serde_json::json!({"name": name});
        let operation = self
            .supervisor
            .core()
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
        if !operation.phase.terminal() {
            self.supervisor.admit(&operation);
        }
        drop(lease);
        if !operation.phase.terminal() {
            self.spawn_drain(&name);
        }
        Ok(Response::new(response))
    }

    async fn restart_environment(
        &self,
        request: Request<v1::EnvironmentSelector>,
    ) -> Result<Response<v1::Operation>, Status> {
        let (name, request_id, expected_environment_id) = mutation_selection(request.into_inner())?;
        self.start_drains()?;
        let lease = self
            .supervisor
            .quiet_lease(&name)
            .await
            .map_err(Status::from)?;
        self.supervisor
            .reconcile(&name)
            .await
            .map_err(Status::from)?;
        let environment = self.supervisor.environment(&name).map_err(Status::from)?;
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
        let existing = self
            .supervisor
            .core()
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
            self.supervisor
                .require_environment_guest_seed_abi(&name, false)
                .await
                .map_err(Status::from)?;
            self.supervisor
                .admit_environment_cw_runtime(&name)
                .await
                .map_err(Status::from)?;
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
            self.supervisor
                .core()
                .store
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
        if !operation.phase.terminal() {
            self.supervisor.admit(&operation);
        }
        drop(lease);
        if !operation.phase.terminal() {
            self.spawn_drain(&name);
        }
        Ok(Response::new(response))
    }

    async fn refresh_environment_skills(
        &self,
        request: Request<v1::EnvironmentSelector>,
    ) -> Result<Response<v1::Operation>, Status> {
        let (name, request_id, expected_environment_id) = mutation_selection(request.into_inner())?;
        self.start_drains()?;
        let lease = self
            .supervisor
            .quiet_lease(&name)
            .await
            .map_err(Status::from)?;
        self.supervisor
            .reconcile(&name)
            .await
            .map_err(Status::from)?;
        let environment = self.supervisor.environment(&name).map_err(Status::from)?;
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
        let prior_storage_generation = workspace_storage_generation(active)
            .map_err(SupervisorError::from)
            .map_err(Status::from)?;
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
        let existing = self
            .supervisor
            .core()
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
            self.supervisor
                .core()
                .store
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
        if !operation.phase.terminal() {
            self.supervisor.admit(&operation);
        }
        drop(lease);
        if !operation.phase.terminal() {
            self.spawn_drain(&name);
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
        self.start_drains()?;
        let lease = self
            .supervisor
            .quiet_lease(&request.name)
            .await
            .map_err(Status::from)?;
        let environment = self
            .supervisor
            .environment(&request.name)
            .map_err(Status::from)?
            .clone();
        require_expected_environment(&environment, expected_environment_id)?;
        reject_environment_workload_secrets(&environment).map_err(Status::from)?;

        let existing = self
            .supervisor
            .core()
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
            self.supervisor
                .core()
                .store
                .begin_operation(request_id, Some(environment.id), kind, &payload)
                .map_err(SupervisorError::from)
                .map_err(Status::from)?
        };
        let response = operation_proto(&operation)?;
        if !operation.phase.terminal() {
            self.supervisor.admit(&operation);
        }
        drop(lease);
        if !operation.phase.terminal() {
            self.spawn_drain(&request.name);
        }
        Ok(Response::new(response))
    }

    async fn update_host_ports(
        &self,
        request: Request<v1::UpdateHostPortsRequest>,
    ) -> Result<Response<v1::Operation>, Status> {
        let request = request.into_inner();
        if !valid_environment_name(&request.name) {
            return Err(Status::from(SupervisorError::InvalidRequest));
        }
        let request_id = parse_request_id(&request.request_id).map_err(Status::from)?;
        let expected_environment_id =
            parse_optional_environment_id(&request.environment_id).map_err(Status::from)?;
        let add = request
            .add
            .iter()
            .map(|binding| serde_json::json!([binding.host_port, binding.guest_port]))
            .collect::<Vec<_>>();
        self.start_drains()?;
        let lease = self
            .supervisor
            .quiet_lease(&request.name)
            .await
            .map_err(Status::from)?;
        let environment = self
            .supervisor
            .environment(&request.name)
            .map_err(Status::from)?
            .clone();
        require_expected_environment(&environment, expected_environment_id)?;
        let existing = self
            .supervisor
            .core()
            .store
            .operation_by_request(request_id)
            .map_err(SupervisorError::from)
            .map_err(Status::from)?;
        let operation = if let Some(operation) = existing {
            if operation.kind != OperationKind::UpdateHostPorts
                || operation.environment_id != Some(environment.id)
                || operation
                    .payload
                    .get("name")
                    .and_then(serde_json::Value::as_str)
                    != Some(request.name.as_str())
                || operation.payload.get("add") != Some(&serde_json::json!(add))
                || operation.payload.get("remove") != Some(&serde_json::json!(request.remove))
            {
                return Err(Status::aborted("local lifecycle request ID collision"));
            }
            operation
        } else {
            if !matches!(
                environment.state,
                StoredEnvironmentState::Running | StoredEnvironmentState::Stopped
            ) || self
                .supervisor
                .core()
                .store
                .has_pending_lifecycle_operation(environment.id)
                .map_err(SupervisorError::from)
                .map_err(Status::from)?
            {
                return Err(Status::failed_precondition(
                    "host ports change only on a running or stopped environment",
                ));
            }
            let target = updated_host_ports(&environment.host_ports, &request)?;
            let payload = serde_json::json!({
                "name": request.name,
                "add": add,
                "remove": request.remove,
                "target": target,
            });
            self.supervisor
                .core()
                .store
                .begin_operation(
                    request_id,
                    Some(environment.id),
                    OperationKind::UpdateHostPorts,
                    &payload,
                )
                .map_err(SupervisorError::from)
                .map_err(Status::from)?
        };
        let response = operation_proto(&operation)?;
        if !operation.phase.terminal() {
            self.supervisor.admit(&operation);
        }
        drop(lease);
        if !operation.phase.terminal() {
            self.spawn_drain(&request.name);
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
        self.start_drains()?;
        let lease = self.supervisor.lease(&name).lock_owned().await;
        // Preserve the selector's stable-identity precondition before replaying
        // any durable work. A replay may remove this environment (including
        // when this request ID names the pending delete itself), but it must
        // not turn a stale caller's NotFound into an effect or replay error.
        let recorded = self
            .supervisor
            .core()
            .store
            .operation_by_request(request_id)
            .map_err(SupervisorError::from)
            .map_err(Status::from)?;
        match recorded {
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
                let environment = self.supervisor.environment(&name).map_err(Status::from)?;
                require_expected_environment(&environment, expected_environment_id)?;
            }
        }
        let lease = self
            .supervisor
            .drain_under(lease, &name)
            .await
            .map_err(Status::from)?;
        let existing = self
            .supervisor
            .core()
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
                let environment = self.supervisor.environment(&name).map_err(Status::from)?;
                require_expected_environment(&environment, expected_environment_id)?;
                let environment_id = environment.id;
                let payload = serde_json::json!({
                    "name": name,
                    "revoke_access": environment_uses_access_profile(&environment)
                        .map_err(Status::from)?,
                });
                let mut core = self.supervisor.core();
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
                // A delete someone asked for frees the layers this name's
                // pulls cached; a failed create's own rollback keeps them
                // (#2952), and another name's stay (#2978).
                core.download_cache.remove(&name);
                operation
            }
        };
        let response = operation_proto(&operation)?;
        if !operation.phase.terminal() {
            self.supervisor.admit(&operation);
        }
        drop(lease);
        if !operation.phase.terminal() {
            self.spawn_drain(&name);
        }
        Ok(Response::new(response))
    }

    async fn get_operation(
        &self,
        request: Request<v1::GetOperationRequest>,
    ) -> Result<Response<v1::Operation>, Status> {
        let request = request.into_inner();
        let operation = match (
            request.operation_id.is_empty(),
            request.request_id.is_empty(),
        ) {
            (false, true) => {
                self.operation(parse_operation_id(&request.operation_id)?)
                    .await?
            }
            (true, false) => {
                self.operation_for_request(
                    parse_request_id(&request.request_id).map_err(Status::from)?,
                )
                .await?
            }
            _ => {
                return Err(Status::invalid_argument(
                    "name the operation by exactly one of its ID or its request ID",
                ));
            }
        };
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
        // A supervisor stopping after a failed operation drains its open
        // connections; a watch of an unfinished operation must end, not wait.
        let mut shutdown = self.supervisor.shutdown.subscribe();
        if *shutdown.borrow() {
            return Err(Status::unavailable(
                "native local supervisor stopped before the operation finished; run the command again",
            ));
        }
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
                    changed = shutdown.changed() => {
                        if changed.is_err() || *shutdown.borrow() {
                            let _ = sender
                                .send(Err(Status::unavailable(
                                    "native local supervisor stopped before the operation finished; run the command again",
                                )))
                                .await;
                            return;
                        }
                    }
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
        self.start_drains()?;
        let _lease = self
            .supervisor
            .quiet_lease(&name)
            .await
            .map_err(Status::from)?;
        self.supervisor
            .daemon_access(&name)
            .await
            .map(Response::new)
            .map_err(Status::from)
    }

    async fn ensure_credential_broker(
        &self,
        request: Request<v1::EnvironmentSelector>,
    ) -> Result<Response<v1::CredentialBrokerRuntime>, Status> {
        let name = selected_name(request.into_inner())?;
        self.start_drains()?;
        let broker_request = {
            let _lease = self
                .supervisor
                .quiet_lease(&name)
                .await
                .map_err(Status::from)?;
            self.supervisor
                .reconcile_active_environment_before_protected_effect(&name)
                .await
                .map_err(Status::from)?;
            self.supervisor
                .core()
                .credential_broker_ensure_request(&name)
                .map_err(Status::from)?
        };
        ensure_credential_broker(broker_request)
            .await
            .map(credential_broker_runtime_proto)
            .map(Response::new)
            .map_err(Status::from)
    }

    type OpenEnvironmentSshStreamStream = ssh::SshFrames;

    async fn open_environment_ssh_stream(
        &self,
        request: Request<tonic::Streaming<v1::SshStreamFrame>>,
    ) -> Result<Response<Self::OpenEnvironmentSshStreamStream>, Status> {
        let mut inbound = request.into_inner();
        let environment_id = ssh::opened_environment(&mut inbound).await?;
        let permit = self.ssh_streams.admit(environment_id)?;
        // Subscribed before access is taken, so no stop between the two is
        // missed.
        let operations = self.operation_events.subscribe();
        let access = self.environment_daemon_access(environment_id).await?;
        let host_key = self
            .host_keys
            .private(environment_id)
            .map_err(|_| Status::internal("local environment SSH host key is unavailable"))?;
        let daemon = ssh::daemon_client(access).await?;
        let features = ssh::DaemonFeatures::read(&daemon).await;
        Ok(Response::new(ssh::serve(
            daemon,
            features,
            host_key,
            inbound,
            operations,
            environment_id,
            permit,
        )))
    }

    async fn get_managed_runtime(
        &self,
        request: Request<v1::EnvironmentSelector>,
    ) -> Result<Response<v1::ManagedRuntime>, Status> {
        let request = request.into_inner();
        let expected = parse_optional_environment_id(&request.environment_id)
            .map_err(Status::from)?
            .ok_or_else(|| {
                Status::invalid_argument("managed runtime requires an environment UUID")
            })?;
        let name = selected_name(request)?;
        self.start_drains()?;
        let _lease = self
            .supervisor
            .quiet_lease(&name)
            .await
            .map_err(Status::from)?;
        self.supervisor
            .reconcile(&name)
            .await
            .map_err(Status::from)?;
        if self
            .supervisor
            .core()
            .incompatible_runners
            .contains(&expected)
        {
            return Err(Status::from(SupervisorError::RunnerProtocolUnsupported));
        }
        let environment = self.supervisor.environment(&name).map_err(Status::from)?;
        let generation = managed_runtime_artifact_generation(&environment, expected)?.to_owned();
        let runtime_generation = environment
            .cw_runtime
            .as_ref()
            .filter(|binding| binding.staging_catalog_generation.is_none())
            .map(|binding| binding.active_catalog_generation.clone())
            .filter(|generation| {
                environment.runner.as_ref().is_some_and(|runner| {
                    runner.cw_runtime_catalog_generation.as_ref() == Some(generation)
                })
            })
            .ok_or_else(|| {
                Status::failed_precondition("running VM has no admitted cw runtime catalog")
            })?;
        let engine_root = self.supervisor.config.engine_root();
        let open_generation = runtime_generation.clone();
        let disk = tokio::task::spawn_blocking(move || {
            let engine = PrivateRoot::open(&engine_root)?;
            CwRuntimeStore::create(&engine)?.open_catalog(&open_generation)
        })
        .await
        .map_err(|_| Status::internal("cw runtime admission task failed"))?
        .map_err(|_| Status::failed_precondition("retained cw runtime catalog is unavailable"))?;
        let provenance_json = serde_json::to_vec(
            disk.manifest
                .catalog
                .active()
                .map_err(Status::failed_precondition)?,
        )
        .map_err(|_| Status::internal("cw runtime provenance encoding failed"))?;
        let catalog_json = disk
            .manifest
            .catalog
            .encode()
            .map_err(Status::failed_precondition)?;
        Ok(Response::new(v1::ManagedRuntime {
            environment_id: expected.to_string(),
            artifact_generation: generation,
            provenance_json,
            catalog_json,
            cw_runtime_catalog_generation: runtime_generation,
        }))
    }

    /// Select the network policy an environment enforces from its next start
    /// (#2537 B1). A running VM keeps the revision it started with.
    async fn update_environment_network_policy(
        &self,
        request: Request<v1::UpdateEnvironmentNetworkPolicyRequest>,
    ) -> Result<Response<v1::Environment>, Status> {
        let request = request.into_inner();
        let selection = network_policies::selection_from_reference(&request.network_policy)?;
        let _lease = self
            .supervisor
            .quiet_lease(&request.name)
            .await
            .map_err(Status::from)?;
        let environment_id = self
            .supervisor
            .environment(&request.name)
            .map_err(Status::from)?
            .id;
        self.network_policies
            .select(environment_id, selection.as_ref())
            .map_err(|error| match error {
                crate::network_policy_store::NetworkPolicyStoreError::NotFound(_) => {
                    Status::not_found(error.to_string())
                }
                other => Status::failed_precondition(other.to_string()),
            })?;
        // A running VM takes it at once; one whose broker cannot take it
        // reports the earlier selection until it restarts.
        let _ = self.supervisor.apply_network_policy(&request.name).await;
        Ok(Response::new(
            self.supervisor
                .core()
                .environment_proto(&request.name)
                .map_err(Status::from)?,
        ))
    }

    async fn create_network_policy(
        &self,
        request: Request<v1::CreateNetworkPolicyRequest>,
    ) -> Result<Response<v1::NetworkPolicy>, Status> {
        network_policies::create(&self.network_policies, request.into_inner()).map(Response::new)
    }

    async fn list_network_policies(
        &self,
        _request: Request<v1::ListNetworkPoliciesRequest>,
    ) -> Result<Response<v1::ListNetworkPoliciesResponse>, Status> {
        network_policies::list(&self.network_policies).map(Response::new)
    }

    async fn get_network_policy(
        &self,
        request: Request<v1::GetNetworkPolicyRequest>,
    ) -> Result<Response<v1::NetworkPolicy>, Status> {
        network_policies::get(&self.network_policies, request.into_inner()).map(Response::new)
    }

    async fn update_network_policy(
        &self,
        request: Request<v1::UpdateNetworkPolicyRequest>,
    ) -> Result<Response<v1::NetworkPolicy>, Status> {
        let mut updated = network_policies::update(&self.network_policies, request.into_inner())?;
        let id = network_policies::policy_id(&updated)?;
        let (enforced, restart_required) = self
            .supervisor
            .apply_network_policy_everywhere(&id)
            .await
            .map_err(Status::from)?;
        updated.enforced_in = enforced;
        updated.restart_required_in = restart_required;
        Ok(Response::new(updated))
    }

    async fn delete_network_policy(
        &self,
        request: Request<v1::NetworkPolicySelector>,
    ) -> Result<Response<v1::NetworkPolicy>, Status> {
        network_policies::delete(&self.network_policies, request.into_inner(), |selecting| {
            let core = self.supervisor.core();
            core.state
                .environments
                .iter()
                .filter(|(_, environment)| selecting.contains(&environment.id))
                .map(|(name, _)| name.clone())
                .collect()
        })
        .map(Response::new)
    }

    /// Hand this state root to a newer cw's supervisor (supervisor_handoff).
    /// Every pending operation runs first, under the one core lock every
    /// request takes. While any environment may still run a VM nothing
    /// changes; otherwise every later request is refused and the supervisor
    /// shuts down, as after a fatal worker error.
    async fn retire_supervisor(
        &self,
        request: Request<v1::RetireSupervisorRequest>,
    ) -> Result<Response<v1::RetireSupervisorResponse>, Status> {
        // The same protocol too: `cw upgrade --vms` moves idle VMs from
        // another cw of this protocol to its own supervisor (#2549 keeps that
        // one serving otherwise). Never for an older one.
        if request.into_inner().successor_protocol < NATIVE_SUPERVISOR_PROTOCOL_VERSION {
            return Err(Status::invalid_argument(
                "a local VM supervisor retires only for its own protocol or a newer one",
            ));
        }
        // Retire never waits (#2978): every lease, recorded names' and any
        // other a request or cw-runtime work took, must be free now, and is
        // held from here, so nothing starts on an environment. With nothing
        // pending and no VM that may run, `retiring` is set before anything
        // is awaited; every later lease acquisition and request is refused.
        let names = self
            .supervisor
            .core()
            .state
            .environments
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        for name in &names {
            let _ = self.supervisor.lease(name);
        }
        let all = self
            .supervisor
            .leases()
            .iter()
            .map(|(name, lease)| (name.clone(), Arc::clone(lease)))
            .collect::<Vec<_>>();
        let mut leases = Vec::with_capacity(all.len());
        for (name, lease) in all {
            let Ok(lease) = lease.try_lock_owned() else {
                // A cw-runtime key is NUL and the environment's ID.
                return Err(Status::from(SupervisorError::RetireRefused(
                    name.trim_start_matches('\0').to_owned(),
                )));
            };
            leases.push(lease);
        }
        {
            let mut core = self.supervisor.core();
            let pending = core
                .store
                .pending_operations()
                .map_err(SupervisorError::from)
                .map_err(Status::from)?;
            if let Some(name) = pending
                .iter()
                .filter(|operation| !operation.kind.cw_runtime())
                .find_map(|operation| operation_name(operation))
            {
                return Err(Status::from(SupervisorError::RetireRefused(
                    name.to_owned(),
                )));
            }
            if let Some((name, _)) = core
                .state
                .environments
                .iter()
                .find(|(_, environment)| may_run_a_vm(environment))
            {
                return Err(Status::from(SupervisorError::RetireRefused(name.clone())));
            }
            core.retiring = true;
        }
        // The rest runs in a task of its own: a request dropped meanwhile
        // still either hands over or keeps serving, and never leaves this
        // supervisor retiring.
        self.supervisor
            .detached(|supervisor| async move {
                // A stopped environment's runner holds no VM, but on Linux it
                // outlives this supervisor, and an older successor (`cw
                // upgrade rollback`) cannot use a newer runner: end each one
                // this supervisor tracks before handing over. A newer
                // successor would end it anyway.
                let idle: Vec<(String, RunnerRecord)> = {
                    let core = supervisor.core();
                    core.state
                        .environments
                        .iter()
                        .filter(|(_, environment)| {
                            environment.state == StoredEnvironmentState::Stopped
                                && core.live_runners.contains_key(&environment.id)
                        })
                        .filter_map(|(name, environment)| {
                            environment
                                .runner
                                .clone()
                                .map(|runner| (name.clone(), runner))
                        })
                        .collect()
                };
                for (name, runner) in idle {
                    if let Err(error) = supervisor.retire_idle_runner(&name, &runner).await {
                        // Not handed over after all: keep serving.
                        supervisor.core().retiring = false;
                        return Err(error);
                    }
                }
                diagnostic_log::record(supervisor.log.as_deref(), "supervisor_retiring", &[]);
                drop(leases);
                let _ = supervisor.shutdown.send(true);
                Ok(())
            })
            .await
            .map_err(Status::from)?;
        Ok(Response::new(v1::RetireSupervisorResponse {}))
    }
}

/// Whether an environment may still have a VM: one running or starting, one
/// whose runner still owns it after a failure (an error with a runner record
/// keeps its VM; `runner_service` reports such failures without stopping it),
/// or, on macOS, one whose ownership is unknown.
fn may_run_a_vm(environment: &EnvironmentRecord) -> bool {
    match environment.state {
        StoredEnvironmentState::Stopped => false,
        StoredEnvironmentState::Error => environment.runner.is_some(),
        StoredEnvironmentState::Starting | StoredEnvironmentState::Running => true,
        // A supervisor's exit stops its VMs only on macOS; a Linux orphan's
        // runner outlives it.
        StoredEnvironmentState::Orphaned => cfg!(target_os = "macos"),
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
        OperationKind::UpdateCwRuntime => v1::OperationKind::UpdateCwRuntime,
        OperationKind::RollbackCwRuntime => v1::OperationKind::RollbackCwRuntime,
        OperationKind::UpdateHostPorts => v1::OperationKind::UpdateHostPorts,
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
    StoredEnvironmentState::from_proto(runner.state)
        .map_err(SupervisorError::from)
        .map_err(Status::from)?;
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
        LifecycleEffect::ApplyHostPorts => v1::OperationStage::ApplyHostPorts,
        LifecycleEffect::RecordHostPorts => v1::OperationStage::RecordHostPorts,
    })
}

fn operation_result_proto(
    operation: &OperationRecord,
    result: &serde_json::Value,
) -> Result<v1::OperationResult, Status> {
    if operation.kind.cw_runtime() {
        let reply = runtime::decode_result(operation, result)?;
        return Ok(v1::OperationResult {
            value: Some(v1::operation_result::Value::CwRuntime(runtime::status(
                &reply,
                Some(operation),
            )?)),
        });
    }
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

fn runner_cw_runtime_identity_matches(
    environment: &EnvironmentRecord,
    record: &RunnerRecord,
    info: &v1::RunnerInfo,
    state: StoredEnvironmentState,
) -> bool {
    let binding = environment.cw_runtime.as_ref();
    let known = record.cw_runtime_catalog_generation.as_deref();
    if known.is_some_and(|generation| {
        !binding.is_some_and(|binding| {
            generation == binding.active_catalog_generation
                || binding.staging_catalog_generation.as_deref() == Some(generation)
        })
    }) {
        return false;
    }
    let expected = known.or_else(|| {
        binding.map(|binding| {
            if environment.state == StoredEnvironmentState::Starting {
                binding
                    .staging_catalog_generation
                    .as_deref()
                    .unwrap_or(&binding.active_catalog_generation)
            } else {
                &binding.active_catalog_generation
            }
        })
    });
    let attached = (!info.cw_runtime_catalog_generation.is_empty())
        .then_some(info.cw_runtime_catalog_generation.as_str());
    attached.is_none_or(valid_sha256)
        && (attached.is_none() || attached == expected)
        && (state != StoredEnvironmentState::Running || attached == expected)
        && (state != StoredEnvironmentState::Stopped || attached.is_none())
}

fn managed_runtime_artifact_generation(
    environment: &EnvironmentRecord,
    expected: Uuid,
) -> Result<&str, Status> {
    require_expected_environment(environment, Some(expected))?;
    let generation = environment
        .active_artifact_generation
        .as_deref()
        .ok_or_else(|| Status::failed_precondition("environment has no retained boot assets"))?;
    if environment.state != StoredEnvironmentState::Running
        || environment.runner.as_ref().is_none_or(|runner| {
            !runner_artifact_identity_matches(&runner.artifact_generation, generation)
        })
    {
        return Err(Status::failed_precondition(
            "managed runtime requires the running retained VM generation",
        ));
    }
    Ok(generation)
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
                vm_only,
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
                vm_only: vm_only.clone(),
            }),
            WorkspaceInput::Local { .. } | WorkspaceInput::Repository { .. } => None,
        })
        .collect())
}

/// Run the runner's StartVm while `held` keeps every checked direct share
/// open, and release them only once it has returned (#3209). Taking the
/// shares by value ties the hold to the start it protects.
async fn while_holding_direct_shares<T>(
    held: CheckedDirectShares,
    start: impl std::future::Future<Output = T>,
) -> T {
    let started = start.await;
    drop(held);
    started
}

/// Whether a failed direct-share revalidation must end an exposing runner.
/// Reading or recording discriminators (#3209) can fail in the store, which
/// says nothing about the shares: the operation fails, the runner stays.
fn revalidation_requires_quarantine(error: &SupervisorError) -> bool {
    !matches!(error, SupervisorError::Store(_))
}

fn revalidate_direct_shares_for_boot(
    plan: &WorkspacePlan,
    forbidden_roots: &[PathBuf],
    recorded: &DirectShareDiscriminators,
) -> Result<CheckedDirectShares, WorkspacePlanError> {
    // A persisted plan may have been admitted under an older supervisor
    // configuration. Recheck the current private roots before any boot-side
    // effects; the runner separately reopens the exact identity at launch.
    plan.validate()?;
    plan.check_direct_shares(forbidden_roots, recorded)
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

fn validate_create(request: &v1::CreateEnvironmentRequest) -> Result<Uuid, SupervisorError> {
    if !valid_environment_name(&request.name)
        || request.vcpus == 0
        || request.vcpus > 32
        || !(128..=65_536).contains(&request.memory_mib)
        || request.disk_bytes < crate::state::MINIMUM_STATE_DISK_BYTES
        || !request.disk_bytes.is_multiple_of(1024 * 1024)
        || (request.docker_disk_bytes != 0
            && (request.docker_disk_bytes < crate::state::MINIMUM_DOCKER_DISK_BYTES
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
        let mode = parse_implicit_path_mode(&request.implicit_path_mode)?;
        if request.source_path.is_empty()
            || !Path::new(&request.source_path).is_absolute()
            || !valid_vm_only_patterns(&request.implicit_vm_only)
            || (mode == WorkspaceSourceMode::Clone && !request.implicit_vm_only.is_empty())
        {
            return Err(SupervisorError::InvalidRequest);
        }
    } else if !request.source_path.is_empty()
        || !request.implicit_path_mode.is_empty()
        || !request.implicit_vm_only.is_empty()
    {
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
            || validate_local_mount_destination(
                &mount.destination,
                mount.mode == v1::LocalMountMode::Direct as i32,
            )
            .is_err()
        {
            return Err(SupervisorError::InvalidRequest);
        }
        match v1::LocalMountMode::try_from(mount.mode) {
            Ok(v1::LocalMountMode::Copy) if mount.read_only.is_none() => {}
            Ok(v1::LocalMountMode::Direct) if mount.read_only == Some(false) => {}
            Ok(v1::LocalMountMode::Direct)
                if mount.read_only == Some(true) && mount.vm_only.is_empty() => {}
            _ => return Err(SupervisorError::InvalidRequest),
        }
        if !valid_vm_only_patterns(&mount.vm_only) {
            return Err(SupervisorError::InvalidRequest);
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
    // Every pair: a repository may sit inside another repository (#4024);
    // any other nesting, and any duplicate, is refused.
    let destinations = project
        .repositories
        .iter()
        .map(|repository| (repository.destination.as_str(), true))
        .chain(
            mounts
                .iter()
                .map(|mount| (mount.destination.as_str(), false)),
        )
        .collect::<Vec<_>>();
    let contains = |outer: &str, inner: &str| {
        inner
            .strip_prefix(outer)
            .is_some_and(|suffix| suffix.starts_with('/'))
    };
    for (index, &(left, left_repository)) in destinations.iter().enumerate() {
        for &(right, right_repository) in &destinations[index + 1..] {
            let nested = contains(left, right) || contains(right, left);
            if left == right || (nested && !(left_repository && right_repository)) {
                return Err(SupervisorError::InvalidRequest);
            }
        }
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

/// Recorded by a create that never reached a workspace generation or a
/// runner, so nothing of it exists on disk except possibly a partial tree.
fn environment_never_provisioned(environment: &EnvironmentRecord) -> bool {
    environment.active_workspace_generation.is_none()
        && environment.staging_workspace_generation.is_none()
        && environment.runner.is_none()
        && environment.generation == 0
}

fn environment_uses_access_profile(
    environment: &EnvironmentRecord,
) -> Result<bool, SupervisorError> {
    if !environment_access_metadata_valid(environment) {
        return Err(SupervisorError::InvalidState);
    }
    Ok(environment.access_binding.is_some())
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
        || request.disk_bytes < crate::state::MINIMUM_STATE_DISK_BYTES
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

/// The exact canonical set after withdrawing `remove` and publishing `add`.
/// A published host port must be withdrawn before it is published again.
fn updated_host_ports(
    current: &[HostPortBinding],
    request: &v1::UpdateHostPortsRequest,
) -> Result<Vec<HostPortBinding>, Status> {
    if request.add.is_empty() && request.remove.is_empty() {
        return Err(Status::invalid_argument(
            "no host ports to publish or withdraw",
        ));
    }
    let mut target = current.to_vec();
    for port in &request.remove {
        let before = target.len();
        target.retain(|binding| u32::from(binding.host_port) != *port);
        if target.len() == before {
            return Err(Status::failed_precondition(format!(
                "host port {port} is not published"
            )));
        }
    }
    for binding in &request.add {
        let (Ok(host_port), Ok(guest_port)) = (
            u16::try_from(binding.host_port),
            u16::try_from(binding.guest_port),
        ) else {
            return Err(Status::invalid_argument("ports are 1 to 65535"));
        };
        if target.iter().any(|current| current.host_port == host_port) {
            return Err(Status::failed_precondition(format!(
                "host port {host_port} is already published; withdraw it first"
            )));
        }
        if target
            .iter()
            .any(|current| current.guest_port == guest_port)
        {
            return Err(Status::failed_precondition(format!(
                "guest port {guest_port} is already published"
            )));
        }
        target.push(HostPortBinding {
            host_port,
            guest_port,
        });
    }
    canonical_host_port_bindings(target)
        .map_err(|error| Status::invalid_argument(error.to_string()))
}

fn parse_request_id(value: &str) -> Result<Uuid, SupervisorError> {
    let id = Uuid::parse_str(value).map_err(|_| SupervisorError::InvalidRequest)?;
    if id.is_nil() {
        return Err(SupervisorError::InvalidRequest);
    }
    Ok(id)
}

/// Journal a create, or return the one already journaled for its request.
/// A new create records its direct shares' admission discriminators in the
/// same transaction; a replay keeps what the first one recorded.
fn begin_create_operation(
    store: &SupervisorStore,
    request_id: Uuid,
    environment_id: Uuid,
    payload: &serde_json::Value,
    discriminators: &DirectShareDiscriminators,
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
            .begin_create_operation(request_id, environment_id, payload, discriminators)
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
    let mut payload = serde_json::json!({
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
    });
    // Only a selection adds the key (#2537), so a create journaled before
    // selections existed replays unchanged and selects `open`.
    if !request.network_policy.is_empty() {
        payload
            .as_object_mut()
            .expect("create payload is an object")
            .insert(
                "network_policy".to_owned(),
                request.network_policy.clone().into(),
            );
    }
    // Likewise only a restore adds `snapshot` (#3046).
    snapshots::journal_payload(&mut payload, request)?;
    Ok(payload)
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
        .filter(|fields| {
            let optional = ["network_policy", "snapshot"]
                .into_iter()
                .filter(|key| fields.contains_key(*key))
                .count();
            fields.len() == 16 + optional
        })
        .ok_or(SupervisorError::InvalidState)?;
    let network_policy = match fields.get("network_policy") {
        None => String::new(),
        Some(value) => value
            .as_str()
            .filter(|reference| !reference.is_empty())
            .ok_or(SupervisorError::InvalidState)?
            .to_owned(),
    };
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
    // The implicit source's skipped paths are recorded in its one plan input.
    let implicit_vm_only = if source_path.is_empty() {
        Vec::new()
    } else {
        workspace_plan
            .inputs
            .first()
            .map(|input| input.vm_only().to_vec())
            .unwrap_or_default()
    };
    let request = v1::CreateEnvironmentRequest {
        snapshot: snapshots::from_payload(fields)?,
        network_policy,
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
        implicit_vm_only,
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
                vm_only,
                ..
            },
        ] = workspace_plan.inputs.as_slice()
        else {
            return Err(SupervisorError::InvalidRequest);
        };
        if source_path != OsStr::new(&request.source_path).as_bytes()
            || *mode != parse_implicit_path_mode(&request.implicit_path_mode)?
            || destination != "/workspace"
            || *vm_only != request.implicit_vm_only
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
                vm_only,
                ..
            } if source_path == &mount.source_path
                && *mode == WorkspaceSourceMode::Copy
                && destination == &mount.destination
                && *vm_only == mount.vm_only
                && mount.mode == v1::LocalMountMode::Copy as i32
                && mount.read_only.is_none() => {}
            WorkspaceInput::Direct {
                source_path,
                destination,
                read_only,
                vm_only,
                ..
            } if source_path == &mount.source_path
                && destination == &mount.destination
                && *vm_only == mount.vm_only
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
                vm_only,
                ..
            } => {
                validate_local_mount_destination(destination, false)
                    .map_err(|_| SupervisorError::InvalidState)?;
                Ok(v1::LocalMountInput {
                    source_path: source_path.clone(),
                    destination: destination.clone(),
                    mode: v1::LocalMountMode::Copy as i32,
                    read_only: None,
                    vm_only: vm_only.clone(),
                })
            }
            WorkspaceInput::Direct {
                source_path,
                destination,
                read_only,
                vm_only,
                ..
            } => {
                validate_local_mount_destination(destination, true)
                    .map_err(|_| SupervisorError::InvalidState)?;
                Ok(v1::LocalMountInput {
                    source_path: source_path.clone(),
                    destination: destination.clone(),
                    mode: v1::LocalMountMode::Direct as i32,
                    read_only: Some(*read_only),
                    vm_only: vm_only.clone(),
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

/// The artifact generation a replacement runner boots to clean up before a
/// delete. A create that failed at VM start reserved generation 1 but never
/// promoted its staged workspace, so it has only the staged generation.
fn delete_cleanup_artifact_generation(
    environment: &EnvironmentRecord,
) -> Result<&str, SupervisorError> {
    let staged_only = environment.active_workspace_generation.is_none()
        && environment.staging_workspace_generation.is_some();
    artifact_generation_for_boot(environment, staged_only)
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
        .filter(|fields| {
            fields.len() == 2
                || (fields.len() == 3
                    && checkpoints::start_payload_checkpoint(fields).is_ok_and(|id| id.is_some()))
        })
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
    // A kept runner records a code exactly when the environment is in Error.
    // A cleared runner records one only for the transition into Error: the
    // code is then the record of why the runner is gone (#2568). Operations
    // written before that carry none, and still validate.
    if clear_runner && runner_error_code.is_some() && target_state != StoredEnvironmentState::Error
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
            *value >= crate::state::MINIMUM_STATE_DISK_BYTES && value.is_multiple_of(1024 * 1024)
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
    prepare_runner_socket_dir(root.path())?;
    Ok(root)
}

/// The root's short private socket directory and its `runners` directory,
/// created on demand (#2735).
fn prepare_runner_socket_dir(root: &Path) -> Result<PathBuf, SupervisorError> {
    let sockets = crate::socket_dir::prepare(root)?;
    Ok(crate::socket_dir::ensure_subdirectory(
        &sockets,
        &["runners"],
    )?)
}

fn spawn_supervisor(
    config: &NativeRuntimeConfig,
    root: &PrivateRoot,
) -> Result<Child, SupervisorError> {
    // Its bounded owner-only log, not /dev/null: the supervisor's exit error or
    // panic and its closed diagnostic events (#2595).
    let (stdout, stderr) = diagnostic_log::child_stdio(root, diagnostic_log::SUPERVISOR_LOG);
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
        .stdout(stdout)
        .stderr(stderr);
    // SAFETY: scalar-only libc operations and one fixed-layout capset syscall
    // prepare a capability-empty, no-new-privileges, FD-clean detached
    // singleton before exec. The supervisor intentionally outlives this CLI.
    #[cfg(target_os = "linux")]
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
    // SAFETY: scalar-only libc operations before exec. Darwin has no capset.
    #[cfg(target_os = "macos")]
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(io::Error::last_os_error());
            }
            crate::darwin::process::mark_inherited_descriptors_close_on_exec();
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

#[cfg(target_os = "linux")]
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
            SupervisorError::ReplacementPreflight(error) => Status::from(*error),
            SupervisorError::AlreadyExists(_) => Status::already_exists(error.to_string()),
            SupervisorError::NotFound(_) => Status::not_found(error.to_string()),
            SupervisorError::NotRunning
            | SupervisorError::Orphaned
            | SupervisorError::OperationTerminal
            | SupervisorError::ArtifactGenerationChanged
            | SupervisorError::RunnerProtocolUnsupported
            | SupervisorError::EnvironmentAccessUnavailable
            | SupervisorError::EnvironmentAccessBindingRejected(_)
            | SupervisorError::WorkloadSecretDeliveryUnavailable => {
                Status::failed_precondition(error.to_string())
            }
            SupervisorError::CredentialAuthorityUnavailable
            | SupervisorError::Retiring
            | SupervisorError::Store(SupervisorStoreError::Stopping) => {
                Status::unavailable(error.to_string())
            }
            SupervisorError::RetireRefused(_) => Status::failed_precondition(error.to_string()),
            SupervisorError::NetworkPolicyStore(_) => Status::internal(error.to_string()),
            SupervisorError::NetworkPolicySelection(_) => {
                Status::failed_precondition(error.to_string())
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
            #[cfg(target_os = "macos")]
            SupervisorError::VzHelperMissing(_) | SupervisorError::VzHelperUnentitled(_) => {
                Status::failed_precondition(error.to_string())
            }
            SupervisorError::Artifact(
                crate::artifact::ArtifactError::GuestSeedProtocolUnsupported(_)
                | crate::artifact::ArtifactError::GuestVmOnlyUnsupported(_)
                | crate::artifact::ArtifactError::GuestWorkspaceRootShareUnsupported(_),
            ) => Status::failed_precondition(error.to_string()),
            SupervisorError::CwRuntime(_) => Status::failed_precondition(error.to_string()),
            SupervisorError::VmStart(_)
            | SupervisorError::GuestDockerToolingMissing
            | SupervisorError::GuestSetupFailed
            | SupervisorError::GuestWorkspaceFailed
            | SupervisorError::HostPortUnavailable
            | SupervisorError::VmStop
            | SupervisorError::VmResize
            | SupervisorError::VmDelete => Status::failed_precondition(error.to_string()),
            #[cfg(target_os = "macos")]
            SupervisorError::VmStartRefused => Status::failed_precondition(error.to_string()),
            SupervisorError::Store(SupervisorStoreError::RequestCollision)
            | SupervisorError::Store(SupervisorStoreError::JournalConflict) => {
                Status::aborted(error.to_string())
            }
            _ => Status::internal("native local supervisor operation failed"),
        }
    }
}

impl From<SupervisorClientError> for SupervisorError {
    fn from(error: SupervisorClientError) -> Self {
        match error {
            SupervisorClientError::Uds(error) => Self::Uds(error),
            SupervisorClientError::Configuration(error) => error.into(),
            SupervisorClientError::SupervisorProtocolUnavailable => {
                Self::SupervisorProtocolUnavailable
            }
            SupervisorClientError::SupervisorInfoUnavailable => Self::SupervisorInfoUnavailable,
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
            SupervisorConfigError::SocketPathTooLong {
                path,
                length,
                limit,
            } => Self::SocketPathTooLong {
                path,
                length,
                limit,
            },
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SupervisorError {
    #[error("native runtime configuration is invalid")]
    InvalidConfiguration,
    #[error(transparent)]
    SocketDir(#[from] crate::socket_dir::SocketDirError),
    #[error(
        "the native supervisor did not come up at {socket}: another one may hold this state root while its socket is not visible here (one started by an older cw, or in another /tmp namespace such as systemd PrivateTmp, Flatpak or Snap); see {log}"
    )]
    SupervisorNotReachable { socket: PathBuf, log: PathBuf },
    #[error("the local VM socket path {path} would be {length} bytes, over the {limit}-byte limit")]
    SocketPathTooLong {
        path: PathBuf,
        length: usize,
        limit: usize,
    },
    #[cfg(target_os = "macos")]
    #[error("the Virtualization.framework helper {0} is missing")]
    VzHelperMissing(PathBuf),
    #[cfg(target_os = "macos")]
    #[error(
        "the Virtualization.framework helper {0} lacks the com.apple.security.virtualization entitlement"
    )]
    VzHelperUnentitled(PathBuf),
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
    #[error(
        "nothing accepts connections at {0}, and no new native local supervisor could take it over because another one still holds its lock"
    )]
    EndpointNotReplaced(PathBuf),
    #[error("the running native supervisor does not implement the required compatibility protocol")]
    SupervisorProtocolUnavailable,
    #[error("{}", crate::supervisor_config::unsupported_protocol_message(*.actual))]
    SupervisorProtocolMismatch { expected: u32, actual: u32 },
    #[error("the running native supervisor returned invalid compatibility information")]
    InvalidSupervisorInfo,
    #[error("query running native supervisor compatibility failed")]
    SupervisorInfoUnavailable,
    #[error("the running native supervisor uses a different runtime configuration")]
    SupervisorConfigurationMismatch,
    #[error("the local VM supervisor is handing this state root to a newer cw")]
    Retiring,
    #[error("local environment {0:?} may still run a VM, so the local VM supervisor stays")]
    RetireRefused(String),
    #[error("the local network policy store could not be opened: {0}")]
    NetworkPolicyStore(String),
    #[error("{0}")]
    NetworkPolicySelection(String),
    #[error("spawn native environment runner failed")]
    SpawnRunner,
    #[error("native environment runner startup timed out")]
    RunnerStartTimeout,
    #[error("native environment runner adoption failed")]
    RunnerAdoption,
    #[error("native environment runner is unavailable")]
    RunnerUnavailable,
    #[error(
        "the retained native runner uses an unsupported protocol; inspect its boot assets before an explicit restart, or use stop/delete for cleanup"
    )]
    RunnerProtocolUnsupported,
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
    #[error(
        "Docker is enabled but the workspace image has no Docker tooling (dockerd, xtables-nft-multi); create with --no-docker or choose an image that includes Docker"
    )]
    GuestDockerToolingMissing,
    #[error(
        "the VM could not install the workspace image (guest setup failed); try another image or a current release of it"
    )]
    GuestSetupFailed,
    #[error("the workspace could not start inside the VM (guest workspace startup failed)")]
    GuestWorkspaceFailed,
    #[error(
        "a host port this environment publishes on 127.0.0.1 is in use by another program or local environment; stop it, or publish a different host port"
    )]
    HostPortUnavailable,
    #[cfg(target_os = "macos")]
    #[error("macOS refused to start the VM (Virtualization.framework)")]
    VmStartRefused,
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
    /// A runtime artifact store directory is not this user's own with mode
    /// 0700 (#3271). `location` names which, as a name compiled into this
    /// binary; the CLI reads the directories to name the path and modes.
    #[error("runtime artifact store directory {location} is not private")]
    UnsafeRuntimeArtifactStore { location: &'static str },
    #[error(transparent)]
    CwRuntime(#[from] CwRuntimeError),
    #[error("cw runtime catalog preparation task failed")]
    CwRuntimeProvisionTask,
    #[error("{0}")]
    ReplacementPreflight(Box<SupervisorError>),
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
/// A runtime artifact store failure as a supervisor error, keeping which
/// store directory was not private (#3271) and nothing else of its text.
fn artifact_store_error(
    error: crate::artifact_store::RuntimeArtifactStoreError,
) -> SupervisorError {
    match crate::artifact_store::unsafe_store_location(&error) {
        Some(location) => SupervisorError::UnsafeRuntimeArtifactStore { location },
        None => SupervisorError::ArtifactStore,
    }
}

/// The operation error code for a runtime artifact store directory that is
/// not private, whichever operation met it (#3271).
const UNSAFE_RUNTIME_ARTIFACT_STORE_CODE: &str =
    crate::supervisor_client::UNSAFE_RUNTIME_ARTIFACT_STORE_ERROR_CODE;

fn create_failure_code(error: &SupervisorError) -> &'static str {
    match error {
        SupervisorError::UnsafeRuntimeArtifactStore { .. } => UNSAFE_RUNTIME_ARTIFACT_STORE_CODE,
        SupervisorError::AlreadyExists(_) => "create_name_taken",
        SupervisorError::GuestDockerToolingMissing => "create_guest_docker_tooling_missing",
        SupervisorError::GuestSetupFailed => "create_guest_setup_failed",
        SupervisorError::GuestWorkspaceFailed => "create_guest_workspace_failed",
        SupervisorError::HostPortUnavailable => "create_host_port_unavailable",
        #[cfg(target_os = "macos")]
        SupervisorError::VmStartRefused => "create_vm_start_refused",
        #[cfg(target_os = "macos")]
        SupervisorError::VzHelperMissing(_) => "create_vz_helper_missing",
        #[cfg(target_os = "macos")]
        SupervisorError::VzHelperUnentitled(_) => "create_vz_helper_unentitled",
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
        SupervisorError::WorkspacePlan(WorkspacePlanError::DirectShareChanged) => {
            "create_direct_share_changed"
        }
        SupervisorError::SkillSnapshot(_) => "create_skill_snapshot",
        SupervisorError::WorkspaceGenerationProvisionTask => "create_workspace_generation_task",
        SupervisorError::WorkspaceGeneration => "create_workspace_generation_invalid",
        SupervisorError::ContentStore(_) => "create_content_store",
        SupervisorError::Path(_) | SupervisorError::Io { .. } => "create_filesystem",
        SupervisorError::InvalidState => "create_state_invalid",
        SupervisorError::InvalidConfiguration => "create_configuration_invalid",
        SupervisorError::Workspace(WorkspaceError::NestedRepositoryTracked { .. }) => {
            "create_nested_repository_tracked"
        }
        _ => "create_failed",
    }
}

/// The closed cause class of a failed lifecycle effect (#2595). Like
/// [`create_failure_code`], it names the error, never its Display, Debug or
/// source chain, so no path, upstream text or secret value reaches the journal
/// or the log. Every cause is a `[a-z_]` token of at most
/// [`MAXIMUM_LIFECYCLE_CAUSE_BYTES`], so `<operation prefix>_<cause>` stays a
/// valid journal error code. The match is exhaustive: a new error variant must
/// be named here.
/// A Stop payload is exactly `{"name"}`, or `{"name", "discard_for_checkpoint"}`
/// for one the checkpoint service admitted for a restore (#3046): `Some` with
/// whether the guest's state is discarded, `None` for any other shape.
fn stop_payload_checkpoint(payload: &serde_json::Value, name: &str) -> Option<bool> {
    let fields = payload.as_object()?;
    if fields.get("name").and_then(serde_json::Value::as_str) != Some(name) {
        return None;
    }
    match fields.len() {
        1 => Some(false),
        2 => fields
            .get("discard_for_checkpoint")
            .and_then(serde_json::Value::as_str)
            .and_then(|id| Uuid::parse_str(id).ok())
            .filter(|id| !id.is_nil())
            .map(|_| true),
        _ => None,
    }
}

/// Logs how long one lifecycle effect took, so a slow create, start, restore
/// or fork shows which effect spent the time (#3046). Closed names and a
/// duration only.
fn log_effect_timing(
    log: Option<&DiagnosticLog>,
    operation: &OperationRecord,
    effect: &'static str,
    started: std::time::Instant,
) {
    let mut fields = vec![
        ("kind", LogField::Name(operation.kind.as_str())),
        ("operation", LogField::Id(operation.operation_id)),
        ("effect", LogField::Name(effect)),
    ];
    if let Some(environment_id) = operation.environment_id {
        fields.push(("environment", LogField::Id(environment_id)));
    }
    fields.push((
        "elapsed_ms",
        LogField::Count(u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)),
    ));
    diagnostic_log::record(log, "operation_effect", &fields);
}

fn lifecycle_failure_cause(error: &SupervisorError) -> &'static str {
    match error {
        SupervisorError::InvalidConfiguration => "invalid_configuration",
        SupervisorError::SocketDir(_) => "socket_dir_unavailable",
        SupervisorError::SupervisorNotReachable { .. } => "supervisor_not_reachable",
        SupervisorError::SocketPathTooLong { .. } => "socket_path_too_long",
        #[cfg(target_os = "macos")]
        SupervisorError::VzHelperMissing(_) => "vz_helper_missing",
        #[cfg(target_os = "macos")]
        SupervisorError::VzHelperUnentitled(_) => "vz_helper_unentitled",
        SupervisorError::InvalidRequest => "invalid_request",
        SupervisorError::AlreadyExists(_) => "already_exists",
        SupervisorError::InvalidState => "invalid_state",
        SupervisorError::SecretInState => "secret_in_state",
        SupervisorError::CredentialAuthorityUnavailable => "credential_authority_unavailable",
        SupervisorError::WorkloadSecretDeliveryUnavailable => {
            "workload_secret_delivery_unavailable"
        }
        SupervisorError::EnvironmentAccessUnavailable => "access_unavailable",
        SupervisorError::EnvironmentAccessBindingRejected(code) => match code {
            tonic::Code::InvalidArgument => "access_binding_invalid",
            tonic::Code::NotFound => "access_binding_not_found",
            tonic::Code::PermissionDenied | tonic::Code::Unauthenticated => "access_binding_denied",
            tonic::Code::FailedPrecondition => "access_binding_precondition",
            tonic::Code::DataLoss => "access_binding_metadata",
            _ => "access_binding_rejected",
        },
        SupervisorError::NotFound(_) => "not_found",
        SupervisorError::NotRunning => "not_running",
        SupervisorError::Orphaned => "orphaned",
        SupervisorError::AlreadyRunning => "already_running",
        SupervisorError::SpawnSupervisor => "supervisor_spawn",
        SupervisorError::SupervisorStartTimeout => "supervisor_start_timeout",
        SupervisorError::EndpointNotReplaced(_) => "endpoint_not_replaced",
        SupervisorError::SupervisorProtocolUnavailable => "supervisor_protocol_unavailable",
        SupervisorError::SupervisorProtocolMismatch { .. } => "supervisor_protocol_mismatch",
        SupervisorError::InvalidSupervisorInfo => "supervisor_info_invalid",
        SupervisorError::SupervisorInfoUnavailable => "supervisor_info_unavailable",
        SupervisorError::SupervisorConfigurationMismatch => "supervisor_configuration_mismatch",
        SupervisorError::Retiring => "supervisor_retiring",
        SupervisorError::RetireRefused(_) => "supervisor_retire_refused",
        SupervisorError::NetworkPolicyStore(_) => "supervisor_network_policy_store",
        SupervisorError::NetworkPolicySelection(_) => "network_policy_selection",
        SupervisorError::SpawnRunner => "runner_spawn",
        SupervisorError::RunnerStartTimeout => "runner_start_timeout",
        SupervisorError::RunnerAdoption => "runner_adoption",
        SupervisorError::RunnerUnavailable => "runner_unavailable",
        SupervisorError::RunnerProtocolUnsupported => "runner_protocol_unsupported",
        SupervisorError::RunnerExitTimeout => "runner_exit_timeout",
        SupervisorError::RunnerRetirement => "runner_retirement",
        SupervisorError::InvalidRunnerResponse => "runner_response_invalid",
        SupervisorError::ArtifactGenerationChanged => "artifact_generation_changed",
        SupervisorError::VmStart(_) => "vm_start",
        SupervisorError::GuestDockerToolingMissing => "guest_docker_tooling_missing",
        SupervisorError::GuestSetupFailed => "guest_setup_failed",
        SupervisorError::GuestWorkspaceFailed => "guest_workspace_failed",
        SupervisorError::HostPortUnavailable => "host_port_unavailable",
        #[cfg(target_os = "macos")]
        SupervisorError::VmStartRefused => "vm_start_refused",
        SupervisorError::VmStop => "vm_stop",
        SupervisorError::VmResize => "vm_resize",
        SupervisorError::VmDelete => "vm_delete",
        SupervisorError::WorkspaceProvisionTask => "workspace_provision_task",
        SupervisorError::WorkspaceGenerationProvisionTask => "workspace_generation_task",
        SupervisorError::OperationTerminal => "operation_terminal",
        SupervisorError::Serve => "serve",
        SupervisorError::Runner(_) => "runner",
        SupervisorError::Artifact(_) => "artifact",
        SupervisorError::ArtifactStore | SupervisorError::UnsafeRuntimeArtifactStore { .. } => {
            "artifact_store"
        }
        SupervisorError::CwRuntime(_) => "cw_runtime",
        SupervisorError::CwRuntimeProvisionTask => "cw_runtime_task",
        SupervisorError::ReplacementPreflight(_) => "replacement_preflight",
        SupervisorError::RunnerService(_) => "runner_service",
        SupervisorError::Recovery(_) => "process_recovery",
        SupervisorError::Workspace(_) => "workspace",
        SupervisorError::WorkspacePlan(WorkspacePlanError::DirectShareChanged) => {
            "direct_share_changed"
        }
        SupervisorError::WorkspacePlan(_) => "workspace_plan",
        SupervisorError::RegistryReference(_) => "registry_reference",
        SupervisorError::RegistryResolver(_) => "registry",
        SupervisorError::ContentStore(_) => "content_store",
        SupervisorError::SetupPack(_) => "setup_pack",
        SupervisorError::SkillSnapshot(_) => "skill_snapshot",
        SupervisorError::WorkspaceGeneration => "workspace_generation",
        SupervisorError::Generation(_) => "root_generation",
        SupervisorError::Uds(_) => "local_socket",
        SupervisorError::Path(_) => "path",
        SupervisorError::State(_) => "vm_state",
        SupervisorError::Store(_) => "store",
        SupervisorError::Io { .. } => "filesystem",
    }
}

const MAXIMUM_LIFECYCLE_CAUSE_BYTES: usize = 40;

/// The journal error code `<prefix>_<cause>` of a failed lifecycle operation.
/// A failed VM start names the runner's own closed code (for example
/// `guest_start_failed`) when the runner reported one.
fn lifecycle_failure_code(
    prefix: &str,
    error: &SupervisorError,
    runner_error_code: Option<&str>,
) -> String {
    if matches!(error, SupervisorError::UnsafeRuntimeArtifactStore { .. }) {
        return UNSAFE_RUNTIME_ARTIFACT_STORE_CODE.to_owned();
    }
    let cause = match (error, runner_error_code) {
        (SupervisorError::VmStart(_), Some(code))
            if runner_event_error_code_valid(code)
                && code.len() <= MAXIMUM_LIFECYCLE_CAUSE_BYTES =>
        {
            code
        }
        _ => lifecycle_failure_cause(error),
    };
    let code = format!("{prefix}_{cause}");
    if runner_event_error_code_valid(&code) {
        code
    } else {
        format!("{prefix}_failed")
    }
}

impl SupervisorError {
    /// Nothing listens on the supervisor endpoint.
    fn refused_connection(&self) -> bool {
        let mut cause: Option<&(dyn std::error::Error + 'static)> = Some(self);
        while let Some(error) = cause {
            if error
                .downcast_ref::<io::Error>()
                .is_some_and(|error| error.kind() == io::ErrorKind::ConnectionRefused)
            {
                return true;
            }
            cause = error.source();
        }
        false
    }

    fn incompatible_supervisor(&self) -> bool {
        matches!(
            self,
            Self::SupervisorProtocolUnavailable
                | Self::SupervisorProtocolMismatch { .. }
                | Self::InvalidSupervisorInfo
                | Self::SupervisorInfoUnavailable
                | Self::SupervisorConfigurationMismatch
                | Self::Uds(UdsError::SupervisorPeerAdmission(_))
        )
    }
}

impl From<WorkspaceGenerationError> for SupervisorError {
    fn from(_: WorkspaceGenerationError) -> Self {
        Self::WorkspaceGeneration
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod runner_exit_tests;

#[cfg(test)]
mod retire_tests;

/// `GetOperation` by request ID (#3609, protocol 22).
#[cfg(test)]
mod operation_lookup_tests;

#[cfg(test)]
mod platform_github_tests;

#[cfg(test)]
mod download_cache_tests;

/// Operations on one environment never wait on another's (#2978).
#[cfg(test)]
mod concurrency_tests;
