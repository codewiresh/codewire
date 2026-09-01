use std::fmt;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream as StdUnixStream;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use codewire_daemon::client::{SessionClient, v1 as daemon_v1};
use codewire_vmm_guest_probe::{
    GUEST_NETWORK_VSOCK_PORT, GUEST_PROGRESS_VSOCK_PORT, GuestBootStage, NetworkKey,
    PROGRESS_CHALLENGE_LEN, PROGRESS_FRAME_LEN, ProgressFrame, ProgressRequest, Seed, SetupBinding,
    guest::CONTAINER_INIT_PATH,
};
use rand::{RngCore, rngs::OsRng};
use rustix::process::Signal;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::artifact::{AdmittedArtifacts, ArtifactError, ArtifactLock};
use crate::ch_api::{ChApiClient, ChApiError};
use crate::cloud_hypervisor::{CloudHypervisorConfig, CloudHypervisorConfigError, CommandSpec};
use crate::hybrid_vsock::{HybridVsockError, HybridVsockTarget};
use crate::network_worker::{
    NETWORK_BOOTSTRAP_FD, NetworkWorkerStartupFailure, NetworkWorkerStartupStatus,
    WORKER_PREPARED_MESSAGE, WORKER_STATUS_MAX_BYTES, decode_worker_startup_status,
    encode_worker_bootstrap, send_worker_network_descriptor,
};

use super::confinement::lock_process_privileges;
use super::path::{FileIdentity, PathError, PrivateRoot, set_socket_private};
use super::preflight::{PreflightError, PreflightReport, preflight};
use super::process::{LiveProcess, RecoveryError, signal_unreaped_child};
use super::state::{
    MINIMUM_ROOT_DISK_BYTES, MINIMUM_STATE_DISK_BYTES, PERSISTED_STATE_SCHEMA_VERSION,
    PersistedVmState, RootGenerationPaths, StateDiskIdentity, StateError, VmLock, VmPaths, VmPhase,
    publish_seed, valid_root_generation,
};

const START_TIMEOUT: Duration = Duration::from_secs(10);
const GUEST_POWEROFF_TIMEOUT: Duration = Duration::from_secs(10);
const GRACEFUL_STOP_TIMEOUT: Duration = Duration::from_secs(5);
const SIGNAL_STOP_TIMEOUT: Duration = Duration::from_secs(2);
const NETWORK_WORKER_RETRY_DELAY: Duration = Duration::from_millis(50);
const NETWORK_WORKER_READY_TIMEOUT: Duration = Duration::from_secs(5);
const NETWORK_WORKER_ATTACH_TIMEOUT: Duration = Duration::from_secs(10);
const NETWORK_WORKER_PROGRESS_FRAME_LIMIT: usize = 64;
const NETWORK_WORKER_HANDSHAKE_ATTEMPT_LIMIT: usize = 8;
const E2FSCK: &str = "/usr/bin/e2fsck";
const RESIZE2FS: &str = "/usr/bin/resize2fs";

#[derive(Debug, Clone)]
pub struct RunnerConfig {
    pub state_root: PathBuf,
    pub artifact_root: PathBuf,
    pub artifact_lock: PathBuf,
}

#[derive(Debug, Clone)]
pub struct CreateVmRequest {
    pub vm_id: Uuid,
    pub generation: u64,
    pub vsock_cid: u32,
    pub daemon_vsock_port: u32,
    pub state_disk_bytes: u64,
    pub root_generation: String,
    pub root_disk_bytes: u64,
    pub vcpus: u8,
    pub memory_mib: u32,
    pub setup: Option<SetupBinding>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SetupDiskIdentity {
    path: PathBuf,
    file: FileIdentity,
}

pub struct CloudHypervisorRunner {
    state_root: PrivateRoot,
    artifacts: AdmittedArtifacts,
}

impl fmt::Debug for CloudHypervisorRunner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CloudHypervisorRunner")
            .field("state_root", &self.state_root.path())
            .field("artifacts", &self.artifacts)
            .finish()
    }
}

impl CloudHypervisorRunner {
    pub async fn new(config: RunnerConfig) -> Result<Self, RunnerError> {
        if config.artifact_lock.parent().is_none()
            || config.artifact_lock.parent() != config.artifact_root.parent()
        {
            return Err(RunnerError::InvalidArtifactStagingLayout);
        }
        let artifact_lock = ArtifactLock::read(&config.artifact_lock)?;
        let artifacts = artifact_lock.admit(&config.artifact_root).await?;
        Self::from_admitted(config.state_root, artifacts)
    }

    pub(crate) fn from_admitted(
        state_root: PathBuf,
        artifacts: AdmittedArtifacts,
    ) -> Result<Self, RunnerError> {
        let state_root = match PrivateRoot::open(&state_root) {
            Ok(root) => root,
            Err(PathError::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => {
                PrivateRoot::create(&state_root)?
            }
            Err(error) => return Err(error.into()),
        };
        Ok(Self {
            state_root,
            artifacts,
        })
    }

    pub fn preflight(&self) -> Result<PreflightReport, RunnerError> {
        preflight().map_err(RunnerError::from)
    }

    /// Reopen the admitted product initramfs and return its exact static
    /// BusyBox payload for a credential-free OCI setup fixture.
    pub fn read_sealed_guest_busybox(&self) -> Result<Vec<u8>, RunnerError> {
        self.artifacts
            .read_guest_busybox()
            .map_err(RunnerError::from)
    }

    pub async fn prepare(&self, request: CreateVmRequest) -> Result<PreparedVm, RunnerError> {
        preflight()?;
        validate_request(&request)?;
        let paths = VmPaths::create(&self.state_root, request.vm_id)?;
        let lock = paths.lock()?;
        let persisted = read_stopped_persisted_state(&paths, request.vm_id)?;
        let state_disk = admit_state_disk(&paths, &request, persisted.as_ref())?;
        let (root_disk_path, root_disk) = admit_root_disk(&paths, &request, persisted.as_ref())?;
        let setup_disk = admit_setup_disk(&paths, &request)?;
        paths.clear_stale_runtime_endpoints()?;

        let token = Zeroizing::new(generate_auth_token());
        let seed = match request.setup {
            Some(setup) => Seed::new_with_setup(
                request.vm_id,
                request.generation,
                request.daemon_vsock_port,
                token.to_string(),
                setup,
            )?,
            None => Seed::new(
                request.vm_id,
                request.generation,
                request.daemon_vsock_port,
                token.to_string(),
            )?,
        };
        publish_seed(&paths.seed_disk, &seed.encode())?;
        paths.prepare_diagnostics()?;

        let config = match &setup_disk {
            Some(setup) => CloudHypervisorConfig::new_with_setup(
                &self.artifacts,
                paths.state_disk.clone(),
                root_disk_path,
                paths.seed_disk.clone(),
                setup.path.clone(),
                paths.api_socket.clone(),
                paths.event_monitor.clone(),
                paths.vsock_socket.clone(),
                paths.serial_log.clone(),
                paths.vmm_log.clone(),
                request.vsock_cid,
                request.vcpus,
                request.memory_mib,
            )?,
            None => CloudHypervisorConfig::new(
                &self.artifacts,
                paths.state_disk.clone(),
                root_disk_path,
                paths.seed_disk.clone(),
                paths.api_socket.clone(),
                paths.event_monitor.clone(),
                paths.vsock_socket.clone(),
                paths.serial_log.clone(),
                paths.vmm_log.clone(),
                request.vsock_cid,
                request.vcpus,
                request.memory_mib,
            )?,
        };
        let command = config.command()?;
        Ok(PreparedVm {
            request,
            paths,
            state_disk,
            root_disk,
            setup_disk,
            token,
            command,
            lock,
        })
    }

    pub async fn start(&self, prepared: PreparedVm) -> Result<RunningVm, RunnerError> {
        preflight()?;
        self.artifacts.revalidate()?;
        prepared.state_disk.revalidate(&prepared.paths.state_disk)?;
        prepared.root_disk.revalidate(&root_disk_path(
            &prepared.paths,
            &prepared.request.root_generation,
        )?)?;
        if let Some(setup) = &prepared.setup_disk {
            revalidate_setup_disk(setup, prepared.request.setup)?;
        }
        validate_seed_file(&prepared.paths.seed_disk)?;
        // Arm cancellation cleanup in the same synchronous span as spawn. An
        // aborted start future must never drop the VM lock while leaving a VMM
        // alive, including before a pidfd identity has been admitted.
        let mut startup = StartupOwnership::new(spawn_cloud_hypervisor(
            &prepared.command,
            &prepared.paths.vm_dir,
        )?);
        let pid = startup.child_mut().id().ok_or(RunnerError::Spawn)?;
        let process = match LiveProcess::capture_child(pid, prepared.command.program()) {
            Ok(process) => process,
            Err(error) => {
                startup.terminate_unadmitted(pid).await?;
                return Err(error.into());
            }
        };
        startup.admit(process);

        // Persist the process identity before waiting on any guest-created
        // endpoint. If the supervisor itself crashes during startup, recovery
        // can still prove which process owns this VM and terminate the orphan.
        let starting_state = PersistedVmState {
            schema_version: PERSISTED_STATE_SCHEMA_VERSION,
            vm_id: prepared.request.vm_id,
            generation: prepared.request.generation,
            vsock_cid: prepared.request.vsock_cid,
            daemon_vsock_port: prepared.request.daemon_vsock_port,
            phase: VmPhase::Starting,
            process: startup.process().identity().clone(),
            state_disk: prepared.state_disk.clone(),
            root_generation: Some(prepared.request.root_generation.clone()),
            root_disk: Some(prepared.root_disk.clone()),
            api_socket: None,
            vsock_socket: None,
        };
        if let Err(error) = starting_state.write_atomic(&prepared.paths.state_file) {
            startup.terminate_admitted().await?;
            return Err(error.into());
        }

        let finalized = async {
            let (api, hybrid) = wait_for_endpoints(
                &prepared.paths,
                startup.process(),
                prepared.request.daemon_vsock_port,
            )
            .await?;
            api.ping().await?;
            prepared.paths.validate_diagnostics()?;
            let persisted = PersistedVmState {
                schema_version: PERSISTED_STATE_SCHEMA_VERSION,
                vm_id: prepared.request.vm_id,
                generation: prepared.request.generation,
                vsock_cid: prepared.request.vsock_cid,
                daemon_vsock_port: prepared.request.daemon_vsock_port,
                phase: VmPhase::Running,
                process: startup.process().identity().clone(),
                state_disk: prepared.state_disk.clone(),
                root_generation: Some(prepared.request.root_generation.clone()),
                root_disk: Some(prepared.root_disk.clone()),
                api_socket: Some(set_socket_private(&prepared.paths.api_socket)?),
                vsock_socket: Some(set_socket_private(&prepared.paths.vsock_socket)?),
            };
            persisted.write_atomic(&prepared.paths.state_file)?;
            Ok::<_, RunnerError>((api, hybrid))
        }
        .await;
        let (api, hybrid) = match finalized {
            Ok(value) => value,
            Err(error) => {
                startup.terminate_admitted().await?;
                return Err(error);
            }
        };
        let (child, process) = startup.disarm();

        Ok(RunningVm {
            request: prepared.request,
            paths: prepared.paths,
            state_disk: prepared.state_disk,
            root_disk: prepared.root_disk,
            setup_disk: prepared.setup_disk,
            token: prepared.token,
            child,
            process,
            api,
            hybrid,
            network_worker: None,
            _lock: prepared.lock,
        })
    }

    pub fn recover(&self, vm_id: Uuid) -> Result<RecoveredVm, RunnerError> {
        let paths = VmPaths::create(&self.state_root, vm_id)?;
        let lock = paths.lock()?;
        let state = PersistedVmState::read(&paths.state_file)?;
        if state.vm_id != vm_id {
            return Err(RunnerError::PersistedIdentityMismatch);
        }
        state.state_disk.revalidate(&paths.state_disk)?;
        if let (Some(generation), Some(root_disk)) = (&state.root_generation, &state.root_disk) {
            root_disk.revalidate(&root_disk_path(&paths, generation)?)?;
        }
        if let Some(identity) = &state.api_socket {
            identity.revalidate(&paths.api_socket)?;
        }
        if let Some(identity) = &state.vsock_socket {
            identity.revalidate(&paths.vsock_socket)?;
        }
        let process = LiveProcess::recover(&state.process)?;
        let api = state
            .api_socket
            .as_ref()
            .map(|_| ChApiClient::new(&paths.api_socket))
            .transpose()?;
        Ok(RecoveredVm {
            paths,
            state,
            process,
            api,
            _lock: lock,
        })
    }

    /// Terminate the exact process recorded for a VM before best-effort test or
    /// supervisor cleanup. Unlike normal recovery, this path deliberately does
    /// not trust guest-mutable disk contents or require control sockets to
    /// remain present. The host-written state and exact process birth identity
    /// are still mandatory, and the per-VM lock prevents racing a live owner.
    pub async fn terminate_tracked_for_cleanup(
        &self,
        vm_id: Uuid,
    ) -> Result<Option<u64>, RunnerError> {
        let paths = VmPaths::create(&self.state_root, vm_id)?;
        let _lock = paths.lock()?;
        let state = match PersistedVmState::read(&paths.state_file) {
            Ok(state) => state,
            Err(error) if error.is_not_found() => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        if state.vm_id != vm_id {
            return Err(RunnerError::PersistedIdentityMismatch);
        }
        let generation = state.generation;
        let process = match LiveProcess::recover(&state.process) {
            Ok(process) => process,
            Err(RecoveryError::ReadProcess(error)) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(Some(generation));
            }
            Err(RecoveryError::ProcessExited | RecoveryError::IdentityMismatch) => {
                return Ok(Some(generation));
            }
            Err(error) => return Err(error.into()),
        };
        terminate_exact_process(&process, None).await?;
        Ok(Some(generation))
    }

    pub async fn grow_stopped_state_disk(
        &self,
        vm_id: Uuid,
        target_bytes: u64,
    ) -> Result<u64, RunnerError> {
        if target_bytes < MINIMUM_STATE_DISK_BYTES || !target_bytes.is_multiple_of(1024 * 1024) {
            return Err(RunnerError::InvalidDiskGrowth(target_bytes));
        }
        let paths = VmPaths::create(&self.state_root, vm_id)?;
        let _lock = paths.lock()?;
        let mut persisted = read_stopped_persisted_state(&paths, vm_id)?;
        let current = StateDiskIdentity::capture(&paths.state_disk)?;
        match plan_stopped_disk_growth(
            persisted.as_ref().map(|state| &state.state_disk),
            &current,
            target_bytes,
            &paths.state_disk,
        )? {
            StoppedDiskGrowthPlan::AlreadyComplete => return Ok(target_bytes),
            StoppedDiskGrowthPlan::ResizeFilesystem => {}
        }

        let disk_root = PrivateRoot::open(&paths.disks_dir)?;
        let disk = disk_root.open_regular(
            Path::new("state.raw"),
            true,
            Some(current.file.size),
            false,
            Some(0o600),
        )?;
        if current.file.size < target_bytes {
            disk.file()
                .set_len(target_bytes)
                .and_then(|()| disk.file().sync_all())
                .map_err(|source| RunnerError::Io {
                    path: paths.state_disk.clone(),
                    source,
                })?;
        }
        drop(disk);

        run_e2fsck(&paths.state_disk).await?;
        run_resize2fs(&paths.state_disk).await?;
        let updated = StateDiskIdentity::capture(&paths.state_disk)?;
        if updated.file.size != target_bytes || !same_disk_object_ignoring_size(&current, &updated)
        {
            return Err(RunnerError::StateDiskGrowthIdentityMismatch(
                paths.state_disk.clone(),
            ));
        }
        if let Some(state) = persisted.as_mut() {
            state.state_disk = updated;
            state.write_atomic(&paths.state_file)?;
        }
        Ok(target_bytes)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StoppedDiskGrowthPlan {
    AlreadyComplete,
    ResizeFilesystem,
}

fn plan_stopped_disk_growth(
    expected: Option<&StateDiskIdentity>,
    current: &StateDiskIdentity,
    target_bytes: u64,
    disk: &Path,
) -> Result<StoppedDiskGrowthPlan, RunnerError> {
    if let Some(expected) = expected {
        if !same_disk_object_ignoring_size(expected, current)
            || !matches!(current.file.size, size if size == expected.file.size || size == target_bytes)
        {
            return Err(RunnerError::StateDiskGrowthIdentityMismatch(
                disk.to_owned(),
            ));
        }
        if expected.file.size == target_bytes && current.file.size == target_bytes {
            return Ok(StoppedDiskGrowthPlan::AlreadyComplete);
        }
    }
    if current.file.size > target_bytes {
        return Err(RunnerError::DiskShrinkUnsupported {
            current: current.file.size,
            requested: target_bytes,
        });
    }
    Ok(StoppedDiskGrowthPlan::ResizeFilesystem)
}

fn same_disk_object_ignoring_size(
    expected: &StateDiskIdentity,
    actual: &StateDiskIdentity,
) -> bool {
    expected.filesystem_uuid == actual.filesystem_uuid
        && expected.file.device == actual.file.device
        && expected.file.inode == actual.file.inode
        && expected.file.uid == actual.file.uid
        && expected.file.mode == actual.file.mode
        && expected.file.links == actual.file.links
}

async fn run_e2fsck(disk: &Path) -> Result<(), RunnerError> {
    let status = tokio::process::Command::new(E2FSCK)
        .args(["-p", "-f"])
        .arg(disk)
        .env_clear()
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .map_err(|_| RunnerError::E2fsckUnavailable)?;
    if !matches!(status.code(), Some(0) | Some(1)) {
        return Err(RunnerError::E2fsckFailed(status.code()));
    }
    Ok(())
}

async fn run_resize2fs(disk: &Path) -> Result<(), RunnerError> {
    let status = tokio::process::Command::new(RESIZE2FS)
        .arg(disk)
        .env_clear()
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .map_err(|_| RunnerError::Resize2fsUnavailable)?;
    if !status.success() {
        return Err(RunnerError::Resize2fsFailed(status.code()));
    }
    Ok(())
}

/// Owns the just-spawned VMM until every fallible/cancellable startup step has
/// completed. `Drop` cannot wait, but it always sends an exact-child kill; the
/// Tokio process driver reaps a dropped child asynchronously. Synchronous error
/// paths additionally use the bounded cleanup helpers below before returning.
struct StartupOwnership {
    child: Option<tokio::process::Child>,
    process: Option<LiveProcess>,
}

impl StartupOwnership {
    fn new(child: tokio::process::Child) -> Self {
        Self {
            child: Some(child),
            process: None,
        }
    }

    fn child_mut(&mut self) -> &mut tokio::process::Child {
        self.child
            .as_mut()
            .expect("armed startup ownership always contains its child")
    }

    fn admit(&mut self, process: LiveProcess) {
        debug_assert!(self.process.is_none());
        self.process = Some(process);
    }

    fn process(&self) -> &LiveProcess {
        self.process
            .as_ref()
            .expect("admitted startup ownership always contains its process")
    }

    async fn terminate_unadmitted(&mut self, pid: u32) -> Result<(), RunnerError> {
        terminate_unadmitted_child(pid, self.child_mut()).await
    }

    async fn terminate_admitted(&mut self) -> Result<(), RunnerError> {
        let Self { child, process } = self;
        terminate_failed_launch(
            process
                .as_ref()
                .expect("admitted startup ownership always contains its process"),
            child
                .as_mut()
                .expect("armed startup ownership always contains its child"),
        )
        .await
    }

    fn disarm(mut self) -> (tokio::process::Child, LiveProcess) {
        let child = self
            .child
            .take()
            .expect("armed startup ownership always contains its child");
        let process = self
            .process
            .take()
            .expect("admitted startup ownership always contains its process");
        (child, process)
    }
}

impl Drop for StartupOwnership {
    fn drop(&mut self) {
        if let Some(process) = &self.process {
            let _ = process.signal(Signal::KILL);
        }
        if let Some(child) = self.child.as_mut() {
            // Before pidfd admission the unreaped Child pins this exact PID;
            // after admission this is a safe fallback for an exit/signal race.
            let _ = child.start_kill();
        }
    }
}

pub struct PreparedVm {
    request: CreateVmRequest,
    paths: VmPaths,
    state_disk: StateDiskIdentity,
    root_disk: StateDiskIdentity,
    setup_disk: Option<SetupDiskIdentity>,
    token: Zeroizing<String>,
    command: CommandSpec,
    lock: VmLock,
}

impl fmt::Debug for PreparedVm {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedVm")
            .field("request", &self.request)
            .field("paths", &self.paths)
            .field("state_disk", &self.state_disk)
            .field("root_disk", &self.root_disk)
            .field("setup_disk", &self.setup_disk)
            .field("token", &"[REDACTED]")
            .field("command", &self.command)
            .finish_non_exhaustive()
    }
}

impl PreparedVm {
    pub fn vm_id(&self) -> Uuid {
        self.request.vm_id
    }

    pub fn generation(&self) -> u64 {
        self.request.generation
    }

    pub fn paths(&self) -> &VmPaths {
        &self.paths
    }

    pub fn state_disk_identity(&self) -> &StateDiskIdentity {
        &self.state_disk
    }

    pub fn root_disk_identity(&self) -> &StateDiskIdentity {
        &self.root_disk
    }

    pub fn auth_token_fingerprint(&self) -> String {
        token_fingerprint(&self.token)
    }
}

pub struct RunningVm {
    request: CreateVmRequest,
    paths: VmPaths,
    state_disk: StateDiskIdentity,
    root_disk: StateDiskIdentity,
    setup_disk: Option<SetupDiskIdentity>,
    token: Zeroizing<String>,
    child: tokio::process::Child,
    process: LiveProcess,
    api: ChApiClient,
    hybrid: HybridVsockTarget,
    network_worker: Option<NetworkWorkerProcess>,
    _lock: VmLock,
}

impl fmt::Debug for RunningVm {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RunningVm")
            .field("request", &self.request)
            .field("paths", &self.paths)
            .field("state_disk", &self.state_disk)
            .field("root_disk", &self.root_disk)
            .field("setup_disk", &self.setup_disk)
            .field("process", &self.process)
            .field("token", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl RunningVm {
    pub fn vm_id(&self) -> Uuid {
        self.request.vm_id
    }

    pub fn generation(&self) -> u64 {
        self.request.generation
    }

    pub fn paths(&self) -> &VmPaths {
        &self.paths
    }

    pub fn process_identity(&self) -> &super::process::ProcessIdentity {
        self.process.identity()
    }

    pub fn state_disk_identity(&self) -> &StateDiskIdentity {
        &self.state_disk
    }

    pub fn root_disk_identity(&self) -> &StateDiskIdentity {
        &self.root_disk
    }

    pub fn api(&self) -> &ChApiClient {
        &self.api
    }

    pub fn auth_token_fingerprint(&self) -> String {
        token_fingerprint(&self.token)
    }

    pub async fn daemon_client(&self) -> Result<SessionClient, RunnerError> {
        self.hybrid
            .connect_daemon(self.token.as_str())
            .await
            .map_err(RunnerError::from)
    }

    pub async fn connect_daemon_with_token(
        &self,
        token: &str,
    ) -> Result<SessionClient, RunnerError> {
        self.hybrid
            .connect_daemon(token)
            .await
            .map_err(RunnerError::from)
    }

    pub(crate) fn daemon_access_parts(&self) -> (&Path, u32, &str) {
        (
            &self.hybrid.socket,
            self.hybrid.guest_port,
            self.token.as_str(),
        )
    }

    pub(crate) fn progress_access_parts(&self) -> (&HybridVsockTarget, &str) {
        (&self.hybrid, self.token.as_str())
    }

    /// Wait for an authenticated, allowlisted terminal guest boot stage. The
    /// generation token and progress transport remain private to the runner
    /// and are never exposed to diagnostics.
    pub async fn authenticated_guest_terminal_stage(
        &self,
        timeout: Duration,
    ) -> Result<GuestBootStage, RunnerError> {
        if timeout.is_zero() {
            return Err(RunnerError::NetworkWorkerStartTimeout);
        }
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            match wait_for_network_progress_attempt(
                &self.hybrid,
                self.token.as_str(),
                self.request.vm_id,
                self.request.generation,
                deadline,
                NetworkProgressGoal::Terminal,
            )
            .await
            {
                Ok(stage) => return Ok(stage),
                Err(NetworkProgressAttemptError::Retry)
                    if tokio::time::Instant::now() < deadline =>
                {
                    tokio::time::sleep(NETWORK_WORKER_RETRY_DELAY).await;
                }
                Err(NetworkProgressAttemptError::Retry | NetworkProgressAttemptError::Timeout) => {
                    return Err(RunnerError::NetworkWorkerStartTimeout);
                }
                Err(NetworkProgressAttemptError::Rejected) => {
                    return Err(RunnerError::NetworkWorkerBootstrap);
                }
            }
        }
    }

    /// Attach the isolated deny-by-default host network worker for this boot.
    /// The worker receives one already-connected hybrid-vsock descriptor and
    /// a derived key; it never receives the guest daemon token.
    pub async fn start_network_worker(
        &mut self,
        executable: &Path,
        timeout: Duration,
    ) -> Result<(), RunnerError> {
        if self.network_worker.is_some()
            || timeout.is_zero()
            || !executable.is_absolute()
            || std::fs::canonicalize(executable).ok().as_deref() != Some(executable)
            || !std::fs::metadata(executable).is_ok_and(|metadata| metadata.is_file())
        {
            return Err(RunnerError::InvalidNetworkWorker);
        }
        let readiness_deadline = tokio::time::Instant::now() + timeout;
        self.wait_for_network_guest_readiness(readiness_deadline)
            .await?;
        // Guest boot readiness and worker attachment are distinct bounded
        // phases. A slow but valid boot must not consume the worker's entire
        // handshake window, while setup boots must not turn attachment into a
        // multi-minute wait merely because their provisioning window is long.
        let deadline = tokio::time::Instant::now() + network_worker_attach_timeout(timeout);
        let mut handshake_attempts = 0_usize;
        let mut last_handshake_failure = None;
        loop {
            if self
                .child
                .try_wait()
                .map_err(|_| RunnerError::Wait)?
                .is_some()
            {
                return Err(last_handshake_failure.map_or(
                    RunnerError::ExitedDuringStart,
                    RunnerError::NetworkWorkerStartup,
                ));
            }
            let key = NetworkKey::derive(
                self.token.as_str(),
                self.request.vm_id,
                self.request.generation,
            )
            .map_err(|_| RunnerError::InvalidNetworkWorker)?;
            match spawn_network_worker_process(
                executable,
                &self.paths.vm_dir,
                &self.hybrid,
                key,
                self.request.vm_id,
                self.request.generation,
                deadline,
            )
            .await
            {
                Ok(worker) => {
                    self.network_worker = Some(worker);
                    return Ok(());
                }
                Err(RunnerError::NetworkWorkerStartup(
                    failure @ (NetworkWorkerStartupFailure::HelloWriteIo
                    | NetworkWorkerStartupFailure::HelloWriteTimeout
                    | NetworkWorkerStartupFailure::AcknowledgementReadIo
                    | NetworkWorkerStartupFailure::AcknowledgementReadTimeout),
                )) => {
                    handshake_attempts += 1;
                    last_handshake_failure = Some(failure);
                    if handshake_attempts >= NETWORK_WORKER_HANDSHAKE_ATTEMPT_LIMIT {
                        return Err(RunnerError::NetworkWorkerStartup(failure));
                    }
                    if tokio::time::Instant::now() >= deadline {
                        return Err(RunnerError::NetworkWorkerStartTimeout);
                    }
                    tokio::time::sleep(NETWORK_WORKER_RETRY_DELAY).await;
                }
                Err(error) => return Err(error),
            }
        }
    }

    async fn wait_for_network_guest_readiness(
        &mut self,
        deadline: tokio::time::Instant,
    ) -> Result<(), RunnerError> {
        loop {
            if self
                .child
                .try_wait()
                .map_err(|_| RunnerError::Wait)?
                .is_some()
            {
                return Err(RunnerError::ExitedDuringStart);
            }
            match wait_for_network_progress_attempt(
                &self.hybrid,
                self.token.as_str(),
                self.request.vm_id,
                self.request.generation,
                deadline,
                NetworkProgressGoal::NetworkReady,
            )
            .await
            {
                Ok(stage) if !stage.is_failure() => return Ok(()),
                Ok(_) => return Err(RunnerError::NetworkWorkerBootstrap),
                Err(NetworkProgressAttemptError::Retry)
                    if tokio::time::Instant::now() < deadline =>
                {
                    tokio::time::sleep(NETWORK_WORKER_RETRY_DELAY).await;
                }
                Err(NetworkProgressAttemptError::Retry | NetworkProgressAttemptError::Timeout) => {
                    return Err(RunnerError::NetworkWorkerStartTimeout);
                }
                Err(NetworkProgressAttemptError::Rejected) => {
                    return Err(RunnerError::NetworkWorkerBootstrap);
                }
            }
        }
    }

    pub fn network_worker_process_identity(&self) -> Option<&super::process::ProcessIdentity> {
        self.network_worker
            .as_ref()
            .map(|worker| worker.process.identity())
    }

    /// Unlink one-boot setup inputs after Cloud Hypervisor and the ready guest
    /// daemon both hold their admitted device handles. The token remains only
    /// in runner/guest memory and cannot be recovered from persistent state;
    /// a setup pack contains no credential material.
    pub fn discard_one_boot_inputs(&self) -> Result<(), RunnerError> {
        discard_one_boot_inputs(&self.paths, self.setup_disk.as_ref(), self.request.setup)
    }

    pub fn try_exit(&mut self) -> Result<ExitClass, RunnerError> {
        let vmm = match self.child.try_wait() {
            Ok(Some(status)) if status.success() => Ok(ExitClass::GuestShutdown),
            Ok(Some(status)) => Ok(ExitClass::VmmFailure(status.code())),
            Ok(None) => Ok(ExitClass::StillRunning),
            Err(_) => Err(RunnerError::Wait),
        }?;
        if vmm != ExitClass::StillRunning {
            return Ok(vmm);
        }
        match self.network_worker.as_mut() {
            Some(worker) => match worker.child.try_wait() {
                Ok(Some(status)) => Ok(ExitClass::NetworkWorkerFailure(status.code())),
                Ok(None) => Ok(ExitClass::StillRunning),
                Err(_) => Err(RunnerError::NetworkWorkerWait),
            },
            None => Ok(ExitClass::StillRunning),
        }
    }

    pub async fn wait_for_exit(&mut self, timeout: Duration) -> Result<ExitClass, RunnerError> {
        let exit = match tokio::time::timeout(timeout, self.child.wait()).await {
            Ok(Ok(status)) if status.success() => Ok(ExitClass::GuestShutdown),
            Ok(Ok(status)) => Ok(ExitClass::VmmFailure(status.code())),
            Ok(Err(_)) => Err(RunnerError::Wait),
            Err(_) => Ok(ExitClass::StillRunning),
        }?;
        if exit != ExitClass::StillRunning {
            self.stop_network_worker().await?;
        }
        Ok(exit)
    }

    pub async fn stop(&mut self) -> Result<ExitClass, RunnerError> {
        let vmm = self.stop_vmm().await;
        let worker = self.stop_network_worker().await;
        match (vmm, worker) {
            (Ok(exit), Ok(())) => Ok(exit),
            (Err(error), _) | (_, Err(error)) => Err(error),
        }
    }

    async fn stop_vmm(&mut self) -> Result<ExitClass, RunnerError> {
        // Ask trusted guest init to stop the daemon, sync the persistent state
        // filesystem, and power off. Keep the transient response stream alive
        // until the VMM exits so transport cancellation cannot kill the
        // poweroff helper before it signals PID 1.
        if let Ok(_poweroff_stream) = self.request_guest_poweroff().await
            && self.process.wait_exited(GUEST_POWEROFF_TIMEOUT).await?
        {
            return self.wait_reaped().await;
        }
        let _ = self.api.shutdown().await;
        if self.process.wait_exited(GRACEFUL_STOP_TIMEOUT).await? {
            return self.wait_reaped().await;
        }
        if signal_or_observe_exit(&self.process, Signal::TERM)?
            || self.process.wait_exited(SIGNAL_STOP_TIMEOUT).await?
        {
            return self.wait_reaped().await;
        }
        kill_and_reap(&self.process, &mut self.child).await
    }

    async fn stop_network_worker(&mut self) -> Result<(), RunnerError> {
        let Some(mut worker) = self.network_worker.take() else {
            return Ok(());
        };
        if worker
            .child
            .try_wait()
            .map_err(|_| RunnerError::NetworkWorkerWait)?
            .is_some()
        {
            return Ok(());
        }
        if worker.process.wait_exited(SIGNAL_STOP_TIMEOUT).await? {
            worker
                .child
                .wait()
                .await
                .map_err(|_| RunnerError::NetworkWorkerWait)?;
            return Ok(());
        }
        if !signal_or_observe_exit(&worker.process, Signal::TERM)?
            && !worker.process.wait_exited(SIGNAL_STOP_TIMEOUT).await?
            && !signal_or_observe_exit(&worker.process, Signal::KILL)?
            && !worker.process.wait_exited(SIGNAL_STOP_TIMEOUT).await?
        {
            return Err(RunnerError::NetworkWorkerKillTimeout);
        }
        worker
            .child
            .wait()
            .await
            .map_err(|_| RunnerError::NetworkWorkerWait)?;
        Ok(())
    }

    async fn request_guest_poweroff(
        &self,
    ) -> Result<tonic::Streaming<daemon_v1::ExecMessage>, RunnerError> {
        self.daemon_client()
            .await?
            .exec_transient(daemon_v1::ExecStartRequest {
                command: guest_poweroff_command(),
                working_dir: "/".to_owned(),
                env: Vec::new(),
            })
            .await
            .map_err(|_| RunnerError::GuestPoweroff)
    }

    pub async fn force_kill_for_test(&mut self) -> Result<ExitClass, RunnerError> {
        let exit = kill_and_reap(&self.process, &mut self.child).await;
        let worker = self.stop_network_worker().await;
        match (exit, worker) {
            (Ok(exit), Ok(())) => Ok(exit),
            (Err(error), _) | (_, Err(error)) => Err(error),
        }
    }

    async fn wait_reaped(&mut self) -> Result<ExitClass, RunnerError> {
        wait_reaped_child(&mut self.child).await
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NetworkProgressAttemptError {
    Retry,
    Timeout,
    Rejected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NetworkProgressGoal {
    NetworkReady,
    Terminal,
}

async fn wait_for_network_progress_attempt(
    hybrid: &HybridVsockTarget,
    token: &str,
    vm_id: Uuid,
    generation: u64,
    deadline: tokio::time::Instant,
    goal: NetworkProgressGoal,
) -> Result<GuestBootStage, NetworkProgressAttemptError> {
    let connected = tokio::time::timeout_at(
        deadline,
        hybrid.connect_guest_port(GUEST_PROGRESS_VSOCK_PORT),
    )
    .await
    .map_err(|_| NetworkProgressAttemptError::Timeout)?;
    let mut stream = match connected {
        Ok(stream) => stream,
        Err(
            HybridVsockError::InvalidSocketPath
            | HybridVsockError::InvalidGuestPort
            | HybridVsockError::SocketIdentity(_),
        ) => return Err(NetworkProgressAttemptError::Rejected),
        Err(_) => return Err(NetworkProgressAttemptError::Retry),
    };

    let mut challenge = [0_u8; PROGRESS_CHALLENGE_LEN];
    while challenge.iter().all(|byte| *byte == 0) {
        OsRng.fill_bytes(&mut challenge);
    }
    let request = ProgressRequest {
        vm_id,
        generation,
        challenge,
    };
    match tokio::time::timeout_at(deadline, async {
        stream.write_all(&request.encode()).await?;
        stream.flush().await
    })
    .await
    {
        Err(_) => return Err(NetworkProgressAttemptError::Timeout),
        Ok(Err(_)) => return Err(NetworkProgressAttemptError::Retry),
        Ok(Ok(())) => {}
    }

    let mut sequence = 0_u64;
    let mut stage = None;
    for _ in 0..NETWORK_WORKER_PROGRESS_FRAME_LIMIT {
        let mut bytes = [0_u8; PROGRESS_FRAME_LEN];
        match tokio::time::timeout_at(deadline, stream.read_exact(&mut bytes)).await {
            Err(_) => return Err(NetworkProgressAttemptError::Timeout),
            Ok(Err(_)) => return Err(NetworkProgressAttemptError::Retry),
            Ok(Ok(_)) => {}
        }
        let frame = ProgressFrame::decode(&bytes, &challenge, token, vm_id, generation)
            .map_err(|_| NetworkProgressAttemptError::Rejected)?;
        if frame.sequence <= sequence || stage.is_some_and(|previous| frame.stage < previous) {
            return Err(NetworkProgressAttemptError::Rejected);
        }
        sequence = frame.sequence;
        stage = Some(frame.stage);
        if frame.stage.is_failure()
            || match goal {
                NetworkProgressGoal::NetworkReady => {
                    frame.stage >= GuestBootStage::RootGenerationReady
                }
                NetworkProgressGoal::Terminal => frame.stage.is_terminal(),
            }
        {
            return Ok(frame.stage);
        }
    }
    Err(NetworkProgressAttemptError::Rejected)
}

fn network_worker_attach_timeout(requested: Duration) -> Duration {
    std::cmp::min(requested, NETWORK_WORKER_ATTACH_TIMEOUT)
}

struct NetworkWorkerProcess {
    child: tokio::process::Child,
    process: LiveProcess,
}

struct NetworkWorkerStartup {
    child: Option<tokio::process::Child>,
    process: Option<LiveProcess>,
}

impl NetworkWorkerStartup {
    fn new(child: tokio::process::Child) -> Self {
        Self {
            child: Some(child),
            process: None,
        }
    }

    fn child_mut(&mut self) -> &mut tokio::process::Child {
        self.child
            .as_mut()
            .expect("armed network worker startup owns its child")
    }

    fn admit(&mut self, process: LiveProcess) {
        self.process = Some(process);
    }

    fn disarm(mut self) -> NetworkWorkerProcess {
        NetworkWorkerProcess {
            child: self
                .child
                .take()
                .expect("admitted network worker owns its child"),
            process: self
                .process
                .take()
                .expect("admitted network worker owns its process identity"),
        }
    }
}

impl Drop for NetworkWorkerStartup {
    fn drop(&mut self) {
        if let Some(process) = &self.process {
            let _ = process.signal(Signal::KILL);
        }
        if let Some(child) = self.child.as_mut() {
            let _ = child.start_kill();
        }
    }
}

async fn reap_failed_network_worker_startup(
    startup: &mut NetworkWorkerStartup,
) -> Result<(), RunnerError> {
    if startup
        .child_mut()
        .try_wait()
        .map_err(|_| RunnerError::NetworkWorkerWait)?
        .is_some()
    {
        return Ok(());
    }
    let _ = startup.child_mut().start_kill();
    tokio::time::timeout(SIGNAL_STOP_TIMEOUT, startup.child_mut().wait())
        .await
        .map_err(|_| RunnerError::NetworkWorkerKillTimeout)?
        .map_err(|_| RunnerError::NetworkWorkerWait)?;
    Ok(())
}

async fn spawn_network_worker_process(
    executable: &Path,
    working_directory: &Path,
    hybrid: &HybridVsockTarget,
    key: NetworkKey,
    vm_id: Uuid,
    generation: u64,
    deadline: tokio::time::Instant,
) -> Result<NetworkWorkerProcess, RunnerError> {
    PrivateRoot::open(working_directory)?;
    let (bootstrap_parent, bootstrap_child) =
        StdUnixStream::pair().map_err(|_| RunnerError::NetworkWorkerSpawn)?;
    bootstrap_parent
        .set_nonblocking(true)
        .map_err(|_| RunnerError::NetworkWorkerSpawn)?;
    let mut bootstrap = tokio::net::UnixStream::from_std(bootstrap_parent)
        .map_err(|_| RunnerError::NetworkWorkerSpawn)?;
    let bytes = encode_worker_bootstrap(vm_id, generation, &key)
        .map_err(|_| RunnerError::NetworkWorkerBootstrap)?;
    let inherited_bootstrap = duplicate_inherited_descriptor(bootstrap_child.as_raw_fd())?;
    let bootstrap_fd = inherited_bootstrap.as_raw_fd();
    let expected_parent = unsafe { libc::getpid() };
    let mut command = tokio::process::Command::new(executable);
    command
        .arg("__native-network-worker")
        .arg("--environment-id")
        .arg(vm_id.to_string())
        .arg("--generation")
        .arg(generation.to_string())
        .env_clear()
        .current_dir(working_directory)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    unsafe {
        command.pre_exec(move || prepare_network_worker_child(expected_parent, bootstrap_fd));
    }
    let child = command
        .spawn()
        .map_err(|_| RunnerError::NetworkWorkerSpawn)?;
    drop(inherited_bootstrap);
    drop(bootstrap_child);
    let mut startup = NetworkWorkerStartup::new(child);
    let Some(pid) = startup.child_mut().id() else {
        reap_failed_network_worker_startup(&mut startup).await?;
        return Err(RunnerError::NetworkWorkerSpawn);
    };

    let bootstrap_write = tokio::time::timeout_at(deadline, async {
        bootstrap.write_all(bytes.as_ref()).await?;
        bootstrap.flush().await
    })
    .await;
    match bootstrap_write {
        Ok(Ok(())) => {}
        Err(_) => {
            reap_failed_network_worker_startup(&mut startup).await?;
            return Err(RunnerError::NetworkWorkerStartTimeout);
        }
        Ok(Err(_)) => {
            reap_failed_network_worker_startup(&mut startup).await?;
            return Err(RunnerError::NetworkWorkerBootstrap);
        }
    }

    let prepared_deadline = std::cmp::min(
        deadline,
        tokio::time::Instant::now() + NETWORK_WORKER_READY_TIMEOUT,
    );
    let prepared = match read_worker_status_frame(&mut bootstrap, prepared_deadline).await {
        Ok(prepared) => prepared,
        Err(error) => {
            let error = classify_network_worker_startup_error(&mut startup, error).await?;
            return Err(error);
        }
    };
    if prepared.as_slice() != WORKER_PREPARED_MESSAGE {
        if let Some(NetworkWorkerStartupStatus::Failed(failure)) =
            decode_worker_startup_status(&prepared)
        {
            reap_failed_network_worker_startup(&mut startup).await?;
            return Err(RunnerError::NetworkWorkerStartup(failure));
        }
        reap_failed_network_worker_startup(&mut startup).await?;
        return Err(RunnerError::NetworkWorkerBootstrap);
    }

    let process = match LiveProcess::capture_child(pid, executable) {
        Ok(process) => process,
        Err(error) => {
            reap_failed_network_worker_startup(&mut startup).await?;
            return Err(error.into());
        }
    };
    startup.admit(process);

    let network = loop {
        match startup.child_mut().try_wait() {
            Ok(Some(status)) => return Err(network_worker_exit_error(status)),
            Ok(None) => {}
            Err(_) => {
                reap_failed_network_worker_startup(&mut startup).await?;
                return Err(RunnerError::NetworkWorkerWait);
            }
        }
        let connection = tokio::time::timeout_at(
            deadline,
            hybrid.connect_guest_port(GUEST_NETWORK_VSOCK_PORT),
        )
        .await;
        match connection {
            Ok(Ok(network)) => break network,
            Ok(Err(
                HybridVsockError::InvalidSocketPath
                | HybridVsockError::InvalidGuestPort
                | HybridVsockError::SocketIdentity(_),
            )) => {
                reap_failed_network_worker_startup(&mut startup).await?;
                return Err(RunnerError::NetworkWorkerBootstrap);
            }
            Ok(Err(_)) if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(NETWORK_WORKER_RETRY_DELAY).await;
            }
            Ok(Err(_)) | Err(_) => {
                reap_failed_network_worker_startup(&mut startup).await?;
                return Err(RunnerError::NetworkWorkerStartTimeout);
            }
        }
    };
    let network = match network.into_std() {
        Ok(network) => network,
        Err(_) => {
            reap_failed_network_worker_startup(&mut startup).await?;
            return Err(RunnerError::NetworkWorkerBootstrap);
        }
    };
    let descriptor_transfer = tokio::time::timeout_at(deadline, async {
        loop {
            bootstrap.writable().await?;
            match send_worker_network_descriptor(bootstrap.as_raw_fd(), network.as_raw_fd()) {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                result => return result,
            }
        }
    })
    .await;
    drop(network);
    match descriptor_transfer {
        Ok(Ok(())) => {}
        Err(_) => {
            reap_failed_network_worker_startup(&mut startup).await?;
            return Err(RunnerError::NetworkWorkerStartTimeout);
        }
        Ok(Err(_)) => {
            reap_failed_network_worker_startup(&mut startup).await?;
            return Err(RunnerError::NetworkWorkerBootstrap);
        }
    }

    let status = match read_worker_status_frame(&mut bootstrap, deadline).await {
        Ok(status) => status,
        Err(error) => {
            let error = classify_network_worker_startup_error(&mut startup, error).await?;
            return Err(error);
        }
    };
    match decode_worker_startup_status(&status) {
        Some(NetworkWorkerStartupStatus::Ready) => {}
        Some(NetworkWorkerStartupStatus::Failed(failure)) => {
            reap_failed_network_worker_startup(&mut startup).await?;
            return Err(RunnerError::NetworkWorkerStartup(failure));
        }
        None => {
            reap_failed_network_worker_startup(&mut startup).await?;
            return Err(RunnerError::NetworkWorkerBootstrap);
        }
    }
    Ok(startup.disarm())
}

async fn read_worker_status_frame(
    stream: &mut tokio::net::UnixStream,
    deadline: tokio::time::Instant,
) -> Result<Vec<u8>, RunnerError> {
    let mut frame = Vec::with_capacity(WORKER_STATUS_MAX_BYTES);
    loop {
        if frame.len() == WORKER_STATUS_MAX_BYTES {
            return Err(RunnerError::NetworkWorkerBootstrap);
        }
        let mut byte = [0_u8; 1];
        let read = tokio::time::timeout_at(deadline, stream.read(&mut byte))
            .await
            .map_err(|_| RunnerError::NetworkWorkerStartTimeout)?
            .map_err(|_| RunnerError::NetworkWorkerBootstrap)?;
        if read == 0 {
            return Err(RunnerError::NetworkWorkerBootstrap);
        }
        frame.push(byte[0]);
        if byte[0] == b'\n' {
            return Ok(frame);
        }
        if byte[0] == b'\r' || !byte[0].is_ascii() {
            return Err(RunnerError::NetworkWorkerBootstrap);
        }
    }
}

async fn classify_network_worker_startup_error(
    startup: &mut NetworkWorkerStartup,
    fallback: RunnerError,
) -> Result<RunnerError, RunnerError> {
    let exit_deadline = tokio::time::Instant::now() + Duration::from_millis(100);
    loop {
        match startup.child_mut().try_wait() {
            Ok(Some(status)) => return Ok(network_worker_exit_error(status)),
            Ok(None) => {}
            Err(_) => return Err(RunnerError::NetworkWorkerWait),
        }
        if tokio::time::Instant::now() >= exit_deadline {
            reap_failed_network_worker_startup(startup).await?;
            return Ok(fallback);
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

fn network_worker_exit_error(status: std::process::ExitStatus) -> RunnerError {
    status
        .code()
        .and_then(NetworkWorkerStartupFailure::from_exit_code)
        .map_or(
            RunnerError::NetworkWorkerBootstrap,
            RunnerError::NetworkWorkerStartup,
        )
}

fn duplicate_inherited_descriptor(descriptor: i32) -> Result<OwnedFd, RunnerError> {
    let duplicated = unsafe { libc::fcntl(descriptor, libc::F_DUPFD_CLOEXEC, 10) };
    if duplicated == -1 {
        return Err(RunnerError::NetworkWorkerSpawn);
    }
    Ok(unsafe { OwnedFd::from_raw_fd(duplicated) })
}

fn prepare_network_worker_child(
    expected_parent: libc::pid_t,
    bootstrap_fd: RawFd,
) -> io::Result<()> {
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) } == -1
        || unsafe { libc::getppid() } != expected_parent
    {
        return Err(io::Error::last_os_error());
    }
    if unsafe {
        libc::syscall(
            libc::SYS_close_range,
            3_u32,
            u32::MAX,
            libc::CLOSE_RANGE_CLOEXEC,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    if bootstrap_fd != NETWORK_BOOTSTRAP_FD
        && unsafe { libc::dup2(bootstrap_fd, NETWORK_BOOTSTRAP_FD) } == -1
    {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(NETWORK_BOOTSTRAP_FD, libc::F_SETFD, 0) } == -1 {
        return Err(io::Error::last_os_error());
    }
    lock_process_privileges()
}

fn guest_poweroff_command() -> Vec<String> {
    vec![CONTAINER_INIT_PATH.to_owned(), "poweroff".to_owned()]
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitClass {
    StillRunning,
    GuestShutdown,
    VmmFailure(Option<i32>),
    NetworkWorkerFailure(Option<i32>),
}

async fn kill_and_reap(
    process: &LiveProcess,
    child: &mut tokio::process::Child,
) -> Result<ExitClass, RunnerError> {
    if !signal_or_observe_exit(process, Signal::KILL)?
        && !process.wait_exited(SIGNAL_STOP_TIMEOUT).await?
    {
        return Err(RunnerError::KillTimeout);
    }
    wait_reaped_child(child).await
}

async fn wait_reaped_child(child: &mut tokio::process::Child) -> Result<ExitClass, RunnerError> {
    let status = tokio::time::timeout(SIGNAL_STOP_TIMEOUT, child.wait())
        .await
        .map_err(|_| RunnerError::KillTimeout)?
        .map_err(|_| RunnerError::Wait)?;
    if status.success() {
        Ok(ExitClass::GuestShutdown)
    } else {
        Ok(ExitClass::VmmFailure(status.code()))
    }
}

pub struct RecoveredVm {
    paths: VmPaths,
    state: PersistedVmState,
    process: LiveProcess,
    api: Option<ChApiClient>,
    _lock: VmLock,
}

impl fmt::Debug for RecoveredVm {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoveredVm")
            .field("paths", &self.paths)
            .field("state", &self.state)
            .field("process", &self.process)
            .finish_non_exhaustive()
    }
}

impl RecoveredVm {
    pub fn state(&self) -> &PersistedVmState {
        &self.state
    }

    pub fn paths(&self) -> &VmPaths {
        &self.paths
    }

    /// A supervisor restart cannot recover the per-boot daemon token. An
    /// orphan is therefore terminated and booted with a fresh generation.
    pub async fn terminate_orphan(&self) -> Result<(), RunnerError> {
        terminate_exact_process(&self.process, self.api.as_ref()).await
    }
}

async fn terminate_exact_process(
    process: &LiveProcess,
    api: Option<&ChApiClient>,
) -> Result<(), RunnerError> {
    let graceful_timeout = if api.is_some() {
        GRACEFUL_STOP_TIMEOUT
    } else {
        Duration::from_millis(250)
    };
    if let Some(api) = api {
        let _ = api.shutdown().await;
    }
    if process.wait_exited(graceful_timeout).await? {
        return Ok(());
    }
    if signal_or_observe_exit(process, Signal::TERM)?
        || process.wait_exited(SIGNAL_STOP_TIMEOUT).await?
    {
        return Ok(());
    }
    if signal_or_observe_exit(process, Signal::KILL)? {
        return Ok(());
    }
    if !process.wait_exited(SIGNAL_STOP_TIMEOUT).await? {
        return Err(RunnerError::KillTimeout);
    }
    Ok(())
}

fn signal_or_observe_exit(process: &LiveProcess, signal: Signal) -> Result<bool, RunnerError> {
    match process.signal(signal) {
        Ok(()) => Ok(false),
        Err(RecoveryError::Pidfd(error)) if error == rustix::io::Errno::SRCH => Ok(true),
        Err(error) => Err(error.into()),
    }
}

fn validate_request(request: &CreateVmRequest) -> Result<(), RunnerError> {
    if request.vm_id.is_nil()
        || request.generation == 0
        || request.vsock_cid < 3
        || request.vsock_cid == u32::MAX
        || request.daemon_vsock_port == 0
        || request.daemon_vsock_port == u32::MAX
        || request.state_disk_bytes < MINIMUM_STATE_DISK_BYTES
        || !request.state_disk_bytes.is_multiple_of(1024 * 1024)
        || !valid_root_generation(&request.root_generation)
        || request.root_disk_bytes < MINIMUM_ROOT_DISK_BYTES
        || !request.root_disk_bytes.is_multiple_of(1024 * 1024)
        || request.vcpus == 0
        || request.vcpus > 32
        || !(128..=65_536).contains(&request.memory_mib)
    {
        return Err(RunnerError::InvalidRequest);
    }
    Ok(())
}

fn read_stopped_persisted_state(
    paths: &VmPaths,
    expected_vm_id: Uuid,
) -> Result<Option<PersistedVmState>, RunnerError> {
    let state = match PersistedVmState::read(&paths.state_file) {
        Ok(state) => state,
        Err(error) if error.is_not_found() => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if state.vm_id != expected_vm_id {
        return Err(RunnerError::PersistedIdentityMismatch);
    }
    match LiveProcess::recover(&state.process) {
        Ok(_) => Err(RunnerError::VmStillRunning),
        Err(RecoveryError::ReadProcess(error)) if error.kind() == io::ErrorKind::NotFound => {
            Ok(Some(state))
        }
        Err(RecoveryError::ProcessExited | RecoveryError::IdentityMismatch) => Ok(Some(state)),
        Err(error) => Err(error.into()),
    }
}

fn admit_state_disk(
    paths: &VmPaths,
    request: &CreateVmRequest,
    persisted: Option<&PersistedVmState>,
) -> Result<StateDiskIdentity, RunnerError> {
    if !paths.state_disk.exists() {
        return Err(RunnerError::MissingPreformattedStateDisk);
    }
    let state_disk = if let Some(state) = persisted {
        if request.generation <= state.generation {
            return Err(RunnerError::GenerationNotAdvanced {
                previous: state.generation,
                requested: request.generation,
            });
        }
        state.state_disk.revalidate(&paths.state_disk)?;
        state.state_disk.clone()
    } else {
        StateDiskIdentity::capture(&paths.state_disk)?
    };
    if state_disk.file.size != request.state_disk_bytes {
        return Err(RunnerError::StateDiskSizeMismatch {
            current: state_disk.file.size,
            requested: request.state_disk_bytes,
        });
    }
    Ok(state_disk)
}

fn admit_root_disk(
    paths: &VmPaths,
    request: &CreateVmRequest,
    persisted: Option<&PersistedVmState>,
) -> Result<(PathBuf, StateDiskIdentity), RunnerError> {
    let path = root_disk_path(paths, &request.root_generation)?;
    if !path.exists() {
        return Err(RunnerError::MissingPreformattedRootDisk);
    }
    let root_disk = match persisted {
        Some(state) if state.root_generation.as_deref() == Some(&request.root_generation) => {
            let expected = state
                .root_disk
                .as_ref()
                .ok_or(RunnerError::PersistedRootGenerationMismatch)?;
            expected.revalidate(&path)?;
            expected.clone()
        }
        _ => StateDiskIdentity::capture(&path)?,
    };
    if root_disk.file.size != request.root_disk_bytes {
        return Err(RunnerError::RootDiskSizeMismatch {
            current: root_disk.file.size,
            requested: request.root_disk_bytes,
        });
    }
    Ok((path, root_disk))
}

fn admit_setup_disk(
    paths: &VmPaths,
    request: &CreateVmRequest,
) -> Result<Option<SetupDiskIdentity>, RunnerError> {
    let Some(binding) = request.setup else {
        return Ok(None);
    };
    let generation = RootGenerationPaths::create(paths, &request.root_generation)?;
    let root = PrivateRoot::open(&generation.generation_dir)?;
    let opened = root.open_regular(
        Path::new("setup.raw"),
        false,
        Some(binding.total_bytes()),
        false,
        Some(0o400),
    )?;
    Ok(Some(SetupDiskIdentity {
        path: generation.setup_disk,
        file: opened.identity().clone(),
    }))
}

fn revalidate_setup_disk(
    expected: &SetupDiskIdentity,
    binding: Option<SetupBinding>,
) -> Result<(), RunnerError> {
    let binding = binding.ok_or(RunnerError::InvalidRequest)?;
    let parent = expected.path.parent().ok_or(RunnerError::InvalidRequest)?;
    let root = PrivateRoot::open(parent)?;
    let opened = root.open_regular(
        Path::new("setup.raw"),
        false,
        Some(binding.total_bytes()),
        false,
        Some(0o400),
    )?;
    if opened.identity() != &expected.file {
        return Err(RunnerError::SetupDiskIdentityChanged);
    }
    Ok(())
}

fn discard_one_boot_inputs(
    paths: &VmPaths,
    setup_disk: Option<&SetupDiskIdentity>,
    binding: Option<SetupBinding>,
) -> Result<(), RunnerError> {
    // A setup cleanup failure must never prevent the secret-bearing seed from
    // being unlinked. Preserve the first setup error for the caller after the
    // independent seed cleanup has been attempted.
    let setup_result = (|| {
        if let Some(setup) = setup_disk {
            revalidate_setup_disk(setup, binding)?;
            let setup_root =
                PrivateRoot::open(setup.path.parent().ok_or(RunnerError::InvalidRequest)?)?;
            if !setup_root.remove_private_regular(Path::new("setup.raw"), 0o400)? {
                return Err(RunnerError::MissingSetupAfterReadiness);
            }
        }
        Ok(())
    })();
    let seed_result = (|| {
        let seed_root = PrivateRoot::open(&paths.seed_dir)?;
        if !seed_root.remove_private_regular(Path::new("seed.raw"), 0o400)? {
            return Err(RunnerError::MissingSeedAfterReadiness);
        }
        Ok(())
    })();
    setup_result?;
    seed_result
}

fn root_disk_path(paths: &VmPaths, generation: &str) -> Result<PathBuf, RunnerError> {
    if !valid_root_generation(generation) {
        return Err(RunnerError::InvalidRequest);
    }
    Ok(paths.generations_dir.join(generation).join("root.raw"))
}

fn generate_auth_token() -> String {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    let mut token = String::with_capacity(64);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut token, "{byte:02x}");
    }
    token
}

fn token_fingerprint(token: &str) -> String {
    format!("{:x}", Sha256::digest(token.as_bytes()))
}

fn validate_seed_file(path: &Path) -> Result<(), RunnerError> {
    let parent = PrivateRoot::open(path.parent().ok_or(RunnerError::InvalidRequest)?)?;
    let name = path
        .file_name()
        .map(Path::new)
        .ok_or(RunnerError::InvalidRequest)?;
    parent.open_regular(name, false, Some(4096), false, Some(0o400))?;
    Ok(())
}

fn cloud_hypervisor_process(
    command: &CommandSpec,
    working_directory: &Path,
) -> Result<tokio::process::Command, RunnerError> {
    // Re-admit the cwd itself immediately before constructing the child. CH
    // must never inherit the supervisor's repository or arbitrary launch cwd,
    // which would also risk broadening its native Landlock file set.
    PrivateRoot::open(working_directory)?;
    // A real supervisor-process death must never strand an untracked VMM in
    // the spawn-to-state-write window. VM persistence is disk persistence for
    // this spike; a restarted supervisor reconciles and boots a new generation.
    // The child-side parent check closes the race where the parent dies before
    // PR_SET_PDEATHSIG is installed.
    // SAFETY: getpid has no preconditions and cannot fail on Linux.
    let expected_parent_pid = unsafe { libc::getpid() };
    let mut process = tokio::process::Command::new(command.program());
    process
        .args(command.arguments())
        .env_clear()
        .current_dir(working_directory)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // SAFETY: prctl, getppid, close_range through syscall, and umask are direct
    // libc operations with no Rust-managed state in the fork-to-exec interval.
    // The returned static OS errors do not run arbitrary code. close_range
    // applies CLOEXEC to every non-stdio descriptor so an eventual supervisor
    // cannot accidentally grant an already-open host capability to the VMM.
    // umask ensures every CH-created socket/log is private even when the
    // supervisor inherited a permissive shell umask.
    unsafe {
        process.pre_exec(move || {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::getppid() != expected_parent_pid {
                return Err(io::Error::from_raw_os_error(libc::ECHILD));
            }
            if libc::syscall(
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
    Ok(process)
}

fn spawn_cloud_hypervisor(
    command: &CommandSpec,
    working_directory: &Path,
) -> Result<tokio::process::Child, RunnerError> {
    cloud_hypervisor_process(command, working_directory)?
        .spawn()
        .map_err(|_| RunnerError::Spawn)
}

async fn terminate_failed_launch(
    process: &LiveProcess,
    child: &mut tokio::process::Child,
) -> Result<(), RunnerError> {
    if child.try_wait().map_err(|_| RunnerError::Wait)?.is_some() {
        return Ok(());
    }
    if process.signal(Signal::KILL).is_err() {
        // The unreaped Child still pins this exact PID, so Tokio's child-handle
        // signal is a safe fallback if the pidfd operation itself fails.
        child.start_kill().map_err(|_| RunnerError::Wait)?;
    }
    tokio::time::timeout(SIGNAL_STOP_TIMEOUT, child.wait())
        .await
        .map_err(|_| RunnerError::KillTimeout)?
        .map_err(|_| RunnerError::Wait)?;
    if !process.is_exited()? {
        return Err(RunnerError::KillTimeout);
    }
    Ok(())
}

async fn terminate_unadmitted_child(
    pid: u32,
    child: &mut tokio::process::Child,
) -> Result<(), RunnerError> {
    if child.try_wait().map_err(|_| RunnerError::Wait)?.is_some() {
        return Ok(());
    }
    if signal_unreaped_child(pid, Signal::KILL).is_err() {
        // A Child that has not been waited cannot relinquish its numeric PID,
        // so this fallback cannot target a replacement process.
        child.start_kill().map_err(|_| RunnerError::Wait)?;
    }
    tokio::time::timeout(SIGNAL_STOP_TIMEOUT, child.wait())
        .await
        .map_err(|_| RunnerError::KillTimeout)?
        .map_err(|_| RunnerError::Wait)?;
    Ok(())
}

async fn wait_for_endpoints(
    paths: &VmPaths,
    process: &LiveProcess,
    daemon_vsock_port: u32,
) -> Result<(ChApiClient, HybridVsockTarget), RunnerError> {
    wait_for_endpoints_with_timeout(paths, process, daemon_vsock_port, START_TIMEOUT).await
}

async fn wait_for_endpoints_with_timeout(
    paths: &VmPaths,
    process: &LiveProcess,
    daemon_vsock_port: u32,
    timeout: Duration,
) -> Result<(ChApiClient, HybridVsockTarget), RunnerError> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if process.is_exited()? {
            return Err(RunnerError::ExitedDuringStart);
        }
        if paths.api_socket.exists() && paths.vsock_socket.exists() {
            set_socket_private(&paths.api_socket)?;
            set_socket_private(&paths.vsock_socket)?;
            let api = ChApiClient::new(&paths.api_socket)?;
            let hybrid = HybridVsockTarget::new(paths.vsock_socket.clone(), daemon_vsock_port)?;
            return Ok((api, hybrid));
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(RunnerError::StartTimeout);
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RunnerError {
    #[error("invalid VM create request")]
    InvalidRequest,
    #[error(
        "artifact lock and artifact directory must be siblings beneath one canonical private parent"
    )]
    InvalidArtifactStagingLayout,
    #[error(transparent)]
    Artifact(#[from] ArtifactError),
    #[error(transparent)]
    Path(#[from] PathError),
    #[error(transparent)]
    State(#[from] StateError),
    #[error(transparent)]
    Preflight(#[from] PreflightError),
    #[error(transparent)]
    Recovery(#[from] RecoveryError),
    #[error(transparent)]
    Config(#[from] CloudHypervisorConfigError),
    #[error(transparent)]
    Api(#[from] ChApiError),
    #[error(transparent)]
    HybridVsock(#[from] HybridVsockError),
    #[error("guest seed is invalid")]
    Seed(#[from] codewire_vmm_guest_probe::SeedError),
    #[error("one-boot guest seed is missing after daemon readiness")]
    MissingSeedAfterReadiness,
    #[error("one-boot guest setup pack is missing after daemon readiness")]
    MissingSetupAfterReadiness,
    #[error("one-boot guest setup pack identity changed before VMM admission")]
    SetupDiskIdentityChanged,
    #[error("the preformatted ext4 state disk is absent; production prepare never formats disks")]
    MissingPreformattedStateDisk,
    #[error(
        "the preformatted ext4 root generation disk is absent; runner prepare never formats it"
    )]
    MissingPreformattedRootDisk,
    #[error(
        "existing state disk size differs from the requested immutable boot size ({current} != {requested}); resize is a separate stopped operation"
    )]
    StateDiskSizeMismatch { current: u64, requested: u64 },
    #[error(
        "existing root generation disk size differs from the requested immutable boot size ({current} != {requested})"
    )]
    RootDiskSizeMismatch { current: u64, requested: u64 },
    #[error("persisted root generation identity is incomplete or inconsistent")]
    PersistedRootGenerationMismatch,
    #[error("invalid state disk growth target {0}")]
    InvalidDiskGrowth(u64),
    #[error("state disk shrink is unsupported ({current} -> {requested})")]
    DiskShrinkUnsupported { current: u64, requested: u64 },
    #[error("state disk identity changed during growth: {0}")]
    StateDiskGrowthIdentityMismatch(PathBuf),
    #[error("/usr/bin/e2fsck is unavailable")]
    E2fsckUnavailable,
    #[error("e2fsck failed with status {0:?}")]
    E2fsckFailed(Option<i32>),
    #[error("/usr/bin/resize2fs is unavailable")]
    Resize2fsUnavailable,
    #[error("resize2fs failed with status {0:?}")]
    Resize2fsFailed(Option<i32>),
    #[error(
        "VM generation must advance beyond persisted generation {previous} (requested {requested})"
    )]
    GenerationNotAdvanced { previous: u64, requested: u64 },
    #[error("Cloud Hypervisor process spawn failed")]
    Spawn,
    #[error("Cloud Hypervisor exited during startup")]
    ExitedDuringStart,
    #[error("Cloud Hypervisor startup timed out")]
    StartTimeout,
    #[error("network worker executable or lifecycle state is invalid")]
    InvalidNetworkWorker,
    #[error("network worker process spawn failed")]
    NetworkWorkerSpawn,
    #[error("network worker did not attach before the guest startup deadline")]
    NetworkWorkerStartTimeout,
    #[error("network worker private bootstrap failed")]
    NetworkWorkerBootstrap,
    #[error("network worker startup failed: {0:?}")]
    NetworkWorkerStartup(NetworkWorkerStartupFailure),
    #[error("wait for network worker failed")]
    NetworkWorkerWait,
    #[error("network worker did not exit after pidfd SIGKILL")]
    NetworkWorkerKillTimeout,
    #[error("wait for Cloud Hypervisor failed")]
    Wait,
    #[error("Cloud Hypervisor did not exit after pidfd SIGKILL")]
    KillTimeout,
    #[error("authenticated guest poweroff request failed")]
    GuestPoweroff,
    #[error("VM is still running")]
    VmStillRunning,
    #[error("persisted VM identity does not match its directory")]
    PersistedIdentityMismatch,
    #[error("filesystem operation failed for {path}: {source}")]
    Io { path: PathBuf, source: io::Error },
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::{Seek, SeekFrom, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    use crate::artifact::AdmittedArtifact;
    use crate::linux::path::{FileIdentity, current_uid};
    use crate::linux::process::ProcessIdentity;
    use crate::linux::state::RootGenerationPaths;

    fn test_runner() -> (tempfile::TempDir, CloudHypervisorRunner) {
        let parent = tempfile::tempdir().unwrap();
        let state_path = parent.path().join("state");
        fs::create_dir(&state_path).unwrap();
        fs::set_permissions(&state_path, fs::Permissions::from_mode(0o700)).unwrap();
        let artifact = AdmittedArtifact::for_test("/nonexistent/test-artifact");
        let runner = CloudHypervisorRunner {
            state_root: PrivateRoot::open(&state_path).unwrap(),
            artifacts: AdmittedArtifacts {
                cloud_hypervisor: artifact.clone(),
                kernel: artifact.clone(),
                initramfs: artifact,
            },
        };
        (parent, runner)
    }

    fn persisted_starting_state(vm_id: Uuid, process: &LiveProcess) -> PersistedVmState {
        PersistedVmState {
            schema_version: PERSISTED_STATE_SCHEMA_VERSION,
            vm_id,
            generation: 1,
            vsock_cid: 7,
            daemon_vsock_port: 7_777,
            phase: VmPhase::Starting,
            process: process.identity().clone(),
            state_disk: StateDiskIdentity {
                file: FileIdentity {
                    device: 1,
                    inode: 2,
                    size: MINIMUM_STATE_DISK_BYTES,
                    uid: current_uid(),
                    mode: 0o100600,
                    links: 1,
                },
                filesystem_uuid: Uuid::new_v4(),
            },
            root_generation: None,
            root_disk: None,
            api_socket: None,
            vsock_socket: None,
        }
    }

    fn write_test_ext4(path: &Path, filesystem_uuid: Uuid) {
        let mut disk = fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        disk.set_len(MINIMUM_STATE_DISK_BYTES).unwrap();
        let mut superblock = [0_u8; 1024];
        superblock[0x38..0x3a].copy_from_slice(&[0x53, 0xef]);
        superblock[0x68..0x78].copy_from_slice(filesystem_uuid.as_bytes());
        disk.seek(SeekFrom::Start(1024)).unwrap();
        disk.write_all(&superblock).unwrap();
        disk.sync_all().unwrap();
    }

    fn request(vcpus: u8, memory_mib: u32) -> CreateVmRequest {
        CreateVmRequest {
            vm_id: Uuid::new_v4(),
            generation: 1,
            vsock_cid: 7,
            daemon_vsock_port: 7_777,
            state_disk_bytes: MINIMUM_STATE_DISK_BYTES,
            root_generation: "a".repeat(64),
            root_disk_bytes: MINIMUM_ROOT_DISK_BYTES,
            vcpus,
            memory_mib,
            setup: None,
        }
    }

    async fn wait_for_exec(pid: u32, executable: &Path) {
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if fs::read_link(format!("/proc/{pid}/exe")).ok().as_deref() == Some(executable) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("child did not reach its expected executable");
    }

    async fn spawn_admitted_sleep(duration: &str) -> (tokio::process::Child, LiveProcess) {
        let executable = std::fs::canonicalize("/usr/bin/sleep").unwrap();
        let child = tokio::process::Command::new(&executable)
            .arg(duration)
            .env_clear()
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let pid = child.id().unwrap();
        wait_for_exec(pid, &executable).await;
        let process = LiveProcess::capture_child(pid, &executable).unwrap();
        (child, process)
    }

    async fn serve_progress_fixture(
        listener: tokio::net::UnixListener,
        token: &'static str,
        vm_id: Uuid,
        generation: u64,
        stages: Vec<GuestBootStage>,
    ) {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut connect = Vec::new();
        loop {
            let mut byte = [0_u8; 1];
            stream.read_exact(&mut byte).await.unwrap();
            connect.push(byte[0]);
            if byte[0] == b'\n' {
                break;
            }
        }
        assert_eq!(
            connect,
            format!("CONNECT {GUEST_PROGRESS_VSOCK_PORT}\n").as_bytes()
        );
        stream
            .write_all(format!("OK {GUEST_PROGRESS_VSOCK_PORT}\n").as_bytes())
            .await
            .unwrap();
        let mut request = [0_u8; codewire_vmm_guest_probe::PROGRESS_REQUEST_LEN];
        stream.read_exact(&mut request).await.unwrap();
        let request = ProgressRequest::decode(&request).unwrap();
        assert_eq!(request.vm_id, vm_id);
        assert_eq!(request.generation, generation);
        for (index, stage) in stages.into_iter().enumerate() {
            let frame = ProgressFrame {
                vm_id,
                generation,
                sequence: index as u64 + 1,
                stage,
            }
            .encode(&request.challenge, token)
            .unwrap();
            stream.write_all(&frame).await.unwrap();
        }
    }

    #[tokio::test]
    async fn network_worker_waits_for_authenticated_guest_network_readiness() {
        const TOKEN: &str = "network-progress-test-token-0123456789abcdef";
        let temporary = tempfile::tempdir().unwrap();
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let socket = temporary.path().join("hybrid.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        set_socket_private(&socket).unwrap();
        let target = HybridVsockTarget::new(socket, 7_777).unwrap();
        let vm_id = Uuid::new_v4();
        let server = tokio::spawn(serve_progress_fixture(
            listener,
            TOKEN,
            vm_id,
            9,
            vec![
                GuestBootStage::WorkspacePlanReady,
                GuestBootStage::RootGenerationReady,
            ],
        ));

        assert_eq!(
            wait_for_network_progress_attempt(
                &target,
                TOKEN,
                vm_id,
                9,
                tokio::time::Instant::now() + Duration::from_secs(1),
                NetworkProgressGoal::NetworkReady,
            )
            .await
            .unwrap(),
            GuestBootStage::RootGenerationReady
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn network_worker_reports_authenticated_guest_startup_failure() {
        const TOKEN: &str = "network-progress-test-token-0123456789abcdef";
        let temporary = tempfile::tempdir().unwrap();
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let socket = temporary.path().join("hybrid.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        set_socket_private(&socket).unwrap();
        let target = HybridVsockTarget::new(socket, 7_777).unwrap();
        let vm_id = Uuid::new_v4();
        let server = tokio::spawn(serve_progress_fixture(
            listener,
            TOKEN,
            vm_id,
            9,
            vec![GuestBootStage::WorkspaceFailed],
        ));

        assert_eq!(
            wait_for_network_progress_attempt(
                &target,
                TOKEN,
                vm_id,
                9,
                tokio::time::Instant::now() + Duration::from_secs(1),
                NetworkProgressGoal::Terminal,
            )
            .await,
            Ok(GuestBootStage::WorkspaceFailed)
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn network_worker_status_reader_preserves_the_two_phase_socket() {
        let (mut runner, mut worker) = tokio::net::UnixStream::pair().unwrap();
        worker.write_all(WORKER_PREPARED_MESSAGE).await.unwrap();
        worker
            .write_all(crate::network_worker::WORKER_READY_MESSAGE)
            .await
            .unwrap();

        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        assert_eq!(
            read_worker_status_frame(&mut runner, deadline)
                .await
                .unwrap(),
            WORKER_PREPARED_MESSAGE
        );
        assert_eq!(
            read_worker_status_frame(&mut runner, deadline)
                .await
                .unwrap(),
            crate::network_worker::WORKER_READY_MESSAGE
        );
    }

    #[tokio::test]
    async fn network_worker_status_reader_rejects_oversized_frames() {
        let (mut runner, mut worker) = tokio::net::UnixStream::pair().unwrap();
        worker
            .write_all(&[b'x'; WORKER_STATUS_MAX_BYTES + 1])
            .await
            .unwrap();
        assert!(matches!(
            read_worker_status_frame(
                &mut runner,
                tokio::time::Instant::now() + Duration::from_secs(1),
            )
            .await,
            Err(RunnerError::NetworkWorkerBootstrap)
        ));
    }

    #[test]
    fn network_worker_attachment_has_a_fresh_bounded_phase() {
        assert_eq!(
            network_worker_attach_timeout(Duration::from_secs(1)),
            Duration::from_secs(1)
        );
        assert_eq!(
            network_worker_attach_timeout(Duration::from_secs(15)),
            NETWORK_WORKER_ATTACH_TIMEOUT
        );
        assert_eq!(
            network_worker_attach_timeout(Duration::from_secs(20 * 60)),
            NETWORK_WORKER_ATTACH_TIMEOUT
        );
    }

    #[tokio::test]
    async fn cleanup_reports_the_last_persisted_launch_generation() {
        let (_parent, runner) = test_runner();
        let vm_id = Uuid::new_v4();
        assert_eq!(
            runner.terminate_tracked_for_cleanup(vm_id).await.unwrap(),
            None
        );

        let paths = VmPaths::create(&runner.state_root, vm_id).unwrap();
        let (mut child, process) = spawn_admitted_sleep("30").await;
        child.start_kill().unwrap();
        child.wait().await.unwrap();
        persisted_starting_state(vm_id, &process)
            .write_atomic(&paths.state_file)
            .unwrap();

        assert_eq!(
            runner.terminate_tracked_for_cleanup(vm_id).await.unwrap(),
            Some(1)
        );
    }

    #[test]
    fn create_request_enforces_resource_bounds() {
        assert!(validate_request(&request(2, 16_384)).is_ok());
        assert!(matches!(
            validate_request(&request(0, 16_384)),
            Err(RunnerError::InvalidRequest)
        ));
        assert!(matches!(
            validate_request(&request(33, 16_384)),
            Err(RunnerError::InvalidRequest)
        ));
        assert!(matches!(
            validate_request(&request(2, 127)),
            Err(RunnerError::InvalidRequest)
        ));
        assert!(matches!(
            validate_request(&request(2, 65_537)),
            Err(RunnerError::InvalidRequest)
        ));
    }

    #[test]
    fn generated_tokens_fit_the_guest_codec_and_debug_is_redacted() {
        let token = Zeroizing::new(generate_auth_token());
        let seed = Seed::new(Uuid::new_v4(), 1, 7777, token.to_string()).unwrap();
        assert_eq!(seed.auth_token(), token.as_str());
        assert_eq!(token_fingerprint(&token).len(), 64);
        assert!(!format!("{seed:?}").contains(token.as_str()));
    }

    #[test]
    fn guest_poweroff_uses_the_sealed_container_helper() {
        assert_eq!(
            guest_poweroff_command(),
            vec![CONTAINER_INIT_PATH.to_owned(), "poweroff".to_owned()]
        );
        assert_ne!(guest_poweroff_command()[0], "/init");
    }

    #[test]
    fn later_generation_is_bound_to_the_persisted_state_disk_identity() {
        let (_parent, runner) = test_runner();
        let vm_id = Uuid::new_v4();
        let paths = VmPaths::create(&runner.state_root, vm_id).unwrap();
        write_test_ext4(&paths.state_disk, Uuid::new_v4());
        let admitted = StateDiskIdentity::capture(&paths.state_disk).unwrap();
        let persisted = PersistedVmState {
            schema_version: PERSISTED_STATE_SCHEMA_VERSION,
            vm_id,
            generation: 1,
            vsock_cid: 7,
            daemon_vsock_port: 7_777,
            phase: VmPhase::Starting,
            process: ProcessIdentity::capture(std::process::id()).unwrap(),
            state_disk: admitted.clone(),
            root_generation: None,
            root_disk: None,
            api_socket: None,
            vsock_socket: None,
        };
        let mut next = request(2, 16_384);
        next.vm_id = vm_id;
        next.generation = 2;
        assert_eq!(
            admit_state_disk(&paths, &next, Some(&persisted)).unwrap(),
            admitted
        );

        next.generation = 1;
        assert!(matches!(
            admit_state_disk(&paths, &next, Some(&persisted)),
            Err(RunnerError::GenerationNotAdvanced {
                previous: 1,
                requested: 1
            })
        ));

        let mut disk = fs::OpenOptions::new()
            .write(true)
            .open(&paths.state_disk)
            .unwrap();
        disk.seek(SeekFrom::Start(1024 + 0x68)).unwrap();
        disk.write_all(Uuid::new_v4().as_bytes()).unwrap();
        disk.sync_all().unwrap();
        next.generation = 2;
        assert!(matches!(
            admit_state_disk(&paths, &next, Some(&persisted)),
            Err(RunnerError::State(StateError::StateDiskIdentityChanged(path)))
                if path == paths.state_disk
        ));
    }

    #[test]
    fn root_generation_replay_is_bound_to_the_persisted_disk_identity() {
        let (_parent, runner) = test_runner();
        let vm_id = Uuid::new_v4();
        let paths = VmPaths::create(&runner.state_root, vm_id).unwrap();
        let generation = "a".repeat(64);
        let root = RootGenerationPaths::create(&paths, &generation).unwrap();
        let filesystem_uuid = Uuid::new_v4();
        write_test_ext4(&root.root_disk, filesystem_uuid);
        let admitted = StateDiskIdentity::capture(&root.root_disk).unwrap();
        let persisted = PersistedVmState {
            schema_version: PERSISTED_STATE_SCHEMA_VERSION,
            vm_id,
            generation: 1,
            vsock_cid: 7,
            daemon_vsock_port: 7_777,
            phase: VmPhase::Starting,
            process: ProcessIdentity::capture(std::process::id()).unwrap(),
            state_disk: admitted.clone(),
            root_generation: Some(generation.clone()),
            root_disk: Some(admitted.clone()),
            api_socket: None,
            vsock_socket: None,
        };
        let mut next = request(2, 16_384);
        next.vm_id = vm_id;
        next.generation = 2;
        assert_eq!(
            admit_root_disk(&paths, &next, Some(&persisted)).unwrap(),
            (root.root_disk.clone(), admitted.clone())
        );

        let replacement = root.generation_dir.join("replacement.raw");
        write_test_ext4(&replacement, filesystem_uuid);
        fs::rename(&replacement, &root.root_disk).unwrap();
        assert!(matches!(
            admit_root_disk(&paths, &next, Some(&persisted)),
            Err(RunnerError::State(StateError::StateDiskIdentityChanged(path)))
                if path == root.root_disk
        ));
    }

    #[test]
    fn setup_pack_is_storage_generation_scoped_and_revalidated_by_file_identity() {
        let (_parent, runner) = test_runner();
        let mut request = request(2, 16_384);
        let paths = VmPaths::create(&runner.state_root, request.vm_id).unwrap();
        let generation = RootGenerationPaths::create(&paths, &request.root_generation).unwrap();
        let total_bytes = (codewire_vmm_guest_probe::SETUP_HEADER_LEN as u64)
            + codewire_vmm_guest_probe::SETUP_ALIGNMENT;
        let setup = fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .mode(0o400)
            .open(&generation.setup_disk)
            .unwrap();
        setup.set_len(total_bytes).unwrap();
        setup.sync_all().unwrap();
        drop(setup);
        let setup_root_generation =
            codewire_vmm_guest_probe::Sha256Value::calculate(b"oci-content-root");
        assert_ne!(setup_root_generation.to_string(), request.root_generation);
        let binding = SetupBinding::new(
            total_bytes,
            setup_root_generation,
            codewire_vmm_guest_probe::Sha256Value::calculate(b"header"),
        )
        .unwrap();
        request.setup = Some(binding);
        let admitted = admit_setup_disk(&paths, &request).unwrap().unwrap();
        assert_eq!(admitted.path, generation.setup_disk);
        revalidate_setup_disk(&admitted, request.setup).unwrap();

        fs::remove_file(&generation.setup_disk).unwrap();
        let replacement = fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .mode(0o400)
            .open(&generation.setup_disk)
            .unwrap();
        replacement.set_len(total_bytes).unwrap();
        replacement.sync_all().unwrap();
        drop(replacement);
        assert!(matches!(
            revalidate_setup_disk(&admitted, request.setup),
            Err(RunnerError::SetupDiskIdentityChanged)
        ));
    }

    #[test]
    fn setup_cleanup_failure_still_unlinks_the_secret_bearing_seed() {
        let (_parent, runner) = test_runner();
        let mut request = request(2, 16_384);
        let paths = VmPaths::create(&runner.state_root, request.vm_id).unwrap();
        let generation = RootGenerationPaths::create(&paths, &request.root_generation).unwrap();
        let total_bytes = (codewire_vmm_guest_probe::SETUP_HEADER_LEN as u64)
            + codewire_vmm_guest_probe::SETUP_ALIGNMENT;
        let setup = fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .mode(0o400)
            .open(&generation.setup_disk)
            .unwrap();
        setup.set_len(total_bytes).unwrap();
        setup.sync_all().unwrap();
        drop(setup);
        request.setup = Some(
            SetupBinding::new(
                total_bytes,
                codewire_vmm_guest_probe::Sha256Value::parse_hex(&request.root_generation).unwrap(),
                codewire_vmm_guest_probe::Sha256Value::calculate(b"header"),
            )
            .unwrap(),
        );
        let admitted = admit_setup_disk(&paths, &request).unwrap().unwrap();
        let mut seed = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o400)
            .open(&paths.seed_disk)
            .unwrap();
        seed.write_all(b"one-boot-seed").unwrap();
        seed.sync_all().unwrap();
        drop(seed);

        fs::remove_file(&generation.setup_disk).unwrap();
        assert!(discard_one_boot_inputs(&paths, Some(&admitted), request.setup).is_err());
        assert!(!paths.seed_disk.exists());
    }

    #[test]
    fn a_new_root_generation_is_admitted_with_an_exact_size() {
        let (_parent, runner) = test_runner();
        let vm_id = Uuid::new_v4();
        let paths = VmPaths::create(&runner.state_root, vm_id).unwrap();
        let previous_generation = "a".repeat(64);
        let previous = RootGenerationPaths::create(&paths, &previous_generation).unwrap();
        write_test_ext4(&previous.root_disk, Uuid::new_v4());
        let previous_identity = StateDiskIdentity::capture(&previous.root_disk).unwrap();
        let persisted = PersistedVmState {
            schema_version: PERSISTED_STATE_SCHEMA_VERSION,
            vm_id,
            generation: 1,
            vsock_cid: 7,
            daemon_vsock_port: 7_777,
            phase: VmPhase::Starting,
            process: ProcessIdentity::capture(std::process::id()).unwrap(),
            state_disk: previous_identity.clone(),
            root_generation: Some(previous_generation),
            root_disk: Some(previous_identity),
            api_socket: None,
            vsock_socket: None,
        };

        let next_generation = "b".repeat(64);
        let next_root = RootGenerationPaths::create(&paths, &next_generation).unwrap();
        write_test_ext4(&next_root.root_disk, Uuid::new_v4());
        let next_identity = StateDiskIdentity::capture(&next_root.root_disk).unwrap();
        let mut next = request(2, 16_384);
        next.vm_id = vm_id;
        next.generation = 2;
        next.root_generation = next_generation;
        assert_eq!(
            admit_root_disk(&paths, &next, Some(&persisted)).unwrap(),
            (next_root.root_disk, next_identity)
        );

        next.root_disk_bytes += 1024 * 1024;
        assert!(matches!(
            admit_root_disk(&paths, &next, Some(&persisted)),
            Err(RunnerError::RootDiskSizeMismatch {
                current: MINIMUM_ROOT_DISK_BYTES,
                requested
            }) if requested == MINIMUM_ROOT_DISK_BYTES + 1024 * 1024
        ));
    }

    #[test]
    fn interrupted_growth_resumes_only_the_same_recorded_disk() {
        let (_parent, runner) = test_runner();
        let vm_id = Uuid::new_v4();
        let paths = VmPaths::create(&runner.state_root, vm_id).unwrap();
        write_test_ext4(&paths.state_disk, Uuid::new_v4());
        let recorded = StateDiskIdentity::capture(&paths.state_disk).unwrap();
        let target = recorded.file.size + 1024 * 1024;

        assert_eq!(
            plan_stopped_disk_growth(Some(&recorded), &recorded, target, &paths.state_disk,)
                .unwrap(),
            StoppedDiskGrowthPlan::ResizeFilesystem
        );

        // This is the interruption boundary after set_len/sync but before
        // e2fsck, resize2fs, and the persisted identity update. Replay must
        // repair the filesystem instead of rejecting or replacing the disk.
        let mut length_applied = recorded.clone();
        length_applied.file.size = target;
        assert_eq!(
            plan_stopped_disk_growth(Some(&recorded), &length_applied, target, &paths.state_disk,)
                .unwrap(),
            StoppedDiskGrowthPlan::ResizeFilesystem
        );
        assert_eq!(
            plan_stopped_disk_growth(
                Some(&length_applied),
                &length_applied,
                target,
                &paths.state_disk,
            )
            .unwrap(),
            StoppedDiskGrowthPlan::AlreadyComplete
        );

        let mut replacement = length_applied.clone();
        replacement.file.inode += 1;
        assert!(matches!(
            plan_stopped_disk_growth(
                Some(&recorded),
                &replacement,
                target,
                &paths.state_disk,
            ),
            Err(RunnerError::StateDiskGrowthIdentityMismatch(path))
                if path == paths.state_disk
        ));
    }

    #[tokio::test]
    async fn failed_launch_cleanup_uses_pidfd_and_reaps_child() {
        let (mut child, process) = spawn_admitted_sleep("30").await;
        terminate_failed_launch(&process, &mut child).await.unwrap();
        assert!(child.try_wait().unwrap().is_some());
        assert!(process.is_exited().unwrap());
    }

    #[tokio::test]
    async fn aborting_start_after_durable_starting_state_kills_the_exact_child() {
        let (_parent, runner) = test_runner();
        let vm_id = Uuid::new_v4();
        let paths = VmPaths::create(&runner.state_root, vm_id).unwrap();
        let state_file = paths.state_file.clone();
        let executable = std::fs::canonicalize("/usr/bin/sleep").unwrap();
        let (persisted_tx, persisted_rx) = tokio::sync::oneshot::channel();

        let start_task = tokio::spawn(async move {
            let child = tokio::process::Command::new(&executable)
                .arg("30")
                .env_clear()
                .spawn()
                .unwrap();
            let mut startup = StartupOwnership::new(child);
            let pid = startup.child_mut().id().unwrap();
            // Avoid making the fixture depend on whether the scheduler lets
            // the child reach exec before Command::spawn returns.
            wait_for_exec(pid, &executable).await;
            let process = LiveProcess::capture_child(pid, &executable).unwrap();
            let identity = process.identity().clone();
            startup.admit(process);
            persisted_starting_state(vm_id, startup.process())
                .write_atomic(&state_file)
                .unwrap();
            persisted_tx.send(identity).unwrap();
            std::future::pending::<()>().await;
            startup.disarm()
        });

        let identity = persisted_rx.await.unwrap();
        let persisted = PersistedVmState::read(&paths.state_file).unwrap();
        assert_eq!(persisted.phase, VmPhase::Starting);
        assert_eq!(persisted.process, identity);
        start_task.abort();
        assert!(start_task.await.unwrap_err().is_cancelled());

        tokio::time::timeout(SIGNAL_STOP_TIMEOUT, async {
            loop {
                match LiveProcess::recover(&identity) {
                    Ok(process) if !process.is_exited().unwrap() => {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                    Ok(_) => break,
                    Err(
                        RecoveryError::ReadProcess(_)
                        | RecoveryError::ProcessExited
                        | RecoveryError::IdentityMismatch,
                    ) => break,
                    Err(error) => panic!("unexpected cancellation cleanup error: {error}"),
                }
            }
        })
        .await
        .expect("aborted startup left its exact child alive");
    }

    #[tokio::test]
    async fn forced_running_kill_is_pidfd_bounded_and_reaped() {
        let (mut child, process) = spawn_admitted_sleep("30").await;
        assert!(matches!(
            kill_and_reap(&process, &mut child).await.unwrap(),
            ExitClass::VmmFailure(_)
        ));
        assert!(child.try_wait().unwrap().is_some());
        assert!(process.is_exited().unwrap());
    }

    #[tokio::test]
    async fn endpoint_early_exit_is_reaped() {
        let (_parent, runner) = test_runner();
        let vm_id = Uuid::new_v4();
        let paths = VmPaths::create(&runner.state_root, vm_id).unwrap();
        let lock = paths.lock().unwrap();
        let (mut child, process) = spawn_admitted_sleep("0.25").await;
        persisted_starting_state(vm_id, &process)
            .write_atomic(&paths.state_file)
            .unwrap();

        let result =
            wait_for_endpoints_with_timeout(&paths, &process, 7_777, Duration::from_secs(2)).await;
        assert!(matches!(result, Err(RunnerError::ExitedDuringStart)));
        terminate_failed_launch(&process, &mut child).await.unwrap();
        assert!(child.try_wait().unwrap().is_some());
        assert!(process.is_exited().unwrap());

        drop(lock);
    }

    #[tokio::test]
    async fn endpoint_readiness_wait_has_a_bounded_deadline() {
        let (_parent, runner) = test_runner();
        let paths = VmPaths::create(&runner.state_root, Uuid::new_v4()).unwrap();
        let identity = super::super::process::ProcessIdentity::capture(std::process::id()).unwrap();
        let process = LiveProcess::recover(&identity).unwrap();

        let result = tokio::time::timeout(
            Duration::from_secs(1),
            wait_for_endpoints_with_timeout(&paths, &process, 7_777, Duration::from_millis(30)),
        )
        .await
        .expect("endpoint waiter exceeded its outer test bound");
        assert!(matches!(result, Err(RunnerError::StartTimeout)));
    }

    #[test]
    fn child_never_inherits_the_supervisor_working_directory() {
        let private = tempfile::tempdir().unwrap();
        std::fs::set_permissions(
            private.path(),
            <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o700),
        )
        .unwrap();
        let command = CommandSpec::for_test("/usr/bin/true".into());
        let process = cloud_hypervisor_process(&command, private.path()).unwrap();
        assert_eq!(process.as_std().get_current_dir(), Some(private.path()));
    }

    #[tokio::test]
    async fn child_exec_closes_an_explicitly_inheritable_host_descriptor() {
        let private = tempfile::tempdir().unwrap();
        fs::set_permissions(private.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let sentinel_path = private.path().join("host-capability-sentinel");
        let sentinel = fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(&sentinel_path)
            .unwrap();
        let descriptor = sentinel.as_raw_fd();
        // SAFETY: descriptor is owned by sentinel for this test. Clearing
        // FD_CLOEXEC deliberately models an unsafe descriptor inherited by a
        // future long-lived supervisor.
        let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
        assert!(flags >= 0);
        // SAFETY: F_SETFD accepts the retrieved descriptor flags.
        assert_eq!(
            unsafe { libc::fcntl(descriptor, libc::F_SETFD, flags & !libc::FD_CLOEXEC) },
            0
        );

        let command = CommandSpec::for_test_with_arguments(
            fs::canonicalize("/bin/sh").unwrap(),
            [
                "-c",
                r#"for descriptor in /proc/self/fd/*; do
  if [ "$(readlink "$descriptor" 2>/dev/null)" = "$1" ]; then
    exit 97
  fi
done
exit 0"#,
                "cw-inherited-fd-check",
                sentinel_path.to_str().unwrap(),
            ]
            .into_iter()
            .map(Into::into)
            .collect(),
        );
        let mut child = cloud_hypervisor_process(&command, private.path())
            .unwrap()
            .spawn()
            .unwrap();
        let status = tokio::time::timeout(SIGNAL_STOP_TIMEOUT, child.wait())
            .await
            .expect("descriptor sentinel child exceeded its bound")
            .unwrap();
        assert!(status.success());
    }
}
