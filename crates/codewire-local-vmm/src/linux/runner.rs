use std::fmt;
use std::io::{self, Read as _};
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener as StdTcpListener};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream as StdUnixStream;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use codewire_daemon::client::{SessionClient, v1 as daemon_v1};
use codewire_egress_broker::ipc::BROKER_IPC_KEY_LEN;
use codewire_vmm_guest_probe::{
    DirectSharePlan, GUEST_NETWORK_VSOCK_PORT, GUEST_PROGRESS_VSOCK_PORT, GuestBootStage,
    NetworkKey, PROGRESS_CHALLENGE_LEN, PROGRESS_FRAME_LEN, ProgressFrame, ProgressRequest, Seed,
    SetupBinding, Sha256Value, guest::CONTAINER_INIT_PATH,
};
use futures::FutureExt as _;
use rand::{RngCore, rngs::OsRng};
use rustix::process::Signal;
use sha2::{Digest, Sha256};
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::task::{JoinHandle, JoinSet};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::artifact::{AdmittedArtifacts, ArtifactError, ArtifactLock};
use crate::ch_api::{ChApiClient, ChApiError};
use crate::cloud_hypervisor::{
    CloudHypervisorConfig, CloudHypervisorConfigError, CommandSpec, VirtioFsConfig,
};
use crate::direct_share::{AdmittedDirectShare, DirectShareRequest};
use crate::egress_broker::{
    EGRESS_BROKER_BOOTSTRAP_FD, EGRESS_BROKER_CONFINE_MESSAGE,
    EGRESS_BROKER_CONFINEMENT_ADMISSION_TIMEOUT, EGRESS_BROKER_PREPARED_MESSAGE,
    EGRESS_BROKER_READY_MESSAGE, EGRESS_BROKER_STATUS_MAX_BYTES, EgressBrokerStartupFailure,
    EgressBrokerStartupStatus, decode_egress_broker_startup_status,
    encode_developer_egress_broker_bootstrap,
};
use crate::host_port::{
    HOST_PORT_CONTROL_KEY_LEN, HostPortBinding, HostPortControlFrame,
    validate_canonical_host_port_bindings,
};
use crate::hybrid_vsock::{HybridVsockError, HybridVsockTarget};
use crate::mesh_enrollment::{
    MESH_ENROLLMENT_BOOTSTRAP_FD, MESH_ENROLLMENT_CONFINE_MESSAGE,
    MESH_ENROLLMENT_PREPARED_MESSAGE, MESH_ENROLLMENT_READY_MESSAGE,
    MESH_ENROLLMENT_STATUS_MAX_BYTES, MESH_ENROLLMENT_TRANSFER_FD, MeshEnrollmentStartupFailure,
    MeshEnrollmentStartupStatus, decode_mesh_enrollment_startup_status,
    encode_mesh_enrollment_bootstrap,
};
use crate::mesh_ingress::{
    AcceptedMeshIngress, MESH_INGRESS_CONTROL_KEY_LEN, MeshAttachment, MeshIngressControlFrame,
    MeshIngressPublisher, mesh_ingress_channel,
};
use crate::mesh_process::{
    MESH_TRANSPORT_BOOTSTRAP_FD, MESH_TRANSPORT_CONFINE_MESSAGE, MESH_TRANSPORT_CONFINED_MESSAGE,
    MESH_TRANSPORT_ENROLLMENT_FD, MESH_TRANSPORT_PREPARED_MESSAGE, MESH_TRANSPORT_READY_MESSAGE,
    MESH_TRANSPORT_STATUS_MAX_BYTES, MeshTransportStartupFailure, MeshTransportStartupStatus,
    decode_mesh_transport_startup_status, encode_mesh_transport_bootstrap,
};
use crate::mesh_transport::{MeshTransportError, receive_mesh_ingress_submissions};
use crate::network_worker::{
    NETWORK_BOOTSTRAP_FD, NetworkWorkerStartupFailure, NetworkWorkerStartupStatus,
    WORKER_BROKER_READY_MESSAGE, WORKER_PREPARED_MESSAGE, WORKER_STATUS_MAX_BYTES,
    decode_worker_startup_status, encode_product_worker_bootstrap, encode_worker_bootstrap,
    send_mesh_ingress_descriptor, send_worker_broker_descriptor, send_worker_host_port_descriptor,
    send_worker_network_descriptor,
};

use super::confinement::{
    install_identity_preserving_setgroups_filter, lock_exec_process_privileges,
    lock_process_privileges, prepare_virtiofsd_filesystem_domain,
};
use super::path::{FileIdentity, PathError, PrivateRoot, current_uid, set_socket_private};
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
const EGRESS_BROKER_READY_TIMEOUT: Duration =
    EGRESS_BROKER_CONFINEMENT_ADMISSION_TIMEOUT.saturating_add(Duration::from_secs(5));
const NETWORK_WORKER_ATTACH_TIMEOUT: Duration = Duration::from_secs(20);
const MESH_STACK_ATTACH_TIMEOUT: Duration = Duration::from_secs(45);
const NETWORK_WORKER_PROGRESS_FRAME_LIMIT: usize = 64;
const NETWORK_WORKER_HANDSHAKE_ATTEMPT_LIMIT: usize = 8;
const HOST_PORT_CONTROL_TIMEOUT: Duration = Duration::from_secs(2);
const HOST_PORT_ACCEPT_QUEUE: usize = 64;
const VMM_CASCADE_EXIT_TIMEOUT: Duration = Duration::from_millis(250);
const E2FSCK: &str = "/usr/bin/e2fsck";
const RESIZE2FS: &str = "/usr/bin/resize2fs";
const DIRECT_SHARE_SOURCE_FD: RawFd = 3;
const DIRECT_SHARE_READY_TIMEOUT: Duration = Duration::from_secs(5);

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
    pub host_ports: Vec<HostPortBinding>,
    pub mesh: Option<MeshAttachment>,
    pub direct_shares: Vec<DirectShareRequest>,
    pub skill_snapshot_sha256: Option<Sha256Value>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SetupDiskIdentity {
    path: PathBuf,
    file: FileIdentity,
}

#[derive(Debug)]
struct PreparedDirectShare {
    request: DirectShareRequest,
    admitted: AdmittedDirectShare,
    socket: PathBuf,
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
        let host_port_listeners = reserve_host_ports(&request.host_ports)?;
        let paths = VmPaths::create(&self.state_root, request.vm_id)?;
        let lock = paths.lock()?;
        let persisted = read_stopped_persisted_state(&paths, request.vm_id)?;
        let state_disk = admit_state_disk(&paths, &request, persisted.as_ref())?;
        let (root_disk_path, root_disk) = admit_root_disk(&paths, &request, persisted.as_ref())?;
        let setup_disk = admit_setup_disk(&paths, &request)?;
        paths.clear_stale_runtime_endpoints()?;

        let direct_shares = self.prepare_direct_shares(&request, &paths)?;
        let direct_share_plan = direct_share_plan(&request.direct_shares)?;
        let direct_shares_sha256 = direct_share_plan
            .as_ref()
            .map(DirectSharePlan::sha256)
            .transpose()
            .map_err(|_| RunnerError::InvalidRequest)?;

        let token = Zeroizing::new(generate_auth_token());
        let seed = Seed::new_with_all_bindings(
            request.vm_id,
            request.generation,
            request.daemon_vsock_port,
            token.to_string(),
            request.setup,
            direct_shares_sha256,
            request.skill_snapshot_sha256,
        )?;
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
        }
        .with_virtiofs(
            direct_shares
                .iter()
                .map(|share| VirtioFsConfig {
                    tag: share.request.mount.tag().to_owned(),
                    socket: share.socket.clone(),
                })
                .collect(),
        )?;
        let command = config.command()?;
        Ok(PreparedVm {
            request,
            paths,
            state_disk,
            root_disk,
            setup_disk,
            direct_shares,
            token,
            command,
            host_port_listeners,
            lock,
        })
    }

    fn prepare_direct_shares(
        &self,
        request: &CreateVmRequest,
        paths: &VmPaths,
    ) -> Result<Vec<PreparedDirectShare>, RunnerError> {
        if request.direct_shares.is_empty() {
            return Ok(Vec::new());
        }
        if self.artifacts.virtiofsd.is_none() {
            return Err(RunnerError::VirtiofsdUnavailable);
        }
        let mut forbidden_roots = vec![self.state_root.path().to_owned()];
        forbidden_roots.extend([
            self.artifacts.cloud_hypervisor.path().to_owned(),
            self.artifacts.kernel.path().to_owned(),
            self.artifacts.initramfs.path().to_owned(),
        ]);
        if let Some(virtiofsd) = &self.artifacts.virtiofsd {
            forbidden_roots.push(virtiofsd.path().to_owned());
        }
        request
            .direct_shares
            .iter()
            .cloned()
            .enumerate()
            .map(|(index, share)| {
                let admitted = share
                    .reopen(&forbidden_roots)
                    .map_err(|_| RunnerError::DirectShareChanged)?;
                Ok(PreparedDirectShare {
                    request: share,
                    admitted,
                    socket: paths.direct_share_socket(index)?,
                })
            })
            .collect()
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
        let mut direct_share_startup = DirectShareStartup::start(
            self.artifacts
                .virtiofsd
                .as_ref()
                .map(|artifact| artifact.path()),
            &prepared.direct_shares,
            &prepared.paths.vm_dir,
        )
        .await?;
        // Arm cancellation cleanup in the same synchronous span as spawn. An
        // aborted start future must never drop the VM lock while leaving a VMM
        // alive, including before a pidfd identity has been admitted.
        let vmm = match spawn_cloud_hypervisor(&prepared.command, &prepared.paths.vm_dir) {
            Ok(vmm) => vmm,
            Err(error) => {
                direct_share_startup.stop().await?;
                return Err(error);
            }
        };
        let mut startup = StartupOwnership::new(vmm);
        let pid = startup.child_mut().id().ok_or(RunnerError::Spawn)?;
        let process = match LiveProcess::capture_child(pid, prepared.command.program()) {
            Ok(process) => process,
            Err(error) => {
                startup.terminate_unadmitted(pid).await?;
                direct_share_startup.stop().await?;
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
            direct_share_startup.stop().await?;
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
                direct_share_startup.stop().await?;
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
            direct_shares: direct_share_startup.disarm(),
            token: prepared.token,
            child,
            process,
            api,
            hybrid,
            network_worker: None,
            host_port_listeners: prepared.host_port_listeners,
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

struct DirectShareProcess {
    child: tokio::process::Child,
    process: LiveProcess,
    socket: PathBuf,
}

struct DirectShareStartup {
    processes: Vec<DirectShareProcess>,
}

impl DirectShareStartup {
    async fn start(
        executable: Option<&Path>,
        shares: &[PreparedDirectShare],
        working_directory: &Path,
    ) -> Result<Self, RunnerError> {
        if shares.is_empty() {
            return Ok(Self {
                processes: Vec::new(),
            });
        }
        let executable = executable.ok_or(RunnerError::VirtiofsdUnavailable)?;
        let mut startup = Self {
            processes: Vec::with_capacity(shares.len()),
        };
        for share in shares {
            share
                .request
                .reopen(&[])
                .map_err(|_| RunnerError::DirectShareChanged)?;
            match start_direct_share(executable, share, working_directory).await {
                Ok(process) => startup.processes.push(process),
                Err(error) => {
                    startup.stop().await?;
                    return Err(error);
                }
            }
        }
        Ok(startup)
    }

    async fn stop(&mut self) -> Result<(), RunnerError> {
        let mut first_error = None;
        for process in &mut self.processes {
            if let Err(error) = stop_direct_share_process(process).await
                && first_error.is_none()
            {
                first_error = Some(error);
            }
        }
        self.processes.clear();
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    fn disarm(mut self) -> Vec<DirectShareProcess> {
        std::mem::take(&mut self.processes)
    }
}

impl Drop for DirectShareStartup {
    fn drop(&mut self) {
        for process in &mut self.processes {
            let _ = process.process.signal(Signal::KILL);
            let _ = process.child.start_kill();
        }
    }
}

struct ReservedHostPort {
    binding: HostPortBinding,
    listener: StdTcpListener,
}

fn reserve_host_ports(bindings: &[HostPortBinding]) -> Result<Vec<ReservedHostPort>, RunnerError> {
    validate_canonical_host_port_bindings(bindings).map_err(|_| RunnerError::InvalidRequest)?;
    let mut listeners = Vec::with_capacity(bindings.len());
    for binding in bindings {
        let address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, binding.host_port);
        let listener = StdTcpListener::bind(address)
            .map_err(|_| RunnerError::HostPortUnavailable(binding.host_port))?;
        listener
            .set_nonblocking(true)
            .map_err(|_| RunnerError::HostPortUnavailable(binding.host_port))?;
        if listener.local_addr().ok() != Some(address.into()) {
            return Err(RunnerError::HostPortUnavailable(binding.host_port));
        }
        listeners.push(ReservedHostPort {
            binding: *binding,
            listener,
        });
    }
    Ok(listeners)
}

pub struct PreparedVm {
    request: CreateVmRequest,
    paths: VmPaths,
    state_disk: StateDiskIdentity,
    root_disk: StateDiskIdentity,
    setup_disk: Option<SetupDiskIdentity>,
    direct_shares: Vec<PreparedDirectShare>,
    token: Zeroizing<String>,
    command: CommandSpec,
    host_port_listeners: Vec<ReservedHostPort>,
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
            .field("direct_share_count", &self.direct_shares.len())
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
    direct_shares: Vec<DirectShareProcess>,
    token: Zeroizing<String>,
    child: tokio::process::Child,
    process: LiveProcess,
    api: ChApiClient,
    hybrid: HybridVsockTarget,
    network_worker: Option<NetworkWorkerProcess>,
    host_port_listeners: Vec<ReservedHostPort>,
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
            .field("direct_share_count", &self.direct_shares.len())
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

    /// Attach the isolated host network worker and its separate policy broker
    /// for this boot. Neither process receives the guest daemon token.
    pub async fn start_network_worker(
        &mut self,
        executable: &Path,
        timeout: Duration,
    ) -> Result<(), RunnerError> {
        self.start_network_worker_with_mode(executable, timeout, NetworkWorkerMode::Product, None)
            .await
    }

    /// Attach the product network stack and, when configured, resolve Mesh
    /// owner credentials only inside the isolated enrollment child.
    pub async fn start_network_worker_with_mesh_credentials(
        &mut self,
        executable: &Path,
        timeout: Duration,
        mesh_data_dir: &Path,
        platform_config_dir: &Path,
    ) -> Result<(), RunnerError> {
        self.start_network_worker_with_mode(
            executable,
            timeout,
            NetworkWorkerMode::Product,
            Some((mesh_data_dir, platform_config_dir)),
        )
        .await
    }

    /// Preserve the socket-free injected broker used only by the checked-in
    /// qualified-host verification binary.
    #[doc(hidden)]
    pub async fn start_network_worker_with_injected_broker_for_verification(
        &mut self,
        executable: &Path,
        timeout: Duration,
    ) -> Result<(), RunnerError> {
        self.start_network_worker_with_mode(
            executable,
            timeout,
            NetworkWorkerMode::InjectedVerification,
            None,
        )
        .await
    }

    async fn start_network_worker_with_mode(
        &mut self,
        executable: &Path,
        timeout: Duration,
        mode: NetworkWorkerMode,
        mesh_credential_roots: Option<(&Path, &Path)>,
    ) -> Result<(), RunnerError> {
        if self.network_worker.is_some()
            || timeout.is_zero()
            || !executable.is_absolute()
            || std::fs::canonicalize(executable).ok().as_deref() != Some(executable)
            || !std::fs::metadata(executable).is_ok_and(|metadata| metadata.is_file())
            || (mode == NetworkWorkerMode::InjectedVerification && self.request.mesh.is_some())
            || (self.request.mesh.is_some()
                && !mesh_credential_roots
                    .is_some_and(|(mesh, platform)| mesh.is_absolute() && platform.is_absolute()))
        {
            return Err(RunnerError::InvalidNetworkWorker);
        }
        let readiness_deadline = tokio::time::Instant::now() + timeout;
        self.wait_for_network_guest_readiness(readiness_deadline)
            .await?;
        // Guest readiness and host-stack attachment are distinct bounded
        // phases. Product attachment budgets one capped phase for the broker
        // and one for the worker; the fixture has only the worker. A slow boot
        // must not consume either, while a long setup window cannot make host
        // attachment unbounded.
        let deadline = tokio::time::Instant::now() + network_stack_attach_timeout(timeout, mode);
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
            let launch = NetworkStackLaunch {
                executable,
                working_directory: &self.paths.vm_dir,
                hybrid: &self.hybrid,
                vm_id: self.request.vm_id,
                generation: self.request.generation,
                deadline,
                mesh: self.request.mesh.as_ref(),
                mesh_credential_roots,
            };
            match spawn_network_stack_processes(&launch, key, mode).await {
                Ok(mut worker) => {
                    if mode == NetworkWorkerMode::Product {
                        let listeners = std::mem::take(&mut self.host_port_listeners);
                        let mesh_ports = self
                            .request
                            .mesh
                            .as_ref()
                            .map(|attachment| attachment.guest_ports.as_slice());
                        if let Err(error) = start_ingress_forwarder(
                            &self.process,
                            &mut worker,
                            listeners,
                            mesh_ports,
                            self.request.vm_id,
                            self.request.generation,
                        ) {
                            let _ = stop_network_worker_process(&mut worker).await;
                            if let Some(broker) = worker.broker.as_mut() {
                                let _ = stop_egress_broker_process(broker).await;
                            }
                            return Err(error);
                        }
                        if launch.mesh.is_some() {
                            let Some(publisher) = worker.mesh_ingress_publisher.clone() else {
                                let _ = stop_network_worker_process(&mut worker).await;
                                if let Some(broker) = worker.broker.as_mut() {
                                    let _ = stop_egress_broker_process(broker).await;
                                }
                                return Err(RunnerError::MeshTransportBootstrap);
                            };
                            match spawn_mesh_stack_processes(&launch, publisher).await {
                                Ok(mesh) => worker.mesh_transport = Some(mesh),
                                Err(error) => {
                                    let _ = stop_network_worker_process(&mut worker).await;
                                    if let Some(broker) = worker.broker.as_mut() {
                                        let _ = stop_egress_broker_process(broker).await;
                                    }
                                    return Err(error);
                                }
                            }
                        }
                    } else if !self.host_port_listeners.is_empty() {
                        return Err(RunnerError::InvalidNetworkWorker);
                    }
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

    pub fn egress_broker_process_identity(&self) -> Option<&super::process::ProcessIdentity> {
        self.network_worker
            .as_ref()
            .and_then(|worker| worker.broker.as_ref())
            .map(|broker| broker.process.identity())
    }

    pub fn mesh_transport_process_identity(&self) -> Option<&super::process::ProcessIdentity> {
        self.network_worker
            .as_ref()
            .and_then(|worker| worker.mesh_transport.as_ref())
            .map(|mesh| mesh.process.identity())
    }

    /// Signal the exact runner-owned broker birth for checked-in qualified-host
    /// verification. The confined broker is deliberately non-dumpable, so a
    /// verifier must not try to reacquire it through `/proc`.
    #[doc(hidden)]
    pub fn force_kill_egress_broker_for_verification(&self) -> Result<(), RunnerError> {
        let broker = self
            .network_worker
            .as_ref()
            .and_then(|worker| worker.broker.as_ref())
            .ok_or(RunnerError::InvalidNetworkWorker)?;
        broker.process.signal(Signal::KILL)?;
        Ok(())
    }

    /// Signal the exact runner-owned Mesh transport birth for checked-in
    /// qualified-host lifecycle verification.
    #[doc(hidden)]
    pub fn force_kill_mesh_transport_for_verification(&self) -> Result<(), RunnerError> {
        let mesh = self
            .network_worker
            .as_ref()
            .and_then(|worker| worker.mesh_transport.as_ref())
            .ok_or(RunnerError::InvalidNetworkWorker)?;
        mesh.process.signal(Signal::KILL)?;
        Ok(())
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
        for share in &mut self.direct_shares {
            match share.child.try_wait() {
                Ok(Some(status)) => return Ok(ExitClass::DirectShareFailure(status.code())),
                Ok(None) => {}
                Err(_) => return Err(RunnerError::VirtiofsdWait),
            }
        }
        let Some(worker) = self.network_worker.as_mut() else {
            return Ok(ExitClass::StillRunning);
        };
        match worker.child.try_wait() {
            Ok(Some(status)) => return Ok(ExitClass::NetworkWorkerFailure(status.code())),
            Ok(None) => {}
            Err(_) => return Err(RunnerError::NetworkWorkerWait),
        }
        if let Some(broker) = worker.broker.as_mut() {
            match broker.child.try_wait() {
                Ok(Some(status)) => {
                    return Ok(ExitClass::EgressBrokerFailure(status.code()));
                }
                Ok(None) => {}
                Err(_) => return Err(RunnerError::EgressBrokerWait),
            }
        }
        if let Some(mesh) = worker.mesh_transport.as_mut() {
            match mesh.child.try_wait() {
                Ok(Some(status)) => {
                    return Ok(ExitClass::MeshTransportFailure(status.code()));
                }
                Ok(None) => {}
                Err(_) => return Err(RunnerError::MeshProcessWait),
            }
            if take_mesh_ingress_receiver_exit(&mut mesh.ingress_receiver) {
                return Ok(ExitClass::MeshIngressReceiverFailure);
            }
        }
        if take_ingress_forwarder_failure(&mut worker.ingress_forwarder) {
            return Ok(ExitClass::IngressForwarderFailure);
        }
        Ok(ExitClass::StillRunning)
    }

    pub fn mesh_ingress_publisher(&self) -> Option<MeshIngressPublisher> {
        self.network_worker
            .as_ref()
            .and_then(|worker| worker.mesh_ingress_publisher.clone())
    }

    pub async fn observe_exit(&mut self) -> Result<ExitClass, RunnerError> {
        let preliminary = self.try_exit()?;
        let observed = prioritize_exited_vmm(&self.process, &mut self.child, preliminary).await?;
        if matches!(
            observed,
            ExitClass::GuestShutdown | ExitClass::VmmFailure(_)
        ) {
            self.stop_network_worker().await?;
            self.stop_direct_shares().await?;
        }
        Ok(observed)
    }

    pub async fn wait_for_exit(&mut self, timeout: Duration) -> Result<ExitClass, RunnerError> {
        let exit = match tokio::time::timeout(timeout, self.child.wait()).await {
            Ok(Ok(status)) if status.success() => Ok(ExitClass::GuestShutdown),
            Ok(Ok(status)) => Ok(ExitClass::VmmFailure(status.code())),
            Ok(Err(_)) => Err(RunnerError::Wait),
            Err(_) => self.try_exit(),
        }?;
        if exit != ExitClass::StillRunning {
            self.stop_network_worker().await?;
            self.stop_direct_shares().await?;
        }
        Ok(exit)
    }

    pub async fn stop(&mut self) -> Result<ExitClass, RunnerError> {
        let vmm = self.stop_vmm().await;
        let worker = self.stop_network_worker().await;
        let shares = self.stop_direct_shares().await;
        match (vmm, worker, shares) {
            (Ok(exit), Ok(()), Ok(())) => Ok(exit),
            (Err(error), _, _) | (_, Err(error), _) | (_, _, Err(error)) => Err(error),
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
        let worker_result = stop_network_worker_process(&mut worker).await;
        let broker_result = match worker.broker.as_mut() {
            Some(broker) => stop_egress_broker_process(broker).await,
            None => Ok(()),
        };
        match (worker_result, broker_result) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(error), _) | (_, Err(error)) => Err(error),
        }
    }

    async fn stop_direct_shares(&mut self) -> Result<(), RunnerError> {
        let mut shares = std::mem::take(&mut self.direct_shares);
        let mut first_error = None;
        for share in &mut shares {
            if let Err(error) = stop_direct_share_process(share).await
                && first_error.is_none()
            {
                first_error = Some(error);
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
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
        let shares = self.stop_direct_shares().await;
        match (exit, worker, shares) {
            (Ok(exit), Ok(()), Ok(())) => Ok(exit),
            (Err(error), _, _) | (_, Err(error), _) | (_, _, Err(error)) => Err(error),
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

fn network_stack_attach_timeout(requested: Duration, mode: NetworkWorkerMode) -> Duration {
    let phase = std::cmp::min(requested, NETWORK_WORKER_ATTACH_TIMEOUT);
    match mode {
        NetworkWorkerMode::Product => phase.saturating_mul(2),
        NetworkWorkerMode::InjectedVerification => phase,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NetworkWorkerMode {
    Product,
    InjectedVerification,
}

enum WorkerBrokerAttachment {
    Product {
        endpoint: StdUnixStream,
        key: Zeroizing<[u8; BROKER_IPC_KEY_LEN]>,
    },
    InjectedVerification,
}

struct EgressBrokerProcess {
    child: tokio::process::Child,
    process: LiveProcess,
}

struct EgressBrokerLaunch {
    process: EgressBrokerProcess,
    endpoint: StdUnixStream,
    key: Zeroizing<[u8; BROKER_IPC_KEY_LEN]>,
}

struct MeshTransportProcess {
    child: tokio::process::Child,
    process: LiveProcess,
    ingress_receiver: Option<JoinHandle<Result<(), MeshTransportError>>>,
}

struct MeshProcessStartup {
    child: Option<tokio::process::Child>,
    process: Option<LiveProcess>,
}

impl MeshProcessStartup {
    fn new(child: tokio::process::Child) -> Self {
        Self {
            child: Some(child),
            process: None,
        }
    }

    fn child_mut(&mut self) -> &mut tokio::process::Child {
        self.child
            .as_mut()
            .expect("armed Mesh startup owns its child")
    }

    fn admit(&mut self, process: LiveProcess) {
        self.process = Some(process);
    }

    fn disarm(mut self) -> (tokio::process::Child, LiveProcess) {
        let child = self
            .child
            .take()
            .expect("admitted Mesh startup owns its child");
        let process = self
            .process
            .take()
            .expect("admitted Mesh startup owns its process identity");
        (child, process)
    }
}

impl Drop for MeshProcessStartup {
    fn drop(&mut self) {
        if let Some(process) = &self.process {
            let _ = process.signal(Signal::KILL);
        }
        if let Some(child) = self.child.as_mut() {
            let _ = child.start_kill();
        }
    }
}

struct PreparedMeshTransport {
    startup: MeshProcessStartup,
    control: tokio::net::UnixStream,
    submission_key: Zeroizing<[u8; MESH_INGRESS_CONTROL_KEY_LEN]>,
}

struct PreparedMeshEnrollment {
    startup: MeshProcessStartup,
    control: tokio::net::UnixStream,
}

struct NetworkStackLaunch<'a> {
    executable: &'a Path,
    working_directory: &'a Path,
    hybrid: &'a HybridVsockTarget,
    vm_id: Uuid,
    generation: u64,
    deadline: tokio::time::Instant,
    mesh: Option<&'a MeshAttachment>,
    mesh_credential_roots: Option<(&'a Path, &'a Path)>,
}

struct NetworkWorkerProcess {
    child: tokio::process::Child,
    process: LiveProcess,
    broker: Option<EgressBrokerProcess>,
    ingress_control: Option<tokio::net::UnixStream>,
    host_port_key: Option<Zeroizing<[u8; HOST_PORT_CONTROL_KEY_LEN]>>,
    mesh_ingress_key: Option<Zeroizing<[u8; MESH_INGRESS_CONTROL_KEY_LEN]>>,
    mesh_ingress_publisher: Option<MeshIngressPublisher>,
    ingress_forwarder: Option<JoinHandle<Result<(), RunnerError>>>,
    mesh_transport: Option<MeshTransportProcess>,
}

fn take_ingress_forwarder_failure(
    forwarder: &mut Option<JoinHandle<Result<(), RunnerError>>>,
) -> bool {
    let outcome = {
        let Some(forwarder) = forwarder.as_mut() else {
            return false;
        };
        if !forwarder.is_finished() {
            return false;
        }
        (&mut *forwarder).now_or_never()
    };
    let Some(outcome) = outcome else {
        return false;
    };
    let _ = forwarder.take();
    !matches!(outcome, Ok(Ok(())))
}

fn take_mesh_ingress_receiver_exit(
    receiver: &mut Option<JoinHandle<Result<(), MeshTransportError>>>,
) -> bool {
    let outcome = {
        let Some(receiver) = receiver.as_mut() else {
            return true;
        };
        if !receiver.is_finished() {
            return false;
        }
        (&mut *receiver).now_or_never()
    };
    if outcome.is_some() {
        let _ = receiver.take();
        true
    } else {
        false
    }
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

    fn disarm(
        mut self,
        ingress_control: Option<tokio::net::UnixStream>,
        host_port_key: Option<Zeroizing<[u8; HOST_PORT_CONTROL_KEY_LEN]>>,
        mesh_ingress_key: Option<Zeroizing<[u8; MESH_INGRESS_CONTROL_KEY_LEN]>>,
    ) -> NetworkWorkerProcess {
        NetworkWorkerProcess {
            child: self
                .child
                .take()
                .expect("admitted network worker owns its child"),
            process: self
                .process
                .take()
                .expect("admitted network worker owns its process identity"),
            broker: None,
            ingress_control,
            host_port_key,
            mesh_ingress_key,
            mesh_ingress_publisher: None,
            ingress_forwarder: None,
            mesh_transport: None,
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

struct EgressBrokerStartup {
    child: Option<tokio::process::Child>,
    process: Option<LiveProcess>,
}

impl EgressBrokerStartup {
    fn new(child: tokio::process::Child) -> Self {
        Self {
            child: Some(child),
            process: None,
        }
    }

    fn child_mut(&mut self) -> &mut tokio::process::Child {
        self.child
            .as_mut()
            .expect("armed egress broker startup owns its child")
    }

    fn admit(&mut self, process: LiveProcess) {
        self.process = Some(process);
    }

    fn disarm(mut self) -> EgressBrokerProcess {
        EgressBrokerProcess {
            child: self
                .child
                .take()
                .expect("admitted egress broker owns its child"),
            process: self
                .process
                .take()
                .expect("admitted egress broker owns its process identity"),
        }
    }
}

impl Drop for EgressBrokerStartup {
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

async fn reap_failed_egress_broker_startup(
    startup: &mut EgressBrokerStartup,
) -> Result<(), RunnerError> {
    if startup
        .child_mut()
        .try_wait()
        .map_err(|_| RunnerError::EgressBrokerWait)?
        .is_some()
    {
        return Ok(());
    }
    let _ = startup.child_mut().start_kill();
    tokio::time::timeout(SIGNAL_STOP_TIMEOUT, startup.child_mut().wait())
        .await
        .map_err(|_| RunnerError::EgressBrokerKillTimeout)?
        .map_err(|_| RunnerError::EgressBrokerWait)?;
    Ok(())
}

async fn stop_network_worker_process(worker: &mut NetworkWorkerProcess) -> Result<(), RunnerError> {
    let mesh_result = match worker.mesh_transport.as_mut() {
        Some(mesh) => stop_mesh_transport_process(mesh).await,
        None => Ok(()),
    };
    worker.mesh_transport = None;
    let worker_result = stop_network_worker_process_inner(worker).await;
    match (mesh_result, worker_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), _) | (_, Err(error)) => Err(error),
    }
}

async fn stop_network_worker_process_inner(
    worker: &mut NetworkWorkerProcess,
) -> Result<(), RunnerError> {
    drop(worker.mesh_ingress_publisher.take());
    if let Some(forwarder) = worker.ingress_forwarder.take() {
        forwarder.abort();
        let _ = forwarder.await;
    }
    drop(worker.ingress_control.take());
    drop(worker.host_port_key.take());
    drop(worker.mesh_ingress_key.take());
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

async fn stop_mesh_transport_process(mesh: &mut MeshTransportProcess) -> Result<(), RunnerError> {
    if let Some(receiver) = mesh.ingress_receiver.take() {
        receiver.abort();
        let _ = receiver.await;
    }
    if mesh
        .child
        .try_wait()
        .map_err(|_| RunnerError::MeshProcessWait)?
        .is_some()
    {
        return Ok(());
    }
    if mesh.process.wait_exited(SIGNAL_STOP_TIMEOUT).await? {
        mesh.child
            .wait()
            .await
            .map_err(|_| RunnerError::MeshProcessWait)?;
        return Ok(());
    }
    if !signal_or_observe_exit(&mesh.process, Signal::TERM)?
        && !mesh.process.wait_exited(SIGNAL_STOP_TIMEOUT).await?
        && !signal_or_observe_exit(&mesh.process, Signal::KILL)?
        && !mesh.process.wait_exited(SIGNAL_STOP_TIMEOUT).await?
    {
        return Err(RunnerError::MeshProcessKillTimeout);
    }
    mesh.child
        .wait()
        .await
        .map_err(|_| RunnerError::MeshProcessWait)?;
    Ok(())
}

async fn stop_egress_broker_process(broker: &mut EgressBrokerProcess) -> Result<(), RunnerError> {
    if broker
        .child
        .try_wait()
        .map_err(|_| RunnerError::EgressBrokerWait)?
        .is_some()
    {
        return Ok(());
    }
    if broker.process.wait_exited(SIGNAL_STOP_TIMEOUT).await? {
        broker
            .child
            .wait()
            .await
            .map_err(|_| RunnerError::EgressBrokerWait)?;
        return Ok(());
    }
    if !signal_or_observe_exit(&broker.process, Signal::TERM)?
        && !broker.process.wait_exited(SIGNAL_STOP_TIMEOUT).await?
        && !signal_or_observe_exit(&broker.process, Signal::KILL)?
        && !broker.process.wait_exited(SIGNAL_STOP_TIMEOUT).await?
    {
        return Err(RunnerError::EgressBrokerKillTimeout);
    }
    broker
        .child
        .wait()
        .await
        .map_err(|_| RunnerError::EgressBrokerWait)?;
    Ok(())
}

struct AcceptedHostPort {
    binding: HostPortBinding,
    stream: tokio::net::TcpStream,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HostPortDependency {
    Vmm,
    NetworkWorker,
    EgressBroker,
}

struct IngressControlKeys {
    host_port: Zeroizing<[u8; HOST_PORT_CONTROL_KEY_LEN]>,
    mesh: Zeroizing<[u8; MESH_INGRESS_CONTROL_KEY_LEN]>,
}

fn start_ingress_forwarder(
    vmm: &LiveProcess,
    worker: &mut NetworkWorkerProcess,
    listeners: Vec<ReservedHostPort>,
    mesh_ports: Option<&[u16]>,
    vm_id: Uuid,
    generation: u64,
) -> Result<(), RunnerError> {
    if listeners.is_empty() && mesh_ports.is_none() {
        return Ok(());
    }
    let control = worker
        .ingress_control
        .take()
        .ok_or(RunnerError::IngressControl)?;
    let host_port_key = worker
        .host_port_key
        .take()
        .ok_or(RunnerError::IngressControl)?;
    let mesh_ingress_key = worker
        .mesh_ingress_key
        .take()
        .ok_or(RunnerError::IngressControl)?;
    let mut async_listeners = Vec::with_capacity(listeners.len());
    for reserved in listeners {
        let binding = reserved.binding;
        let listener = tokio::net::TcpListener::from_std(reserved.listener)
            .map_err(|_| RunnerError::IngressControl)?;
        let address = listener
            .local_addr()
            .map_err(|_| RunnerError::IngressControl)?;
        if address.ip() != Ipv4Addr::LOCALHOST || address.port() != binding.host_port {
            return Err(RunnerError::IngressControl);
        }
        async_listeners.push((listener, binding));
    }
    let (mesh_ingress_publisher, mesh_ingress_receiver) =
        mesh_ingress_channel(mesh_ports.unwrap_or_default())
            .map_err(|_| RunnerError::IngressControl)?;
    let mut process_wait_descriptors = vec![
        (HostPortDependency::Vmm, vmm.duplicate_wait_descriptor()?),
        (
            HostPortDependency::NetworkWorker,
            worker.process.duplicate_wait_descriptor()?,
        ),
    ];
    if let Some(broker) = worker.broker.as_ref() {
        process_wait_descriptors.push((
            HostPortDependency::EgressBroker,
            broker.process.duplicate_wait_descriptor()?,
        ));
    }
    worker.mesh_ingress_publisher = mesh_ports.map(|_| mesh_ingress_publisher);
    worker.ingress_forwarder = Some(tokio::spawn(run_ingress_forwarder(
        control,
        IngressControlKeys {
            host_port: host_port_key,
            mesh: mesh_ingress_key,
        },
        async_listeners,
        mesh_ingress_receiver,
        process_wait_descriptors,
        vm_id,
        generation,
    )));
    Ok(())
}

async fn run_ingress_forwarder(
    mut control: tokio::net::UnixStream,
    keys: IngressControlKeys,
    listeners: Vec<(tokio::net::TcpListener, HostPortBinding)>,
    mut mesh_ingress: tokio::sync::mpsc::Receiver<AcceptedMeshIngress>,
    process_wait_descriptors: Vec<(HostPortDependency, OwnedFd)>,
    vm_id: Uuid,
    generation: u64,
) -> Result<(), RunnerError> {
    let (accepted_tx, mut accepted_rx) = tokio::sync::mpsc::channel(HOST_PORT_ACCEPT_QUEUE);
    let mut acceptors = JoinSet::new();
    for (listener, binding) in listeners {
        let accepted_tx = accepted_tx.clone();
        acceptors.spawn(accept_host_port(listener, binding, accepted_tx));
    }
    drop(accepted_tx);
    let mut monitors = JoinSet::new();
    for (dependency, descriptor) in process_wait_descriptors {
        monitors.spawn(async move {
            let descriptor = AsyncFd::new(descriptor).map_err(|_| RunnerError::IngressControl)?;
            let _ready = descriptor
                .readable()
                .await
                .map_err(|_| RunnerError::IngressControl)?;
            Ok::<HostPortDependency, RunnerError>(dependency)
        });
    }
    let mut host_sequence = 1_u64;
    let mut mesh_sequence = 1_u64;
    let mut accepting_host_ports = !acceptors.is_empty();
    let mut accepting_mesh = true;
    loop {
        tokio::select! {
            accepted = accepted_rx.recv(), if accepting_host_ports => {
                let accepted = accepted.ok_or(RunnerError::IngressControl)?;
                transfer_host_port_connection(
                    &mut control,
                    &keys.host_port,
                    vm_id,
                    generation,
                    host_sequence,
                    accepted,
                ).await?;
                host_sequence = host_sequence
                    .checked_add(1)
                    .ok_or(RunnerError::IngressControl)?;
            }
            accepted = mesh_ingress.recv(), if accepting_mesh => {
                let Some(accepted) = accepted else {
                    accepting_mesh = false;
                    continue;
                };
                transfer_mesh_ingress_connection(
                    &mut control,
                    &keys.mesh,
                    vm_id,
                    generation,
                    mesh_sequence,
                    accepted,
                ).await?;
                mesh_sequence = mesh_sequence
                    .checked_add(1)
                    .ok_or(RunnerError::IngressControl)?;
            }
            readable = control.readable() => {
                readable.map_err(|_| RunnerError::IngressControl)?;
                let mut unexpected = [0_u8; 1];
                match control.try_read(&mut unexpected) {
                    Ok(0) | Ok(_) => return Err(RunnerError::IngressControl),
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(_) => return Err(RunnerError::IngressControl),
                }
            }
            completed = acceptors.join_next(), if !acceptors.is_empty() => {
                let _ = completed;
                return Err(RunnerError::IngressControl);
            }
            completed = monitors.join_next(), if !monitors.is_empty() => {
                let dependency = completed
                    .ok_or(RunnerError::IngressControl)?
                    .map_err(|_| RunnerError::IngressControl)??;
                match dependency {
                    HostPortDependency::Vmm | HostPortDependency::NetworkWorker => return Ok(()),
                    HostPortDependency::EgressBroker => {
                        // Egress and ingress have separate authorities. Broker
                        // loss must release every host listener, but closing the
                        // worker control stream here would turn the resulting
                        // fail-closed worker into a misleading worker failure.
                        accepting_host_ports = false;
                        acceptors.abort_all();
                        while acceptors.join_next().await.is_some() {}
                        accepted_rx.close();
                        while accepted_rx.try_recv().is_ok() {}
                    }
                }
            }
        }
    }
}

async fn accept_host_port(
    listener: tokio::net::TcpListener,
    binding: HostPortBinding,
    accepted: tokio::sync::mpsc::Sender<AcceptedHostPort>,
) -> Result<(), RunnerError> {
    loop {
        let (stream, peer) = listener
            .accept()
            .await
            .map_err(|_| RunnerError::IngressControl)?;
        if !peer.ip().is_loopback()
            || stream.local_addr().ok().is_none_or(|address| {
                address.ip() != Ipv4Addr::LOCALHOST || address.port() != binding.host_port
            })
        {
            continue;
        }
        accepted
            .send(AcceptedHostPort { binding, stream })
            .await
            .map_err(|_| RunnerError::IngressControl)?;
    }
}

async fn transfer_host_port_connection(
    control: &mut tokio::net::UnixStream,
    key: &[u8; HOST_PORT_CONTROL_KEY_LEN],
    vm_id: Uuid,
    generation: u64,
    sequence: u64,
    accepted: AcceptedHostPort,
) -> Result<(), RunnerError> {
    let frame = HostPortControlFrame::encode(vm_id, generation, sequence, accepted.binding, key)
        .map_err(|_| RunnerError::IngressControl)?;
    let deadline = tokio::time::Instant::now() + HOST_PORT_CONTROL_TIMEOUT;
    tokio::time::timeout_at(deadline, async {
        control.write_all(&frame).await?;
        control.flush().await
    })
    .await
    .map_err(|_| RunnerError::IngressControl)?
    .map_err(|_| RunnerError::IngressControl)?;
    transfer_worker_descriptor(
        control,
        accepted.stream.as_raw_fd(),
        deadline,
        send_worker_host_port_descriptor,
    )
    .await
    .map_err(|_| RunnerError::IngressControl)
}

async fn transfer_mesh_ingress_connection(
    control: &mut tokio::net::UnixStream,
    key: &[u8; MESH_INGRESS_CONTROL_KEY_LEN],
    vm_id: Uuid,
    generation: u64,
    sequence: u64,
    accepted: AcceptedMeshIngress,
) -> Result<(), RunnerError> {
    let frame = MeshIngressControlFrame::encode(vm_id, generation, sequence, accepted.binding, key)
        .map_err(|_| RunnerError::IngressControl)?;
    let deadline = tokio::time::Instant::now() + HOST_PORT_CONTROL_TIMEOUT;
    tokio::time::timeout_at(deadline, async {
        control.write_all(&frame).await?;
        control.flush().await
    })
    .await
    .map_err(|_| RunnerError::IngressControl)?
    .map_err(|_| RunnerError::IngressControl)?;
    transfer_worker_descriptor(
        control,
        accepted.stream.as_raw_fd(),
        deadline,
        send_mesh_ingress_descriptor,
    )
    .await
    .map_err(|_| RunnerError::IngressControl)
}

async fn spawn_mesh_stack_processes(
    context: &NetworkStackLaunch<'_>,
    publisher: MeshIngressPublisher,
) -> Result<MeshTransportProcess, RunnerError> {
    let attachment = context.mesh.ok_or(RunnerError::MeshTransportBootstrap)?;
    let (mesh_data_dir, platform_config_dir) = context
        .mesh_credential_roots
        .ok_or(RunnerError::MeshEnrollmentBrokerBootstrap)?;
    let deadline = tokio::time::Instant::now() + MESH_STACK_ATTACH_TIMEOUT;
    let (enrollment_transfer, transport_enrollment) =
        StdUnixStream::pair().map_err(|_| RunnerError::MeshTransportSpawn)?;

    let mut transport =
        spawn_mesh_transport_process(context, attachment, transport_enrollment, deadline).await?;
    let mut enrollment = match spawn_mesh_enrollment_process(
        context,
        attachment,
        mesh_data_dir,
        platform_config_dir,
        enrollment_transfer,
        deadline,
    )
    .await
    {
        Ok(enrollment) => enrollment,
        Err(error) => {
            reap_failed_mesh_process_startup(&mut transport.startup).await?;
            return Err(error);
        }
    };

    if let Err(error) = write_mesh_control_frame(
        &mut transport.control,
        MESH_TRANSPORT_CONFINE_MESSAGE,
        deadline,
    )
    .await
    {
        return match error {
            MeshStatusReadError::Timeout => {
                reap_mesh_stack_startup(&mut transport.startup, &mut enrollment.startup).await?;
                Err(RunnerError::MeshTransportStartTimeout)
            }
            MeshStatusReadError::Protocol => {
                let failure = mesh_transport_exit_or(
                    &mut transport.startup,
                    RunnerError::MeshTransportBootstrap,
                )
                .await?;
                reap_failed_mesh_process_startup(&mut enrollment.startup).await?;
                Err(failure)
            }
        };
    }
    let confined_status = match read_mesh_status_frame(
        &mut transport.control,
        MESH_TRANSPORT_STATUS_MAX_BYTES,
        deadline,
    )
    .await
    {
        Ok(status) => status,
        Err(MeshStatusReadError::Timeout) => {
            reap_mesh_stack_startup(&mut transport.startup, &mut enrollment.startup).await?;
            return Err(RunnerError::MeshTransportStartTimeout);
        }
        Err(MeshStatusReadError::Protocol) => {
            let failure =
                mesh_transport_exit_or(&mut transport.startup, RunnerError::MeshTransportBootstrap)
                    .await?;
            reap_failed_mesh_process_startup(&mut enrollment.startup).await?;
            return Err(failure);
        }
    };
    match decode_mesh_transport_startup_status(&confined_status) {
        Some(MeshTransportStartupStatus::Confined)
            if confined_status.as_slice() == MESH_TRANSPORT_CONFINED_MESSAGE => {}
        Some(MeshTransportStartupStatus::Failed(failure)) => {
            reap_mesh_stack_startup(&mut transport.startup, &mut enrollment.startup).await?;
            return Err(RunnerError::MeshTransportStartup(failure));
        }
        Some(MeshTransportStartupStatus::Ready | MeshTransportStartupStatus::Confined) | None => {
            reap_mesh_stack_startup(&mut transport.startup, &mut enrollment.startup).await?;
            return Err(RunnerError::MeshTransportBootstrap);
        }
    }
    if let Err(error) = write_mesh_control_frame(
        &mut enrollment.control,
        MESH_ENROLLMENT_CONFINE_MESSAGE,
        deadline,
    )
    .await
    {
        return match error {
            MeshStatusReadError::Timeout => {
                reap_mesh_stack_startup(&mut transport.startup, &mut enrollment.startup).await?;
                Err(RunnerError::MeshEnrollmentBrokerStartTimeout)
            }
            MeshStatusReadError::Protocol => {
                let failure = mesh_enrollment_exit_or(
                    &mut enrollment.startup,
                    RunnerError::MeshEnrollmentBrokerBootstrap,
                )
                .await?;
                reap_failed_mesh_process_startup(&mut transport.startup).await?;
                Err(failure)
            }
        };
    }

    let enrollment_status = match read_mesh_status_frame(
        &mut enrollment.control,
        MESH_ENROLLMENT_STATUS_MAX_BYTES,
        deadline,
    )
    .await
    {
        Ok(status) => status,
        Err(MeshStatusReadError::Timeout) => {
            reap_mesh_stack_startup(&mut transport.startup, &mut enrollment.startup).await?;
            return Err(RunnerError::MeshEnrollmentBrokerStartTimeout);
        }
        Err(MeshStatusReadError::Protocol) => {
            let error = mesh_enrollment_exit_or(
                &mut enrollment.startup,
                RunnerError::MeshEnrollmentBrokerBootstrap,
            )
            .await?;
            reap_failed_mesh_process_startup(&mut transport.startup).await?;
            return Err(error);
        }
    };
    match decode_mesh_enrollment_startup_status(&enrollment_status) {
        Some(MeshEnrollmentStartupStatus::Ready)
            if enrollment_status.as_slice() == MESH_ENROLLMENT_READY_MESSAGE => {}
        Some(MeshEnrollmentStartupStatus::Failed(failure)) => {
            reap_mesh_stack_startup(&mut transport.startup, &mut enrollment.startup).await?;
            return Err(RunnerError::MeshEnrollmentBrokerStartup(failure));
        }
        _ => {
            reap_mesh_stack_startup(&mut transport.startup, &mut enrollment.startup).await?;
            return Err(RunnerError::MeshEnrollmentBrokerBootstrap);
        }
    }
    let enrollment_exit =
        match tokio::time::timeout_at(deadline, enrollment.startup.child_mut().wait()).await {
            Ok(Ok(status)) => status,
            Ok(Err(_)) => {
                reap_mesh_stack_startup(&mut transport.startup, &mut enrollment.startup).await?;
                return Err(RunnerError::MeshProcessWait);
            }
            Err(_) => {
                reap_mesh_stack_startup(&mut transport.startup, &mut enrollment.startup).await?;
                return Err(RunnerError::MeshEnrollmentBrokerStartTimeout);
            }
        };
    enrollment.startup.child.take();
    enrollment.startup.process.take();
    if !enrollment_exit.success() {
        reap_failed_mesh_process_startup(&mut transport.startup).await?;
        return Err(enrollment_exit
            .code()
            .and_then(MeshEnrollmentStartupFailure::from_exit_code)
            .map_or(
                RunnerError::MeshEnrollmentBrokerBootstrap,
                RunnerError::MeshEnrollmentBrokerStartup,
            ));
    }

    let transport_status = match read_mesh_status_frame(
        &mut transport.control,
        MESH_TRANSPORT_STATUS_MAX_BYTES,
        deadline,
    )
    .await
    {
        Ok(status) => status,
        Err(MeshStatusReadError::Timeout) => {
            reap_failed_mesh_process_startup(&mut transport.startup).await?;
            return Err(RunnerError::MeshTransportStartTimeout);
        }
        Err(MeshStatusReadError::Protocol) => {
            let error =
                mesh_transport_exit_or(&mut transport.startup, RunnerError::MeshTransportBootstrap)
                    .await?;
            return Err(error);
        }
    };
    match decode_mesh_transport_startup_status(&transport_status) {
        Some(MeshTransportStartupStatus::Ready)
            if transport_status.as_slice() == MESH_TRANSPORT_READY_MESSAGE => {}
        Some(MeshTransportStartupStatus::Failed(failure)) => {
            reap_failed_mesh_process_startup(&mut transport.startup).await?;
            return Err(RunnerError::MeshTransportStartup(failure));
        }
        Some(MeshTransportStartupStatus::Confined | MeshTransportStartupStatus::Ready) | None => {
            reap_failed_mesh_process_startup(&mut transport.startup).await?;
            return Err(RunnerError::MeshTransportBootstrap);
        }
    }

    let (child, process) = transport.startup.disarm();
    let ingress_receiver = tokio::spawn(receive_mesh_ingress_submissions(
        transport.control,
        publisher,
        context.vm_id,
        context.generation,
        attachment.guest_ports.clone(),
        transport.submission_key,
    ));
    Ok(MeshTransportProcess {
        child,
        process,
        ingress_receiver: Some(ingress_receiver),
    })
}

async fn spawn_mesh_transport_process(
    context: &NetworkStackLaunch<'_>,
    attachment: &MeshAttachment,
    enrollment: StdUnixStream,
    deadline: tokio::time::Instant,
) -> Result<PreparedMeshTransport, RunnerError> {
    let submission_key = fresh_mesh_ingress_control_key();
    let bootstrap = encode_mesh_transport_bootstrap(
        context.vm_id,
        context.generation,
        attachment,
        &submission_key,
    )
    .map_err(|_| RunnerError::MeshTransportBootstrap)?;
    let (control_parent, control_child) =
        StdUnixStream::pair().map_err(|_| RunnerError::MeshTransportSpawn)?;
    control_parent
        .set_nonblocking(true)
        .map_err(|_| RunnerError::MeshTransportSpawn)?;
    let mut control = tokio::net::UnixStream::from_std(control_parent)
        .map_err(|_| RunnerError::MeshTransportSpawn)?;
    let inherited_control = duplicate_inherited_descriptor(control_child.as_raw_fd())
        .map_err(|_| RunnerError::MeshTransportSpawn)?;
    let inherited_enrollment = duplicate_inherited_descriptor(enrollment.as_raw_fd())
        .map_err(|_| RunnerError::MeshTransportSpawn)?;
    let expected_parent = unsafe { libc::getpid() };
    let mut command = tokio::process::Command::new(context.executable);
    command
        .arg("__native-mesh-transport")
        .arg("--environment-id")
        .arg(context.vm_id.to_string())
        .arg("--generation")
        .arg(context.generation.to_string())
        .env_clear()
        .current_dir(context.working_directory)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let control_fd = inherited_control.as_raw_fd();
    let enrollment_fd = inherited_enrollment.as_raw_fd();
    unsafe {
        command.pre_exec(move || {
            prepare_isolated_child_pair(
                expected_parent,
                control_fd,
                MESH_TRANSPORT_BOOTSTRAP_FD,
                enrollment_fd,
                MESH_TRANSPORT_ENROLLMENT_FD,
            )
        });
    }
    let child = command
        .spawn()
        .map_err(|_| RunnerError::MeshTransportSpawn)?;
    drop(inherited_control);
    drop(inherited_enrollment);
    drop(control_child);
    drop(enrollment);
    let mut startup = MeshProcessStartup::new(child);
    let Some(pid) = startup.child_mut().id() else {
        reap_failed_mesh_process_startup(&mut startup).await?;
        return Err(RunnerError::MeshTransportSpawn);
    };
    if let Err(error) = write_mesh_control_frame(&mut control, bootstrap.as_ref(), deadline).await {
        return match error {
            MeshStatusReadError::Timeout => {
                reap_failed_mesh_process_startup(&mut startup).await?;
                Err(RunnerError::MeshTransportStartTimeout)
            }
            MeshStatusReadError::Protocol => Err(mesh_transport_exit_or(
                &mut startup,
                RunnerError::MeshTransportBootstrap,
            )
            .await?),
        };
    }
    let prepared =
        match read_mesh_status_frame(&mut control, MESH_TRANSPORT_STATUS_MAX_BYTES, deadline).await
        {
            Ok(prepared) => prepared,
            Err(MeshStatusReadError::Timeout) => {
                reap_failed_mesh_process_startup(&mut startup).await?;
                return Err(RunnerError::MeshTransportStartTimeout);
            }
            Err(MeshStatusReadError::Protocol) => {
                return Err(mesh_transport_exit_or(
                    &mut startup,
                    RunnerError::MeshTransportBootstrap,
                )
                .await?);
            }
        };
    if prepared.as_slice() != MESH_TRANSPORT_PREPARED_MESSAGE {
        let error = decode_mesh_transport_startup_status(&prepared).map_or(
            RunnerError::MeshTransportBootstrap,
            |status| match status {
                MeshTransportStartupStatus::Confined | MeshTransportStartupStatus::Ready => {
                    RunnerError::MeshTransportBootstrap
                }
                MeshTransportStartupStatus::Failed(failure) => {
                    RunnerError::MeshTransportStartup(failure)
                }
            },
        );
        reap_failed_mesh_process_startup(&mut startup).await?;
        return Err(error);
    }
    let process = match LiveProcess::capture_child(pid, context.executable) {
        Ok(process) => process,
        Err(error) => {
            let fallback = RunnerError::Recovery(error);
            return Err(mesh_transport_exit_or(&mut startup, fallback).await?);
        }
    };
    startup.admit(process);
    Ok(PreparedMeshTransport {
        startup,
        control,
        submission_key,
    })
}

async fn spawn_mesh_enrollment_process(
    context: &NetworkStackLaunch<'_>,
    attachment: &MeshAttachment,
    mesh_data_dir: &Path,
    platform_config_dir: &Path,
    transfer: StdUnixStream,
    deadline: tokio::time::Instant,
) -> Result<PreparedMeshEnrollment, RunnerError> {
    let bootstrap = encode_mesh_enrollment_bootstrap(context.vm_id, context.generation, attachment)
        .map_err(|_| RunnerError::MeshEnrollmentBrokerBootstrap)?;
    let (control_parent, control_child) =
        StdUnixStream::pair().map_err(|_| RunnerError::MeshEnrollmentBrokerSpawn)?;
    control_parent
        .set_nonblocking(true)
        .map_err(|_| RunnerError::MeshEnrollmentBrokerSpawn)?;
    let mut control = tokio::net::UnixStream::from_std(control_parent)
        .map_err(|_| RunnerError::MeshEnrollmentBrokerSpawn)?;
    let inherited_control = duplicate_inherited_descriptor(control_child.as_raw_fd())
        .map_err(|_| RunnerError::MeshEnrollmentBrokerSpawn)?;
    let inherited_transfer = duplicate_inherited_descriptor(transfer.as_raw_fd())
        .map_err(|_| RunnerError::MeshEnrollmentBrokerSpawn)?;
    let expected_parent = unsafe { libc::getpid() };
    let mut command = tokio::process::Command::new(context.executable);
    command
        .arg("__native-mesh-enrollment-broker")
        .arg("--environment-id")
        .arg(context.vm_id.to_string())
        .arg("--generation")
        .arg(context.generation.to_string())
        .arg("--mesh-data-dir")
        .arg(mesh_data_dir)
        .arg("--platform-config-dir")
        .arg(platform_config_dir)
        .env_clear()
        .current_dir(context.working_directory)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let control_fd = inherited_control.as_raw_fd();
    let transfer_fd = inherited_transfer.as_raw_fd();
    unsafe {
        command.pre_exec(move || {
            prepare_isolated_child_pair(
                expected_parent,
                control_fd,
                MESH_ENROLLMENT_BOOTSTRAP_FD,
                transfer_fd,
                MESH_ENROLLMENT_TRANSFER_FD,
            )
        });
    }
    let child = command
        .spawn()
        .map_err(|_| RunnerError::MeshEnrollmentBrokerSpawn)?;
    drop(inherited_control);
    drop(inherited_transfer);
    drop(control_child);
    drop(transfer);
    let mut startup = MeshProcessStartup::new(child);
    let Some(pid) = startup.child_mut().id() else {
        reap_failed_mesh_process_startup(&mut startup).await?;
        return Err(RunnerError::MeshEnrollmentBrokerSpawn);
    };
    if let Err(error) = write_mesh_control_frame(&mut control, &bootstrap, deadline).await {
        return match error {
            MeshStatusReadError::Timeout => {
                reap_failed_mesh_process_startup(&mut startup).await?;
                Err(RunnerError::MeshEnrollmentBrokerStartTimeout)
            }
            MeshStatusReadError::Protocol => Err(mesh_enrollment_exit_or(
                &mut startup,
                RunnerError::MeshEnrollmentBrokerBootstrap,
            )
            .await?),
        };
    }
    let prepared = match read_mesh_status_frame(
        &mut control,
        MESH_ENROLLMENT_STATUS_MAX_BYTES,
        deadline,
    )
    .await
    {
        Ok(prepared) => prepared,
        Err(MeshStatusReadError::Timeout) => {
            reap_failed_mesh_process_startup(&mut startup).await?;
            return Err(RunnerError::MeshEnrollmentBrokerStartTimeout);
        }
        Err(MeshStatusReadError::Protocol) => {
            return Err(mesh_enrollment_exit_or(
                &mut startup,
                RunnerError::MeshEnrollmentBrokerBootstrap,
            )
            .await?);
        }
    };
    if prepared.as_slice() != MESH_ENROLLMENT_PREPARED_MESSAGE {
        let error = decode_mesh_enrollment_startup_status(&prepared).map_or(
            RunnerError::MeshEnrollmentBrokerBootstrap,
            |status| match status {
                MeshEnrollmentStartupStatus::Ready => RunnerError::MeshEnrollmentBrokerBootstrap,
                MeshEnrollmentStartupStatus::Failed(failure) => {
                    RunnerError::MeshEnrollmentBrokerStartup(failure)
                }
            },
        );
        reap_failed_mesh_process_startup(&mut startup).await?;
        return Err(error);
    }
    let process = match LiveProcess::capture_child(pid, context.executable) {
        Ok(process) => process,
        Err(error) => {
            let fallback = RunnerError::Recovery(error);
            return Err(mesh_enrollment_exit_or(&mut startup, fallback).await?);
        }
    };
    startup.admit(process);
    Ok(PreparedMeshEnrollment { startup, control })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MeshStatusReadError {
    Timeout,
    Protocol,
}

async fn write_mesh_control_frame(
    control: &mut tokio::net::UnixStream,
    frame: &[u8],
    deadline: tokio::time::Instant,
) -> Result<(), MeshStatusReadError> {
    tokio::time::timeout_at(deadline, async {
        control.write_all(frame).await?;
        control.flush().await
    })
    .await
    .map_err(|_| MeshStatusReadError::Timeout)?
    .map_err(|_| MeshStatusReadError::Protocol)
}

async fn read_mesh_status_frame(
    control: &mut tokio::net::UnixStream,
    maximum_bytes: usize,
    deadline: tokio::time::Instant,
) -> Result<Vec<u8>, MeshStatusReadError> {
    let mut frame = Vec::with_capacity(maximum_bytes);
    loop {
        if frame.len() == maximum_bytes {
            return Err(MeshStatusReadError::Protocol);
        }
        let mut byte = [0_u8; 1];
        let read = tokio::time::timeout_at(deadline, control.read(&mut byte))
            .await
            .map_err(|_| MeshStatusReadError::Timeout)?
            .map_err(|_| MeshStatusReadError::Protocol)?;
        if read == 0 || byte[0] == b'\r' || !byte[0].is_ascii() {
            return Err(MeshStatusReadError::Protocol);
        }
        frame.push(byte[0]);
        if byte[0] == b'\n' {
            return Ok(frame);
        }
    }
}

async fn mesh_transport_exit_or(
    startup: &mut MeshProcessStartup,
    fallback: RunnerError,
) -> Result<RunnerError, RunnerError> {
    let exit_deadline = tokio::time::Instant::now() + Duration::from_millis(100);
    loop {
        match startup.child_mut().try_wait() {
            Ok(Some(status)) => {
                startup.child.take();
                startup.process.take();
                return Ok(status
                    .code()
                    .and_then(MeshTransportStartupFailure::from_exit_code)
                    .map_or(fallback, RunnerError::MeshTransportStartup));
            }
            Ok(None) => {}
            Err(_) => return Err(RunnerError::MeshProcessWait),
        }
        if tokio::time::Instant::now() >= exit_deadline {
            reap_failed_mesh_process_startup(startup).await?;
            return Ok(fallback);
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

async fn mesh_enrollment_exit_or(
    startup: &mut MeshProcessStartup,
    fallback: RunnerError,
) -> Result<RunnerError, RunnerError> {
    let exit_deadline = tokio::time::Instant::now() + Duration::from_millis(100);
    loop {
        match startup.child_mut().try_wait() {
            Ok(Some(status)) => {
                startup.child.take();
                startup.process.take();
                return Ok(status
                    .code()
                    .and_then(MeshEnrollmentStartupFailure::from_exit_code)
                    .map_or(fallback, RunnerError::MeshEnrollmentBrokerStartup));
            }
            Ok(None) => {}
            Err(_) => return Err(RunnerError::MeshProcessWait),
        }
        if tokio::time::Instant::now() >= exit_deadline {
            reap_failed_mesh_process_startup(startup).await?;
            return Ok(fallback);
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

async fn reap_mesh_stack_startup(
    transport: &mut MeshProcessStartup,
    enrollment: &mut MeshProcessStartup,
) -> Result<(), RunnerError> {
    let transport_result = reap_failed_mesh_process_startup(transport).await;
    let enrollment_result = reap_failed_mesh_process_startup(enrollment).await;
    match (transport_result, enrollment_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), _) | (_, Err(error)) => Err(error),
    }
}

async fn reap_failed_mesh_process_startup(
    startup: &mut MeshProcessStartup,
) -> Result<(), RunnerError> {
    if startup
        .child_mut()
        .try_wait()
        .map_err(|_| RunnerError::MeshProcessWait)?
        .is_some()
    {
        startup.child.take();
        startup.process.take();
        return Ok(());
    }
    if let Some(process) = startup.process.as_ref() {
        let _ = process.signal(Signal::KILL);
    } else {
        let _ = startup.child_mut().start_kill();
    }
    tokio::time::timeout(SIGNAL_STOP_TIMEOUT, startup.child_mut().wait())
        .await
        .map_err(|_| RunnerError::MeshProcessKillTimeout)?
        .map_err(|_| RunnerError::MeshProcessWait)?;
    startup.child.take();
    startup.process.take();
    Ok(())
}

async fn spawn_network_stack_processes(
    context: &NetworkStackLaunch<'_>,
    network_key: NetworkKey,
    mode: NetworkWorkerMode,
) -> Result<NetworkWorkerProcess, RunnerError> {
    let launch = match mode {
        NetworkWorkerMode::Product => Some(spawn_egress_broker_process(context).await?),
        NetworkWorkerMode::InjectedVerification => None,
    };
    let (attachment, mut broker) = match launch {
        Some(EgressBrokerLaunch {
            process,
            endpoint,
            key,
        }) => (
            WorkerBrokerAttachment::Product { endpoint, key },
            Some(process),
        ),
        None => (WorkerBrokerAttachment::InjectedVerification, None),
    };
    let worker = spawn_network_worker_process(context, network_key, attachment).await;
    match worker {
        Ok(mut worker) => {
            worker.broker = broker;
            Ok(worker)
        }
        Err(error) => {
            if let Some(broker) = broker.as_mut() {
                stop_egress_broker_process(broker).await?;
            }
            Err(error)
        }
    }
}

async fn spawn_egress_broker_process(
    context: &NetworkStackLaunch<'_>,
) -> Result<EgressBrokerLaunch, RunnerError> {
    PrivateRoot::open(context.working_directory)?;
    let (bootstrap_parent, bootstrap_child) =
        StdUnixStream::pair().map_err(|_| RunnerError::EgressBrokerSpawn)?;
    bootstrap_parent
        .set_nonblocking(true)
        .map_err(|_| RunnerError::EgressBrokerSpawn)?;
    let mut bootstrap = tokio::net::UnixStream::from_std(bootstrap_parent)
        .map_err(|_| RunnerError::EgressBrokerSpawn)?;
    let key = fresh_egress_broker_key();
    let bytes = encode_developer_egress_broker_bootstrap(context.vm_id, context.generation, &key)
        .map_err(|_| RunnerError::EgressBrokerBootstrap)?;
    let inherited_bootstrap = duplicate_inherited_descriptor(bootstrap_child.as_raw_fd())
        .map_err(|_| RunnerError::EgressBrokerSpawn)?;
    let bootstrap_fd = inherited_bootstrap.as_raw_fd();
    let expected_parent = unsafe { libc::getpid() };
    let mut command = tokio::process::Command::new(context.executable);
    command
        .arg("__native-egress-broker")
        .arg("--environment-id")
        .arg(context.vm_id.to_string())
        .arg("--generation")
        .arg(context.generation.to_string())
        .env_clear()
        .current_dir(context.working_directory)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    unsafe {
        command.pre_exec(move || {
            prepare_isolated_child(expected_parent, bootstrap_fd, EGRESS_BROKER_BOOTSTRAP_FD)
        });
    }
    let child = command
        .spawn()
        .map_err(|_| RunnerError::EgressBrokerSpawn)?;
    drop(inherited_bootstrap);
    drop(bootstrap_child);
    let mut startup = EgressBrokerStartup::new(child);
    let Some(pid) = startup.child_mut().id() else {
        reap_failed_egress_broker_startup(&mut startup).await?;
        return Err(RunnerError::EgressBrokerSpawn);
    };

    let ready_deadline = std::cmp::min(
        context.deadline,
        tokio::time::Instant::now() + EGRESS_BROKER_READY_TIMEOUT,
    );
    let bootstrap_write = tokio::time::timeout_at(ready_deadline, async {
        bootstrap.write_all(bytes.as_ref()).await?;
        bootstrap.flush().await
    })
    .await;
    match bootstrap_write {
        Ok(Ok(())) => {}
        Err(_) => {
            reap_failed_egress_broker_startup(&mut startup).await?;
            return Err(RunnerError::EgressBrokerStartTimeout);
        }
        Ok(Err(_)) => {
            reap_failed_egress_broker_startup(&mut startup).await?;
            return Err(RunnerError::EgressBrokerBootstrap);
        }
    }
    let prepared = match read_egress_broker_status_frame(&mut bootstrap, ready_deadline).await {
        Ok(prepared) => prepared,
        Err(error) => {
            let error = classify_egress_broker_startup_error(&mut startup, error).await?;
            return Err(error);
        }
    };
    if prepared.as_slice() != EGRESS_BROKER_PREPARED_MESSAGE {
        if let Some(EgressBrokerStartupStatus::Failed(failure)) =
            decode_egress_broker_startup_status(&prepared)
        {
            reap_failed_egress_broker_startup(&mut startup).await?;
            return Err(RunnerError::EgressBrokerStartup(failure));
        }
        reap_failed_egress_broker_startup(&mut startup).await?;
        return Err(RunnerError::EgressBrokerBootstrap);
    }
    // The child has validated its generation-bound bootstrap but deliberately
    // waits before locking dumpability. This lets the runner capture and hash
    // the exact executable without racing either the short initial bootstrap
    // deadline or the broker's final confinement boundary.
    let process = match LiveProcess::capture_child(pid, context.executable) {
        Ok(process) => process,
        Err(error) => {
            let fallback = RunnerError::Recovery(error);
            let error = classify_egress_broker_startup_error(&mut startup, fallback).await?;
            return Err(error);
        }
    };
    startup.admit(process);
    let confinement_admission = tokio::time::timeout_at(ready_deadline, async {
        bootstrap.write_all(EGRESS_BROKER_CONFINE_MESSAGE).await?;
        bootstrap.flush().await
    })
    .await;
    match confinement_admission {
        Ok(Ok(())) => {}
        Err(_) => {
            reap_failed_egress_broker_startup(&mut startup).await?;
            return Err(RunnerError::EgressBrokerStartTimeout);
        }
        Ok(Err(_)) => {
            reap_failed_egress_broker_startup(&mut startup).await?;
            return Err(RunnerError::EgressBrokerBootstrap);
        }
    }
    let status = match read_egress_broker_status_frame(&mut bootstrap, ready_deadline).await {
        Ok(status) => status,
        Err(error) => {
            let error = classify_egress_broker_startup_error(&mut startup, error).await?;
            return Err(error);
        }
    };
    match decode_egress_broker_startup_status(&status) {
        Some(EgressBrokerStartupStatus::Ready) => {}
        Some(EgressBrokerStartupStatus::Failed(failure)) => {
            reap_failed_egress_broker_startup(&mut startup).await?;
            return Err(RunnerError::EgressBrokerStartup(failure));
        }
        None => {
            reap_failed_egress_broker_startup(&mut startup).await?;
            return Err(RunnerError::EgressBrokerBootstrap);
        }
    }
    if status.as_slice() != EGRESS_BROKER_READY_MESSAGE {
        reap_failed_egress_broker_startup(&mut startup).await?;
        return Err(RunnerError::EgressBrokerBootstrap);
    }
    let endpoint = bootstrap
        .into_std()
        .map_err(|_| RunnerError::EgressBrokerBootstrap)?;
    Ok(EgressBrokerLaunch {
        process: startup.disarm(),
        endpoint,
        key,
    })
}

async fn spawn_network_worker_process(
    context: &NetworkStackLaunch<'_>,
    key: NetworkKey,
    attachment: WorkerBrokerAttachment,
) -> Result<NetworkWorkerProcess, RunnerError> {
    PrivateRoot::open(context.working_directory)?;
    let (bootstrap_parent, bootstrap_child) =
        StdUnixStream::pair().map_err(|_| RunnerError::NetworkWorkerSpawn)?;
    bootstrap_parent
        .set_nonblocking(true)
        .map_err(|_| RunnerError::NetworkWorkerSpawn)?;
    let mut bootstrap = tokio::net::UnixStream::from_std(bootstrap_parent)
        .map_err(|_| RunnerError::NetworkWorkerSpawn)?;
    let product_worker = matches!(&attachment, WorkerBrokerAttachment::Product { .. });
    let host_port_key = product_worker.then(fresh_host_port_control_key);
    let mesh_ingress_key = product_worker.then(fresh_mesh_ingress_control_key);
    let (bytes, mut broker_endpoint) = match attachment {
        WorkerBrokerAttachment::Product {
            endpoint,
            key: broker_key,
        } => (
            encode_product_worker_bootstrap(
                context.vm_id,
                context.generation,
                &key,
                &broker_key,
                host_port_key
                    .as_deref()
                    .expect("product worker has a host-port control key"),
                mesh_ingress_key
                    .as_deref()
                    .expect("product worker has a Mesh ingress control key"),
                context
                    .mesh
                    .map(|attachment| attachment.guest_ports.as_slice())
                    .unwrap_or_default(),
            )
            .map(|bytes| Zeroizing::new(bytes.to_vec())),
            Some(endpoint),
        ),
        WorkerBrokerAttachment::InjectedVerification => (
            encode_worker_bootstrap(context.vm_id, context.generation, &key)
                .map(|bytes| Zeroizing::new(bytes.to_vec())),
            None,
        ),
    };
    let bytes = bytes.map_err(|_| RunnerError::NetworkWorkerBootstrap)?;
    let inherited_bootstrap = duplicate_inherited_descriptor(bootstrap_child.as_raw_fd())
        .map_err(|_| RunnerError::NetworkWorkerSpawn)?;
    let bootstrap_fd = inherited_bootstrap.as_raw_fd();
    let expected_parent = unsafe { libc::getpid() };
    let mut command = tokio::process::Command::new(context.executable);
    command
        .arg(if product_worker {
            "__native-network-worker"
        } else {
            "__native-network-worker-fixture"
        })
        .arg("--environment-id")
        .arg(context.vm_id.to_string())
        .arg("--generation")
        .arg(context.generation.to_string())
        .env_clear()
        .current_dir(context.working_directory)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    unsafe {
        command.pre_exec(move || {
            prepare_isolated_child(expected_parent, bootstrap_fd, NETWORK_BOOTSTRAP_FD)
        });
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

    let bootstrap_write = tokio::time::timeout_at(context.deadline, async {
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
    drop(bytes);

    let prepared_deadline = std::cmp::min(
        context.deadline,
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

    let process = match LiveProcess::capture_child(pid, context.executable) {
        Ok(process) => process,
        Err(error) => {
            let fallback = RunnerError::Recovery(error);
            let error = classify_network_worker_startup_error(&mut startup, fallback).await?;
            return Err(error);
        }
    };
    startup.admit(process);

    if let Some(endpoint) = broker_endpoint.as_ref() {
        if let Err(error) = transfer_worker_descriptor(
            &bootstrap,
            endpoint.as_raw_fd(),
            context.deadline,
            send_worker_broker_descriptor,
        )
        .await
        {
            reap_failed_network_worker_startup(&mut startup).await?;
            return Err(error);
        }
        drop(broker_endpoint.take());

        let status = match read_worker_status_frame(&mut bootstrap, context.deadline).await {
            Ok(status) => status,
            Err(error) => {
                let error = classify_network_worker_startup_error(&mut startup, error).await?;
                return Err(error);
            }
        };
        if status.as_slice() != WORKER_BROKER_READY_MESSAGE {
            if let Some(NetworkWorkerStartupStatus::Failed(failure)) =
                decode_worker_startup_status(&status)
            {
                reap_failed_network_worker_startup(&mut startup).await?;
                return Err(RunnerError::NetworkWorkerStartup(failure));
            }
            reap_failed_network_worker_startup(&mut startup).await?;
            return Err(RunnerError::NetworkWorkerBootstrap);
        }
    }

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
            context.deadline,
            context.hybrid.connect_guest_port(GUEST_NETWORK_VSOCK_PORT),
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
            Ok(Err(_)) if tokio::time::Instant::now() < context.deadline => {
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
    let descriptor_transfer = transfer_worker_descriptor(
        &bootstrap,
        network.as_raw_fd(),
        context.deadline,
        send_worker_network_descriptor,
    )
    .await;
    drop(network);
    match descriptor_transfer {
        Ok(()) => {}
        Err(error) => {
            reap_failed_network_worker_startup(&mut startup).await?;
            return Err(error);
        }
    }

    let status = match read_worker_status_frame(&mut bootstrap, context.deadline).await {
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
    let ingress_control = product_worker.then_some(bootstrap);
    Ok(startup.disarm(ingress_control, host_port_key, mesh_ingress_key))
}

async fn transfer_worker_descriptor(
    bootstrap: &tokio::net::UnixStream,
    descriptor: RawFd,
    deadline: tokio::time::Instant,
    transfer: fn(RawFd, RawFd) -> io::Result<()>,
) -> Result<(), RunnerError> {
    tokio::time::timeout_at(deadline, async {
        loop {
            bootstrap.writable().await?;
            match transfer(bootstrap.as_raw_fd(), descriptor) {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                result => return result,
            }
        }
    })
    .await
    .map_err(|_| RunnerError::NetworkWorkerStartTimeout)?
    .map_err(|_| RunnerError::NetworkWorkerBootstrap)
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

async fn read_egress_broker_status_frame(
    stream: &mut tokio::net::UnixStream,
    deadline: tokio::time::Instant,
) -> Result<Vec<u8>, RunnerError> {
    let mut frame = Vec::with_capacity(EGRESS_BROKER_STATUS_MAX_BYTES);
    loop {
        if frame.len() == EGRESS_BROKER_STATUS_MAX_BYTES {
            return Err(RunnerError::EgressBrokerBootstrap);
        }
        let mut byte = [0_u8; 1];
        let read = tokio::time::timeout_at(deadline, stream.read(&mut byte))
            .await
            .map_err(|_| RunnerError::EgressBrokerStartTimeout)?
            .map_err(|_| RunnerError::EgressBrokerBootstrap)?;
        if read == 0 {
            return Err(RunnerError::EgressBrokerBootstrap);
        }
        frame.push(byte[0]);
        if byte[0] == b'\n' {
            return Ok(frame);
        }
        if byte[0] == b'\r' || !byte[0].is_ascii() {
            return Err(RunnerError::EgressBrokerBootstrap);
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

async fn classify_egress_broker_startup_error(
    startup: &mut EgressBrokerStartup,
    fallback: RunnerError,
) -> Result<RunnerError, RunnerError> {
    let exit_deadline = tokio::time::Instant::now() + Duration::from_millis(100);
    loop {
        match startup.child_mut().try_wait() {
            Ok(Some(status)) => return Ok(egress_broker_exit_error(status)),
            Ok(None) => {}
            Err(_) => return Err(RunnerError::EgressBrokerWait),
        }
        if tokio::time::Instant::now() >= exit_deadline {
            reap_failed_egress_broker_startup(startup).await?;
            return Ok(fallback);
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

fn egress_broker_exit_error(status: std::process::ExitStatus) -> RunnerError {
    status
        .code()
        .and_then(EgressBrokerStartupFailure::from_exit_code)
        .map_or(
            RunnerError::EgressBrokerBootstrap,
            RunnerError::EgressBrokerStartup,
        )
}

fn duplicate_inherited_descriptor(descriptor: i32) -> io::Result<OwnedFd> {
    let duplicated = unsafe { libc::fcntl(descriptor, libc::F_DUPFD_CLOEXEC, 10) };
    if duplicated == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(duplicated) })
}

fn prepare_isolated_child(
    expected_parent: libc::pid_t,
    bootstrap_fd: RawFd,
    target_fd: RawFd,
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
    if bootstrap_fd != target_fd && unsafe { libc::dup2(bootstrap_fd, target_fd) } == -1 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(target_fd, libc::F_SETFD, 0) } == -1 {
        return Err(io::Error::last_os_error());
    }
    lock_process_privileges()
}

fn prepare_isolated_child_pair(
    expected_parent: libc::pid_t,
    first_source: RawFd,
    first_target: RawFd,
    second_source: RawFd,
    second_target: RawFd,
) -> io::Result<()> {
    if first_source == second_source || first_target == second_target {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }
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
    for (source, target) in [(first_source, first_target), (second_source, second_target)] {
        if source != target && unsafe { libc::dup2(source, target) } == -1 {
            return Err(io::Error::last_os_error());
        }
        if unsafe { libc::fcntl(target, libc::F_SETFD, 0) } == -1 {
            return Err(io::Error::last_os_error());
        }
    }
    // Both children deliberately lock privileges only after sending PREPARED.
    // This lets the runner capture their exact executable before either child
    // can receive an owner credential or one-use enrollment capability.
    Ok(())
}

fn guest_poweroff_command() -> Vec<String> {
    vec![CONTAINER_INIT_PATH.to_owned(), "poweroff".to_owned()]
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitClass {
    StillRunning,
    GuestShutdown,
    VmmFailure(Option<i32>),
    DirectShareFailure(Option<i32>),
    NetworkWorkerFailure(Option<i32>),
    EgressBrokerFailure(Option<i32>),
    IngressForwarderFailure,
    MeshTransportFailure(Option<i32>),
    MeshIngressReceiverFailure,
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

async fn prioritize_exited_vmm(
    process: &LiveProcess,
    child: &mut tokio::process::Child,
    observed: ExitClass,
) -> Result<ExitClass, RunnerError> {
    if matches!(
        observed,
        ExitClass::GuestShutdown | ExitClass::VmmFailure(_)
    ) {
        return Ok(observed);
    }

    let exited = match observed {
        ExitClass::NetworkWorkerFailure(_)
        | ExitClass::DirectShareFailure(_)
        | ExitClass::EgressBrokerFailure(_)
        | ExitClass::IngressForwarderFailure
        | ExitClass::MeshTransportFailure(_)
        | ExitClass::MeshIngressReceiverFailure => {
            process.wait_exited(VMM_CASCADE_EXIT_TIMEOUT).await?
        }
        ExitClass::StillRunning => process.is_exited()?,
        ExitClass::GuestShutdown | ExitClass::VmmFailure(_) => unreachable!(),
    };
    if !exited {
        return Ok(observed);
    }

    wait_reaped_child(child).await
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
    let direct_share_plan = direct_share_plan(&request.direct_shares)?;
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
        || validate_canonical_host_port_bindings(&request.host_ports).is_err()
        || request
            .mesh
            .as_ref()
            .is_some_and(|attachment| attachment.validate().is_err())
        || direct_share_plan
            .as_ref()
            .is_some_and(|plan| plan.sha256().is_err())
    {
        return Err(RunnerError::InvalidRequest);
    }
    Ok(())
}

fn direct_share_plan(
    shares: &[DirectShareRequest],
) -> Result<Option<DirectSharePlan>, RunnerError> {
    if shares.is_empty() {
        return Ok(None);
    }
    DirectSharePlan::new(shares.iter().map(|share| share.mount.clone()).collect())
        .map(Some)
        .map_err(|_| RunnerError::InvalidRequest)
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

fn fresh_egress_broker_key() -> Zeroizing<[u8; BROKER_IPC_KEY_LEN]> {
    loop {
        let mut key = Zeroizing::new([0_u8; BROKER_IPC_KEY_LEN]);
        OsRng.fill_bytes(key.as_mut());
        if key.iter().any(|byte| *byte != 0) {
            return key;
        }
    }
}

fn fresh_host_port_control_key() -> Zeroizing<[u8; HOST_PORT_CONTROL_KEY_LEN]> {
    loop {
        let mut key = Zeroizing::new([0_u8; HOST_PORT_CONTROL_KEY_LEN]);
        OsRng.fill_bytes(key.as_mut());
        if key.iter().any(|byte| *byte != 0) {
            return key;
        }
    }
}

fn fresh_mesh_ingress_control_key() -> Zeroizing<[u8; MESH_INGRESS_CONTROL_KEY_LEN]> {
    loop {
        let mut key = Zeroizing::new([0_u8; MESH_INGRESS_CONTROL_KEY_LEN]);
        OsRng.fill_bytes(key.as_mut());
        if key.iter().any(|byte| *byte != 0) {
            return key;
        }
    }
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

async fn start_direct_share(
    executable: &Path,
    share: &PreparedDirectShare,
    working_directory: &Path,
) -> Result<DirectShareProcess, RunnerError> {
    let pid_file = virtiofsd_pid_path(&share.socket);
    let mut child = direct_share_process(executable, share, working_directory)?
        .spawn()
        .map_err(|_| RunnerError::VirtiofsdSpawn)?;
    let Some(pid) = child.id() else {
        cleanup_direct_share_endpoints(&share.socket)?;
        return Err(RunnerError::VirtiofsdSpawn);
    };
    let process = match LiveProcess::capture_child(pid, executable) {
        Ok(process) => process,
        Err(error) => {
            terminate_unadmitted_child(pid, &mut child).await?;
            cleanup_direct_share_endpoints(&share.socket)?;
            return Err(error.into());
        }
    };
    let deadline = tokio::time::Instant::now() + DIRECT_SHARE_READY_TIMEOUT;
    loop {
        let exited = match child.try_wait() {
            Ok(status) => status.is_some(),
            Err(_) => {
                terminate_failed_launch(&process, &mut child).await?;
                cleanup_direct_share_endpoints(&share.socket)?;
                return Err(RunnerError::VirtiofsdWait);
            }
        };
        if exited {
            cleanup_direct_share_endpoints(&share.socket)?;
            return Err(RunnerError::VirtiofsdExitedDuringStart);
        }
        if share.socket.exists() && pid_file.exists() {
            if let Err(error) = set_socket_private(&share.socket) {
                terminate_failed_launch(&process, &mut child).await?;
                cleanup_direct_share_endpoints(&share.socket)?;
                return Err(error.into());
            }
            match virtiofsd_pid_file_matches(&pid_file, pid) {
                Ok(true) => {}
                Ok(false) => {
                    terminate_failed_launch(&process, &mut child).await?;
                    cleanup_direct_share_endpoints(&share.socket)?;
                    return Err(RunnerError::VirtiofsdPidFile);
                }
                Err(error) => {
                    terminate_failed_launch(&process, &mut child).await?;
                    cleanup_direct_share_endpoints(&share.socket)?;
                    return Err(error);
                }
            }
            return Ok(DirectShareProcess {
                child,
                process,
                socket: share.socket.clone(),
            });
        }
        if tokio::time::Instant::now() >= deadline {
            terminate_failed_launch(&process, &mut child).await?;
            cleanup_direct_share_endpoints(&share.socket)?;
            return Err(RunnerError::VirtiofsdStartTimeout);
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn virtiofsd_pid_path(socket: &Path) -> PathBuf {
    let mut name = socket.as_os_str().to_os_string();
    name.push(".pid");
    PathBuf::from(name)
}

fn cleanup_direct_share_endpoints(socket: &Path) -> Result<(), RunnerError> {
    let parent = socket.parent().ok_or(RunnerError::InvalidRequest)?;
    let socket_name = socket
        .file_name()
        .map(Path::new)
        .ok_or(RunnerError::InvalidRequest)?;
    let pid_file = virtiofsd_pid_path(socket);
    let pid_name = pid_file
        .file_name()
        .map(Path::new)
        .ok_or(RunnerError::InvalidRequest)?;
    let root = PrivateRoot::open(parent)?;
    root.remove_private_socket_with_permissions(socket_name, &[0o600, 0o700])?;
    root.remove_private_regular(pid_name, 0o600)?;
    Ok(())
}

fn virtiofsd_pid_file_matches(path: &Path, expected_pid: u32) -> Result<bool, RunnerError> {
    let parent = path.parent().ok_or(RunnerError::InvalidRequest)?;
    let name = path
        .file_name()
        .map(Path::new)
        .ok_or(RunnerError::InvalidRequest)?;
    let opened = PrivateRoot::open(parent)?.open_regular(name, false, None, false, Some(0o600))?;
    let mut contents = String::new();
    opened
        .file()
        .take(32)
        .read_to_string(&mut contents)
        .map_err(|source| RunnerError::Io {
            path: path.to_owned(),
            source,
        })?;
    Ok(contents.trim().parse::<u32>().ok() == Some(expected_pid))
}

fn direct_share_process(
    executable: &Path,
    share: &PreparedDirectShare,
    working_directory: &Path,
) -> Result<tokio::process::Command, RunnerError> {
    let source_fd = share.admitted.descriptor().as_raw_fd();
    if source_fd < DIRECT_SHARE_SOURCE_FD {
        return Err(RunnerError::DirectShareChanged);
    }
    let socket_directory = share.socket.parent().ok_or(RunnerError::InvalidRequest)?;
    let filesystem_domain = prepare_virtiofsd_filesystem_domain(
        source_fd,
        socket_directory,
        executable,
        share.request.mount.read_only(),
    )
    .map_err(|_| RunnerError::VirtiofsdConfinement)?;
    let expected_parent_pid = unsafe { libc::getpid() };
    let host_uid = current_uid();
    let host_gid = unsafe { libc::getegid() };
    let mut process = tokio::process::Command::new(executable);
    process
        .arg("--shared-dir")
        // virtiofsd deliberately opens this value with O_PATH|O_NOFOLLOW. The
        // trailing slash makes the kernel resolve the procfs descriptor link
        // and require its target to remain a directory.
        .arg(format!("/proc/self/fd/{DIRECT_SHARE_SOURCE_FD}/"))
        .arg("--socket-path")
        .arg(&share.socket)
        .arg("--tag")
        .arg(share.request.mount.tag())
        .arg("--thread-pool-size")
        .arg("1")
        .arg("--sandbox")
        .arg("none")
        .arg("--seccomp")
        .arg("kill")
        .arg("--no-announce-submounts")
        .arg("--inode-file-handles=never")
        .arg("--cache=never")
        // The daemon runs without capabilities, so it must never try to adopt
        // a guest credential. Collapse every guest identity to this process's
        // one admitted host identity while leaving numeric host ownership
        // visible to the guest. This grants no access beyond the selected
        // source descriptor.
        .arg("--translate-uid")
        .arg(format!("squash-guest:0:{host_uid}:{}", u32::MAX))
        .arg("--translate-gid")
        .arg(format!("squash-guest:0:{host_gid}:{}", u32::MAX))
        .arg("--log-level")
        .arg("off")
        .arg("--preserve-noatime")
        .arg("--rlimit-nofile")
        .arg("65536")
        .env_clear()
        .current_dir(working_directory)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    if share.request.mount.read_only() {
        process.arg("--readonly");
    }
    // SAFETY: only direct syscalls and async-signal-safe libc calls execute
    // between fork and exec.
    // The already-open source directory is duplicated to one fixed descriptor;
    // every other non-stdio descriptor remains close-on-exec.
    unsafe {
        process.pre_exec(move || {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::getppid() != expected_parent_pid {
                return Err(io::Error::from_raw_os_error(libc::ECHILD));
            }
            if source_fd != DIRECT_SHARE_SOURCE_FD
                && libc::dup2(source_fd, DIRECT_SHARE_SOURCE_FD) == -1
            {
                return Err(io::Error::last_os_error());
            }
            if libc::fcntl(DIRECT_SHARE_SOURCE_FD, libc::F_SETFD, 0) == -1 {
                return Err(io::Error::last_os_error());
            }
            if libc::syscall(
                libc::SYS_close_range,
                u32::try_from(DIRECT_SHARE_SOURCE_FD + 1).expect("fixed descriptor fits u32"),
                u32::MAX,
                libc::CLOSE_RANGE_CLOEXEC,
            ) != 0
            {
                return Err(io::Error::last_os_error());
            }
            lock_exec_process_privileges()?;
            install_identity_preserving_setgroups_filter()?;
            filesystem_domain.restrict_self()?;
            Ok(())
        });
    }
    Ok(process)
}

async fn stop_direct_share_process(process: &mut DirectShareProcess) -> Result<(), RunnerError> {
    if process
        .child
        .try_wait()
        .map_err(|_| RunnerError::VirtiofsdWait)?
        .is_none()
        && !signal_or_observe_exit(&process.process, Signal::TERM)?
        && !process.process.wait_exited(SIGNAL_STOP_TIMEOUT).await?
        && !signal_or_observe_exit(&process.process, Signal::KILL)?
        && !process.process.wait_exited(SIGNAL_STOP_TIMEOUT).await?
    {
        return Err(RunnerError::VirtiofsdKillTimeout);
    }
    process
        .child
        .wait()
        .await
        .map_err(|_| RunnerError::VirtiofsdWait)?;
    cleanup_direct_share_endpoints(&process.socket)?;
    Ok(())
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
    #[error("direct shares require the locked virtiofsd artifact")]
    VirtiofsdUnavailable,
    #[error("direct-share source changed before launch")]
    DirectShareChanged,
    #[error("virtiofsd process spawn failed")]
    VirtiofsdSpawn,
    #[error("virtiofsd filesystem confinement could not be prepared or installed")]
    VirtiofsdConfinement,
    #[error("virtiofsd exited during startup")]
    VirtiofsdExitedDuringStart,
    #[error("virtiofsd did not publish its private socket before the startup deadline")]
    VirtiofsdStartTimeout,
    #[error("virtiofsd published an invalid private pid file")]
    VirtiofsdPidFile,
    #[error("virtiofsd process wait failed")]
    VirtiofsdWait,
    #[error("virtiofsd process did not stop")]
    VirtiofsdKillTimeout,
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
    #[error("local loopback host port {0} is unavailable")]
    HostPortUnavailable(u16),
    #[error("ingress forwarding control failed")]
    IngressControl,
    #[error("egress broker process spawn failed")]
    EgressBrokerSpawn,
    #[error("egress broker did not become ready before the startup deadline")]
    EgressBrokerStartTimeout,
    #[error("egress broker private bootstrap failed")]
    EgressBrokerBootstrap,
    #[error("egress broker startup failed: {0:?}")]
    EgressBrokerStartup(EgressBrokerStartupFailure),
    #[error("wait for egress broker failed")]
    EgressBrokerWait,
    #[error("egress broker did not exit after pidfd SIGKILL")]
    EgressBrokerKillTimeout,
    #[error("Mesh transport process spawn failed")]
    MeshTransportSpawn,
    #[error("Mesh transport did not become ready before the startup deadline")]
    MeshTransportStartTimeout,
    #[error("Mesh transport private bootstrap failed")]
    MeshTransportBootstrap,
    #[error("Mesh transport startup failed: {0:?}")]
    MeshTransportStartup(MeshTransportStartupFailure),
    #[error("Mesh enrollment broker process spawn failed")]
    MeshEnrollmentBrokerSpawn,
    #[error("Mesh enrollment broker did not become ready before the startup deadline")]
    MeshEnrollmentBrokerStartTimeout,
    #[error("Mesh enrollment broker private bootstrap failed")]
    MeshEnrollmentBrokerBootstrap,
    #[error("Mesh enrollment broker startup failed: {0:?}")]
    MeshEnrollmentBrokerStartup(MeshEnrollmentStartupFailure),
    #[error("wait for isolated Mesh process failed")]
    MeshProcessWait,
    #[error("isolated Mesh process did not exit after pidfd SIGKILL")]
    MeshProcessKillTimeout,
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
    use crate::direct_share::admit_direct_share;
    use crate::host_port::RESERVED_GUEST_DAEMON_PORT;
    use crate::linux::path::{FileIdentity, current_uid};
    use crate::linux::process::ProcessIdentity;
    use crate::linux::state::RootGenerationPaths;
    use crate::mesh_ingress::{MESH_INGRESS_CONTROL_FRAME_LEN, MeshIngressControlReceiver};
    use crate::network_worker::receive_mesh_ingress_descriptor;
    use codewire_vmm_guest_probe::DirectShareMount;

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
                virtiofsd: None,
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
            host_ports: Vec::new(),
            mesh: None,
            direct_shares: Vec::new(),
            skill_snapshot_sha256: None,
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
    async fn network_worker_status_reader_preserves_the_staged_socket() {
        let (mut runner, mut worker) = tokio::net::UnixStream::pair().unwrap();
        worker.write_all(WORKER_PREPARED_MESSAGE).await.unwrap();
        worker.write_all(WORKER_BROKER_READY_MESSAGE).await.unwrap();
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
            WORKER_BROKER_READY_MESSAGE
        );
        assert_eq!(
            read_worker_status_frame(&mut runner, deadline)
                .await
                .unwrap(),
            crate::network_worker::WORKER_READY_MESSAGE
        );
    }

    #[tokio::test]
    async fn egress_broker_status_reader_is_exact_and_bounded() {
        let (mut runner, mut broker) = tokio::net::UnixStream::pair().unwrap();
        broker
            .write_all(EGRESS_BROKER_PREPARED_MESSAGE)
            .await
            .unwrap();
        broker.write_all(EGRESS_BROKER_READY_MESSAGE).await.unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        assert_eq!(
            read_egress_broker_status_frame(&mut runner, deadline)
                .await
                .unwrap(),
            EGRESS_BROKER_PREPARED_MESSAGE
        );
        assert_eq!(
            read_egress_broker_status_frame(&mut runner, deadline)
                .await
                .unwrap(),
            EGRESS_BROKER_READY_MESSAGE
        );

        broker
            .write_all(&[b'x'; EGRESS_BROKER_STATUS_MAX_BYTES + 1])
            .await
            .unwrap();
        assert!(matches!(
            read_egress_broker_status_frame(&mut runner, deadline).await,
            Err(RunnerError::EgressBrokerBootstrap)
        ));
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
    fn network_stack_attachment_budgets_each_isolated_process_phase() {
        assert!(
            EGRESS_BROKER_READY_TIMEOUT > EGRESS_BROKER_CONFINEMENT_ADMISSION_TIMEOUT,
            "the runner must retain a margin around the child's executable-admission window"
        );
        assert_eq!(
            network_stack_attach_timeout(Duration::from_secs(1), NetworkWorkerMode::Product),
            Duration::from_secs(2)
        );
        assert_eq!(
            network_stack_attach_timeout(Duration::from_secs(15), NetworkWorkerMode::Product),
            Duration::from_secs(30)
        );
        assert!(
            network_stack_attach_timeout(Duration::from_secs(15), NetworkWorkerMode::Product)
                > EGRESS_BROKER_READY_TIMEOUT
        );
        assert!(
            MESH_STACK_ATTACH_TIMEOUT
                > crate::mesh_process::MESH_TRANSPORT_CONFINEMENT_ADMISSION_TIMEOUT,
            "the Mesh stack must retain a margin around exact child admission"
        );
        assert!(
            crate::mesh_process::MESH_TRANSPORT_CONFINEMENT_ADMISSION_TIMEOUT
                >= crate::mesh_enrollment::MESH_ENROLLMENT_CONFINEMENT_ADMISSION_TIMEOUT
                    .saturating_mul(2),
            "transport admission must cover its own and the enrollment child's exact captures"
        );
        assert_eq!(
            network_stack_attach_timeout(Duration::from_secs(20 * 60), NetworkWorkerMode::Product),
            Duration::from_secs(40)
        );
        assert!(
            Duration::from_secs(codewire_vmm_guest_probe::NETWORK_HOST_READY_TIMEOUT_SECONDS)
                > network_stack_attach_timeout(
                    Duration::from_secs(20 * 60),
                    NetworkWorkerMode::Product,
                ),
            "the guest must outlive the complete bounded host attachment window"
        );
        assert_eq!(
            network_stack_attach_timeout(
                Duration::from_secs(1),
                NetworkWorkerMode::InjectedVerification
            ),
            Duration::from_secs(1)
        );
        assert_eq!(
            network_stack_attach_timeout(
                Duration::from_secs(20 * 60),
                NetworkWorkerMode::InjectedVerification
            ),
            NETWORK_WORKER_ATTACH_TIMEOUT
        );
    }

    #[tokio::test]
    async fn network_stack_stop_reaps_worker_broker_and_mesh_independently() {
        let (worker_child, worker_process) = spawn_admitted_sleep("30").await;
        let (broker_child, broker_process) = spawn_admitted_sleep("30").await;
        let (mesh_child, mesh_process) = spawn_admitted_sleep("30").await;
        let mesh_receiver =
            tokio::spawn(async { std::future::pending::<Result<(), MeshTransportError>>().await });
        let mut stack = NetworkWorkerProcess {
            child: worker_child,
            process: worker_process,
            broker: Some(EgressBrokerProcess {
                child: broker_child,
                process: broker_process,
            }),
            ingress_control: None,
            host_port_key: None,
            mesh_ingress_key: None,
            mesh_ingress_publisher: None,
            ingress_forwarder: None,
            mesh_transport: Some(MeshTransportProcess {
                child: mesh_child,
                process: mesh_process,
                ingress_receiver: Some(mesh_receiver),
            }),
        };

        stop_network_worker_process(&mut stack).await.unwrap();
        assert!(stack.child.try_wait().unwrap().is_some());
        assert!(stack.mesh_transport.is_none());
        let broker = stack.broker.as_mut().unwrap();
        assert!(broker.child.try_wait().unwrap().is_none());

        stop_egress_broker_process(broker).await.unwrap();
        assert!(broker.child.try_wait().unwrap().is_some());
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

        let mut valid_host_port = request(2, 16_384);
        valid_host_port.host_ports = vec![HostPortBinding::new(18_080, 3_000).unwrap()];
        assert!(validate_request(&valid_host_port).is_ok());

        let mut duplicate_host_port = request(2, 16_384);
        duplicate_host_port.host_ports = vec![
            HostPortBinding::new(18_080, 3_000).unwrap(),
            HostPortBinding::new(18_080, 3_001).unwrap(),
        ];
        assert!(matches!(
            validate_request(&duplicate_host_port),
            Err(RunnerError::InvalidRequest)
        ));

        let mut daemon_port = request(2, 16_384);
        daemon_port.host_ports = vec![HostPortBinding {
            host_port: 18_080,
            guest_port: RESERVED_GUEST_DAEMON_PORT,
        }];
        assert!(matches!(
            validate_request(&daemon_port),
            Err(RunnerError::InvalidRequest)
        ));

        let mut valid_mesh = request(2, 16_384);
        valid_mesh.mesh = Some(
            MeshAttachment::new(
                "https://mesh.example.test",
                "org",
                "network",
                "environment",
                [3_000, 8_080],
            )
            .unwrap(),
        );
        assert!(validate_request(&valid_mesh).is_ok());

        let mut noncanonical_mesh = valid_mesh;
        noncanonical_mesh
            .mesh
            .as_mut()
            .unwrap()
            .guest_ports
            .reverse();
        assert!(matches!(
            validate_request(&noncanonical_mesh),
            Err(RunnerError::InvalidRequest)
        ));
    }

    #[test]
    fn host_port_reservation_is_loopback_collision_safe_and_atomic() {
        let (first_port, blocked_port, blocker) = (20_000_u16..60_000)
            .find_map(|first_port| {
                let blocked_port = first_port.checked_add(1)?;
                let blocker = StdTcpListener::bind((Ipv4Addr::LOCALHOST, blocked_port)).ok()?;
                let first = StdTcpListener::bind((Ipv4Addr::LOCALHOST, first_port)).ok()?;
                drop(first);
                Some((first_port, blocked_port, blocker))
            })
            .expect("two adjacent loopback ports must be available for the collision fixture");
        let bindings = vec![
            HostPortBinding::new(first_port, 3_000).unwrap(),
            HostPortBinding::new(blocked_port, 3_001).unwrap(),
        ];

        assert!(matches!(
            reserve_host_ports(&bindings),
            Err(RunnerError::HostPortUnavailable(port)) if port == blocked_port
        ));
        let rebound = StdTcpListener::bind((Ipv4Addr::LOCALHOST, first_port))
            .expect("an atomic reservation failure must release earlier listeners");
        assert_eq!(
            rebound.local_addr().unwrap(),
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, first_port).into()
        );
        assert!(StdTcpListener::bind((Ipv4Addr::LOCALHOST, blocked_port)).is_err());
        drop(rebound);
        drop(blocker);

        let listeners = reserve_host_ports(&bindings).unwrap();
        assert_eq!(listeners.len(), bindings.len());
        for (listener, binding) in listeners.iter().zip(bindings) {
            assert_eq!(listener.binding, binding);
            assert_eq!(
                listener.listener.local_addr().unwrap(),
                SocketAddrV4::new(Ipv4Addr::LOCALHOST, binding.host_port).into()
            );
        }
    }

    #[tokio::test]
    async fn expected_ingress_forwarder_completion_defers_to_process_exit() {
        let mut forwarder = Some(tokio::spawn(async { Ok::<(), RunnerError>(()) }));
        tokio::time::timeout(Duration::from_secs(1), async {
            while !forwarder.as_ref().unwrap().is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();

        assert!(!take_ingress_forwarder_failure(&mut forwarder));
        assert!(forwarder.is_none());
    }

    #[tokio::test]
    async fn failed_ingress_forwarder_is_reported() {
        let mut forwarder = Some(tokio::spawn(async {
            Err::<(), RunnerError>(RunnerError::IngressControl)
        }));
        tokio::time::timeout(Duration::from_secs(1), async {
            while !forwarder.as_ref().unwrap().is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();

        assert!(take_ingress_forwarder_failure(&mut forwarder));
        assert!(forwarder.is_none());
    }

    #[tokio::test]
    async fn broker_loss_releases_host_ports_without_closing_mesh_ingress() {
        let (mut vmm_child, vmm) = spawn_admitted_sleep("30").await;
        let (mut worker_child, worker) = spawn_admitted_sleep("30").await;
        let (mut broker_child, broker) = spawn_admitted_sleep("30").await;
        let listener = StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let host_port = listener.local_addr().unwrap().port();
        let listener = tokio::net::TcpListener::from_std(listener).unwrap();
        let (control, worker_control) = StdUnixStream::pair().unwrap();
        control.set_nonblocking(true).unwrap();
        worker_control.set_nonblocking(true).unwrap();
        let control = tokio::net::UnixStream::from_std(control).unwrap();
        let mut worker_control = tokio::net::UnixStream::from_std(worker_control).unwrap();
        let (mesh_publisher, mesh_receiver) = mesh_ingress_channel(&[4_000]).unwrap();
        let vm_id = Uuid::new_v4();
        let mesh_key = [8_u8; MESH_INGRESS_CONTROL_KEY_LEN];
        let mut forwarder = tokio::spawn(run_ingress_forwarder(
            control,
            IngressControlKeys {
                host_port: Zeroizing::new([7_u8; HOST_PORT_CONTROL_KEY_LEN]),
                mesh: Zeroizing::new(mesh_key),
            },
            vec![(listener, HostPortBinding::new(host_port, 3_000).unwrap())],
            mesh_receiver,
            vec![
                (
                    HostPortDependency::Vmm,
                    vmm.duplicate_wait_descriptor().unwrap(),
                ),
                (
                    HostPortDependency::NetworkWorker,
                    worker.duplicate_wait_descriptor().unwrap(),
                ),
                (
                    HostPortDependency::EgressBroker,
                    broker.duplicate_wait_descriptor().unwrap(),
                ),
            ],
            vm_id,
            1,
        ));

        broker.signal(Signal::KILL).unwrap();
        broker_child.wait().await.unwrap();
        let rebound = tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                match StdTcpListener::bind((Ipv4Addr::LOCALHOST, host_port)) {
                    Ok(listener) => break listener,
                    Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
                }
            }
        })
        .await
        .expect("broker loss did not release the host listener");
        drop(rebound);
        assert!(!forwarder.is_finished());

        let (published_stream, mut transport_stream) = StdUnixStream::pair().unwrap();
        mesh_publisher.publish(4_000, published_stream).unwrap();
        let mut frame = [0_u8; MESH_INGRESS_CONTROL_FRAME_LEN];
        tokio::time::timeout(
            Duration::from_secs(1),
            worker_control.read_exact(&mut frame),
        )
        .await
        .expect("Mesh ingress control frame was not forwarded")
        .unwrap();
        let decoded = MeshIngressControlReceiver::new(vm_id, 1, &[4_000])
            .unwrap()
            .decode(&frame, &mesh_key)
            .unwrap();
        assert_eq!(decoded.binding.guest_port, 4_000);
        let descriptor = tokio::time::timeout(
            Duration::from_secs(1),
            receive_mesh_ingress_descriptor(&worker_control),
        )
        .await
        .expect("Mesh ingress descriptor was not forwarded")
        .unwrap();
        transport_stream.write_all(b"still connected").unwrap();
        let mut admitted_stream = StdUnixStream::from(descriptor);
        let mut transferred = [0_u8; 15];
        admitted_stream.read_exact(&mut transferred).unwrap();
        assert_eq!(&transferred, b"still connected");

        worker.signal(Signal::KILL).unwrap();
        worker_child.wait().await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), &mut forwarder)
            .await
            .expect("worker loss did not end the ingress forwarder")
            .unwrap()
            .unwrap();

        vmm.signal(Signal::KILL).unwrap();
        vmm_child.wait().await.unwrap();
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
    fn generated_egress_broker_keys_are_nonzero_and_bootstrap_admissible() {
        let key = fresh_egress_broker_key();
        assert!(key.iter().any(|byte| *byte != 0));
        assert!(encode_developer_egress_broker_bootstrap(Uuid::new_v4(), 1, &key).is_ok());
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
    async fn cascading_vmm_exit_is_reaped_before_a_sidecar_failure_is_reported() {
        let (mut child, process) = spawn_admitted_sleep("30").await;
        let identity = process.identity().clone();
        let delayed_kill = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(25)).await;
            LiveProcess::recover(&identity)
                .unwrap()
                .signal(Signal::KILL)
                .unwrap();
        });

        assert!(matches!(
            prioritize_exited_vmm(&process, &mut child, ExitClass::IngressForwarderFailure,)
                .await
                .unwrap(),
            ExitClass::VmmFailure(_)
        ));
        delayed_kill.await.unwrap();
        assert!(child.try_wait().unwrap().is_some());
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
    async fn direct_share_helper_uses_only_the_fixed_descriptor_and_enters_confinement() {
        let source = tempfile::tempdir().unwrap();
        let source_path = fs::canonicalize(source.path()).unwrap();
        let admitted = admit_direct_share(&source_path, &[]).unwrap();
        let request = DirectShareRequest::new(
            source_path.clone(),
            admitted.identity().clone(),
            DirectShareMount::for_index(0, "/workspace/source", true).unwrap(),
        )
        .unwrap();
        let private = tempfile::tempdir().unwrap();
        fs::set_permissions(private.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let share = PreparedDirectShare {
            request,
            admitted,
            socket: private.path().join("share-00.sock"),
        };
        let executable = fs::canonicalize("/usr/bin/true").unwrap();
        let mut command = direct_share_process(&executable, &share, private.path()).unwrap();
        let arguments = command
            .as_std()
            .get_args()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert!(
            arguments
                .iter()
                .any(|argument| argument == "/proc/self/fd/3/")
        );
        assert!(!arguments.iter().any(|argument| argument == &source_path));
        assert!(
            arguments
                .windows(2)
                .any(|pair| pair == ["--sandbox", "none"])
        );
        assert!(arguments.windows(2).any(|pair| {
            pair == [
                "--translate-uid",
                &format!("squash-guest:0:{}:{}", current_uid(), u32::MAX),
            ]
        }));
        assert!(arguments.windows(2).any(|pair| {
            pair == [
                "--translate-gid",
                &format!("squash-guest:0:{}:{}", unsafe { libc::getegid() }, u32::MAX),
            ]
        }));
        assert!(
            !arguments
                .iter()
                .any(|argument| argument.starts_with("host:"))
        );

        let mut child = command.spawn().unwrap();
        let status = tokio::time::timeout(SIGNAL_STOP_TIMEOUT, child.wait())
            .await
            .expect("confined fixture exceeded its deadline")
            .unwrap();
        assert!(status.success());
    }

    #[test]
    fn direct_share_startup_cleanup_normalizes_daemon_socket_permissions() {
        let private = tempfile::tempdir().unwrap();
        fs::set_permissions(private.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let socket = private.path().join("share-00.sock");
        let pid_file = virtiofsd_pid_path(&socket);
        let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(&pid_file, b"1234\n").unwrap();
        fs::set_permissions(&pid_file, fs::Permissions::from_mode(0o600)).unwrap();

        cleanup_direct_share_endpoints(&socket).unwrap();

        assert!(!socket.exists());
        assert!(!pid_file.exists());
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
