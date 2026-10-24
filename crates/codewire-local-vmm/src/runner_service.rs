//! Private per-environment process which owns the live VMM and its one-boot
//! daemon capability. The supervisor may restart and reconnect to this socket;
//! the capability never enters persistent state.

use std::ffi::OsString;
use std::io;
use std::os::fd::{AsRawFd as _, OwnedFd};
use std::os::unix::ffi::OsStringExt as _;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as SyncMutex};

use futures::Stream;
use rand::{RngCore as _, rngs::OsRng};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::sync::{Mutex, mpsc, oneshot, watch};
use tonic::{Request, Response, Status};
use uuid::Uuid;
use zeroize::Zeroizing;

use codewire_vmm_guest_probe::{
    DirectShareMount, GUEST_PROGRESS_VSOCK_PORT, GuestBootStage, MAX_DIRECT_SHARES,
    PROGRESS_CHALLENGE_LEN, PROGRESS_FRAME_LEN, ProgressError, ProgressFrame, ProgressRequest,
    SetupBinding, Sha256Value,
};

use crate::artifact_store::RuntimeArtifactStore;
use crate::control::v1;
use crate::control::v1::environment_runner_service_client::EnvironmentRunnerServiceClient;
use crate::control::v1::environment_runner_service_server::{
    EnvironmentRunnerService, EnvironmentRunnerServiceServer,
};
use crate::diagnostic_log::{self, DiagnosticLog, LogField};
use crate::direct_share::{DirectShareIdentity, DirectShareRequest};
use crate::host::path::PrivateRoot;
use crate::host_port::{HostPortBinding, canonical_host_port_bindings};
use crate::hybrid_vsock::{HybridVsockError, HybridVsockTarget};
use crate::mesh_ingress::{MeshAttachment, MeshEnrollmentAuthSource};
use crate::runner::ExitClass;
use crate::uds::{UdsError, bind_owner_only, connect_owner_only, remove_bound_socket};
use crate::{CloudHypervisorRunner, CreateVmRequest, RunnerError, RunningVm};

// A cached restart still cold-boots the kernel, trusted init, the OCI
// workspace, and its daemon. Keep that path bounded, but give authenticated
// guest progress the same product window as host-network attachment.
const DAEMON_READY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(45);
const SETUP_DAEMON_READY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20 * 60);
const DAEMON_RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(50);
const PROGRESS_RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(25);
const MAXIMUM_GUEST_PROGRESS_FRAMES: usize = 64;
const RUNNER_WATCH_BUFFER: usize = 8;
// Bump for every detached-runner behavior change, even if the protobuf
// message layout itself remains wire-compatible.
// 6: direct shares carry vm_only paths into the digest-bound guest plan.
// 7: those entries are patterns the guest expands at every boot.
// 8: StartVmRequest.network_policy_document selects the policy the egress
//    broker enforces (#2537); an older runner would enforce `open` instead.
// 9: ReplaceNetworkPolicy enforces a new policy on the running broker, which
//    ends the flows it refuses (#2537).
const NATIVE_RUNNER_PROTOCOL_VERSION: u32 = 9;
const RUNNER_PROTOCOL_INFO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);
const RUNNER_SHUTDOWN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);
pub(crate) const RUNNER_SERVER_DRAIN_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(3);
const GENERATION_ACCESS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);
const GENERATION_ACCESS_MAX_BYTES: usize = 4096;

#[derive(Debug, Clone)]
pub struct RunnerEntrypointConfig {
    pub environment_id: Uuid,
    pub socket: PathBuf,
    pub engine_state_root: PathBuf,
    pub artifact_generation: String,
    pub mesh_data_dir: PathBuf,
    pub platform_config_dir: PathBuf,
}

#[derive(Clone)]
pub struct RunnerClient {
    inner: EnvironmentRunnerServiceClient<tonic::transport::Channel>,
}

impl RunnerClient {
    pub async fn connect(socket: &std::path::Path) -> Result<Self, RunnerServiceError> {
        let channel = connect_owner_only(socket).await?;
        let mut client = Self {
            inner: EnvironmentRunnerServiceClient::new(channel),
        };
        let info = tokio::time::timeout(
            RUNNER_PROTOCOL_INFO_TIMEOUT,
            client
                .inner
                .get_runner_protocol_info(v1::GetRunnerProtocolInfoRequest {}),
        )
        .await
        .map_err(|_| RunnerServiceError::RunnerProtocolInfoUnavailable)?
        .map_err(runner_protocol_info_rpc_error)?
        .into_inner();
        admit_runner_protocol_info(&info)?;
        Ok(client)
    }

    pub async fn adopt(&mut self, environment_id: Uuid) -> Result<v1::RunnerInfo, Status> {
        Ok(self
            .inner
            .adopt_runner(v1::AdoptRunnerRequest {
                environment_id: environment_id.to_string(),
            })
            .await?
            .into_inner())
    }

    pub async fn info(&mut self) -> Result<v1::RunnerInfo, Status> {
        Ok(self
            .inner
            .get_runner_info(v1::GetRunnerInfoRequest {})
            .await?
            .into_inner())
    }

    pub async fn watch(
        &mut self,
        environment_id: Uuid,
    ) -> Result<tonic::Streaming<v1::RunnerEvent>, Status> {
        Ok(self
            .inner
            .watch_runner(v1::WatchRunnerRequest {
                environment_id: environment_id.to_string(),
            })
            .await?
            .into_inner())
    }

    pub async fn start(&mut self, request: v1::StartVmRequest) -> Result<v1::RunnerInfo, Status> {
        Ok(self.inner.start_vm(request).await?.into_inner())
    }

    pub async fn stop(&mut self) -> Result<v1::RunnerInfo, Status> {
        Ok(self.inner.stop_vm(v1::StopVmRequest {}).await?.into_inner())
    }

    pub async fn grow_state_disk(
        &mut self,
        environment_id: Uuid,
        disk_bytes: u64,
    ) -> Result<u64, Status> {
        Ok(self
            .inner
            .grow_state_disk(v1::GrowStateDiskRequest {
                environment_id: environment_id.to_string(),
                disk_bytes,
            })
            .await?
            .into_inner()
            .disk_bytes)
    }

    pub async fn set_host_ports(
        &mut self,
        environment_id: Uuid,
        generation: u64,
        host_ports: &[HostPortBinding],
    ) -> Result<(), Status> {
        self.inner
            .set_host_ports(v1::SetHostPortsRequest {
                environment_id: environment_id.to_string(),
                generation,
                host_ports: host_ports
                    .iter()
                    .map(|binding| v1::HostPortBinding {
                        host_port: u32::from(binding.host_port),
                        guest_port: u32::from(binding.guest_port),
                    })
                    .collect(),
            })
            .await?;
        Ok(())
    }

    /// Enforce `policy` on the running generation's egress broker; the
    /// digest it acknowledged.
    pub async fn replace_network_policy(
        &mut self,
        environment_id: Uuid,
        generation: u64,
        policy: &codewire_egress_policy::CompiledPolicy,
    ) -> Result<codewire_egress_policy::PolicyDigest, Status> {
        let document = policy
            .canonical_json()
            .map_err(|_| Status::internal("network policy has no canonical document"))?;
        let response = self
            .inner
            .replace_network_policy(v1::ReplaceNetworkPolicyRequest {
                environment_id: environment_id.to_string(),
                generation,
                network_policy_document: document,
            })
            .await?
            .into_inner();
        let digest: [u8; 32] = response
            .enforced_digest
            .as_slice()
            .try_into()
            .map_err(|_| Status::internal("runner returned a malformed policy digest"))?;
        Ok(codewire_egress_policy::PolicyDigest::from_bytes(digest))
    }

    pub async fn prepare_retire(&mut self) -> Result<(), Status> {
        self.inner
            .prepare_retire_runner(v1::PrepareRetireRunnerRequest {})
            .await?;
        Ok(())
    }

    pub async fn shutdown(&mut self, environment_id: Uuid, generation: u64) -> Result<(), Status> {
        tokio::time::timeout(
            RUNNER_SHUTDOWN_TIMEOUT,
            self.inner.shutdown_runner(v1::ShutdownRunnerRequest {
                environment_id: environment_id.to_string(),
                generation,
            }),
        )
        .await
        .map_err(|_| Status::deadline_exceeded("runner shutdown timed out"))??;
        Ok(())
    }

    pub async fn daemon_access(&mut self) -> Result<v1::DaemonAccess, Status> {
        Ok(self
            .inner
            .get_daemon_access(v1::GetDaemonAccessRequest {})
            .await?
            .into_inner())
    }

    /// Private bootstrap transport for exactly one owned boot, including while
    /// install is in progress. Callers must discard this general client and
    /// daemon capability before entering their protected-material domain.
    pub async fn generation_daemon_access(
        &mut self,
        environment_id: Uuid,
        generation: u64,
    ) -> Result<v1::DaemonAccess, Status> {
        if environment_id.is_nil() || generation == 0 {
            return Err(Status::invalid_argument(
                "invalid runner generation identity",
            ));
        }
        let mut client = self
            .inner
            .clone()
            .max_decoding_message_size(GENERATION_ACCESS_MAX_BYTES);
        let access = tokio::time::timeout(
            GENERATION_ACCESS_TIMEOUT,
            client.get_generation_daemon_access(v1::GetGenerationDaemonAccessRequest {
                environment_id: environment_id.to_string(),
                generation,
            }),
        )
        .await
        .map_err(|_| Status::deadline_exceeded("runner generation access timed out"))??
        .into_inner();
        validate_generation_access(environment_id, generation, &access)?;
        Ok(access)
    }
}

fn validate_generation_access(
    environment_id: Uuid,
    generation: u64,
    access: &v1::DaemonAccess,
) -> Result<(), Status> {
    if access.hybrid_socket.len() > GENERATION_ACCESS_MAX_BYTES
        || access.hybrid_socket.contains('\0')
        || HybridVsockTarget::new(PathBuf::from(&access.hybrid_socket), access.guest_port).is_err()
        || codewire_vmm_guest_probe::Seed::new(
            environment_id,
            generation,
            access.guest_port,
            access.generation_capability.clone(),
        )
        .is_err()
    {
        return Err(Status::failed_precondition(
            "invalid runner generation transport",
        ));
    }
    Ok(())
}

/// A second, short-held lock is intentional: startup retains the lifecycle
/// mutex while install may need this transport. No VM mutation uses this cell.
/// Its token is ephemeral and never Debug/serialized except the private reply.
struct GenerationAccessCell {
    environment_id: Uuid,
    current: SyncMutex<GenerationAccessState>,
}

#[derive(Default)]
struct GenerationAccessState {
    retiring: bool,
    access: Option<PublishedGenerationAccess>,
}

struct PublishedGenerationAccess {
    generation: u64,
    socket: String,
    port: u32,
    token: Zeroizing<String>,
    liveness: OwnedFd,
}

struct GenerationAccessGuard {
    cell: Arc<GenerationAccessCell>,
    generation: u64,
}

impl GenerationAccessCell {
    fn new(environment_id: Uuid) -> Arc<Self> {
        Arc::new(Self {
            environment_id,
            current: SyncMutex::new(GenerationAccessState::default()),
        })
    }

    fn retire(&self) {
        // Publication, lookup, and this permanent revocation use one lock.
        // No install/get can race a separate retirement flag and restore a
        // capability after the lifecycle owner has begun retirement.
        let mut current = self
            .current
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        current.retiring = true;
        current.access = None;
    }

    fn publish(self: &Arc<Self>, running: &RunningVm) -> Result<GenerationAccessGuard, Status> {
        if running.vm_id() != self.environment_id {
            return Err(Status::permission_denied("runner identity mismatch"));
        }
        let (socket, port, token) = running.daemon_access_parts();
        let socket = socket
            .to_str()
            .ok_or_else(|| Status::internal("invalid runner transport path"))?;
        let liveness = running
            .duplicate_liveness_descriptor()
            .map_err(|_| Status::internal("observe owned VMM liveness failed"))?;
        self.install(
            running.generation(),
            v1::DaemonAccess {
                hybrid_socket: socket.to_owned(),
                guest_port: port,
                generation_capability: token.to_owned(),
            },
            liveness,
        )
    }

    fn install(
        self: &Arc<Self>,
        generation: u64,
        access: v1::DaemonAccess,
        liveness: OwnedFd,
    ) -> Result<GenerationAccessGuard, Status> {
        validate_generation_access(self.environment_id, generation, &access)?;
        if !generation_process_alive(&liveness) {
            return Err(Status::failed_precondition("runner generation is not live"));
        }
        let mut current = self
            .current
            .lock()
            .map_err(|_| Status::unavailable("runner generation access unavailable"))?;
        if current.retiring {
            return Err(Status::failed_precondition("runner is retiring"));
        }
        if current.access.is_some() {
            return Err(Status::failed_precondition(
                "runner generation access already owned",
            ));
        }
        current.access = Some(PublishedGenerationAccess {
            generation,
            socket: access.hybrid_socket,
            port: access.guest_port,
            token: Zeroizing::new(access.generation_capability),
            liveness,
        });
        Ok(GenerationAccessGuard {
            cell: Arc::clone(self),
            generation,
        })
    }

    fn get(&self, environment_id: Uuid, generation: u64) -> Result<v1::DaemonAccess, Status> {
        if environment_id != self.environment_id {
            return Err(Status::permission_denied("runner identity mismatch"));
        }
        if generation == 0 {
            return Err(Status::invalid_argument(
                "invalid runner generation identity",
            ));
        }
        let mut current = self
            .current
            .lock()
            .map_err(|_| Status::unavailable("runner generation access unavailable"))?;
        if current.retiring {
            return Err(Status::failed_precondition("runner is retiring"));
        }
        let access = current
            .access
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("runner generation access unavailable"))?;
        if access.generation != generation {
            return Err(Status::failed_precondition(
                "runner generation does not match",
            ));
        }
        if !generation_process_alive(&access.liveness) {
            current.access = None;
            return Err(Status::failed_precondition("runner generation is not live"));
        }
        Ok(v1::DaemonAccess {
            hybrid_socket: access.socket.clone(),
            guest_port: access.port,
            generation_capability: access.token.to_string(),
        })
    }
}

impl GenerationAccessGuard {
    fn revoke(&self) {
        let mut current = self
            .cell
            .current
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if current
            .access
            .as_ref()
            .is_some_and(|access| access.generation == self.generation)
        {
            current.access = None;
        }
    }
}

impl Drop for GenerationAccessGuard {
    fn drop(&mut self) {
        self.revoke();
    }
}

fn generation_process_alive(liveness: &OwnedFd) -> bool {
    let mut descriptor = libc::pollfd {
        fd: liveness.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one owned pidfd pins the process birth. Zero-timeout poll never
    // waits on lifecycle state; exit, descriptor errors and interruption deny.
    unsafe { libc::poll(&mut descriptor, 1, 0) == 0 && descriptor.revents == 0 }
}

fn runner_protocol_info_rpc_error(status: Status) -> RunnerServiceError {
    if status.code() == tonic::Code::Unimplemented {
        RunnerServiceError::RunnerProtocolUnavailable
    } else {
        RunnerServiceError::RunnerProtocolInfoUnavailable
    }
}

pub(crate) fn admit_runner_protocol_info(
    info: &v1::RunnerProtocolInfo,
) -> Result<(), RunnerServiceError> {
    if info.protocol_version != NATIVE_RUNNER_PROTOCOL_VERSION {
        return Err(RunnerServiceError::RunnerProtocolMismatch {
            expected: NATIVE_RUNNER_PROTOCOL_VERSION,
            actual: info.protocol_version,
        });
    }
    Ok(())
}

struct RunnerEvents {
    environment_id: Uuid,
    artifact_generation: String,
    sequence: AtomicU64,
    sender: watch::Sender<v1::RunnerEvent>,
}

impl RunnerEvents {
    fn new(environment_id: Uuid, artifact_generation: String, generation: u64) -> Self {
        let runner = v1::RunnerInfo {
            environment_id: environment_id.to_string(),
            state: v1::EnvironmentState::Stopped as i32,
            generation,
            artifact_generation: artifact_generation.clone(),
            error_code: String::new(),
            cw_runtime_catalog_generation: String::new(),
        };
        let initial = v1::RunnerEvent {
            sequence: 1,
            runner: Some(runner),
            stage: v1::RunnerStage::WaitingAdoption as i32,
            guest_sequence: 0,
            guest_stage: v1::GuestBootStage::Unspecified as i32,
            error_code: String::new(),
        };
        Self {
            environment_id,
            artifact_generation,
            sequence: AtomicU64::new(1),
            sender: watch::channel(initial).0,
        }
    }

    fn publish(
        &self,
        state: v1::EnvironmentState,
        generation: u64,
        stage: v1::RunnerStage,
        guest: Option<GuestProgressUpdate>,
        error_code: Option<&str>,
        cw_runtime_catalog_generation: Option<&str>,
    ) -> Result<v1::RunnerEvent, Status> {
        if cw_runtime_catalog_generation
            .is_some_and(|generation| !crate::state::valid_root_generation(generation))
        {
            return Err(Status::internal("runner runtime attachment is invalid"));
        }
        if error_code.is_some_and(|code| {
            code.is_empty()
                || code.len() > 64
                || !code
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
        }) {
            return Err(Status::internal("runner event error code is invalid"));
        }
        let sequence = self
            .sequence
            .try_update(Ordering::AcqRel, Ordering::Acquire, |sequence| {
                sequence.checked_add(1)
            })
            .map_err(|_| Status::internal("runner event sequence overflow"))?
            + 1;
        let event = v1::RunnerEvent {
            sequence,
            runner: Some(v1::RunnerInfo {
                environment_id: self.environment_id.to_string(),
                state: state as i32,
                generation,
                artifact_generation: self.artifact_generation.clone(),
                error_code: error_code.unwrap_or_default().to_owned(),
                cw_runtime_catalog_generation: cw_runtime_catalog_generation
                    .unwrap_or_default()
                    .to_owned(),
            }),
            stage: stage as i32,
            guest_sequence: guest.map_or(0, |update| update.sequence),
            guest_stage: guest
                .map(|update| guest_boot_stage_proto(update.stage) as i32)
                .unwrap_or(v1::GuestBootStage::Unspecified as i32),
            error_code: error_code.unwrap_or_default().to_owned(),
        };
        self.sender.send_replace(event.clone());
        Ok(event)
    }

    fn subscribe(&self) -> watch::Receiver<v1::RunnerEvent> {
        self.sender.subscribe()
    }
}

fn guest_boot_stage_proto(stage: GuestBootStage) -> v1::GuestBootStage {
    match stage {
        GuestBootStage::StateMounted => v1::GuestBootStage::StateMounted,
        GuestBootStage::CgroupsReady => v1::GuestBootStage::CgroupsReady,
        GuestBootStage::DisksAdmitted => v1::GuestBootStage::DisksAdmitted,
        GuestBootStage::RootMounted => v1::GuestBootStage::RootMounted,
        GuestBootStage::SetupHeaderReady => v1::GuestBootStage::SetupHeaderReady,
        GuestBootStage::SetupContentReady => v1::GuestBootStage::SetupContentReady,
        GuestBootStage::RootLayersReady => v1::GuestBootStage::RootLayersReady,
        GuestBootStage::WorkspacePlanReady => v1::GuestBootStage::WorkspacePlanReady,
        GuestBootStage::OwnershipReady => v1::GuestBootStage::OwnershipReady,
        GuestBootStage::ContainerControlReady => v1::GuestBootStage::ContainerControlReady,
        GuestBootStage::RootGenerationReady => v1::GuestBootStage::RootGenerationReady,
        GuestBootStage::PersistentLayoutReady => v1::GuestBootStage::PersistentLayoutReady,
        GuestBootStage::RuncLaunching => v1::GuestBootStage::RuncLaunching,
        GuestBootStage::RuncRunning => v1::GuestBootStage::RuncRunning,
        GuestBootStage::WorkspaceRunning => v1::GuestBootStage::WorkspaceRunning,
        GuestBootStage::DaemonStarted => v1::GuestBootStage::DaemonStarted,
        GuestBootStage::SetupFailed => v1::GuestBootStage::SetupFailed,
        GuestBootStage::WorkspaceFailed | GuestBootStage::DockerToolingMissing => {
            v1::GuestBootStage::WorkspaceFailed
        }
    }
}

pub async fn serve_runner(config: RunnerEntrypointConfig) -> Result<(), RunnerServiceError> {
    // Darwin has no parent-death signal: the runner exits with its supervisor
    // and is never adopted by another one.
    #[cfg(target_os = "macos")]
    crate::host::process::exit_with_parent().map_err(|_| RunnerServiceError::Configuration)?;
    if !config.mesh_data_dir.is_absolute() || !config.platform_config_dir.is_absolute() {
        return Err(RunnerServiceError::Configuration);
    }
    // Taken while the parent-death signal still holds, so the parent is the
    // supervisor that spawned this runner.
    #[cfg(target_os = "linux")]
    let spawner = spawning_supervisor()?;
    let engine = PrivateRoot::open(&config.engine_state_root).map_err(RunnerError::from)?;
    let artifacts = RuntimeArtifactStore::create(&engine)
        .map_err(|_| RunnerServiceError::ArtifactStore)?
        .open_generation(&config.artifact_generation)
        .await
        .map_err(|_| RunnerServiceError::ArtifactStore)?;
    let runner = CloudHypervisorRunner::from_admitted(config.engine_state_root, artifacts)?;
    // If a prior runner died, Cloud Hypervisor received PDEATHSIG. Reconcile
    // the exact persisted process identity anyway before this runner accepts
    // lifecycle requests; no orphan is ever adopted without a fresh token.
    let generation = runner
        .terminate_tracked_for_cleanup(config.environment_id)
        .await?
        .unwrap_or(0);
    let events = Arc::new(RunnerEvents::new(
        config.environment_id,
        config.artifact_generation.clone(),
        generation,
    ));
    let (adoption_tx, mut adoption_rx) = mpsc::channel::<AdoptionRequest>(1);
    let generation_access = GenerationAccessCell::new(config.environment_id);
    let service = RunnerRpc {
        state: Arc::new(Mutex::new(RunnerState {
            environment_id: config.environment_id,
            artifact_generation: config.artifact_generation,
            runner,
            generation_access: None,
            running: None,
            generation,
            state: v1::EnvironmentState::Stopped,
            error_code: None,
            adopted: false,
            retirement: RetirementState::Active,
            mesh_data_dir: config.mesh_data_dir,
            platform_config_dir: config.platform_config_dir,
        })),
        adoption: adoption_tx,
        log: DiagnosticLog::inherited().map(Arc::new),
        events,
        generation_access,
        shutdown: watch::channel(None).0,
    };
    diagnostic_log::record(
        service.log.as_deref(),
        "runner_started",
        &[
            ("environment", LogField::Id(config.environment_id)),
            ("pid", LogField::Count(u64::from(std::process::id()))),
            ("generation", LogField::Count(generation)),
        ],
    );
    #[cfg(target_os = "linux")]
    drop(tokio::spawn(exit_when_idle_without_supervisor(
        spawner,
        Arc::clone(&service.state),
        Arc::clone(&service.events),
        service.shutdown.clone(),
    )));
    let server = tokio::spawn(serve_runner_rpc(config.socket, service));
    let adoption = adoption_rx.recv().await.ok_or(RunnerServiceError::Serve)?;
    #[cfg(target_os = "linux")]
    clear_parent_death_signal().map_err(|_| RunnerServiceError::Adoption)?;
    let _ = adoption.acknowledged.send(());
    server.await.map_err(|_| RunnerServiceError::Serve)?
}

/// A pidfd for the supervisor that spawned this runner. A parent already
/// gone is init's, so the runner exits rather than watch the wrong process.
#[cfg(target_os = "linux")]
fn spawning_supervisor() -> Result<OwnedFd, RunnerServiceError> {
    let parent = rustix::process::getppid().ok_or(RunnerServiceError::Configuration)?;
    let pidfd = rustix::process::pidfd_open(parent, rustix::process::PidfdFlags::empty())
        .map_err(|_| RunnerServiceError::Configuration)?;
    if rustix::process::getppid() != Some(parent) {
        return Err(RunnerServiceError::Configuration);
    }
    Ok(pidfd)
}

/// Once the supervisor that spawned this runner is gone, end the runner as
/// soon as it has no VM to keep (#3270). A runner with a running VM still
/// outlives its supervisor, and a new one adopts the VM; an idle one never
/// lingers without a supervisor to reuse or retire it.
#[cfg(target_os = "linux")]
async fn exit_when_idle_without_supervisor(
    spawner: OwnedFd,
    state: Arc<Mutex<RunnerState>>,
    events: Arc<RunnerEvents>,
    shutdown: watch::Sender<Option<v1::RunnerEvent>>,
) {
    // RUSTSEC-2026-0386: an owned `OwnedFd` is outside `AsyncFd::new`'s unsound case; `register` migration is #3249.
    #[allow(deprecated)]
    let Ok(spawner) =
        tokio::io::unix::AsyncFd::with_interest(spawner, tokio::io::Interest::READABLE)
    else {
        return;
    };
    if spawner.readable().await.is_err() {
        return;
    }
    let mut changes = events.sender.subscribe();
    loop {
        {
            let mut state = state.lock().await;
            if state.running.is_none() && state.retirement == RetirementState::Active {
                state.retirement = RetirementState::ShutdownRequested;
                shutdown.send_replace(Some(events.sender.borrow().clone()));
                return;
            }
        }
        if changes.changed().await.is_err() {
            return;
        }
    }
}

async fn wait_runner_shutdown(shutdown: &mut watch::Receiver<Option<v1::RunnerEvent>>) {
    loop {
        if shutdown.borrow().is_some() || shutdown.changed().await.is_err() {
            return;
        }
    }
}

async fn serve_runner_rpc(socket: PathBuf, service: RunnerRpc) -> Result<(), RunnerServiceError> {
    let (incoming, socket_identity) = bind_owner_only(&socket)?;
    let result = {
        let mut shutdown = service.shutdown.subscribe();
        let mut drain = shutdown.clone();
        let server = tonic::transport::Server::builder()
            .add_service(EnvironmentRunnerServiceServer::new(service))
            .serve_with_incoming_shutdown(incoming, async move {
                wait_runner_shutdown(&mut shutdown).await;
            });
        tokio::pin!(server);
        tokio::select! {
            result = &mut server => result.map_err(|_| RunnerServiceError::Serve),
            () = wait_runner_shutdown(&mut drain) => {
                // Give in-flight unary responses and terminal watcher events a
                // chance to flush. A non-reading owner must not keep a retired
                // process alive forever; timeout is an error, not a successful
                // graceful drain. The supervisor separately observes process exit.
                tokio::time::timeout(RUNNER_SERVER_DRAIN_TIMEOUT, &mut server)
                    .await
                    .map_err(|_| RunnerServiceError::Serve)
                    .and_then(|result| result.map_err(|_| RunnerServiceError::Serve))
            }
        }
    }; // Drop the server future and listener before unlinking their exact name.
    remove_bound_socket(&socket, &socket_identity)?;
    result
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RetirementState {
    Active,
    Preparing,
    Prepared,
    ShutdownRequested,
}

impl RetirementState {
    fn require_active(self) -> Result<(), Status> {
        if self == Self::Active {
            Ok(())
        } else {
            Err(Status::failed_precondition("runner is retiring"))
        }
    }
}

struct RunnerState {
    environment_id: Uuid,
    artifact_generation: String,
    runner: CloudHypervisorRunner,
    // Declared before running so teardown revokes lookup before dropping VM
    // ownership. During startup its guard stays on the StartVm future stack.
    generation_access: Option<GenerationAccessGuard>,
    running: Option<RunningVm>,
    generation: u64,
    state: v1::EnvironmentState,
    error_code: Option<&'static str>,
    adopted: bool,
    retirement: RetirementState,
    mesh_data_dir: PathBuf,
    platform_config_dir: PathBuf,
}

impl RunnerState {
    fn info(&self) -> v1::RunnerInfo {
        v1::RunnerInfo {
            environment_id: self.environment_id.to_string(),
            state: self.state as i32,
            generation: self.generation,
            artifact_generation: self.artifact_generation.clone(),
            error_code: self.error_code.unwrap_or_default().to_owned(),
            cw_runtime_catalog_generation: self
                .cw_runtime_catalog_generation()
                .unwrap_or_default()
                .to_owned(),
        }
    }

    fn cw_runtime_catalog_generation(&self) -> Option<&str> {
        self.running
            .as_ref()
            .and_then(RunningVm::cw_runtime_catalog_generation)
    }

    async fn observe_exit(&mut self) -> Result<(), RunnerError> {
        self.observe_exit_with_reason().await.map(drop)
    }

    async fn observe_exit_with_reason(&mut self) -> Result<Option<&'static str>, RunnerError> {
        let Some(running) = self.running.as_mut() else {
            self.generation_access = None;
            return Ok(None);
        };
        let exit = running.observe_exit().await;
        self.record_observed_exit(exit)
    }

    fn record_observed_exit(
        &mut self,
        exit: Result<ExitClass, RunnerError>,
    ) -> Result<Option<&'static str>, RunnerError> {
        let exit = match exit {
            Ok(exit) => exit,
            Err(error) => {
                self.generation_access = None;
                return Err(error);
            }
        };
        if exit != ExitClass::StillRunning {
            // A failed sidecar can leave the VMM owned for safe later cleanup.
            // That retained ownership must not keep bootstrap access active.
            self.generation_access = None;
        }
        let error_code = runner_exit_error_code(exit);
        match exit {
            ExitClass::StillRunning => Ok(error_code),
            ExitClass::GuestShutdown => {
                self.running = None;
                // A requested stop is handled synchronously by stop_vm below.
                // Any shutdown first discovered by observation is therefore
                // an unrequested guest/runtime exit and must require repair.
                self.state = v1::EnvironmentState::Error;
                self.error_code = error_code;
                Ok(error_code)
            }
            ExitClass::VmmFailure(_) => {
                self.running = None;
                self.state = v1::EnvironmentState::Error;
                self.error_code = error_code;
                Ok(error_code)
            }
            ExitClass::DirectShareFailure(_) => {
                // Keep ownership of the live VM. Losing one separately
                // confined filesystem server fails the admitted workspace
                // layout closed until an explicit stop/restart.
                self.state = v1::EnvironmentState::Error;
                self.error_code = error_code;
                Ok(error_code)
            }
            ExitClass::NetworkWorkerFailure(_) => {
                // Keep ownership of the live, now fail-closed VMM so an
                // explicit stop/restart can reap it safely.
                self.state = v1::EnvironmentState::Error;
                self.error_code = error_code;
                Ok(error_code)
            }
            ExitClass::EgressBrokerFailure(_) => {
                // The public packet path is fail-closed as soon as the
                // separately confined policy broker disappears.
                self.state = v1::EnvironmentState::Error;
                self.error_code = error_code;
                Ok(error_code)
            }
            ExitClass::IngressForwarderFailure => {
                self.state = v1::EnvironmentState::Error;
                self.error_code = error_code;
                Ok(error_code)
            }
            ExitClass::MeshTransportFailure(_) | ExitClass::MeshIngressReceiverFailure => {
                // Mesh ingress is fail-closed as soon as either the isolated
                // transport or its authenticated runner receiver disappears.
                self.state = v1::EnvironmentState::Error;
                self.error_code = error_code;
                Ok(error_code)
            }
        }
    }
}

fn runner_exit_error_code(exit: ExitClass) -> Option<&'static str> {
    match exit {
        ExitClass::StillRunning => None,
        ExitClass::GuestShutdown => Some("guest_shutdown"),
        ExitClass::VmmFailure(_) => Some("vmm_exit"),
        ExitClass::DirectShareFailure(_) => Some("direct_share_exit"),
        ExitClass::NetworkWorkerFailure(_) => Some("network_worker_exit"),
        ExitClass::EgressBrokerFailure(_) => Some("egress_broker_exit"),
        ExitClass::IngressForwarderFailure => Some("ingress_forwarder_exit"),
        ExitClass::MeshTransportFailure(_) => Some("mesh_transport_exit"),
        ExitClass::MeshIngressReceiverFailure => Some("mesh_ingress_receiver_exit"),
    }
}

#[derive(Clone)]
struct RunnerRpc {
    state: Arc<Mutex<RunnerState>>,
    adoption: mpsc::Sender<AdoptionRequest>,
    // The bounded owner-only log the supervisor gave this runner, if any.
    log: Option<Arc<DiagnosticLog>>,
    events: Arc<RunnerEvents>,
    generation_access: Arc<GenerationAccessCell>,
    // Carries the final prepared event as well as the shutdown signal, so
    // watchers cannot select shutdown and lose the final state before EOF.
    shutdown: watch::Sender<Option<v1::RunnerEvent>>,
}

struct AdoptionRequest {
    acknowledged: oneshot::Sender<()>,
}

impl RunnerRpc {
    /// Logs a failed VM start: the runner's closed error code and, for a
    /// guest that never became ready, the closed reason and last guest stage.
    fn log_start_failure(
        &self,
        environment_id: Uuid,
        generation: u64,
        error_code: &str,
        guest: Option<&GuestStartFailure>,
        started: std::time::Instant,
    ) {
        self.log_start_failure_fields(environment_id, generation, error_code, None, guest, started);
    }

    /// Logs a failed prepare or VMM start. Their error codes cover every
    /// runner error alike, so the line also names which error it was (#2595).
    fn log_runner_start_failure(
        &self,
        environment_id: Uuid,
        generation: u64,
        error_code: &str,
        error: &RunnerError,
        started: std::time::Instant,
    ) {
        self.log_start_failure_fields(
            environment_id,
            generation,
            error_code,
            Some(error.variant_name()),
            None,
            started,
        );
    }

    fn log_start_failure_fields(
        &self,
        environment_id: Uuid,
        generation: u64,
        error_code: &str,
        runner_error: Option<&'static str>,
        guest: Option<&GuestStartFailure>,
        started: std::time::Instant,
    ) {
        let mut fields = vec![
            ("environment", LogField::Id(environment_id)),
            ("generation", LogField::Count(generation)),
            ("error_code", LogField::Code(error_code)),
        ];
        if let Some(runner_error) = runner_error {
            fields.push(("detail", LogField::Name(runner_error)));
        }
        if let Some(guest) = guest {
            fields.push(("detail", LogField::Name(guest.detail)));
            fields.push((
                "guest_stage",
                LogField::Name(guest.guest_stage.map_or("none", guest_stage_name)),
            ));
            fields.push((
                "daemon_ready",
                LogField::Count(u64::from(guest.daemon_ready)),
            ));
        }
        fields.push(("elapsed_ms", LogField::Count(elapsed_ms(started))));
        diagnostic_log::record(self.log.as_deref(), "vm_start_failed", &fields);
    }
}

fn elapsed_ms(started: std::time::Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

#[tonic::async_trait]
impl EnvironmentRunnerService for RunnerRpc {
    async fn get_runner_protocol_info(
        &self,
        _request: Request<v1::GetRunnerProtocolInfoRequest>,
    ) -> Result<Response<v1::RunnerProtocolInfo>, Status> {
        Ok(Response::new(v1::RunnerProtocolInfo {
            protocol_version: NATIVE_RUNNER_PROTOCOL_VERSION,
        }))
    }

    async fn adopt_runner(
        &self,
        request: Request<v1::AdoptRunnerRequest>,
    ) -> Result<Response<v1::RunnerInfo>, Status> {
        let requested = parse_environment_id(&request.into_inner().environment_id)?;
        let state = self.state.lock().await;
        if requested != state.environment_id {
            return Err(Status::permission_denied("runner identity mismatch"));
        }
        state.retirement.require_active()?;
        if state.adopted {
            return Ok(Response::new(state.info()));
        }
        drop(state);
        let (acknowledged, received) = oneshot::channel();
        self.adoption
            .send(AdoptionRequest { acknowledged })
            .await
            .map_err(|_| Status::unavailable("runner adoption channel closed"))?;
        received
            .await
            .map_err(|_| Status::unavailable("runner adoption was not acknowledged"))?;
        let mut state = self.state.lock().await;
        state.retirement.require_active()?;
        state.adopted = true;
        let info = state.info();
        self.events.publish(
            v1::EnvironmentState::Stopped,
            info.generation,
            v1::RunnerStage::Ready,
            None,
            None,
            state.cw_runtime_catalog_generation(),
        )?;
        Ok(Response::new(info))
    }

    async fn get_runner_info(
        &self,
        _request: Request<v1::GetRunnerInfoRequest>,
    ) -> Result<Response<v1::RunnerInfo>, Status> {
        let mut state = self.state.lock().await;
        let prior = state.state;
        let exit_reason = state
            .observe_exit_with_reason()
            .await
            .map_err(|_| Status::internal("observe VMM state failed"))?;
        if state.state != prior {
            let stage = if state.state == v1::EnvironmentState::Stopped {
                v1::RunnerStage::Stopped
            } else {
                v1::RunnerStage::Error
            };
            self.events.publish(
                state.state,
                state.generation,
                stage,
                None,
                (stage == v1::RunnerStage::Error).then_some(exit_reason.unwrap_or("runtime_exit")),
                state.cw_runtime_catalog_generation(),
            )?;
        }
        Ok(Response::new(state.info()))
    }

    type WatchRunnerStream =
        Pin<Box<dyn Stream<Item = Result<v1::RunnerEvent, Status>> + Send + 'static>>;

    async fn watch_runner(
        &self,
        request: Request<v1::WatchRunnerRequest>,
    ) -> Result<Response<Self::WatchRunnerStream>, Status> {
        let environment_id = parse_environment_id(&request.into_inner().environment_id)?;
        if environment_id != self.events.environment_id {
            return Err(Status::permission_denied("runner identity mismatch"));
        }
        // A demand-driven stream owns no detached producer. It coalesces
        // ordinary watch updates as before and always yields the final
        // retirement event (once) before EOF, including a late subscriber.
        let stream = futures::stream::unfold(
            (self.events.subscribe(), self.shutdown.subscribe(), 0),
            |(mut events, mut shutdown, mut sequence)| async move {
                loop {
                    let terminal = shutdown.borrow_and_update().clone();
                    let event = terminal
                        .clone()
                        .unwrap_or_else(|| events.borrow_and_update().clone());
                    if event.sequence > sequence {
                        sequence = event.sequence;
                        return Some((Ok(event), (events, shutdown, sequence)));
                    }
                    if terminal.is_some() {
                        return None;
                    }
                    tokio::select! {
                        changed = events.changed() => if changed.is_err() { return None; },
                        changed = shutdown.changed() => if changed.is_err() { return None; },
                    }
                }
            },
        );
        Ok(Response::new(Box::pin(stream)))
    }

    async fn start_vm(
        &self,
        request: Request<v1::StartVmRequest>,
    ) -> Result<Response<v1::RunnerInfo>, Status> {
        let request = request.into_inner();
        let environment_id = parse_environment_id(&request.environment_id)?;
        let vcpus = u8::try_from(request.vcpus)
            .map_err(|_| Status::invalid_argument("invalid vCPU count"))?;
        let setup = parse_setup_binding(&request)?;
        let host_ports = parse_host_ports(&request.host_ports)?;
        let mesh = parse_mesh_attachment(&request)?;
        let direct_shares = parse_direct_shares(&request)?;
        let skill_snapshot_sha256 = parse_skill_snapshot(&request)?;
        let environment_projection_sha256 = parse_environment_projection(&request)?;
        let cw_runtime_catalog_generation = parse_cw_runtime_catalog_generation(&request)?;
        let managed_credential_clients =
            codewire_access::ManagedCredentialClients::decode(&request.managed_credential_clients)
                .map_err(|_| {
                    Status::invalid_argument("invalid managed credential client selection")
                })?;
        let daemon_ready_timeout = daemon_ready_timeout(setup.is_some());
        let started = std::time::Instant::now();
        let mut state = self.state.lock().await;
        state.retirement.require_active()?;
        if !state.adopted {
            return Err(Status::failed_precondition("runner is not adopted"));
        }
        if environment_id != state.environment_id {
            return Err(Status::permission_denied("runner identity mismatch"));
        }
        state
            .observe_exit()
            .await
            .map_err(|_| Status::internal("observe VMM state failed"))?;
        if state.running.is_some() {
            return Err(Status::already_exists("environment is already running"));
        }
        state.state = v1::EnvironmentState::Starting;
        state.error_code = None;
        self.events.publish(
            v1::EnvironmentState::Starting,
            request.generation,
            v1::RunnerStage::PreparingVm,
            None,
            None,
            state.cw_runtime_catalog_generation(),
        )?;
        let network_policy = start_network_policy(&request.network_policy_document)?;
        let prepared = match state
            .runner
            .prepare(CreateVmRequest {
                vm_id: environment_id,
                generation: request.generation,
                vsock_cid: request.vsock_cid,
                daemon_vsock_port: request.daemon_vsock_port,
                state_disk_bytes: request.state_disk_bytes,
                docker_disk_bytes: (request.docker_disk_bytes != 0)
                    .then_some(request.docker_disk_bytes),
                root_generation: request.root_generation,
                root_disk_bytes: request.root_disk_bytes,
                vcpus,
                memory_mib: request.memory_mib,
                setup,
                host_ports,
                mesh,
                direct_shares,
                skill_snapshot_sha256,
                environment_projection_sha256,
                managed_credential_clients,
                cw_runtime_catalog_generation,
                network_policy,
            })
            .await
        {
            Ok(prepared) => prepared,
            Err(error) => {
                let error_code = prepare_error_code(&error);
                self.log_runner_start_failure(
                    environment_id,
                    request.generation,
                    error_code,
                    &error,
                    started,
                );
                // A failed attempt consumes its generation as a prepared one
                // does (below), so the generation this runner reports matches
                // its last event, which a retry compares it with (#2579).
                state.generation = state.generation.max(request.generation);
                state.state = v1::EnvironmentState::Error;
                state.error_code = Some(error_code);
                self.events.publish(
                    v1::EnvironmentState::Error,
                    request.generation,
                    v1::RunnerStage::Error,
                    None,
                    Some(error_code),
                    state.cw_runtime_catalog_generation(),
                )?;
                return Err(map_start_error(error));
            }
        };
        // Preparing a launch consumes its monotonically increasing generation.
        // This keeps a failed pre-readiness attempt visible to the supervisor
        // and prevents a later start from replaying a generation already bound
        // into persisted VMM state and the one-boot guest seed.
        state.generation = request.generation;
        self.events.publish(
            v1::EnvironmentState::Starting,
            request.generation,
            v1::RunnerStage::StartingVmm,
            None,
            None,
            state.cw_runtime_catalog_generation(),
        )?;
        let mut running = match state.runner.start(prepared).await {
            Ok(running) => running,
            Err(error) => {
                self.log_runner_start_failure(
                    environment_id,
                    request.generation,
                    "vmm_start_failed",
                    &error,
                    started,
                );
                state.state = v1::EnvironmentState::Error;
                state.error_code = Some("vmm_start_failed");
                self.events.publish(
                    v1::EnvironmentState::Error,
                    request.generation,
                    v1::RunnerStage::Error,
                    None,
                    Some("vmm_start_failed"),
                    state.cw_runtime_catalog_generation(),
                )?;
                return Err(map_start_error(error));
            }
        };
        // Publish only after the exact VMM process is owned. If this future is
        // cancelled, its local guard revokes access before RunningVm drops.
        let generation_access = match self.generation_access.publish(&running) {
            Ok(guard) => guard,
            Err(error) => {
                self.log_start_failure(
                    environment_id,
                    request.generation,
                    "daemon_access_failed",
                    None,
                    started,
                );
                let _ = running.stop().await;
                state.state = v1::EnvironmentState::Error;
                state.error_code = Some("daemon_access_failed");
                self.events.publish(
                    v1::EnvironmentState::Error,
                    request.generation,
                    v1::RunnerStage::Error,
                    None,
                    Some("daemon_access_failed"),
                    state.cw_runtime_catalog_generation(),
                )?;
                return Err(error);
            }
        };
        let worker_executable = std::env::current_exe()
            .ok()
            .and_then(|path| std::fs::canonicalize(path).ok())
            .ok_or(());
        let worker_executable = match worker_executable {
            Ok(executable) => executable,
            Err(()) => {
                self.log_start_failure(
                    environment_id,
                    request.generation,
                    "network_worker_failed",
                    None,
                    started,
                );
                generation_access.revoke();
                let _ = running.stop().await;
                state.state = v1::EnvironmentState::Error;
                state.error_code = Some("network_worker_failed");
                self.events.publish(
                    v1::EnvironmentState::Error,
                    request.generation,
                    v1::RunnerStage::Error,
                    None,
                    Some("network_worker_failed"),
                    state.cw_runtime_catalog_generation(),
                )?;
                return Err(Status::internal("resolve network worker executable failed"));
            }
        };
        if let Err(error) = running
            .start_network_worker_with_mesh_credentials(
                &worker_executable,
                daemon_ready_timeout,
                &state.mesh_data_dir,
                &state.platform_config_dir,
            )
            .await
        {
            generation_access.revoke();
            let _ = running.stop().await;
            let error_code = network_start_error_code(&error);
            self.log_start_failure(
                environment_id,
                request.generation,
                error_code,
                None,
                started,
            );
            state.state = v1::EnvironmentState::Error;
            state.error_code = Some(error_code);
            self.events.publish(
                v1::EnvironmentState::Error,
                request.generation,
                v1::RunnerStage::Error,
                None,
                Some(error_code),
                state.cw_runtime_catalog_generation(),
            )?;
            return Err(map_start_error(error));
        }
        self.events.publish(
            v1::EnvironmentState::Starting,
            request.generation,
            v1::RunnerStage::WaitingGuest,
            None,
            None,
            running.cw_runtime_catalog_generation(),
        )?;
        if let Err(failure) =
            wait_for_guest_daemon(&mut running, daemon_ready_timeout, &self.events).await
        {
            self.log_start_failure(
                environment_id,
                request.generation,
                "guest_start_failed",
                Some(&failure),
                started,
            );
            generation_access.revoke();
            let _ = running.stop().await;
            state.state = v1::EnvironmentState::Error;
            state.error_code = Some("guest_start_failed");
            self.events.publish(
                v1::EnvironmentState::Error,
                request.generation,
                v1::RunnerStage::Error,
                None,
                Some("guest_start_failed"),
                state.cw_runtime_catalog_generation(),
            )?;
            return Err(failure.status);
        }
        if running.discard_one_boot_inputs().is_err() {
            self.log_start_failure(
                environment_id,
                request.generation,
                "input_cleanup_failed",
                None,
                started,
            );
            generation_access.revoke();
            let _ = running.stop().await;
            state.state = v1::EnvironmentState::Error;
            state.error_code = Some("input_cleanup_failed");
            self.events.publish(
                v1::EnvironmentState::Error,
                request.generation,
                v1::RunnerStage::Error,
                None,
                Some("input_cleanup_failed"),
                state.cw_runtime_catalog_generation(),
            )?;
            return Err(Status::internal("one-boot guest input cleanup failed"));
        }
        state.generation = request.generation;
        state.state = v1::EnvironmentState::Running;
        state.error_code = None;
        state.running = Some(running);
        state.generation_access = Some(generation_access);
        if let Err(error) = self.events.publish(
            v1::EnvironmentState::Running,
            request.generation,
            v1::RunnerStage::DaemonReady,
            None,
            None,
            state.cw_runtime_catalog_generation(),
        ) {
            self.log_start_failure(
                environment_id,
                request.generation,
                "daemon_access_failed",
                None,
                started,
            );
            state.generation_access = None;
            state.state = v1::EnvironmentState::Error;
            state.error_code = Some("daemon_access_failed");
            return Err(error);
        }
        diagnostic_log::record(
            self.log.as_deref(),
            "vm_started",
            &[
                ("environment", LogField::Id(environment_id)),
                ("generation", LogField::Count(request.generation)),
                ("elapsed_ms", LogField::Count(elapsed_ms(started))),
            ],
        );
        Ok(Response::new(state.info()))
    }

    async fn stop_vm(
        &self,
        _request: Request<v1::StopVmRequest>,
    ) -> Result<Response<v1::RunnerInfo>, Status> {
        let mut state = self.state.lock().await;
        state.retirement.require_active()?;
        state.generation_access = None;
        state
            .observe_exit()
            .await
            .map_err(|_| Status::internal("observe VMM state failed"))?;
        self.events.publish(
            state.state,
            state.generation,
            v1::RunnerStage::StoppingVm,
            None,
            None,
            state.cw_runtime_catalog_generation(),
        )?;
        if let Some(running) = state.running.as_mut() {
            match running
                .stop()
                .await
                .map_err(|_| Status::internal("bounded stop of the owned VMM process failed"))?
            {
                ExitClass::StillRunning => {
                    return Err(Status::internal("owned VMM process is still running"));
                }
                ExitClass::GuestShutdown
                | ExitClass::VmmFailure(_)
                | ExitClass::DirectShareFailure(_)
                | ExitClass::NetworkWorkerFailure(_)
                | ExitClass::EgressBrokerFailure(_)
                | ExitClass::IngressForwarderFailure
                | ExitClass::MeshTransportFailure(_)
                | ExitClass::MeshIngressReceiverFailure => {}
            }
        }
        state.running = None;
        state.state = v1::EnvironmentState::Stopped;
        state.error_code = None;
        self.events.publish(
            v1::EnvironmentState::Stopped,
            state.generation,
            v1::RunnerStage::Stopped,
            None,
            None,
            state.cw_runtime_catalog_generation(),
        )?;
        Ok(Response::new(state.info()))
    }

    async fn prepare_retire_runner(
        &self,
        _request: Request<v1::PrepareRetireRunnerRequest>,
    ) -> Result<Response<v1::PrepareRetireRunnerResponse>, Status> {
        let mut state = self.state.lock().await;
        if !state.adopted {
            return Err(Status::failed_precondition("runner is not adopted"));
        }
        if matches!(
            state.retirement,
            RetirementState::Prepared | RetirementState::ShutdownRequested
        ) {
            return Ok(Response::new(v1::PrepareRetireRunnerResponse {}));
        }
        // Once accepted, even a failed or cancelled cleanup never reopens
        // Start/Grow/daemon access. A later Prepare may retry the owned cleanup.
        state.retirement = RetirementState::Preparing;
        self.generation_access.retire();
        state.generation_access = None;
        self.events.publish(
            state.state,
            state.generation,
            v1::RunnerStage::Retiring,
            None,
            None,
            state.cw_runtime_catalog_generation(),
        )?;
        if let Some(running) = state.running.as_mut() {
            let exit = running
                .stop()
                .await
                .map_err(|_| Status::internal("bounded stop before delete failed"))?;
            if exit == ExitClass::StillRunning {
                return Err(Status::internal("owned VMM process is still running"));
            }
        }
        state.running = None;
        let environment_id = state.environment_id;
        state
            .runner
            .terminate_tracked_for_cleanup(environment_id)
            .await
            .map_err(|_| Status::internal("tracked VMM cleanup failed"))?;
        state.state = v1::EnvironmentState::Stopped;
        state.error_code = None;
        self.events.publish(
            v1::EnvironmentState::Stopped,
            state.generation,
            v1::RunnerStage::Stopped,
            None,
            None,
            state.cw_runtime_catalog_generation(),
        )?;
        state.retirement = RetirementState::Prepared;
        Ok(Response::new(v1::PrepareRetireRunnerResponse {}))
    }

    async fn shutdown_runner(
        &self,
        request: Request<v1::ShutdownRunnerRequest>,
    ) -> Result<Response<v1::ShutdownRunnerResponse>, Status> {
        let request = request.into_inner();
        let environment_id = parse_environment_id(&request.environment_id)?;
        let mut state = self.state.lock().await;
        if environment_id != state.environment_id || request.generation != state.generation {
            return Err(Status::permission_denied("runner identity mismatch"));
        }
        if !state.adopted
            || !matches!(
                state.retirement,
                RetirementState::Prepared | RetirementState::ShutdownRequested
            )
        {
            return Err(Status::failed_precondition(
                "runner retirement is not prepared",
            ));
        }
        if state.retirement != RetirementState::ShutdownRequested {
            state.retirement = RetirementState::ShutdownRequested;
            self.shutdown
                .send_replace(Some(self.events.sender.borrow().clone()));
        }
        Ok(Response::new(v1::ShutdownRunnerResponse {}))
    }

    async fn grow_state_disk(
        &self,
        request: Request<v1::GrowStateDiskRequest>,
    ) -> Result<Response<v1::GrowStateDiskResponse>, Status> {
        let request = request.into_inner();
        let environment_id = parse_environment_id(&request.environment_id)?;
        let mut state = self.state.lock().await;
        state.retirement.require_active()?;
        if !state.adopted {
            return Err(Status::failed_precondition("runner is not adopted"));
        }
        if environment_id != state.environment_id {
            return Err(Status::permission_denied("runner identity mismatch"));
        }
        state
            .observe_exit()
            .await
            .map_err(|_| Status::internal("observe VMM state failed"))?;
        if state.running.is_some() {
            return Err(Status::failed_precondition(
                "state disk growth requires a stopped VM",
            ));
        }
        self.events.publish(
            v1::EnvironmentState::Stopped,
            state.generation,
            v1::RunnerStage::GrowingDisk,
            None,
            None,
            state.cw_runtime_catalog_generation(),
        )?;
        let disk_bytes = state
            .runner
            .grow_stopped_state_disk(environment_id, request.disk_bytes)
            .await
            .map_err(map_grow_error)?;
        self.events.publish(
            v1::EnvironmentState::Stopped,
            state.generation,
            v1::RunnerStage::Ready,
            None,
            None,
            state.cw_runtime_catalog_generation(),
        )?;
        Ok(Response::new(v1::GrowStateDiskResponse { disk_bytes }))
    }

    async fn set_host_ports(
        &self,
        request: Request<v1::SetHostPortsRequest>,
    ) -> Result<Response<v1::SetHostPortsResponse>, Status> {
        let request = request.into_inner();
        let environment_id = parse_environment_id(&request.environment_id)?;
        let host_ports = parse_host_ports(&request.host_ports)?;
        let mut state = self.state.lock().await;
        state.retirement.require_active()?;
        if !state.adopted {
            return Err(Status::failed_precondition("runner is not adopted"));
        }
        if environment_id != state.environment_id {
            return Err(Status::permission_denied("runner identity mismatch"));
        }
        state
            .observe_exit()
            .await
            .map_err(|_| Status::internal("observe VMM state failed"))?;
        if state.generation != request.generation || state.state != v1::EnvironmentState::Running {
            return Err(Status::failed_precondition(
                "host ports change only on the running generation",
            ));
        }
        let running = state.running.as_mut().ok_or_else(|| {
            Status::failed_precondition("host ports change only on the running generation")
        })?;
        running
            .set_host_ports(&host_ports)
            .await
            .map_err(map_host_port_error)?;
        Ok(Response::new(v1::SetHostPortsResponse {}))
    }

    async fn replace_network_policy(
        &self,
        request: Request<v1::ReplaceNetworkPolicyRequest>,
    ) -> Result<Response<v1::ReplaceNetworkPolicyResponse>, Status> {
        let request = request.into_inner();
        let environment_id = parse_environment_id(&request.environment_id)?;
        if request.network_policy_document.is_empty() {
            return Err(Status::invalid_argument("network policy document is empty"));
        }
        let policy = start_network_policy(&request.network_policy_document)?;
        let mut state = self.state.lock().await;
        state.retirement.require_active()?;
        if !state.adopted {
            return Err(Status::failed_precondition("runner is not adopted"));
        }
        if environment_id != state.environment_id {
            return Err(Status::permission_denied("runner identity mismatch"));
        }
        state
            .observe_exit()
            .await
            .map_err(|_| Status::internal("observe VMM state failed"))?;
        if state.generation != request.generation || state.state != v1::EnvironmentState::Running {
            return Err(Status::failed_precondition(
                "a network policy is replaced only on the running generation",
            ));
        }
        let running = state.running.as_mut().ok_or_else(|| {
            Status::failed_precondition(
                "a network policy is replaced only on the running generation",
            )
        })?;
        let enforced = running
            .replace_network_policy(policy)
            .await
            .map_err(|error| Status::unavailable(error.to_string()))?;
        Ok(Response::new(v1::ReplaceNetworkPolicyResponse {
            enforced_digest: enforced.as_bytes().to_vec(),
        }))
    }

    async fn get_daemon_access(
        &self,
        _request: Request<v1::GetDaemonAccessRequest>,
    ) -> Result<Response<v1::DaemonAccess>, Status> {
        let mut state = self.state.lock().await;
        state.retirement.require_active()?;
        state
            .observe_exit()
            .await
            .map_err(|_| Status::internal("observe VMM state failed"))?;
        if state.state != v1::EnvironmentState::Running {
            return Err(Status::failed_precondition("environment is not running"));
        }
        let running = state
            .running
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("environment is not running"))?;
        let (socket, guest_port, capability) = running.daemon_access_parts();
        Ok(Response::new(v1::DaemonAccess {
            hybrid_socket: socket.to_string_lossy().into_owned(),
            guest_port,
            generation_capability: capability.to_owned(),
        }))
    }

    async fn get_generation_daemon_access(
        &self,
        request: Request<v1::GetGenerationDaemonAccessRequest>,
    ) -> Result<Response<v1::DaemonAccess>, Status> {
        let request = request.into_inner();
        let environment_id = parse_environment_id(&request.environment_id)?;
        // Do not inspect/adopt/reconcile through self.state here. Its mutex is
        // intentionally held by StartVm until authenticated install completes.
        self.generation_access
            .get(environment_id, request.generation)
            .map(Response::new)
    }
}

fn parse_environment_id(value: &str) -> Result<Uuid, Status> {
    let id =
        Uuid::parse_str(value).map_err(|_| Status::invalid_argument("invalid environment ID"))?;
    if id.is_nil() {
        return Err(Status::invalid_argument("invalid environment ID"));
    }
    Ok(id)
}

fn parse_cw_runtime_catalog_generation(
    request: &v1::StartVmRequest,
) -> Result<Option<String>, Status> {
    let generation = &request.cw_runtime_catalog_generation;
    if generation.is_empty() {
        return Ok(None);
    }
    if !crate::state::valid_root_generation(generation) {
        return Err(Status::invalid_argument(
            "invalid cw runtime catalog generation",
        ));
    }
    Ok(Some(generation.clone()))
}

fn parse_setup_binding(request: &v1::StartVmRequest) -> Result<Option<SetupBinding>, Status> {
    match (
        request.setup_total_bytes,
        request.setup_header_sha256.as_str(),
        request.setup_root_generation.as_str(),
    ) {
        (0, "", "") => Ok(None),
        (total_bytes, header_sha256, setup_root_generation)
            if total_bytes > 0
                && !header_sha256.is_empty()
                && !setup_root_generation.is_empty() =>
        {
            let root_generation = Sha256Value::parse_hex(setup_root_generation)
                .map_err(|_| Status::invalid_argument("invalid setup root generation"))?;
            let header_sha256 = Sha256Value::parse_hex(header_sha256)
                .map_err(|_| Status::invalid_argument("invalid setup header digest"))?;
            Ok(Some(
                SetupBinding::new(total_bytes, root_generation, header_sha256)
                    .map_err(|_| Status::invalid_argument("invalid setup binding"))?,
            ))
        }
        _ => Err(Status::invalid_argument("incomplete setup binding")),
    }
}

fn parse_host_ports(host_ports: &[v1::HostPortBinding]) -> Result<Vec<HostPortBinding>, Status> {
    let provided = host_ports
        .iter()
        .map(|binding| {
            Ok(HostPortBinding {
                host_port: u16::try_from(binding.host_port)
                    .map_err(|_| Status::invalid_argument("invalid host-port binding"))?,
                guest_port: u16::try_from(binding.guest_port)
                    .map_err(|_| Status::invalid_argument("invalid host-port binding"))?,
            })
        })
        .collect::<Result<Vec<_>, Status>>()?;
    let canonical = canonical_host_port_bindings(provided.clone())
        .map_err(|_| Status::invalid_argument("invalid host-port binding"))?;
    if canonical != provided {
        return Err(Status::invalid_argument(
            "host-port bindings are not canonical",
        ));
    }
    Ok(canonical)
}

fn parse_mesh_attachment(request: &v1::StartVmRequest) -> Result<Option<MeshAttachment>, Status> {
    let Some(raw) = request.mesh.as_ref() else {
        return Ok(None);
    };
    let guest_ports = raw
        .guest_ports
        .iter()
        .map(|port| u16::try_from(*port).map_err(|_| Status::invalid_argument("invalid Mesh port")))
        .collect::<Result<Vec<_>, _>>()?;
    let auth_source = match v1::MeshEnrollmentAuthSource::try_from(raw.auth_source) {
        Ok(v1::MeshEnrollmentAuthSource::StandaloneLocal) => {
            MeshEnrollmentAuthSource::StandaloneLocal
        }
        Ok(v1::MeshEnrollmentAuthSource::HostedCurrent) => MeshEnrollmentAuthSource::HostedCurrent,
        Ok(v1::MeshEnrollmentAuthSource::Unspecified) | Err(_) => {
            return Err(Status::invalid_argument("invalid Mesh auth source"));
        }
    };
    let attachment = MeshAttachment::new_with_auth_source(
        auth_source,
        &raw.mesh_url,
        &raw.organization_id,
        &raw.network_id,
        &raw.node_name,
        guest_ports,
    )
    .map_err(|_| Status::invalid_argument("invalid Mesh attachment"))?;
    if attachment.mesh_url != raw.mesh_url
        || attachment.organization_id != raw.organization_id
        || attachment.network_id != raw.network_id
        || attachment.node_name != raw.node_name
        || match attachment.auth_source {
            MeshEnrollmentAuthSource::StandaloneLocal => {
                raw.auth_source != v1::MeshEnrollmentAuthSource::StandaloneLocal as i32
            }
            MeshEnrollmentAuthSource::HostedCurrent => {
                raw.auth_source != v1::MeshEnrollmentAuthSource::HostedCurrent as i32
            }
        }
        || attachment
            .guest_ports
            .iter()
            .copied()
            .map(u32::from)
            .ne(raw.guest_ports.iter().copied())
    {
        return Err(Status::invalid_argument("noncanonical Mesh attachment"));
    }
    Ok(Some(attachment))
}

fn parse_direct_shares(request: &v1::StartVmRequest) -> Result<Vec<DirectShareRequest>, Status> {
    if request.direct_shares.len() > MAX_DIRECT_SHARES {
        return Err(Status::invalid_argument("too many direct shares"));
    }
    request
        .direct_shares
        .iter()
        .enumerate()
        .map(|(index, raw)| {
            if raw.source_path.is_empty() || raw.source_path.contains(&0) {
                return Err(Status::invalid_argument("invalid direct share"));
            }
            let identity = DirectShareIdentity::new(
                raw.device_major,
                raw.device_minor,
                raw.inode,
                raw.mount_id,
                raw.owner_uid,
                raw.filesystem_magic,
            )
            .map_err(|_| Status::invalid_argument("invalid direct share"))?;
            let mount = DirectShareMount::for_index(index, raw.destination.clone(), raw.read_only)
                .and_then(|mount| mount.with_vm_only(raw.vm_only.clone()))
                .map_err(|_| Status::invalid_argument("invalid direct share"))?;
            DirectShareRequest::new(
                PathBuf::from(OsString::from_vec(raw.source_path.clone())),
                identity,
                mount,
            )
            .map_err(|_| Status::invalid_argument("invalid direct share"))
        })
        .collect()
}

fn parse_skill_snapshot(request: &v1::StartVmRequest) -> Result<Option<Sha256Value>, Status> {
    if request.skill_snapshot_sha256.is_empty() {
        Ok(None)
    } else {
        Sha256Value::parse_hex(&request.skill_snapshot_sha256)
            .map(Some)
            .map_err(|_| Status::invalid_argument("invalid skill snapshot digest"))
    }
}

fn parse_environment_projection(
    request: &v1::StartVmRequest,
) -> Result<Option<Sha256Value>, Status> {
    if request.environment_projection_sha256.is_empty() {
        return Ok(None);
    }
    let digest = Sha256Value::parse_hex(&request.environment_projection_sha256)
        .map_err(|_| Status::invalid_argument("invalid environment projection digest"))?;
    if digest.as_bytes() == [0; 32] {
        return Err(Status::invalid_argument(
            "invalid environment projection digest",
        ));
    }
    Ok(Some(digest))
}

/// A busy port names itself after the stable code, so the supervisor can say
/// which one is taken.
fn map_host_port_error(error: RunnerError) -> Status {
    match error {
        RunnerError::HostPortUnavailable(port) => {
            Status::failed_precondition(format!("{HOST_PORT_UNAVAILABLE} {port}"))
        }
        RunnerError::InvalidRequest => Status::invalid_argument("invalid host-port bindings"),
        _ => Status::internal("host-port update failed"),
    }
}

/// The policy a boot's egress broker enforces: the selected revision's
/// canonical document, or `open` when none is selected (#2537).
fn start_network_policy(document: &[u8]) -> Result<codewire_egress_policy::CompiledPolicy, Status> {
    if document.is_empty() {
        return Ok(codewire_egress_policy::CompiledPolicy::developer_baseline());
    }
    if document.len() > codewire_egress_policy::MAX_POLICY_DOCUMENT_BYTES {
        return Err(Status::invalid_argument(
            "network policy document is too large",
        ));
    }
    let document: codewire_egress_policy::PolicyDocument = serde_json::from_slice(document)
        .map_err(|_| Status::invalid_argument("network policy document is invalid"))?;
    codewire_egress_policy::CompiledPolicy::compile(document)
        .map_err(|_| Status::invalid_argument("network policy document is invalid"))
}

fn map_start_error(error: RunnerError) -> Status {
    Status::failed_precondition(error.to_string())
}

/// The runner error code for a guest whose image lacks Docker tooling.
pub(crate) const GUEST_DOCKER_TOOLING_MISSING: &str = "guest_docker_tooling_missing";
/// The runner error code for a guest that could not install the workspace
/// image (#3322).
pub(crate) const GUEST_SETUP_FAILED: &str = "guest_setup_failed";
/// The runner error code for a workspace the guest could not start (#3322).
pub(crate) const GUEST_WORKSPACE_FAILED: &str = "guest_workspace_failed";
/// The runner error code for a published host port another program holds.
pub(crate) const HOST_PORT_UNAVAILABLE: &str = "host_port_unavailable";

/// Name the one prepare failure a user can fix without reading runner logs.
fn prepare_error_code(error: &RunnerError) -> &'static str {
    match error {
        RunnerError::HostPortUnavailable(_) => HOST_PORT_UNAVAILABLE,
        _ => "prepare_failed",
    }
}

fn network_start_error_code(error: &RunnerError) -> &'static str {
    match error {
        RunnerError::InvalidNetworkWorker => "network_worker_invalid",
        RunnerError::NetworkWorkerSpawn => "network_worker_spawn",
        RunnerError::NetworkWorkerStartTimeout => "network_worker_start_timeout",
        RunnerError::NetworkWorkerBootstrap => "network_worker_bootstrap",
        RunnerError::GuestDockerToolingMissing => GUEST_DOCKER_TOOLING_MISSING,
        RunnerError::GuestSetupFailed => GUEST_SETUP_FAILED,
        RunnerError::GuestWorkspaceFailed => GUEST_WORKSPACE_FAILED,
        RunnerError::NetworkWorkerStartup(failure) => failure.runner_error_code(),
        RunnerError::NetworkWorkerWait => "network_worker_wait",
        RunnerError::NetworkWorkerKillTimeout => "network_worker_kill_timeout",
        RunnerError::HostPortUnavailable(_) => HOST_PORT_UNAVAILABLE,
        RunnerError::IngressControl => "ingress_forwarder_start",
        RunnerError::EgressPolicyControl => "egress_policy_control",
        RunnerError::EgressBrokerSpawn => "egress_broker_spawn",
        RunnerError::EgressBrokerStartTimeout => "egress_broker_start_timeout",
        RunnerError::EgressBrokerBootstrap => "egress_broker_bootstrap",
        RunnerError::EgressBrokerStartup(failure) => failure.runner_error_code(),
        RunnerError::EgressBrokerWait => "egress_broker_wait",
        RunnerError::EgressBrokerKillTimeout => "egress_broker_kill_timeout",
        RunnerError::MeshTransportSpawn => "mesh_transport_spawn",
        RunnerError::MeshTransportStartTimeout => "mesh_transport_start_timeout",
        RunnerError::MeshTransportBootstrap => "mesh_transport_bootstrap",
        RunnerError::MeshTransportStartup(failure) => failure.runner_error_code(),
        RunnerError::MeshEnrollmentBrokerSpawn => "mesh_enrollment_broker_spawn",
        RunnerError::MeshEnrollmentBrokerStartTimeout => "mesh_enrollment_broker_start_timeout",
        RunnerError::MeshEnrollmentBrokerBootstrap => "mesh_enrollment_broker_bootstrap",
        RunnerError::MeshEnrollmentBrokerStartup(failure) => failure.runner_error_code(),
        RunnerError::MeshProcessWait => "mesh_process_wait",
        RunnerError::MeshProcessKillTimeout => "mesh_process_kill_timeout",
        _ => "network_stack_failed",
    }
}

fn map_grow_error(error: RunnerError) -> Status {
    match error {
        RunnerError::InvalidDiskGrowth(_) | RunnerError::DiskShrinkUnsupported { .. } => {
            Status::invalid_argument(error.to_string())
        }
        _ => Status::failed_precondition(error.to_string()),
    }
}

fn daemon_ready_timeout(has_setup: bool) -> std::time::Duration {
    if has_setup {
        SETUP_DAEMON_READY_TIMEOUT
    } else {
        DAEMON_READY_TIMEOUT
    }
}

struct GuestProgressTarget {
    hybrid: HybridVsockTarget,
    vm_id: Uuid,
    generation: u64,
    token: Zeroizing<String>,
}

impl GuestProgressTarget {
    fn from_running(running: &RunningVm) -> Self {
        let (hybrid, token) = running.progress_access_parts();
        Self {
            hybrid: hybrid.clone(),
            vm_id: running.vm_id(),
            generation: running.generation(),
            token: Zeroizing::new(token.to_owned()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct GuestProgressUpdate {
    sequence: u64,
    stage: GuestBootStage,
}

struct GuestProgressValidator {
    vm_id: Uuid,
    generation: u64,
    challenge: [u8; PROGRESS_CHALLENGE_LEN],
    token: Zeroizing<String>,
    sequence: u64,
    stage: Option<GuestBootStage>,
    frames: usize,
}

impl GuestProgressValidator {
    fn new(target: &GuestProgressTarget, challenge: [u8; PROGRESS_CHALLENGE_LEN]) -> Self {
        Self {
            vm_id: target.vm_id,
            generation: target.generation,
            challenge,
            token: target.token.clone(),
            sequence: 0,
            stage: None,
            frames: 0,
        }
    }

    fn accept(&mut self, bytes: &[u8]) -> Result<GuestProgressUpdate, GuestProgressStreamError> {
        let frame = ProgressFrame::decode(
            bytes,
            &self.challenge,
            self.token.as_str(),
            self.vm_id,
            self.generation,
        )?;
        self.frames = self
            .frames
            .checked_add(1)
            .ok_or(GuestProgressStreamError::Flood)?;
        if self.frames > MAXIMUM_GUEST_PROGRESS_FRAMES {
            return Err(GuestProgressStreamError::Flood);
        }
        if frame.sequence <= self.sequence || self.stage.is_some_and(|stage| frame.stage < stage) {
            return Err(GuestProgressStreamError::InvalidSequence);
        }
        self.sequence = frame.sequence;
        self.stage = Some(frame.stage);
        Ok(GuestProgressUpdate {
            sequence: frame.sequence,
            stage: frame.stage,
        })
    }
}

async fn stream_guest_progress(
    target: GuestProgressTarget,
    sender: mpsc::Sender<GuestProgressUpdate>,
) -> Result<(), GuestProgressStreamError> {
    let mut stream = loop {
        match target
            .hybrid
            .connect_guest_port(GUEST_PROGRESS_VSOCK_PORT)
            .await
        {
            Ok(stream) => break stream,
            Err(
                error @ (HybridVsockError::InvalidSocketPath
                | HybridVsockError::InvalidGuestPort
                | HybridVsockError::SocketIdentity(_)),
            ) => return Err(error.into()),
            Err(_) => tokio::time::sleep(PROGRESS_RETRY_DELAY).await,
        }
    };
    let mut challenge = [0_u8; PROGRESS_CHALLENGE_LEN];
    while challenge.iter().all(|byte| *byte == 0) {
        OsRng.fill_bytes(&mut challenge);
    }
    let request = ProgressRequest {
        vm_id: target.vm_id,
        generation: target.generation,
        challenge,
    };
    stream.write_all(&request.encode()).await?;
    stream.flush().await?;
    let mut validator = GuestProgressValidator::new(&target, challenge);
    loop {
        let mut bytes = [0_u8; PROGRESS_FRAME_LEN];
        stream.read_exact(&mut bytes).await?;
        let update = validator.accept(&bytes)?;
        let terminal = update.stage.is_terminal();
        if sender.send(update).await.is_err() || terminal {
            return Ok(());
        }
    }
}

#[derive(Debug, thiserror::Error)]
enum GuestProgressStreamError {
    #[error("guest progress hybrid-vsock transport failed")]
    Hybrid(#[from] HybridVsockError),
    #[error("guest progress I/O failed")]
    Io(#[from] io::Error),
    #[error("guest progress authentication or framing failed")]
    Progress(#[from] ProgressError),
    #[error("guest progress sequence is invalid")]
    InvalidSequence,
    #[error("guest progress exceeded its frame budget")]
    Flood,
}

/// Why a started guest never became ready. `detail` and `guest_stage` are
/// closed names for the runner log (#2595); the status keeps its existing text.
struct GuestStartFailure {
    status: Status,
    detail: &'static str,
    guest_stage: Option<GuestBootStage>,
    daemon_ready: bool,
}

async fn wait_for_guest_daemon(
    running: &mut RunningVm,
    timeout: std::time::Duration,
    events: &RunnerEvents,
) -> Result<(), GuestStartFailure> {
    let target = GuestProgressTarget::from_running(running);
    let generation = running.generation();
    let (progress_tx, mut progress_rx) = mpsc::channel(RUNNER_WATCH_BUFFER);
    let mut progress_task = tokio::spawn(stream_guest_progress(target, progress_tx));
    let mut progress_joined = false;
    let mut guest_stage = None;
    let mut daemon_ready = false;
    let result = tokio::time::timeout(timeout, async {
        let mut progress_open = true;
        let mut progress_ready = false;
        loop {
            tokio::select! {
                progress = progress_rx.recv(), if progress_open => match progress {
                    Some(progress) => {
                        events.publish(
                            v1::EnvironmentState::Starting,
                            generation,
                            v1::RunnerStage::GuestInit,
                            Some(progress),
                            None,
                        running.cw_runtime_catalog_generation(),
                        ).map_err(|status| ("event_publish", status))?;
                        guest_stage = Some(progress.stage);
                        if progress.stage.is_failure() {
                            return Err((
                                guest_failure_detail(progress.stage),
                                Status::failed_precondition(
                                    "authenticated guest initialization failed",
                                ),
                            ));
                        }
                        progress_ready |= progress.stage == GuestBootStage::DaemonStarted;
                    }
                    None => {
                        progress_open = false;
                        progress_joined = true;
                        match (&mut progress_task).await {
                            Ok(Ok(())) if progress_ready => {}
                            Ok(Ok(())) => {
                                return Err((
                                    "guest_progress_ended",
                                    Status::unavailable(
                                        "guest progress ended before daemon startup",
                                    ),
                                ));
                            }
                            Ok(Err(_)) | Err(_) => {
                                return Err((
                                    "guest_progress_invalid",
                                    Status::failed_precondition("guest progress validation failed"),
                                ));
                            }
                        }
                    }
                },
                _ = tokio::time::sleep(DAEMON_RETRY_DELAY) => {
                    match running
                        .observe_exit()
                        .await
                        .map_err(|error| ("vm_observe_failed", Status::internal(error.to_string())))?
                    {
                        ExitClass::StillRunning => {}
                        ExitClass::GuestShutdown => {
                            return Err((
                                "guest_shutdown",
                                Status::unavailable("guest shut down before daemon readiness"),
                            ));
                        }
                        ExitClass::VmmFailure(code) => {
                            return Err(("vmm_exited", Status::unavailable(format!(
                                "Cloud Hypervisor exited before guest daemon readiness with status {code:?}"
                            ))));
                        }
                        ExitClass::DirectShareFailure(code) => {
                            return Err(("direct_share_exited", Status::unavailable(format!(
                                "isolated direct-share server exited before guest daemon readiness with status {code:?}"
                            ))));
                        }
                        ExitClass::NetworkWorkerFailure(code) => {
                            return Err(("network_worker_exited", Status::unavailable(format!(
                                "isolated network worker exited before guest daemon readiness with status {code:?}"
                            ))));
                        }
                        ExitClass::EgressBrokerFailure(code) => {
                            return Err(("egress_broker_exited", Status::unavailable(format!(
                                "isolated egress broker exited before guest daemon readiness with status {code:?}"
                            ))));
                        }
                        ExitClass::IngressForwarderFailure => {
                            return Err((
                                "ingress_forwarder_exited",
                                Status::unavailable(
                                    "ingress forwarder exited before guest daemon readiness",
                                ),
                            ));
                        }
                        ExitClass::MeshTransportFailure(code) => {
                            return Err(("mesh_transport_exited", Status::unavailable(format!(
                                "isolated Mesh transport exited before guest daemon readiness with status {code:?}"
                            ))));
                        }
                        ExitClass::MeshIngressReceiverFailure => {
                            return Err((
                                "mesh_ingress_receiver_exited",
                                Status::unavailable(
                                    "Mesh ingress receiver exited before guest daemon readiness",
                                ),
                            ));
                        }
                    }
                    if !daemon_ready
                        && let Ok(client) = running.daemon_client().await
                        && client.require_ready().await.is_ok()
                    {
                        daemon_ready = true;
                    }
                }
            }
            if daemon_ready && progress_ready {
                return Ok(());
            }
        }
    })
    .await
    .unwrap_or_else(|_| {
        Err((
            "readiness_timeout",
            Status::unavailable("guest daemon readiness timed out"),
        ))
    });
    if !progress_joined {
        progress_task.abort();
        let _ = progress_task.await;
    }
    result.map_err(|(detail, status)| GuestStartFailure {
        status,
        detail,
        guest_stage,
        daemon_ready,
    })
}

fn guest_failure_detail(stage: GuestBootStage) -> &'static str {
    match stage {
        GuestBootStage::SetupFailed => GUEST_SETUP_FAILED,
        GuestBootStage::DockerToolingMissing => GUEST_DOCKER_TOOLING_MISSING,
        _ => GUEST_WORKSPACE_FAILED,
    }
}

/// The closed log name of a guest boot stage.
fn guest_stage_name(stage: GuestBootStage) -> &'static str {
    match stage {
        GuestBootStage::StateMounted => "state_mounted",
        GuestBootStage::CgroupsReady => "cgroups_ready",
        GuestBootStage::DisksAdmitted => "disks_admitted",
        GuestBootStage::RootMounted => "root_mounted",
        GuestBootStage::SetupHeaderReady => "setup_header_ready",
        GuestBootStage::SetupContentReady => "setup_content_ready",
        GuestBootStage::RootLayersReady => "root_layers_ready",
        GuestBootStage::WorkspacePlanReady => "workspace_plan_ready",
        GuestBootStage::OwnershipReady => "ownership_ready",
        GuestBootStage::ContainerControlReady => "container_control_ready",
        GuestBootStage::RootGenerationReady => "root_generation_ready",
        GuestBootStage::PersistentLayoutReady => "persistent_layout_ready",
        GuestBootStage::RuncLaunching => "runc_launching",
        GuestBootStage::RuncRunning => "runc_running",
        GuestBootStage::WorkspaceRunning => "workspace_running",
        GuestBootStage::DaemonStarted => "daemon_started",
        GuestBootStage::SetupFailed => "setup_failed",
        GuestBootStage::WorkspaceFailed => "workspace_failed",
        GuestBootStage::DockerToolingMissing => "docker_tooling_missing",
    }
}

#[cfg(target_os = "linux")]
fn clear_parent_death_signal() -> Result<(), Status> {
    // SAFETY: PR_SET_PDEATHSIG with zero only clears the calling process's
    // parent-death signal and has no pointer argument.
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, 0) } != 0 {
        return Err(Status::internal("runner adoption failed"));
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum RunnerServiceError {
    #[error(transparent)]
    Runner(#[from] RunnerError),
    #[error(transparent)]
    Uds(#[from] UdsError),
    #[error("runtime artifact store operation failed")]
    ArtifactStore,
    #[error("serve private environment runner failed")]
    Serve,
    #[error("adopt private environment runner failed")]
    Adoption,
    #[error("private environment runner configuration is invalid")]
    Configuration,
    #[error("the native environment runner does not implement the required compatibility protocol")]
    RunnerProtocolUnavailable,
    #[error(
        "native environment runner protocol version mismatch: expected {expected}, running runner reported {actual}"
    )]
    RunnerProtocolMismatch { expected: u32, actual: u32 },
    #[error("query native environment runner compatibility failed")]
    RunnerProtocolInfoUnavailable,
}

impl RunnerServiceError {
    pub(crate) fn incompatible_protocol(&self) -> bool {
        matches!(
            self,
            Self::RunnerProtocolUnavailable | Self::RunnerProtocolMismatch { .. }
        )
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;
    use std::sync::atomic::AtomicUsize;

    use tokio::net::UnixListener;

    use super::*;
    use crate::uds::bind_owner_only_listener;

    const PROGRESS_TOKEN: &str = "runner-progress-test-token-0123456789abcdef";

    fn bootstrap_access() -> (
        tempfile::TempDir,
        std::os::unix::net::UnixListener,
        v1::DaemonAccess,
    ) {
        let parent = tempfile::tempdir().unwrap();
        std::fs::set_permissions(parent.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let socket = parent.path().join("vsock.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
        let access = v1::DaemonAccess {
            hybrid_socket: socket.to_str().unwrap().into(),
            guest_port: 7_777,
            generation_capability: PROGRESS_TOKEN.into(),
        };
        (parent, listener, access)
    }

    #[cfg(target_os = "linux")]
    fn current_process_liveness() -> OwnedFd {
        rustix::process::pidfd_open(
            rustix::process::getpid(),
            rustix::process::PidfdFlags::empty(),
        )
        .unwrap()
    }

    #[cfg(target_os = "macos")]
    fn current_process_liveness() -> OwnedFd {
        crate::host::process::exit_queue(std::process::id()).unwrap()
    }

    fn bootstrap_rpc() -> (tempfile::TempDir, RunnerRpc) {
        let parent = tempfile::tempdir().unwrap();
        std::fs::set_permissions(parent.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let environment_id = Uuid::new_v4();
        // Metadata-only service fixture: no artifact is executed or VM booted.
        let artifact = crate::artifact::AdmittedArtifact::for_test("/nonexistent/test-artifact");
        let runner = CloudHypervisorRunner::from_admitted(
            parent.path().join("state"),
            crate::artifact::AdmittedArtifacts::for_test(
                artifact.clone(),
                artifact.clone(),
                artifact,
            ),
        )
        .unwrap();
        let rpc = RunnerRpc {
            state: Arc::new(Mutex::new(RunnerState {
                environment_id,
                artifact_generation: "synthetic".into(),
                runner,
                generation_access: None,
                running: None,
                generation: 1,
                state: v1::EnvironmentState::Starting,
                error_code: None,
                adopted: true,
                retirement: RetirementState::Active,
                mesh_data_dir: parent.path().join("mesh"),
                platform_config_dir: parent.path().join("platform"),
            })),
            adoption: mpsc::channel(1).0,
            log: None,
            events: Arc::new(RunnerEvents::new(environment_id, "synthetic".into(), 1)),
            generation_access: GenerationAccessCell::new(environment_id),
            shutdown: watch::channel(None).0,
        };
        (parent, rpc)
    }

    /// #3270: an idle runner shuts down once the supervisor that spawned it
    /// is gone, and only then.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn an_idle_runner_shuts_down_when_its_supervisor_is_gone() {
        let (_parent, rpc) = bootstrap_rpc();
        let mut supervisor = crate::test_child(&mut std::process::Command::new(
            std::fs::canonicalize("/bin/sleep").unwrap(),
        ))
        .arg("60")
        .spawn()
        .unwrap();
        let pidfd = rustix::process::pidfd_open(
            rustix::process::Pid::from_raw(i32::try_from(supervisor.id()).unwrap()).unwrap(),
            rustix::process::PidfdFlags::empty(),
        )
        .unwrap();
        let shutdown = rpc.shutdown.subscribe();
        let watcher = tokio::spawn(exit_when_idle_without_supervisor(
            pidfd,
            Arc::clone(&rpc.state),
            Arc::clone(&rpc.events),
            rpc.shutdown.clone(),
        ));
        tokio::task::yield_now().await;
        assert!(shutdown.borrow().is_none(), "its supervisor still runs");

        supervisor.kill().unwrap();
        supervisor.wait().unwrap();
        // The supervisor's exit ends the wait; the bound only turns a hang
        // into a failure.
        tokio::time::timeout(std::time::Duration::from_secs(120), watcher)
            .await
            .expect("the idle runner did not see its supervisor exit")
            .unwrap();
        assert!(shutdown.borrow().is_some());
        assert_eq!(
            rpc.state.lock().await.retirement,
            RetirementState::ShutdownRequested
        );
    }

    #[test]
    fn guest_start_failures_log_distinct_closed_causes_without_their_status_text() {
        const CANARY: &str = "synthetic-application-secret-value-must-not-be-logged";
        let (parent, mut rpc) = bootstrap_rpc();
        let root_path = parent.path().join("runtime");
        std::fs::create_dir(&root_path).unwrap();
        std::fs::set_permissions(&root_path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let root = PrivateRoot::open(&std::fs::canonicalize(&root_path).unwrap()).unwrap();
        let environment_id = Uuid::new_v4();
        let name = diagnostic_log::runner_log_name(environment_id);
        rpc.log = Some(Arc::new(
            DiagnosticLog::adopt(diagnostic_log::open_child_log(&root, &name).unwrap()).unwrap(),
        ));

        // Install (setup) and startup (workspace) failures are guest stages;
        // readiness is the bounded wait. Each is its own closed cause.
        let failures = [
            (
                guest_failure_detail(GuestBootStage::SetupFailed),
                Some(GuestBootStage::SetupFailed),
            ),
            (
                guest_failure_detail(GuestBootStage::WorkspaceFailed),
                Some(GuestBootStage::WorkspaceFailed),
            ),
            ("readiness_timeout", Some(GuestBootStage::RuncRunning)),
            ("vmm_exited", None),
        ];
        for (detail, guest_stage) in failures {
            let failure = GuestStartFailure {
                status: Status::unavailable(CANARY),
                detail,
                guest_stage,
                daemon_ready: false,
            };
            rpc.log_start_failure(
                environment_id,
                3,
                "guest_start_failed",
                Some(&failure),
                std::time::Instant::now(),
            );
        }
        rpc.log_start_failure(
            environment_id,
            4,
            "vmm_start_failed",
            None,
            std::time::Instant::now(),
        );

        let log = std::fs::read_to_string(root.path().join("logs").join(&name)).unwrap();
        let lines = log.lines().collect::<Vec<_>>();
        let expected = [
            "detail=guest_setup_failed guest_stage=setup_failed daemon_ready=0",
            "detail=guest_workspace_failed guest_stage=workspace_failed daemon_ready=0",
            "detail=readiness_timeout guest_stage=runc_running daemon_ready=0",
            "detail=vmm_exited guest_stage=none daemon_ready=0",
        ];
        assert_eq!(lines.len(), expected.len() + 1, "{log}");
        for (line, detail) in lines.iter().zip(expected) {
            assert!(
                line.contains(&format!(
                    " event=vm_start_failed environment={environment_id} generation=3 \
                     error_code=guest_start_failed {detail} elapsed_ms="
                )),
                "{line}"
            );
        }
        assert!(
            lines[4].contains(&format!(
                " event=vm_start_failed environment={environment_id} generation=4 \
                 error_code=vmm_start_failed elapsed_ms="
            )),
            "{}",
            lines[4]
        );
        assert!(!log.contains(CANARY));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_timed_out_vmm_start_logs_which_runner_error_it_was() {
        const CANARY: &str = "synthetic-path-must-not-be-logged";
        let (parent, mut rpc) = bootstrap_rpc();
        let root_path = parent.path().join("runtime");
        std::fs::create_dir(&root_path).unwrap();
        std::fs::set_permissions(&root_path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let root = PrivateRoot::open(&std::fs::canonicalize(&root_path).unwrap()).unwrap();
        let environment_id = Uuid::new_v4();
        let name = diagnostic_log::runner_log_name(environment_id);
        rpc.log = Some(Arc::new(
            DiagnosticLog::adopt(diagnostic_log::open_child_log(&root, &name).unwrap()).unwrap(),
        ));

        // The VMM answered no API request in time, the VMM exited, and an
        // error that carries a path: one error code, three named errors.
        let failures = [
            (
                RunnerError::Api(crate::ch_api::ChApiError::RequestTimeout),
                "api_request_timeout",
            ),
            (RunnerError::ExitedDuringStart, "exited_during_start"),
            (
                RunnerError::Io {
                    path: PathBuf::from(format!("/{CANARY}")),
                    source: io::Error::other(CANARY),
                },
                "io",
            ),
        ];
        for (error, _) in &failures {
            rpc.log_runner_start_failure(
                environment_id,
                2,
                "vmm_start_failed",
                error,
                std::time::Instant::now(),
            );
        }

        let log = std::fs::read_to_string(root.path().join("logs").join(&name)).unwrap();
        let lines = log.lines().collect::<Vec<_>>();
        assert_eq!(lines.len(), failures.len(), "{log}");
        for (line, (_, detail)) in lines.iter().zip(&failures) {
            assert!(
                line.contains(&format!(
                    " event=vm_start_failed environment={environment_id} generation=2 \
                     error_code=vmm_start_failed detail={detail} elapsed_ms="
                )),
                "{line}"
            );
        }
        assert!(!log.contains(CANARY));
    }

    #[test]
    fn generation_access_is_exact_and_old_guard_cannot_clear_a_new_boot() {
        let (_parent, _listener, access) = bootstrap_access();
        let environment_id = Uuid::new_v4();
        let cell = GenerationAccessCell::new(environment_id);
        let first = cell
            .install(1, access.clone(), current_process_liveness())
            .unwrap();
        assert!(cell.get(Uuid::new_v4(), 1).is_err());
        assert!(cell.get(environment_id, 0).is_err());
        assert!(cell.get(environment_id, 2).is_err());
        assert_eq!(cell.get(environment_id, 1).unwrap(), access);
        assert!(
            cell.install(2, access.clone(), current_process_liveness())
                .is_err()
        );
        first.revoke();
        let second = cell
            .install(2, access.clone(), current_process_liveness())
            .unwrap();
        drop(first);
        assert_eq!(cell.get(environment_id, 2).unwrap(), access);
        assert!(cell.get(environment_id, 1).is_err());
        drop(second);
        assert!(cell.get(environment_id, 2).is_err());
    }

    #[test]
    fn retirement_atomically_revokes_and_permanently_fences_generation_access() {
        let (_parent, _listener, access) = bootstrap_access();
        let id = Uuid::new_v4();
        let cell = GenerationAccessCell::new(id);
        let guard = cell
            .install(1, access.clone(), current_process_liveness())
            .unwrap();
        cell.retire();
        assert!(cell.current.lock().unwrap().access.is_none());
        assert!(cell.get(id, 1).is_err());
        assert!(
            cell.install(2, access.clone(), current_process_liveness())
                .is_err()
        );
        drop(guard);
        cell.retire();
        assert!(cell.install(1, access, current_process_liveness()).is_err());
    }

    fn stopped_start_request(id: Uuid) -> v1::StartVmRequest {
        v1::StartVmRequest {
            environment_id: id.to_string(),
            generation: 2,
            vcpus: 1,
            memory_mib: 128,
            vsock_cid: 42,
            daemon_vsock_port: 7777,
            state_disk_bytes: 128 * 1024 * 1024,
            managed_credential_clients: codewire_access::ManagedCredentialClients::default()
                .encode()
                .to_owned(),
            ..Default::default()
        }
    }

    #[test]
    fn cw_runtime_generation_is_empty_or_one_lowercase_sha256() {
        let mut request = stopped_start_request(Uuid::new_v4());
        assert_eq!(parse_cw_runtime_catalog_generation(&request).unwrap(), None);
        request.cw_runtime_catalog_generation = "a".repeat(64);
        assert_eq!(
            parse_cw_runtime_catalog_generation(&request).unwrap(),
            Some("a".repeat(64))
        );
        for invalid in [
            "A".repeat(64),
            "a".repeat(63),
            "../catalog".to_owned(),
            format!("{}\n", "a".repeat(64)),
        ] {
            request.cw_runtime_catalog_generation = invalid;
            assert_eq!(
                parse_cw_runtime_catalog_generation(&request)
                    .unwrap_err()
                    .code(),
                tonic::Code::InvalidArgument
            );
        }
    }

    async fn assert_retired_capabilities_denied(rpc: &RunnerRpc) {
        let id = rpc.events.environment_id;
        for result in [
            rpc.start_vm(Request::new(stopped_start_request(id)))
                .await
                .map(drop),
            rpc.stop_vm(Request::new(v1::StopVmRequest {}))
                .await
                .map(drop),
            rpc.grow_state_disk(Request::new(v1::GrowStateDiskRequest {
                environment_id: id.to_string(),
                disk_bytes: 256 * 1024 * 1024,
            }))
            .await
            .map(drop),
            rpc.adopt_runner(Request::new(v1::AdoptRunnerRequest {
                environment_id: id.to_string(),
            }))
            .await
            .map(drop),
            rpc.get_daemon_access(Request::new(v1::GetDaemonAccessRequest {}))
                .await
                .map(drop),
            rpc.get_generation_daemon_access(Request::new(v1::GetGenerationDaemonAccessRequest {
                environment_id: id.to_string(),
                generation: 1,
            }))
            .await
            .map(drop),
        ] {
            let error = result.unwrap_err();
            assert_eq!(error.code(), tonic::Code::FailedPrecondition);
            assert_eq!(error.message(), "runner is retiring");
        }
    }

    #[tokio::test]
    async fn failed_prepare_stays_fenced_and_can_be_retried() {
        let (_parent, rpc) = bootstrap_rpc();
        let (_transport, _listener, access) = bootstrap_access();
        let guard = rpc
            .generation_access
            .install(1, access.clone(), current_process_liveness())
            .unwrap();
        // The existing bounded event error forces failure before cleanup.
        rpc.events.sequence.store(u64::MAX, Ordering::Relaxed);
        assert!(
            rpc.prepare_retire_runner(Request::new(v1::PrepareRetireRunnerRequest {}))
                .await
                .is_err()
        );
        assert_eq!(
            rpc.state.lock().await.retirement,
            RetirementState::Preparing
        );
        assert_retired_capabilities_denied(&rpc).await;
        assert!(
            rpc.generation_access
                .install(2, access, current_process_liveness())
                .is_err()
        );
        let id = rpc.events.environment_id;
        assert_eq!(
            rpc.shutdown_runner(Request::new(v1::ShutdownRunnerRequest {
                environment_id: id.to_string(),
                generation: 1,
            }))
            .await
            .unwrap_err()
            .code(),
            tonic::Code::FailedPrecondition
        );
        assert!(rpc.shutdown.borrow().is_none());
        drop(guard);

        rpc.events.sequence.store(1, Ordering::Relaxed);
        rpc.prepare_retire_runner(Request::new(v1::PrepareRetireRunnerRequest {}))
            .await
            .unwrap();
        assert_eq!(rpc.state.lock().await.retirement, RetirementState::Prepared);
        assert_retired_capabilities_denied(&rpc).await;
    }

    #[tokio::test]
    async fn shutdown_requires_exact_adopted_prepared_identity_and_is_idempotent() {
        let (_parent, rpc) = bootstrap_rpc();
        let id = rpc.events.environment_id;
        let request = v1::ShutdownRunnerRequest {
            environment_id: id.to_string(),
            generation: 1,
        };
        assert_eq!(
            rpc.shutdown_runner(Request::new(request.clone()))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::FailedPrecondition
        );
        rpc.state.lock().await.adopted = false;
        assert!(
            rpc.prepare_retire_runner(Request::new(v1::PrepareRetireRunnerRequest {}))
                .await
                .is_err()
        );
        assert_eq!(rpc.state.lock().await.retirement, RetirementState::Active);
        assert!(!rpc.generation_access.current.lock().unwrap().retiring);
        rpc.state.lock().await.adopted = true;
        rpc.prepare_retire_runner(Request::new(v1::PrepareRetireRunnerRequest {}))
            .await
            .unwrap();
        let sequence = rpc.events.sequence.load(Ordering::Acquire);
        rpc.prepare_retire_runner(Request::new(v1::PrepareRetireRunnerRequest {}))
            .await
            .unwrap();
        assert_eq!(rpc.events.sequence.load(Ordering::Acquire), sequence);
        for wrong in [
            v1::ShutdownRunnerRequest {
                environment_id: Uuid::new_v4().to_string(),
                generation: 1,
            },
            v1::ShutdownRunnerRequest {
                environment_id: id.to_string(),
                generation: 2,
            },
        ] {
            assert_eq!(
                rpc.shutdown_runner(Request::new(wrong))
                    .await
                    .unwrap_err()
                    .code(),
                tonic::Code::PermissionDenied
            );
            assert!(rpc.shutdown.borrow().is_none());
        }
        rpc.shutdown_runner(Request::new(request.clone()))
            .await
            .unwrap();
        rpc.shutdown_runner(Request::new(request)).await.unwrap();
        rpc.prepare_retire_runner(Request::new(v1::PrepareRetireRunnerRequest {}))
            .await
            .unwrap();
        assert_eq!(rpc.events.sequence.load(Ordering::Acquire), sequence);
        assert_eq!(
            rpc.state.lock().await.retirement,
            RetirementState::ShutdownRequested
        );
        assert_retired_capabilities_denied(&rpc).await;
    }

    /// A start that fails before its VM is prepared still consumes its
    /// generation, so the generation the runner reports and the one on its
    /// last event agree. A supervisor's retry compares the two; when they
    /// disagreed, the first retry after a failed start (such as a taken host
    /// port) was refused as an invalid runner response (#2579).
    #[tokio::test]
    async fn a_start_that_fails_to_prepare_reports_its_generation_consistently() {
        let (_parent, rpc) = bootstrap_rpc();
        let id = rpc.events.environment_id;
        let request = stopped_start_request(id);
        rpc.start_vm(Request::new(request.clone()))
            .await
            .unwrap_err();
        let info = rpc.state.lock().await.info();
        let last = rpc.events.subscribe().borrow().clone();
        let event = last.runner.as_ref().unwrap();
        assert_eq!(last.stage, v1::RunnerStage::Error as i32, "{last:?}");
        assert_eq!(info.state, v1::EnvironmentState::Error as i32);
        assert_eq!(event.generation, request.generation);
        assert_eq!(info.generation, event.generation);
        assert_eq!(info.error_code, event.error_code);
    }

    #[tokio::test]
    async fn retirement_and_start_linearize_in_both_lock_orders() {
        for prepare_first in [false, true] {
            let (_parent, rpc) = bootstrap_rpc();
            let id = rpc.events.environment_id;
            let held = rpc.state.lock().await;
            let start = rpc.start_vm(Request::new(stopped_start_request(id)));
            let prepare =
                rpc.prepare_retire_runner(Request::new(v1::PrepareRetireRunnerRequest {}));
            tokio::pin!(start, prepare);
            // Poll each future once while holding the mutex to deterministically
            // enqueue both orders. Tokio's mutex preserves waiter order.
            if prepare_first {
                assert!(futures::poll!(&mut prepare).is_pending());
                assert!(futures::poll!(&mut start).is_pending());
            } else {
                assert!(futures::poll!(&mut start).is_pending());
                assert!(futures::poll!(&mut prepare).is_pending());
            }
            drop(held);
            let (started, prepared) = tokio::join!(start, prepare);
            prepared.unwrap();
            let start_error = started.unwrap_err();
            if prepare_first {
                assert_eq!(start_error.message(), "runner is retiring");
                assert_eq!(rpc.events.sequence.load(Ordering::Acquire), 3);
            } else {
                // This metadata-only fixture cannot launch its nonexistent
                // artifact. Start enters its real preparation path first;
                // retirement then cleans it up and permanently fences it.
                assert_ne!(start_error.message(), "runner is retiring");
                assert!(rpc.events.sequence.load(Ordering::Acquire) > 3);
            }
            assert_eq!(rpc.state.lock().await.retirement, RetirementState::Prepared);
            assert_retired_capabilities_denied(&rpc).await;
        }
    }

    #[tokio::test]
    async fn concurrent_prepare_and_late_watch_are_idempotent_and_terminal() {
        use futures::StreamExt as _;
        let (_parent, rpc) = bootstrap_rpc();
        let first = rpc.prepare_retire_runner(Request::new(v1::PrepareRetireRunnerRequest {}));
        let second = rpc.prepare_retire_runner(Request::new(v1::PrepareRetireRunnerRequest {}));
        let (first, second) = tokio::join!(first, second);
        first.unwrap();
        second.unwrap();
        assert_eq!(rpc.events.sequence.load(Ordering::Acquire), 3);
        let id = rpc.events.environment_id;
        rpc.shutdown_runner(Request::new(v1::ShutdownRunnerRequest {
            environment_id: id.to_string(),
            generation: 1,
        }))
        .await
        .unwrap();
        let mut stream = rpc
            .watch_runner(Request::new(v1::WatchRunnerRequest {
                environment_id: id.to_string(),
            }))
            .await
            .unwrap()
            .into_inner();
        let final_event = stream.next().await.unwrap().unwrap();
        assert_eq!(final_event.sequence, 3);
        assert_eq!(final_event.stage, v1::RunnerStage::Stopped as i32);
        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn real_uds_shutdown_flushes_response_final_watch_and_removes_socket() {
        let (parent, rpc) = bootstrap_rpc();
        let id = rpc.events.environment_id;
        let socket = parent.path().join("retire.sock");
        let server = tokio::spawn(serve_runner_rpc(socket.clone(), rpc.clone()));
        let mut client = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if let Ok(client) = RunnerClient::connect(&socket).await {
                    break client;
                }
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();
        let mut early = client.watch(id).await.unwrap();
        client.prepare_retire().await.unwrap();
        let mut late = client.watch(id).await.unwrap();
        // Do not consume either stream before shutdown; both must retain the
        // final event while the unary response still reaches this client.
        client.shutdown(id, 1).await.unwrap();
        for stream in [&mut early, &mut late] {
            let final_event = tokio::time::timeout(std::time::Duration::from_secs(2), async {
                let mut last = None;
                while let Some(event) = stream.message().await.unwrap() {
                    last = Some(event);
                }
                last.unwrap()
            })
            .await
            .unwrap();
            assert_eq!(final_event.stage, v1::RunnerStage::Stopped as i32);
            assert_eq!(
                final_event.runner.unwrap().state,
                v1::EnvironmentState::Stopped as i32
            );
        }
        tokio::time::timeout(std::time::Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(!socket.exists());
        assert_eq!(
            rpc.state.lock().await.retirement,
            RetirementState::ShutdownRequested
        );
    }

    #[tokio::test]
    async fn cancelling_startup_owner_revokes_generation_access() {
        let (_parent, _listener, access) = bootstrap_access();
        let environment_id = Uuid::new_v4();
        let cell = GenerationAccessCell::new(environment_id);
        let owner = Arc::clone(&cell);
        let (ready, started) = oneshot::channel();
        let task = tokio::spawn(async move {
            let _guard = owner
                .install(1, access, current_process_liveness())
                .unwrap();
            ready.send(()).unwrap();
            std::future::pending::<()>().await;
        });
        started.await.unwrap();
        assert!(cell.get(environment_id, 1).is_ok());
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert!(cell.get(environment_id, 1).is_err());
    }

    #[tokio::test]
    async fn nonreading_watch_cannot_hold_a_retired_server_past_its_drain_bound() {
        let (parent, rpc) = bootstrap_rpc();
        let id = rpc.events.environment_id;
        let socket = parent.path().join("blocked-watch.sock");
        let server = tokio::spawn(serve_runner_rpc(socket.clone(), rpc));
        let mut client = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if let Ok(client) = RunnerClient::connect(&socket).await {
                    break client;
                }
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();
        let connector = crate::uds::owner_only_connector(&socket).unwrap();
        let channel = tonic::transport::Endpoint::from_static("http://codewire-retirement-test")
            // Deliberately never provide body flow control on this separate
            // owner connection. The normal shutdown client remains readable.
            .initial_stream_window_size(0)
            .connect_with_connector(connector)
            .await
            .unwrap();
        let mut unresponsive = EnvironmentRunnerServiceClient::new(channel);
        let _unread = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            unresponsive.watch_runner(v1::WatchRunnerRequest {
                environment_id: id.to_string(),
            }),
        )
        .await
        .unwrap()
        .unwrap();
        client.prepare_retire().await.unwrap();
        client.shutdown(id, 1).await.unwrap();
        let result = tokio::time::timeout(
            RUNNER_SERVER_DRAIN_TIMEOUT + std::time::Duration::from_secs(1),
            server,
        )
        .await
        .unwrap()
        .unwrap();
        assert!(
            matches!(result, Err(RunnerServiceError::Serve)),
            "blocked stream is not a successful graceful drain"
        );
        assert!(!socket.exists());
    }

    #[tokio::test]
    async fn generation_access_denies_exited_process_before_state_observation() {
        let (_parent, _listener, access) = bootstrap_access();
        let environment_id = Uuid::new_v4();
        let cell = GenerationAccessCell::new(environment_id);
        let mut command = tokio::process::Command::new("/bin/sleep");
        crate::test_child(command.as_std_mut());
        let mut child = command.arg("60").kill_on_drop(true).spawn().unwrap();
        #[cfg(target_os = "linux")]
        let descriptor = {
            let pid = rustix::process::Pid::from_raw(child.id().unwrap() as i32).unwrap();
            rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty()).unwrap()
        };
        #[cfg(target_os = "macos")]
        let descriptor = crate::host::process::LiveProcess::capture_child(
            child.id().unwrap(),
            std::path::Path::new("/bin/sleep"),
        )
        .unwrap()
        .duplicate_wait_descriptor()
        .unwrap();
        let _guard = cell.install(1, access, descriptor).unwrap();
        assert!(cell.get(environment_id, 1).is_ok());
        child.kill().await.unwrap();
        child.wait().await.unwrap();
        assert!(cell.get(environment_id, 1).is_err());
        assert!(cell.current.lock().unwrap().access.is_none());
    }

    #[tokio::test]
    async fn bootstrap_rpc_and_protocol_info_do_not_wait_for_startup_state_lock() {
        let (parent, rpc) = bootstrap_rpc();
        let (_transport_parent, _listener, expected_access) = bootstrap_access();
        let id = rpc.events.environment_id;
        let _guard = rpc
            .generation_access
            .install(1, expected_access.clone(), current_process_liveness())
            .unwrap();
        let socket = parent.path().join("runner.sock");
        let (incoming, identity) = bind_owner_only(&socket).unwrap();
        let (shutdown, stopped) = oneshot::channel();
        let service = rpc.clone();
        let server = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(EnvironmentRunnerServiceServer::new(service))
                .serve_with_incoming_shutdown(incoming, async {
                    let _ = stopped.await;
                })
                .await
                .unwrap();
        });
        let held = rpc.state.lock().await;
        let mut client = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            RunnerClient::connect(&socket),
        )
        .await
        .unwrap()
        .unwrap();
        let access = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client.generation_daemon_access(id, 1),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(access, expected_access);
        assert!(
            client
                .generation_daemon_access(Uuid::new_v4(), 1)
                .await
                .is_err()
        );
        assert!(client.generation_daemon_access(id, 2).await.is_err());
        assert!(client.generation_daemon_access(id, 0).await.is_err());
        // The normal route deliberately remains serialized and readiness-gated.
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(25),
                rpc.get_daemon_access(Request::new(v1::GetDaemonAccessRequest {}))
            )
            .await
            .is_err()
        );
        drop(held);
        assert!(
            rpc.get_daemon_access(Request::new(v1::GetDaemonAccessRequest {}))
                .await
                .is_err()
        );
        drop(client);
        shutdown.send(()).unwrap();
        server.await.unwrap();
        remove_bound_socket(&socket, &identity).unwrap();
    }

    #[tokio::test]
    async fn stop_retire_and_observed_failures_revoke_even_retained_generation_access() {
        let (_transport_parent, _listener, access) = bootstrap_access();
        for retire in [false, true] {
            let (_parent, rpc) = bootstrap_rpc();
            let id = rpc.events.environment_id;
            rpc.state.lock().await.generation_access = Some(
                rpc.generation_access
                    .install(1, access.clone(), current_process_liveness())
                    .unwrap(),
            );
            // Force an early error before the stop body can complete; revoke
            // must precede even event publication, not depend on successful stop.
            rpc.events.sequence.store(u64::MAX, Ordering::Relaxed);
            if retire {
                assert!(
                    rpc.prepare_retire_runner(Request::new(v1::PrepareRetireRunnerRequest {}))
                        .await
                        .is_err()
                );
            } else {
                assert!(
                    rpc.stop_vm(Request::new(v1::StopVmRequest {}))
                        .await
                        .is_err()
                );
            }
            assert!(rpc.generation_access.get(id, 1).is_err());
        }
        for exit in [
            Ok(ExitClass::GuestShutdown),
            Ok(ExitClass::VmmFailure(Some(1))),
            Ok(ExitClass::DirectShareFailure(Some(1))),
            Ok(ExitClass::NetworkWorkerFailure(Some(1))),
            Ok(ExitClass::EgressBrokerFailure(Some(1))),
            Ok(ExitClass::IngressForwarderFailure),
            Ok(ExitClass::MeshTransportFailure(Some(1))),
            Ok(ExitClass::MeshIngressReceiverFailure),
            Err(RunnerError::Wait),
        ] {
            let (_parent, rpc) = bootstrap_rpc();
            let id = rpc.events.environment_id;
            let mut state = rpc.state.lock().await;
            state.generation_access = Some(
                rpc.generation_access
                    .install(1, access.clone(), current_process_liveness())
                    .unwrap(),
            );
            // The real state-transition seam covers failures that deliberately
            // retain an owned VMM for cleanup; it must clear the separate cell.
            let _ = state.record_observed_exit(exit);
            assert!(rpc.generation_access.get(id, 1).is_err());
        }
    }

    #[test]
    fn generation_transport_and_projection_digest_are_bounded_and_canonical() {
        let id = Uuid::new_v4();
        let (_parent, _listener, access) = bootstrap_access();
        validate_generation_access(id, 1, &access).unwrap();
        for invalid in [
            v1::DaemonAccess {
                hybrid_socket: "relative.sock".into(),
                ..access.clone()
            },
            v1::DaemonAccess {
                hybrid_socket: format!("/{}", "x".repeat(GENERATION_ACCESS_MAX_BYTES)),
                ..access.clone()
            },
            v1::DaemonAccess {
                hybrid_socket: "/invalid\0sock".into(),
                ..access.clone()
            },
            v1::DaemonAccess {
                guest_port: 0,
                ..access.clone()
            },
            v1::DaemonAccess {
                generation_capability: "x".repeat(513),
                ..access.clone()
            },
            v1::DaemonAccess {
                generation_capability: "invalid\ntoken".into(),
                ..access.clone()
            },
        ] {
            let error = validate_generation_access(id, 1, &invalid).unwrap_err();
            assert_eq!(error.message(), "invalid runner generation transport");
            assert!(!error.to_string().contains(PROGRESS_TOKEN));
        }
        assert!(
            parse_environment_projection(&v1::StartVmRequest::default())
                .unwrap()
                .is_none()
        );
        let digest = "ab".repeat(32);
        assert_eq!(
            parse_environment_projection(&v1::StartVmRequest {
                environment_projection_sha256: digest.clone(),
                ..Default::default()
            })
            .unwrap()
            .unwrap()
            .to_string(),
            digest
        );
        for invalid in [
            "0".repeat(64),
            "A".repeat(64),
            "a".repeat(63),
            "a".repeat(65),
            "g".repeat(64),
        ] {
            assert!(
                parse_environment_projection(&v1::StartVmRequest {
                    environment_projection_sha256: invalid,
                    ..Default::default()
                })
                .is_err()
            );
        }
    }

    async fn read_connect_line(stream: &mut tokio::net::UnixStream) -> String {
        let mut line = Vec::new();
        loop {
            let byte = stream.read_u8().await.unwrap();
            line.push(byte);
            if byte == b'\n' {
                return String::from_utf8(line).unwrap();
            }
        }
    }

    fn progress_target(socket: PathBuf, vm_id: Uuid, generation: u64) -> GuestProgressTarget {
        GuestProgressTarget {
            hybrid: HybridVsockTarget::new(socket, 7_777).unwrap(),
            vm_id,
            generation,
            token: Zeroizing::new(PROGRESS_TOKEN.to_owned()),
        }
    }

    #[test]
    fn runner_protocol_requires_the_exact_current_version() {
        admit_runner_protocol_info(&v1::RunnerProtocolInfo {
            protocol_version: NATIVE_RUNNER_PROTOCOL_VERSION,
        })
        .unwrap();

        for actual in
            (0..NATIVE_RUNNER_PROTOCOL_VERSION).chain([NATIVE_RUNNER_PROTOCOL_VERSION + 1])
        {
            let error = admit_runner_protocol_info(&v1::RunnerProtocolInfo {
                protocol_version: actual,
            })
            .unwrap_err();
            assert!(matches!(
                error,
                RunnerServiceError::RunnerProtocolMismatch {
                    expected: NATIVE_RUNNER_PROTOCOL_VERSION,
                    actual: reported,
                } if reported == actual
            ));
        }
    }

    #[tokio::test]
    async fn runner_client_rejects_an_old_runner_before_adoption() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("runtime");
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let socket = root.join("runner.sock");
        let (listener, socket_identity) = bind_owner_only_listener(&socket).unwrap();
        let adoption_calls = Arc::new(AtomicUsize::new(0));
        let adoption_counter = Arc::clone(&adoption_calls);
        let app = axum::Router::new()
            .route(
                "/codewire.local.v1.EnvironmentRunnerService/GetRunnerProtocolInfo",
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
            )
            .route(
                "/codewire.local.v1.EnvironmentRunnerService/AdoptRunner",
                axum::routing::post(move || {
                    let adoption_counter = Arc::clone(&adoption_counter);
                    async move {
                        adoption_counter.fetch_add(1, Ordering::Relaxed);
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
                    }
                }),
            );
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = shutdown_rx.await;
                })
                .await
                .unwrap();
        });

        let error = match RunnerClient::connect(&socket).await {
            Ok(_) => panic!("old runner was admitted"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            RunnerServiceError::RunnerProtocolUnavailable
        ));
        assert_eq!(
            error.to_string(),
            "the native environment runner does not implement the required compatibility protocol"
        );
        assert_eq!(adoption_calls.load(Ordering::Relaxed), 0);

        shutdown_tx.send(()).unwrap();
        server.await.unwrap();
        remove_bound_socket(&socket, &socket_identity).unwrap();
    }

    #[test]
    fn start_failure_preserves_the_actionable_runner_cause() {
        let status = map_start_error(RunnerError::StartTimeout);
        assert_eq!(status.code(), tonic::Code::FailedPrecondition);
        assert_eq!(status.message(), "Cloud Hypervisor startup timed out");
        assert_eq!(
            network_start_error_code(&RunnerError::NetworkWorkerStartTimeout),
            "network_worker_start_timeout"
        );
        assert_eq!(
            network_start_error_code(&RunnerError::MeshTransportStartTimeout),
            "mesh_transport_start_timeout"
        );
        assert_eq!(
            network_start_error_code(&RunnerError::MeshTransportStartup(
                crate::mesh_process::MeshTransportStartupFailure::TransportSetup,
            )),
            "mesh_transport_transport_setup"
        );
        assert_eq!(
            network_start_error_code(&RunnerError::MeshEnrollmentBrokerStartup(
                crate::mesh_enrollment::MeshEnrollmentStartupFailure::EnrollmentRequest,
            )),
            "mesh_enrollment_broker_enrollment_request"
        );
        assert_eq!(
            network_start_error_code(&RunnerError::HostPortUnavailable(3_000)),
            "host_port_unavailable"
        );
        assert_eq!(
            network_start_error_code(&RunnerError::StartTimeout),
            "network_stack_failed"
        );
        assert_eq!(
            network_start_error_code(&RunnerError::GuestSetupFailed),
            GUEST_SETUP_FAILED
        );
        assert_eq!(
            network_start_error_code(&RunnerError::GuestWorkspaceFailed),
            GUEST_WORKSPACE_FAILED
        );
    }

    #[test]
    fn prepare_names_only_an_unavailable_host_port() {
        assert_eq!(
            prepare_error_code(&RunnerError::HostPortUnavailable(18_080)),
            HOST_PORT_UNAVAILABLE
        );
        assert_eq!(
            prepare_error_code(&RunnerError::InvalidRequest),
            "prepare_failed"
        );
    }

    #[test]
    fn private_start_requires_an_exact_complete_setup_binding() {
        let root_generation = "a".repeat(64);
        let header_sha256 = "b".repeat(64);
        let request = v1::StartVmRequest {
            root_generation: "c".repeat(64),
            setup_total_bytes: codewire_vmm_guest_probe::SETUP_HEADER_LEN as u64
                + codewire_vmm_guest_probe::SETUP_ALIGNMENT,
            setup_header_sha256: header_sha256.clone(),
            setup_root_generation: root_generation.clone(),
            ..Default::default()
        };
        let binding = parse_setup_binding(&request).unwrap().unwrap();
        assert_eq!(binding.root_generation().to_string(), root_generation);
        assert_eq!(binding.header_sha256().to_string(), header_sha256);

        let mut incomplete = request.clone();
        incomplete.setup_header_sha256.clear();
        assert_eq!(
            parse_setup_binding(&incomplete).unwrap_err().code(),
            tonic::Code::InvalidArgument
        );

        let mut invalid = request;
        invalid.setup_header_sha256 = "B".repeat(64);
        assert_eq!(
            parse_setup_binding(&invalid).unwrap_err().code(),
            tonic::Code::InvalidArgument
        );
        assert!(
            parse_setup_binding(&v1::StartVmRequest::default())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn private_start_requires_an_exact_non_secret_mesh_attachment() {
        let request = v1::StartVmRequest {
            mesh: Some(v1::MeshAttachment {
                mesh_url: "https://mesh.example.test/base".to_owned(),
                organization_id: "org-test".to_owned(),
                network_id: "network-test".to_owned(),
                node_name: "dev".to_owned(),
                guest_ports: vec![3_000, 8_080],
                auth_source: v1::MeshEnrollmentAuthSource::StandaloneLocal as i32,
            }),
            ..Default::default()
        };
        let attachment = parse_mesh_attachment(&request).unwrap().unwrap();
        assert_eq!(attachment.network_id, "network-test");
        assert_eq!(attachment.guest_ports, vec![3_000, 8_080]);
        assert_eq!(
            attachment.auth_source,
            MeshEnrollmentAuthSource::StandaloneLocal
        );

        let mut noncanonical = request.clone();
        noncanonical.mesh.as_mut().unwrap().guest_ports.reverse();
        assert_eq!(
            parse_mesh_attachment(&noncanonical).unwrap_err().code(),
            tonic::Code::InvalidArgument
        );
        let mut credential_url = request.clone();
        credential_url.mesh.as_mut().unwrap().mesh_url =
            "https://user:secret@mesh.example.test".to_owned();
        assert_eq!(
            parse_mesh_attachment(&credential_url).unwrap_err().code(),
            tonic::Code::InvalidArgument
        );
        let mut unspecified = request;
        unspecified.mesh.as_mut().unwrap().auth_source =
            v1::MeshEnrollmentAuthSource::Unspecified as i32;
        assert_eq!(
            parse_mesh_attachment(&unspecified).unwrap_err().code(),
            tonic::Code::InvalidArgument
        );
        assert!(
            parse_mesh_attachment(&v1::StartVmRequest::default())
                .unwrap()
                .is_none()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn private_start_binds_direct_shares_to_exact_host_identity_and_guest_order() {
        let source = tempfile::tempdir().unwrap();
        let source_path = std::fs::canonicalize(source.path()).unwrap();
        let admitted = crate::direct_share::admit_direct_share(&source_path, &[]).unwrap();
        let identity = admitted.identity();
        let raw = v1::DirectShareAttachment {
            vm_only: Vec::new(),
            source_path: std::os::unix::ffi::OsStrExt::as_bytes(source_path.as_os_str()).to_vec(),
            device_major: identity.device_major(),
            device_minor: identity.device_minor(),
            inode: identity.inode(),
            mount_id: identity.mount_id(),
            owner_uid: identity.owner_uid(),
            filesystem_magic: identity.filesystem_magic(),
            destination: "/workspace/source".to_owned(),
            read_only: true,
        };
        let request = v1::StartVmRequest {
            direct_shares: vec![raw.clone()],
            ..Default::default()
        };
        let parsed = parse_direct_shares(&request).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].mount.tag(), "cw-direct-00");
        assert_eq!(parsed[0].mount.destination(), "/workspace/source");
        assert!(parsed[0].mount.read_only());
        assert!(!format!("{parsed:?}").contains(source_path.to_str().unwrap()));

        let mut invalid = request;
        invalid.direct_shares[0].inode = 0;
        assert_eq!(
            parse_direct_shares(&invalid).unwrap_err().code(),
            tonic::Code::InvalidArgument
        );
        invalid.direct_shares = vec![raw; MAX_DIRECT_SHARES + 1];
        assert_eq!(
            parse_direct_shares(&invalid).unwrap_err().code(),
            tonic::Code::InvalidArgument
        );
    }

    #[test]
    fn skill_snapshot_parser_accepts_only_an_exact_optional_sha256() {
        let digest = Sha256Value::calculate(b"skill-snapshot-plan");
        let request = v1::StartVmRequest {
            skill_snapshot_sha256: digest.to_string(),
            ..Default::default()
        };
        assert_eq!(parse_skill_snapshot(&request).unwrap(), Some(digest));
        assert_eq!(
            parse_skill_snapshot(&v1::StartVmRequest::default()).unwrap(),
            None
        );

        let invalid = v1::StartVmRequest {
            skill_snapshot_sha256: "not-a-sha256".to_owned(),
            ..Default::default()
        };
        assert_eq!(
            parse_skill_snapshot(&invalid).unwrap_err().code(),
            tonic::Code::InvalidArgument
        );
    }

    #[test]
    fn setup_boots_have_a_distinct_bounded_readiness_window() {
        assert_eq!(daemon_ready_timeout(false), DAEMON_READY_TIMEOUT);
        assert_eq!(daemon_ready_timeout(true), SETUP_DAEMON_READY_TIMEOUT);
        assert!(SETUP_DAEMON_READY_TIMEOUT > DAEMON_READY_TIMEOUT);
    }

    #[tokio::test]
    async fn authenticated_guest_progress_stream_is_fixed_port_and_terminal() {
        let temp = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let socket = temp.path().join("hybrid.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
        let vm_id = Uuid::new_v4();
        let generation = 9;
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            assert_eq!(
                read_connect_line(&mut stream).await,
                format!("CONNECT {GUEST_PROGRESS_VSOCK_PORT}\n")
            );
            stream.write_all(b"OK 49152\n").await.unwrap();
            let mut request = [0_u8; codewire_vmm_guest_probe::PROGRESS_REQUEST_LEN];
            stream.read_exact(&mut request).await.unwrap();
            let request = ProgressRequest::decode(&request).unwrap();
            assert_eq!(request.vm_id, vm_id);
            assert_eq!(request.generation, generation);
            for (sequence, stage) in [
                (3, GuestBootStage::RootMounted),
                (8, GuestBootStage::DaemonStarted),
            ] {
                let frame = ProgressFrame {
                    vm_id,
                    generation,
                    sequence,
                    stage,
                }
                .encode(&request.challenge, PROGRESS_TOKEN)
                .unwrap();
                stream.write_all(&frame).await.unwrap();
            }
        });
        let target = progress_target(socket, vm_id, generation);
        let (sender, mut receiver) = mpsc::channel(2);
        stream_guest_progress(target, sender).await.unwrap();
        assert_eq!(
            receiver.recv().await.unwrap(),
            GuestProgressUpdate {
                sequence: 3,
                stage: GuestBootStage::RootMounted,
            }
        );
        assert_eq!(
            receiver.recv().await.unwrap(),
            GuestProgressUpdate {
                sequence: 8,
                stage: GuestBootStage::DaemonStarted,
            }
        );
        assert!(receiver.recv().await.is_none());
        server.await.unwrap();
    }

    #[test]
    fn guest_progress_validator_rejects_replay_regression_and_flood() {
        let temp = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let socket = temp.path().join("hybrid.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
        let target = progress_target(socket, Uuid::new_v4(), 4);
        let challenge = [0x44; PROGRESS_CHALLENGE_LEN];
        let mut validator = GuestProgressValidator::new(&target, challenge);
        let encode = |sequence, stage| {
            ProgressFrame {
                vm_id: target.vm_id,
                generation: target.generation,
                sequence,
                stage,
            }
            .encode(&challenge, target.token.as_str())
            .unwrap()
        };
        validator
            .accept(&encode(3, GuestBootStage::RootMounted))
            .unwrap();
        assert!(matches!(
            validator.accept(&encode(3, GuestBootStage::WorkspacePlanReady)),
            Err(GuestProgressStreamError::InvalidSequence)
        ));
        assert!(matches!(
            validator.accept(&encode(4, GuestBootStage::StateMounted)),
            Err(GuestProgressStreamError::InvalidSequence)
        ));

        let mut flood = GuestProgressValidator::new(&target, challenge);
        for sequence in 1..=MAXIMUM_GUEST_PROGRESS_FRAMES as u64 {
            flood
                .accept(&encode(sequence, GuestBootStage::RootMounted))
                .unwrap();
        }
        assert!(matches!(
            flood.accept(&encode(
                MAXIMUM_GUEST_PROGRESS_FRAMES as u64 + 1,
                GuestBootStage::RootMounted,
            )),
            Err(GuestProgressStreamError::Flood)
        ));
    }

    #[tokio::test]
    async fn runner_events_are_sequenced_and_never_contain_the_one_boot_token() {
        let environment_id = Uuid::new_v4();
        let events = RunnerEvents::new(environment_id, "a".repeat(64), 0);
        let mut receiver = events.subscribe();
        let initial = receiver.borrow_and_update().clone();
        assert_eq!(initial.sequence, 1);
        assert_eq!(
            v1::RunnerStage::try_from(initial.stage).unwrap(),
            v1::RunnerStage::WaitingAdoption
        );
        let update = events
            .publish(
                v1::EnvironmentState::Starting,
                1,
                v1::RunnerStage::GuestInit,
                Some(GuestProgressUpdate {
                    sequence: 5,
                    stage: GuestBootStage::WorkspaceRunning,
                }),
                None,
                None,
            )
            .unwrap();
        receiver.changed().await.unwrap();
        assert_eq!(*receiver.borrow_and_update(), update);
        assert_eq!(update.sequence, 2);
        assert_eq!(update.guest_sequence, 5);
        assert_eq!(update.runner.as_ref().unwrap().error_code, "");
        assert!(!format!("{update:?}").contains(PROGRESS_TOKEN));

        let failed = events
            .publish(
                v1::EnvironmentState::Error,
                1,
                v1::RunnerStage::Error,
                None,
                Some("mesh_ingress_receiver_exit"),
                None,
            )
            .unwrap();
        assert_eq!(
            failed.runner.as_ref().unwrap().error_code,
            "mesh_ingress_receiver_exit"
        );
    }

    #[test]
    fn internal_runner_exit_codes_preserve_the_failed_component() {
        assert_eq!(runner_exit_error_code(ExitClass::StillRunning), None);
        assert_eq!(
            runner_exit_error_code(ExitClass::GuestShutdown),
            Some("guest_shutdown")
        );
        assert_eq!(
            runner_exit_error_code(ExitClass::VmmFailure(Some(1))),
            Some("vmm_exit")
        );
        assert_eq!(
            runner_exit_error_code(ExitClass::DirectShareFailure(Some(7))),
            Some("direct_share_exit")
        );
        assert_eq!(
            runner_exit_error_code(ExitClass::NetworkWorkerFailure(Some(2))),
            Some("network_worker_exit")
        );
        assert_eq!(
            runner_exit_error_code(ExitClass::EgressBrokerFailure(Some(3))),
            Some("egress_broker_exit")
        );
        assert_eq!(
            runner_exit_error_code(ExitClass::IngressForwarderFailure),
            Some("ingress_forwarder_exit")
        );
        assert_eq!(
            runner_exit_error_code(ExitClass::MeshTransportFailure(Some(4))),
            Some("mesh_transport_exit")
        );
        assert_eq!(
            runner_exit_error_code(ExitClass::MeshIngressReceiverFailure),
            Some("mesh_ingress_receiver_exit")
        );
    }
}
