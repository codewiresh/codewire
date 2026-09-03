//! Private per-environment process which owns the live VMM and its one-boot
//! daemon capability. The supervisor may restart and reconnect to this socket;
//! the capability never enters persistent state.

use std::ffi::OsString;
use std::io;
use std::os::unix::ffi::OsStringExt as _;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use futures::Stream;
use rand::{RngCore as _, rngs::OsRng};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::sync::{Mutex, mpsc, oneshot, watch};
use tokio_stream::wrappers::ReceiverStream;
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
use crate::direct_share::{DirectShareIdentity, DirectShareRequest};
use crate::host_port::{HostPortBinding, canonical_host_port_bindings};
use crate::hybrid_vsock::{HybridVsockError, HybridVsockTarget};
use crate::linux::path::PrivateRoot;
use crate::linux::runner::ExitClass;
use crate::mesh_ingress::{MeshAttachment, MeshEnrollmentAuthSource};
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
        Ok(Self {
            inner: EnvironmentRunnerServiceClient::new(channel),
        })
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

    pub async fn prepare_retire(&mut self) -> Result<(), Status> {
        self.inner
            .prepare_retire_runner(v1::PrepareRetireRunnerRequest {})
            .await?;
        Ok(())
    }

    pub async fn daemon_access(&mut self) -> Result<v1::DaemonAccess, Status> {
        Ok(self
            .inner
            .get_daemon_access(v1::GetDaemonAccessRequest {})
            .await?
            .into_inner())
    }
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
    ) -> Result<v1::RunnerEvent, Status> {
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
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |sequence| {
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
        GuestBootStage::WorkspaceFailed => v1::GuestBootStage::WorkspaceFailed,
    }
}

pub async fn serve_runner(config: RunnerEntrypointConfig) -> Result<(), RunnerServiceError> {
    if !config.mesh_data_dir.is_absolute() || !config.platform_config_dir.is_absolute() {
        return Err(RunnerServiceError::Configuration);
    }
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
    let service = RunnerRpc {
        state: Arc::new(Mutex::new(RunnerState {
            environment_id: config.environment_id,
            artifact_generation: config.artifact_generation,
            runner,
            running: None,
            generation,
            state: v1::EnvironmentState::Stopped,
            error_code: None,
            adopted: false,
            mesh_data_dir: config.mesh_data_dir,
            platform_config_dir: config.platform_config_dir,
        })),
        adoption: adoption_tx,
        events,
    };
    let (incoming, socket_identity) = bind_owner_only(&config.socket)?;
    let server = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(EnvironmentRunnerServiceServer::new(service))
            .serve_with_incoming(incoming)
            .await
    });
    let adoption = adoption_rx.recv().await.ok_or(RunnerServiceError::Serve)?;
    clear_parent_death_signal().map_err(|_| RunnerServiceError::Adoption)?;
    let _ = adoption.acknowledged.send(());
    let result = server
        .await
        .map_err(|_| RunnerServiceError::Serve)?
        .map_err(|_| RunnerServiceError::Serve);
    remove_bound_socket(&config.socket, &socket_identity)?;
    result
}

struct RunnerState {
    environment_id: Uuid,
    artifact_generation: String,
    runner: CloudHypervisorRunner,
    running: Option<RunningVm>,
    generation: u64,
    state: v1::EnvironmentState,
    error_code: Option<&'static str>,
    adopted: bool,
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
        }
    }

    async fn observe_exit(&mut self) -> Result<(), RunnerError> {
        self.observe_exit_with_reason().await.map(drop)
    }

    async fn observe_exit_with_reason(&mut self) -> Result<Option<&'static str>, RunnerError> {
        let Some(running) = self.running.as_mut() else {
            return Ok(None);
        };
        let exit = running.observe_exit().await?;
        let error_code = runner_exit_error_code(exit);
        match exit {
            ExitClass::StillRunning => Ok(error_code),
            ExitClass::GuestShutdown => {
                self.running = None;
                self.state = v1::EnvironmentState::Stopped;
                self.error_code = None;
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
        ExitClass::StillRunning | ExitClass::GuestShutdown => None,
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
    events: Arc<RunnerEvents>,
}

struct AdoptionRequest {
    acknowledged: oneshot::Sender<()>,
}

#[tonic::async_trait]
impl EnvironmentRunnerService for RunnerRpc {
    async fn adopt_runner(
        &self,
        request: Request<v1::AdoptRunnerRequest>,
    ) -> Result<Response<v1::RunnerInfo>, Status> {
        let requested = parse_environment_id(&request.into_inner().environment_id)?;
        let state = self.state.lock().await;
        if requested != state.environment_id {
            return Err(Status::permission_denied("runner identity mismatch"));
        }
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
        state.adopted = true;
        let info = state.info();
        self.events.publish(
            v1::EnvironmentState::Stopped,
            info.generation,
            v1::RunnerStage::Ready,
            None,
            None,
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
        let mut events = self.events.subscribe();
        let (sender, receiver) = mpsc::channel(RUNNER_WATCH_BUFFER);
        tokio::spawn(async move {
            let initial = events.borrow_and_update().clone();
            if sender.send(Ok(initial)).await.is_err() {
                return;
            }
            while events.changed().await.is_ok() {
                let event = events.borrow_and_update().clone();
                if sender.send(Ok(event)).await.is_err() {
                    return;
                }
            }
        });
        Ok(Response::new(Box::pin(ReceiverStream::new(receiver))))
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
        let host_ports = parse_host_ports(&request)?;
        let mesh = parse_mesh_attachment(&request)?;
        let direct_shares = parse_direct_shares(&request)?;
        let daemon_ready_timeout = daemon_ready_timeout(setup.is_some());
        let mut state = self.state.lock().await;
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
        )?;
        let prepared = match state
            .runner
            .prepare(CreateVmRequest {
                vm_id: environment_id,
                generation: request.generation,
                vsock_cid: request.vsock_cid,
                daemon_vsock_port: request.daemon_vsock_port,
                state_disk_bytes: request.state_disk_bytes,
                root_generation: request.root_generation,
                root_disk_bytes: request.root_disk_bytes,
                vcpus,
                memory_mib: request.memory_mib,
                setup,
                host_ports,
                mesh,
                direct_shares,
            })
            .await
        {
            Ok(prepared) => prepared,
            Err(error) => {
                state.state = v1::EnvironmentState::Error;
                state.error_code = Some("prepare_failed");
                self.events.publish(
                    v1::EnvironmentState::Error,
                    request.generation,
                    v1::RunnerStage::Error,
                    None,
                    Some("prepare_failed"),
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
        )?;
        let mut running = match state.runner.start(prepared).await {
            Ok(running) => running,
            Err(error) => {
                state.state = v1::EnvironmentState::Error;
                state.error_code = Some("vmm_start_failed");
                self.events.publish(
                    v1::EnvironmentState::Error,
                    request.generation,
                    v1::RunnerStage::Error,
                    None,
                    Some("vmm_start_failed"),
                )?;
                return Err(map_start_error(error));
            }
        };
        let worker_executable = std::env::current_exe()
            .ok()
            .and_then(|path| std::fs::canonicalize(path).ok())
            .ok_or(());
        let worker_executable = match worker_executable {
            Ok(executable) => executable,
            Err(()) => {
                let _ = running.stop().await;
                state.state = v1::EnvironmentState::Error;
                state.error_code = Some("network_worker_failed");
                self.events.publish(
                    v1::EnvironmentState::Error,
                    request.generation,
                    v1::RunnerStage::Error,
                    None,
                    Some("network_worker_failed"),
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
            let _ = running.stop().await;
            let error_code = network_start_error_code(&error);
            state.state = v1::EnvironmentState::Error;
            state.error_code = Some(error_code);
            self.events.publish(
                v1::EnvironmentState::Error,
                request.generation,
                v1::RunnerStage::Error,
                None,
                Some(error_code),
            )?;
            return Err(map_start_error(error));
        }
        self.events.publish(
            v1::EnvironmentState::Starting,
            request.generation,
            v1::RunnerStage::WaitingGuest,
            None,
            None,
        )?;
        if let Err(error) =
            wait_for_guest_daemon(&mut running, daemon_ready_timeout, &self.events).await
        {
            let _ = running.stop().await;
            state.state = v1::EnvironmentState::Error;
            state.error_code = Some("guest_start_failed");
            self.events.publish(
                v1::EnvironmentState::Error,
                request.generation,
                v1::RunnerStage::Error,
                None,
                Some("guest_start_failed"),
            )?;
            return Err(error);
        }
        if running.discard_one_boot_inputs().is_err() {
            let _ = running.stop().await;
            state.state = v1::EnvironmentState::Error;
            state.error_code = Some("input_cleanup_failed");
            self.events.publish(
                v1::EnvironmentState::Error,
                request.generation,
                v1::RunnerStage::Error,
                None,
                Some("input_cleanup_failed"),
            )?;
            return Err(Status::internal("one-boot guest input cleanup failed"));
        }
        state.generation = request.generation;
        state.state = v1::EnvironmentState::Running;
        state.error_code = None;
        state.running = Some(running);
        self.events.publish(
            v1::EnvironmentState::Running,
            request.generation,
            v1::RunnerStage::DaemonReady,
            None,
            None,
        )?;
        Ok(Response::new(state.info()))
    }

    async fn stop_vm(
        &self,
        _request: Request<v1::StopVmRequest>,
    ) -> Result<Response<v1::RunnerInfo>, Status> {
        let mut state = self.state.lock().await;
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
        )?;
        Ok(Response::new(state.info()))
    }

    async fn prepare_retire_runner(
        &self,
        _request: Request<v1::PrepareRetireRunnerRequest>,
    ) -> Result<Response<v1::PrepareRetireRunnerResponse>, Status> {
        let mut state = self.state.lock().await;
        self.events.publish(
            state.state,
            state.generation,
            v1::RunnerStage::Retiring,
            None,
            None,
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
        )?;
        Ok(Response::new(v1::PrepareRetireRunnerResponse {}))
    }

    async fn grow_state_disk(
        &self,
        request: Request<v1::GrowStateDiskRequest>,
    ) -> Result<Response<v1::GrowStateDiskResponse>, Status> {
        let request = request.into_inner();
        let environment_id = parse_environment_id(&request.environment_id)?;
        let mut state = self.state.lock().await;
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
        )?;
        Ok(Response::new(v1::GrowStateDiskResponse { disk_bytes }))
    }

    async fn get_daemon_access(
        &self,
        _request: Request<v1::GetDaemonAccessRequest>,
    ) -> Result<Response<v1::DaemonAccess>, Status> {
        let mut state = self.state.lock().await;
        state
            .observe_exit()
            .await
            .map_err(|_| Status::internal("observe VMM state failed"))?;
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
}

fn parse_environment_id(value: &str) -> Result<Uuid, Status> {
    let id =
        Uuid::parse_str(value).map_err(|_| Status::invalid_argument("invalid environment ID"))?;
    if id.is_nil() {
        return Err(Status::invalid_argument("invalid environment ID"));
    }
    Ok(id)
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

fn parse_host_ports(request: &v1::StartVmRequest) -> Result<Vec<HostPortBinding>, Status> {
    let provided = request
        .host_ports
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

fn map_start_error(error: RunnerError) -> Status {
    Status::failed_precondition(error.to_string())
}

fn network_start_error_code(error: &RunnerError) -> &'static str {
    match error {
        RunnerError::InvalidNetworkWorker => "network_worker_invalid",
        RunnerError::NetworkWorkerSpawn => "network_worker_spawn",
        RunnerError::NetworkWorkerStartTimeout => "network_worker_start_timeout",
        RunnerError::NetworkWorkerBootstrap => "network_worker_bootstrap",
        RunnerError::NetworkWorkerStartup(failure) => failure.runner_error_code(),
        RunnerError::NetworkWorkerWait => "network_worker_wait",
        RunnerError::NetworkWorkerKillTimeout => "network_worker_kill_timeout",
        RunnerError::HostPortUnavailable(_) => "host_port_unavailable",
        RunnerError::IngressControl => "ingress_forwarder_start",
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

async fn wait_for_guest_daemon(
    running: &mut RunningVm,
    timeout: std::time::Duration,
    events: &RunnerEvents,
) -> Result<(), Status> {
    let target = GuestProgressTarget::from_running(running);
    let generation = running.generation();
    let (progress_tx, mut progress_rx) = mpsc::channel(RUNNER_WATCH_BUFFER);
    let mut progress_task = tokio::spawn(stream_guest_progress(target, progress_tx));
    let mut progress_joined = false;
    let result = tokio::time::timeout(timeout, async {
        let mut progress_open = true;
        let mut progress_ready = false;
        let mut daemon_ready = false;
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
                        )?;
                        if progress.stage.is_failure() {
                            return Err(Status::failed_precondition(
                                "authenticated guest initialization failed",
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
                                return Err(Status::unavailable(
                                    "guest progress ended before daemon startup",
                                ));
                            }
                            Ok(Err(_)) | Err(_) => {
                                return Err(Status::failed_precondition(
                                    "guest progress validation failed",
                                ));
                            }
                        }
                    }
                },
                _ = tokio::time::sleep(DAEMON_RETRY_DELAY) => {
                    match running
                        .observe_exit()
                        .await
                        .map_err(|error| Status::internal(error.to_string()))?
                    {
                        ExitClass::StillRunning => {}
                        ExitClass::GuestShutdown => {
                            return Err(Status::unavailable(
                                "guest shut down before daemon readiness",
                            ));
                        }
                        ExitClass::VmmFailure(code) => {
                            return Err(Status::unavailable(format!(
                                "Cloud Hypervisor exited before guest daemon readiness with status {code:?}"
                            )));
                        }
                        ExitClass::DirectShareFailure(code) => {
                            return Err(Status::unavailable(format!(
                                "isolated direct-share server exited before guest daemon readiness with status {code:?}"
                            )));
                        }
                        ExitClass::NetworkWorkerFailure(code) => {
                            return Err(Status::unavailable(format!(
                                "isolated network worker exited before guest daemon readiness with status {code:?}"
                            )));
                        }
                        ExitClass::EgressBrokerFailure(code) => {
                            return Err(Status::unavailable(format!(
                                "isolated egress broker exited before guest daemon readiness with status {code:?}"
                            )));
                        }
                        ExitClass::IngressForwarderFailure => {
                            return Err(Status::unavailable(
                                "ingress forwarder exited before guest daemon readiness",
                            ));
                        }
                        ExitClass::MeshTransportFailure(code) => {
                            return Err(Status::unavailable(format!(
                                "isolated Mesh transport exited before guest daemon readiness with status {code:?}"
                            )));
                        }
                        ExitClass::MeshIngressReceiverFailure => {
                            return Err(Status::unavailable(
                                "Mesh ingress receiver exited before guest daemon readiness",
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
    .map_err(|_| Status::unavailable("guest daemon readiness timed out"));
    if !progress_joined {
        progress_task.abort();
        let _ = progress_task.await;
    }
    result?
}

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
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use tokio::net::UnixListener;

    use super::*;

    const PROGRESS_TOKEN: &str = "runner-progress-test-token-0123456789abcdef";

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

    #[test]
    fn private_start_binds_direct_shares_to_exact_host_identity_and_guest_order() {
        let source = tempfile::tempdir().unwrap();
        let source_path = std::fs::canonicalize(source.path()).unwrap();
        let admitted = crate::direct_share::admit_direct_share(&source_path, &[]).unwrap();
        let identity = admitted.identity();
        let raw = v1::DirectShareAttachment {
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
    fn setup_boots_have_a_distinct_bounded_readiness_window() {
        assert_eq!(daemon_ready_timeout(false), DAEMON_READY_TIMEOUT);
        assert_eq!(daemon_ready_timeout(true), SETUP_DAEMON_READY_TIMEOUT);
        assert!(SETUP_DAEMON_READY_TIMEOUT > DAEMON_READY_TIMEOUT);
    }

    #[tokio::test]
    async fn authenticated_guest_progress_stream_is_fixed_port_and_terminal() {
        let temp = tempfile::tempdir().unwrap();
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
        let temp = tempfile::tempdir().unwrap();
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
        assert_eq!(runner_exit_error_code(ExitClass::GuestShutdown), None);
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
