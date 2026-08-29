//! Private per-environment process which owns the live VMM and its one-boot
//! daemon capability. The supervisor may restart and reconnect to this socket;
//! the capability never enters persistent state.

use std::path::PathBuf;
use std::sync::Arc;

use tokio::sync::{Mutex, mpsc, oneshot};
use tonic::{Request, Response, Status};
use uuid::Uuid;

use crate::control::v1;
use crate::control::v1::environment_runner_service_client::EnvironmentRunnerServiceClient;
use crate::control::v1::environment_runner_service_server::{
    EnvironmentRunnerService, EnvironmentRunnerServiceServer,
};
use crate::linux::runner::ExitClass;
use crate::uds::{UdsError, bind_owner_only, connect_owner_only, remove_bound_socket};
use crate::{CloudHypervisorRunner, CreateVmRequest, RunnerConfig, RunnerError, RunningVm};

const DAEMON_READY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);
const DAEMON_RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(50);

#[derive(Debug, Clone)]
pub struct RunnerEntrypointConfig {
    pub environment_id: Uuid,
    pub socket: PathBuf,
    pub engine_state_root: PathBuf,
    pub artifact_root: PathBuf,
    pub artifact_lock: PathBuf,
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

    pub async fn start(&mut self, request: v1::StartVmRequest) -> Result<v1::RunnerInfo, Status> {
        Ok(self.inner.start_vm(request).await?.into_inner())
    }

    pub async fn stop(&mut self) -> Result<v1::RunnerInfo, Status> {
        Ok(self.inner.stop_vm(v1::StopVmRequest {}).await?.into_inner())
    }

    pub async fn delete(&mut self) -> Result<(), Status> {
        self.inner.delete_vm(v1::DeleteVmRequest {}).await?;
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

pub async fn serve_runner(config: RunnerEntrypointConfig) -> Result<(), RunnerServiceError> {
    let runner = CloudHypervisorRunner::new(RunnerConfig {
        state_root: config.engine_state_root,
        artifact_root: config.artifact_root,
        artifact_lock: config.artifact_lock,
    })
    .await?;
    // If a prior runner died, Cloud Hypervisor received PDEATHSIG. Reconcile
    // the exact persisted process identity anyway before this runner accepts
    // lifecycle requests; no orphan is ever adopted without a fresh token.
    runner
        .terminate_tracked_for_cleanup(config.environment_id)
        .await?;
    let (adoption_tx, mut adoption_rx) = mpsc::channel::<AdoptionRequest>(1);
    let service = RunnerRpc {
        state: Arc::new(Mutex::new(RunnerState {
            environment_id: config.environment_id,
            runner,
            running: None,
            generation: 0,
            state: v1::EnvironmentState::Stopped,
            adopted: false,
        })),
        adoption: adoption_tx,
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
    runner: CloudHypervisorRunner,
    running: Option<RunningVm>,
    generation: u64,
    state: v1::EnvironmentState,
    adopted: bool,
}

impl RunnerState {
    fn info(&self) -> v1::RunnerInfo {
        v1::RunnerInfo {
            environment_id: self.environment_id.to_string(),
            state: self.state as i32,
            generation: self.generation,
        }
    }

    fn observe_exit(&mut self) -> Result<(), RunnerError> {
        let Some(running) = self.running.as_mut() else {
            return Ok(());
        };
        match running.try_exit()? {
            ExitClass::StillRunning => Ok(()),
            ExitClass::GuestShutdown => {
                self.running = None;
                self.state = v1::EnvironmentState::Stopped;
                Ok(())
            }
            ExitClass::VmmFailure(_) => {
                self.running = None;
                self.state = v1::EnvironmentState::Error;
                Ok(())
            }
        }
    }
}

#[derive(Clone)]
struct RunnerRpc {
    state: Arc<Mutex<RunnerState>>,
    adoption: mpsc::Sender<AdoptionRequest>,
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
        Ok(Response::new(state.info()))
    }

    async fn get_runner_info(
        &self,
        _request: Request<v1::GetRunnerInfoRequest>,
    ) -> Result<Response<v1::RunnerInfo>, Status> {
        let mut state = self.state.lock().await;
        state
            .observe_exit()
            .map_err(|_| Status::internal("observe VMM state failed"))?;
        Ok(Response::new(state.info()))
    }

    async fn start_vm(
        &self,
        request: Request<v1::StartVmRequest>,
    ) -> Result<Response<v1::RunnerInfo>, Status> {
        let request = request.into_inner();
        let environment_id = parse_environment_id(&request.environment_id)?;
        let vcpus = u8::try_from(request.vcpus)
            .map_err(|_| Status::invalid_argument("invalid vCPU count"))?;
        let mut state = self.state.lock().await;
        if !state.adopted {
            return Err(Status::failed_precondition("runner is not adopted"));
        }
        if environment_id != state.environment_id {
            return Err(Status::permission_denied("runner identity mismatch"));
        }
        state
            .observe_exit()
            .map_err(|_| Status::internal("observe VMM state failed"))?;
        if state.running.is_some() {
            return Err(Status::already_exists("environment is already running"));
        }
        state.state = v1::EnvironmentState::Starting;
        let prepared = match state
            .runner
            .prepare(CreateVmRequest {
                vm_id: environment_id,
                generation: request.generation,
                vsock_cid: request.vsock_cid,
                daemon_vsock_port: request.daemon_vsock_port,
                state_disk_bytes: request.state_disk_bytes,
                vcpus,
                memory_mib: request.memory_mib,
            })
            .await
        {
            Ok(prepared) => prepared,
            Err(error) => {
                state.state = v1::EnvironmentState::Error;
                return Err(map_start_error(error));
            }
        };
        let mut running = match state.runner.start(prepared).await {
            Ok(running) => running,
            Err(error) => {
                state.state = v1::EnvironmentState::Error;
                return Err(map_start_error(error));
            }
        };
        if let Err(error) = wait_for_guest_daemon(&mut running).await {
            let _ = running.stop().await;
            state.state = v1::EnvironmentState::Error;
            return Err(error);
        }
        if running.discard_seed().is_err() {
            let _ = running.stop().await;
            state.state = v1::EnvironmentState::Error;
            return Err(Status::internal("one-boot guest seed cleanup failed"));
        }
        state.generation = request.generation;
        state.state = v1::EnvironmentState::Running;
        state.running = Some(running);
        Ok(Response::new(state.info()))
    }

    async fn stop_vm(
        &self,
        _request: Request<v1::StopVmRequest>,
    ) -> Result<Response<v1::RunnerInfo>, Status> {
        let mut state = self.state.lock().await;
        state
            .observe_exit()
            .map_err(|_| Status::internal("observe VMM state failed"))?;
        if let Some(running) = state.running.as_mut() {
            match running
                .stop()
                .await
                .map_err(|_| Status::internal("bounded stop of the owned VMM process failed"))?
            {
                ExitClass::StillRunning => {
                    return Err(Status::internal("owned VMM process is still running"));
                }
                ExitClass::GuestShutdown | ExitClass::VmmFailure(_) => {}
            }
        }
        state.running = None;
        state.state = v1::EnvironmentState::Stopped;
        Ok(Response::new(state.info()))
    }

    async fn delete_vm(
        &self,
        _request: Request<v1::DeleteVmRequest>,
    ) -> Result<Response<v1::DeleteVmResponse>, Status> {
        let mut state = self.state.lock().await;
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
        state
            .runner
            .delete_stopped(environment_id)
            .map_err(|_| Status::internal("workspace disk cleanup failed"))?;
        state.state = v1::EnvironmentState::Stopped;
        Ok(Response::new(v1::DeleteVmResponse {}))
    }

    async fn get_daemon_access(
        &self,
        _request: Request<v1::GetDaemonAccessRequest>,
    ) -> Result<Response<v1::DaemonAccess>, Status> {
        let mut state = self.state.lock().await;
        state
            .observe_exit()
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

fn map_start_error(error: RunnerError) -> Status {
    Status::failed_precondition(error.to_string())
}

async fn wait_for_guest_daemon(running: &mut RunningVm) -> Result<(), Status> {
    tokio::time::timeout(DAEMON_READY_TIMEOUT, async {
        loop {
            match running
                .try_exit()
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
            }
            if let Ok(client) = running.daemon_client().await
                && client.require_ready().await.is_ok()
            {
                return Ok(());
            }
            tokio::time::sleep(DAEMON_RETRY_DELAY).await;
        }
    })
    .await
    .map_err(|_| Status::unavailable("guest daemon readiness timed out"))?
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
    #[error("serve private environment runner failed")]
    Serve,
    #[error("adopt private environment runner failed")]
    Adoption,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn start_failure_preserves_the_actionable_runner_cause() {
        let status = map_start_error(RunnerError::StartTimeout);
        assert_eq!(status.code(), tonic::Code::FailedPrecondition);
        assert_eq!(status.message(), "Cloud Hypervisor startup timed out");
    }
}
