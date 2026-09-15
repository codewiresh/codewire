//! First native supervisor: private stopped-state metadata operations only.
//! No runner, credential authority, VM control, or lifecycle replay is enabled.

use std::fs::File;
use std::future::Future;
use std::io;
use std::os::fd::AsRawFd as _;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tokio::sync::{Mutex, oneshot};
use tokio_stream::Stream;
use tonic::{Request, Response, Status};
use uuid::Uuid;

use super::path::{FileIdentity, PathError, PrivateRoot};
use super::process::{BootSessionId, ObservationError};
use super::store::{NativeStore, StoreError};
use crate::control::v1;
use crate::control::v1::local_supervisor_service_server::{
    LocalSupervisorService, LocalSupervisorServiceServer,
};
use crate::supervisor_config::{NativeRuntimeConfig, SupervisorConfigError, supervisor_info};
use crate::supervisor_metadata::valid_environment_name;
use crate::uds::{UdsError, bind_owner_only, remove_bound_socket};

const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

pub async fn serve_supervisor(config: NativeRuntimeConfig) -> Result<(), SupervisorError> {
    // Register termination before any state or listener mutation.
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(SupervisorError::Signal)?;
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
        .map_err(SupervisorError::Signal)?;
    serve_until(config, async move {
        tokio::select! { _ = terminate.recv() => {}, _ = interrupt.recv() => {} }
    })
    .await
}

async fn serve_until(
    config: NativeRuntimeConfig,
    shutdown: impl Future<Output = ()>,
) -> Result<(), SupervisorError> {
    config.validate()?;
    // Creation requires an already-private parent; never discover or repair a
    // default home/credential directory in this explicit-path entrypoint.
    let root = PrivateRoot::create(&config.root)?;
    let singleton = Singleton::acquire(&root)?;
    let boot = Uuid::from_bytes(*BootSessionId::current()?.as_bytes());
    let store = NativeStore::open(root, boot)?;
    let socket = config.supervisor_socket();
    singleton.revalidate()?;
    let (incoming, identity) = bind_owner_only(&socket)?;
    let core = Arc::new(Mutex::new(Core { store, singleton }));
    let closed = Arc::new(AtomicBool::new(false));
    let rpc = SupervisorRpc {
        core: core.clone(),
        info: supervisor_info(&config),
        closed: closed.clone(),
    };
    let (stop_tx, stop_rx) = oneshot::channel::<()>();
    let result = {
        let server = tonic::transport::Server::builder()
            .add_service(LocalSupervisorServiceServer::new(rpc))
            .serve_with_incoming_shutdown(incoming, async {
                let _ = stop_rx.await;
            });
        tokio::pin!(server);
        tokio::pin!(shutdown);
        tokio::select! {
            result = &mut server => result.map_err(SupervisorError::Serve),
            _ = &mut shutdown => {
                closed.store(true, Ordering::Release);
                let _ = stop_tx.send(());
                match tokio::time::timeout(SHUTDOWN_TIMEOUT, &mut server).await {
                    Ok(result) => result.map_err(SupervisorError::Serve),
                    Err(_) => Err(SupervisorError::ShutdownTimeout),
                }
            }
        }
    };
    closed.store(true, Ordering::Release);
    // The singleton is held in the shared core, including by any request still
    // draining after a timeout. Never release it while a store user survives.
    remove_bound_socket(&socket, &identity)?;
    result
}

struct Singleton {
    file: File,
    root: PrivateRoot,
    identity: FileIdentity,
}

impl Singleton {
    fn acquire(root: &PrivateRoot) -> Result<Self, SupervisorError> {
        let file = root.create_regular(Path::new("supervisor.lock"), 0o600, false)?;
        let identity = file.identity().clone();
        let file = file.into_file();
        for attempt in 0..=25 {
            // SAFETY: file is retained for the complete singleton lifetime.
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                let singleton = Self {
                    file,
                    root: PrivateRoot::open(root.path())?,
                    identity,
                };
                singleton.revalidate()?;
                return Ok(singleton);
            }
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted && attempt < 25 {
                continue;
            }
            if error.kind() == io::ErrorKind::WouldBlock {
                if attempt == 25 {
                    return Err(SupervisorError::AlreadyRunning);
                }
                std::thread::sleep(Duration::from_millis(10));
                continue;
            }
            return Err(SupervisorError::Lock(error));
        }
        Err(SupervisorError::AlreadyRunning)
    }

    fn revalidate(&self) -> Result<(), SupervisorError> {
        let named = self.root.open_regular(
            Path::new("supervisor.lock"),
            false,
            Some(0),
            false,
            Some(0o600),
        )?;
        if named.identity() != &self.identity
            || FileIdentity::from_metadata(&self.file.metadata().map_err(SupervisorError::Lock)?)
                != self.identity
        {
            return Err(SupervisorError::LockIdentityChanged);
        }
        Ok(())
    }
}

struct Core {
    store: NativeStore,
    singleton: Singleton,
}

#[derive(Clone)]
struct SupervisorRpc {
    core: Arc<Mutex<Core>>,
    info: v1::SupervisorInfo,
    closed: Arc<AtomicBool>,
}

impl SupervisorRpc {
    fn admit_request(&self) -> Result<(), Status> {
        if self.closed.load(Ordering::Acquire) {
            return Err(Status::unavailable("native supervisor is shutting down"));
        }
        Ok(())
    }

    async fn admitted_core(&self) -> Result<tokio::sync::MutexGuard<'_, Core>, Status> {
        self.admit_request()?;
        let core = self.core.lock().await;
        self.admit_request()?;
        core.singleton
            .revalidate()
            .map_err(|_| Status::unavailable("native supervisor ownership changed"))?;
        Ok(core)
    }
}

#[tonic::async_trait]
impl LocalSupervisorService for SupervisorRpc {
    async fn get_supervisor_info(
        &self,
        _: Request<v1::GetSupervisorInfoRequest>,
    ) -> Result<Response<v1::SupervisorInfo>, Status> {
        let _core = self.admitted_core().await?;
        Ok(Response::new(self.info.clone()))
    }

    async fn list_environments(
        &self,
        _: Request<v1::ListEnvironmentsRequest>,
    ) -> Result<Response<v1::ListEnvironmentsResponse>, Status> {
        let core = self.admitted_core().await?;
        let state = core.store.state().map_err(store_status)?;
        let environments = state
            .environments
            .values()
            .map(|record| record.proto(state.current.as_deref() == Some(record.name.as_str())))
            .collect();
        Ok(Response::new(v1::ListEnvironmentsResponse { environments }))
    }

    async fn get_environment(
        &self,
        request: Request<v1::EnvironmentSelector>,
    ) -> Result<Response<v1::Environment>, Status> {
        let request = request.into_inner();
        validate_name(&request.name)?;
        let core = self.admitted_core().await?;
        let state = core.store.state().map_err(store_status)?;
        let record = state
            .environments
            .get(&request.name)
            .ok_or_else(not_found)?;
        Ok(Response::new(record.proto(
            state.current.as_deref() == Some(record.name.as_str()),
        )))
    }

    async fn select_environment(
        &self,
        request: Request<v1::EnvironmentSelector>,
    ) -> Result<Response<v1::Environment>, Status> {
        let request = request.into_inner();
        parse_non_nil(&request.request_id)?;
        let expected = if request.environment_id.is_empty() {
            None
        } else {
            Some(parse_non_nil(&request.environment_id)?)
        };
        validate_name(&request.name)?;
        let mut core = self.admitted_core().await?;
        let state = core
            .store
            .select(&request.name, expected)
            .map_err(store_status)?;
        let record = state
            .environments
            .get(&request.name)
            .ok_or_else(not_found)?;
        Ok(Response::new(record.proto(true)))
    }

    async fn create_environment(
        &self,
        _: Request<v1::CreateEnvironmentRequest>,
    ) -> Result<Response<v1::Operation>, Status> {
        Err(unsupported())
    }

    async fn list_orphans(
        &self,
        _: Request<v1::ListOrphansRequest>,
    ) -> Result<Response<v1::ListOrphansResponse>, Status> {
        Err(unsupported())
    }

    async fn start_environment(
        &self,
        _: Request<v1::EnvironmentSelector>,
    ) -> Result<Response<v1::Operation>, Status> {
        Err(unsupported())
    }

    async fn stop_environment(
        &self,
        _: Request<v1::EnvironmentSelector>,
    ) -> Result<Response<v1::Operation>, Status> {
        Err(unsupported())
    }

    async fn restart_environment(
        &self,
        _: Request<v1::EnvironmentSelector>,
    ) -> Result<Response<v1::Operation>, Status> {
        Err(unsupported())
    }

    async fn refresh_environment_skills(
        &self,
        _: Request<v1::EnvironmentSelector>,
    ) -> Result<Response<v1::Operation>, Status> {
        Err(unsupported())
    }

    async fn resize_environment(
        &self,
        _: Request<v1::ResizeEnvironmentRequest>,
    ) -> Result<Response<v1::Operation>, Status> {
        Err(unsupported())
    }

    async fn update_environment_sources(
        &self,
        _: Request<v1::UpdateEnvironmentSourcesRequest>,
    ) -> Result<Response<v1::Operation>, Status> {
        Err(unsupported())
    }

    async fn delete_environment(
        &self,
        _: Request<v1::EnvironmentSelector>,
    ) -> Result<Response<v1::Operation>, Status> {
        Err(unsupported())
    }

    async fn get_operation(
        &self,
        _: Request<v1::GetOperationRequest>,
    ) -> Result<Response<v1::Operation>, Status> {
        Err(unsupported())
    }

    async fn ensure_credential_broker(
        &self,
        _: Request<v1::EnvironmentSelector>,
    ) -> Result<Response<v1::CredentialBrokerRuntime>, Status> {
        Err(unsupported())
    }

    async fn get_daemon_access(
        &self,
        _: Request<v1::EnvironmentSelector>,
    ) -> Result<Response<v1::DaemonAccess>, Status> {
        Err(unsupported())
    }

    type WatchOperationStream =
        Pin<Box<dyn Stream<Item = Result<v1::Operation, Status>> + Send + 'static>>;

    async fn watch_operation(
        &self,
        _: Request<v1::WatchOperationRequest>,
    ) -> Result<Response<Self::WatchOperationStream>, Status> {
        Err(unsupported())
    }
}

fn validate_name(name: &str) -> Result<(), Status> {
    if !valid_environment_name(name) {
        return Err(Status::invalid_argument("invalid environment name"));
    }
    Ok(())
}

fn parse_non_nil(value: &str) -> Result<Uuid, Status> {
    Uuid::parse_str(value)
        .ok()
        .filter(|id| !id.is_nil())
        .ok_or_else(|| Status::invalid_argument("invalid native supervisor request"))
}

fn not_found() -> Status {
    Status::not_found("local environment was not found")
}

fn store_status(error: StoreError) -> Status {
    match error {
        StoreError::NotFound => not_found(),
        _ => Status::failed_precondition(
            "native supervisor state is unavailable; retained state requires inspection",
        ),
    }
}

fn unsupported() -> Status {
    Status::unimplemented("native macOS supervisor currently supports stopped-state metadata only")
}

#[derive(Debug, thiserror::Error)]
pub enum SupervisorError {
    #[error("native supervisor is already running")]
    AlreadyRunning,
    #[error("native supervisor singleton identity changed")]
    LockIdentityChanged,
    #[error("native supervisor singleton lock failed: {0}")]
    Lock(#[source] io::Error),
    #[error("register native supervisor termination signal: {0}")]
    Signal(#[source] io::Error),
    #[error("native supervisor shutdown timed out; retain state for inspection")]
    ShutdownTimeout,
    #[error(transparent)]
    Serve(#[from] tonic::transport::Error),
    #[error(transparent)]
    Configuration(#[from] SupervisorConfigError),
    #[error(transparent)]
    Path(#[from] PathError),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Socket(#[from] UdsError),
    #[error(transparent)]
    Observation(#[from] ObservationError),
}

#[cfg(test)]
mod tests;
