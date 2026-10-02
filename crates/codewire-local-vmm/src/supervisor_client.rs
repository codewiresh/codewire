//! Shared native-supervisor requests and durable operation following.
//!
//! Connection admission checks socket identity, owner UID and the exact protocol.
//! Only configuration-aware callers additionally bind an expected digest. None
//! of these checks is process adoption. Linux startup and restart effects remain
//! in the native supervisor; Darwin can only connect to an existing endpoint.

use std::path::Path;
use std::time::Duration;

use tonic::Status;
use uuid::Uuid;

use crate::control::v1;
use crate::control::v1::local_supervisor_service_client::LocalSupervisorServiceClient;
#[cfg(target_os = "linux")]
use crate::linux::supervisor_peer::SupervisorPeerPin;
#[cfg(target_os = "linux")]
use crate::supervisor_config::NativeRuntimeConfig;
use crate::supervisor_config::{SupervisorConfigError, admit_supervisor_info};
pub use crate::uds::UdsError;
#[cfg(target_os = "macos")]
use crate::uds::connect_owner_only;
#[cfg(target_os = "linux")]
use crate::uds::{capture_supervisor_peer, connect_supervisor_peer};
#[cfg(target_os = "linux")]
use std::sync::Arc;

const SUPERVISOR_INFO_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Clone)]
pub struct NativeSupervisorClient {
    inner: LocalSupervisorServiceClient<tonic::transport::Channel>,
    #[cfg(target_os = "linux")]
    pub(crate) peer_pin: Arc<SupervisorPeerPin>,
    #[cfg(target_os = "linux")]
    pub(crate) expected_configuration_digest: [u8; 32],
    #[cfg(target_os = "linux")]
    pub(crate) reconnect_enabled: bool,
}

impl NativeSupervisorClient {
    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn into_rpc_client_for_test(
        self,
    ) -> LocalSupervisorServiceClient<tonic::transport::Channel> {
        // The Linux source-transition regression must submit and disconnect
        // before following completion. Keep this escape hatch test-only.
        self.inner
    }

    pub(crate) async fn connect_admitted(
        socket: &Path,
        expected_configuration_digest: Option<[u8; 32]>,
    ) -> Result<Self, SupervisorClientError> {
        #[cfg(target_os = "linux")]
        {
            let pin = capture_supervisor_peer(socket, None).await?;
            Self::connect_pinned(pin, expected_configuration_digest, false).await
        }
        #[cfg(target_os = "macos")]
        {
            let channel = connect_owner_only(socket).await?;
            let mut inner = LocalSupervisorServiceClient::new(channel);
            query_supervisor_info(&mut inner, expected_configuration_digest).await?;
            Ok(Self { inner })
        }
    }

    #[cfg(target_os = "linux")]
    pub(crate) async fn connect_configured(
        config: &NativeRuntimeConfig,
    ) -> Result<Self, SupervisorClientError> {
        config.validate()?;
        let pin = capture_supervisor_peer(&config.supervisor_socket(), Some(config)).await?;
        let expected = pin
            .configuration_digest()
            .ok_or(SupervisorConfigError::InvalidConfiguration)?;
        Self::connect_pinned(pin, Some(expected), true).await
    }

    #[cfg(target_os = "linux")]
    pub(crate) async fn connect_pinned(
        peer_pin: Arc<SupervisorPeerPin>,
        expected_configuration_digest: Option<[u8; 32]>,
        reconnect_enabled: bool,
    ) -> Result<Self, SupervisorClientError> {
        let channel = connect_supervisor_peer(peer_pin.clone()).await?;
        let mut inner = LocalSupervisorServiceClient::new(channel);
        let expected_configuration_digest =
            query_supervisor_info(&mut inner, expected_configuration_digest).await?;
        Ok(Self {
            inner,
            peer_pin,
            expected_configuration_digest,
            reconnect_enabled,
        })
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn supervisor_peer_pin(&self) -> Arc<SupervisorPeerPin> {
        self.peer_pin.clone()
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

    pub async fn managed_runtime(
        &mut self,
        name: &str,
        environment_id: &str,
    ) -> Result<v1::ManagedRuntime, Status> {
        Ok(self
            .inner
            .get_managed_runtime(v1::EnvironmentSelector {
                name: name.to_owned(),
                environment_id: environment_id.to_owned(),
                request_id: String::new(),
            })
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
            self.reconnect_after_watch_failure(&operation_id).await?;
        }
    }
}

pub(crate) fn operation_watch_failure(operation_id: &str, failure: Status) -> Status {
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

pub(crate) fn operation_terminal(operation: &v1::Operation) -> Result<bool, Status> {
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

pub(crate) fn operation_outcome(operation: v1::Operation) -> Result<v1::Operation, Status> {
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

pub(crate) fn read_selector(name: &str) -> v1::EnvironmentSelector {
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

#[cfg(target_os = "macos")]
impl NativeSupervisorClient {
    /// Connect without creating/restarting a supervisor or binding its configuration.
    pub async fn connect(socket: &Path) -> Result<Self, SupervisorClientError> {
        Self::connect_admitted(socket, None).await
    }

    async fn reconnect_after_watch_failure(&mut self, operation_id: &str) -> Result<(), Status> {
        Err(operation_watch_failure(
            operation_id,
            Status::unavailable("local supervisor reconnect is unavailable"),
        ))
    }
}

async fn query_supervisor_info(
    inner: &mut LocalSupervisorServiceClient<tonic::transport::Channel>,
    expected_configuration_digest: Option<[u8; 32]>,
) -> Result<[u8; 32], SupervisorClientError> {
    let info = tokio::time::timeout(
        SUPERVISOR_INFO_TIMEOUT,
        inner.get_supervisor_info(v1::GetSupervisorInfoRequest {}),
    )
    .await
    .map_err(|_| SupervisorClientError::SupervisorInfoUnavailable)?
    .map_err(supervisor_info_rpc_error)?
    .into_inner();
    admit_supervisor_info(&info, expected_configuration_digest.as_ref())?;
    info.configuration_sha256
        .as_slice()
        .try_into()
        .map_err(|_| SupervisorConfigError::InvalidSupervisorInfo.into())
}

fn supervisor_info_rpc_error(status: Status) -> SupervisorClientError {
    if status.code() == tonic::Code::Unimplemented {
        SupervisorClientError::SupervisorProtocolUnavailable
    } else {
        SupervisorClientError::SupervisorInfoUnavailable
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SupervisorClientError {
    #[error(transparent)]
    Uds(#[from] UdsError),
    #[error(transparent)]
    Configuration(#[from] SupervisorConfigError),
    #[error("the running native supervisor does not implement the required compatibility protocol")]
    SupervisorProtocolUnavailable,
    #[error("query running native supervisor compatibility failed")]
    SupervisorInfoUnavailable,
}

#[cfg(test)]
mod tests;
