//! Shared native-supervisor requests and durable operation following.
//!
//! Connection admission checks socket identity, owner UID and the exact protocol.
//! Only configuration-aware callers additionally bind an expected digest. None
//! of these checks is process adoption. Linux also pins the supervisor's
//! socket-derived process birth; Darwin admits the owner-only socket.

use std::path::Path;
use std::time::Duration;

use tonic::Status;
use uuid::Uuid;

use crate::control::v1;
use crate::control::v1::local_supervisor_service_client::LocalSupervisorServiceClient;
use crate::host::supervisor_peer::SupervisorPeerPin;
use crate::supervisor_config::NativeRuntimeConfig;
use crate::supervisor_config::{SupervisorConfigError, admit_supervisor_info};
pub use crate::uds::UdsError;
use crate::uds::{capture_supervisor_peer, connect_supervisor_peer};
use std::sync::Arc;

const SUPERVISOR_INFO_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Clone)]
pub struct NativeSupervisorClient {
    inner: LocalSupervisorServiceClient<tonic::transport::Channel>,
    pub(crate) peer_pin: Arc<SupervisorPeerPin>,
    pub(crate) expected_configuration_digest: [u8; 32],
    pub(crate) reconnect_enabled: bool,
}

impl NativeSupervisorClient {
    #[cfg(test)]
    pub(crate) fn into_rpc_client_for_test(
        self,
    ) -> LocalSupervisorServiceClient<tonic::transport::Channel> {
        // The source-transition regression must submit and disconnect
        // before following completion. Keep this escape hatch test-only.
        self.inner
    }

    pub(crate) async fn connect_admitted(
        socket: &Path,
        expected_configuration_digest: Option<[u8; 32]>,
    ) -> Result<Self, SupervisorClientError> {
        let pin = capture_supervisor_peer(socket, None).await?;
        Self::connect_pinned(pin, expected_configuration_digest, false).await
    }

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

    pub(crate) fn supervisor_peer_pin(&self) -> Arc<SupervisorPeerPin> {
        self.peer_pin.clone()
    }
    pub async fn create(
        &mut self,
        request: v1::CreateEnvironmentRequest,
    ) -> Result<v1::Environment, Status> {
        self.create_observed(request, &mut |_| {}).await
    }

    /// Create, reporting the lifecycle operation and each of its non-terminal
    /// updates to `observe` as the supervisor publishes them.
    pub async fn create_observed(
        &mut self,
        request: v1::CreateEnvironmentRequest,
        observe: &mut (dyn FnMut(&v1::Operation) + Send),
    ) -> Result<v1::Environment, Status> {
        let name = request.name.clone();
        let operation = match self.inner.create_environment(request).await {
            Ok(response) => response.into_inner(),
            Err(status) if status.code() == tonic::Code::AlreadyExists => {
                return Err(Status::already_exists(format!(
                    "{} (remove it with `cw env --local rm {name}` or choose another --name)",
                    status.message()
                )));
            }
            Err(status) => return Err(status),
        };
        match self
            .follow_environment_operation(operation, &name, observe)
            .await
        {
            Err(failure) if failure.code() == tonic::Code::FailedPrecondition => {
                Err(self.with_create_cleanup_outcome(failure, &name).await)
            }
            outcome => outcome,
        }
    }

    /// A failed create removes what it recorded (#2491). Reading the
    /// environment waits for that rollback, so the message says only what
    /// is known: removed, kept, or unknown.
    async fn with_create_cleanup_outcome(&mut self, failure: Status, name: &str) -> Status {
        let outcome = match self.get(name).await {
            Err(status) if status.code() == tonic::Code::NotFound => {
                " Nothing was kept.".to_owned()
            }
            Ok(_) => format!(
                " The failed environment could not be removed; run `cw env --local rm {name}`."
            ),
            Err(_) => format!(
                " Whether the failed environment was removed is unknown; check `cw env --local list` and remove {name} if it is listed."
            ),
        };
        Status::new(failure.code(), format!("{}{outcome}", failure.message()))
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
        self.start_observed(name, &mut |_| {}).await
    }

    /// Start, reporting the lifecycle operation's progress to `observe`.
    pub async fn start_observed(
        &mut self,
        name: &str,
        observe: &mut (dyn FnMut(&v1::Operation) + Send),
    ) -> Result<v1::Environment, Status> {
        let operation = self
            .inner
            .start_environment(mutation_selector(name))
            .await?
            .into_inner();
        self.follow_environment_operation(operation, name, observe)
            .await
    }

    pub async fn stop(&mut self, name: &str) -> Result<v1::Environment, Status> {
        let operation = self
            .inner
            .stop_environment(mutation_selector(name))
            .await?
            .into_inner();
        self.follow_environment_operation(operation, name, &mut |_| {})
            .await
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
        self.follow_environment_operation(operation, name, &mut |_| {})
            .await
    }

    pub async fn refresh_skills(&mut self, name: &str) -> Result<v1::Environment, Status> {
        let operation = self
            .inner
            .refresh_environment_skills(mutation_selector(name))
            .await?
            .into_inner();
        self.follow_environment_operation(operation, name, &mut |_| {})
            .await
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
        self.follow_environment_operation(operation, name, &mut |_| {})
            .await
    }

    /// Publish `add` and withdraw `remove` (host ports), waiting for the
    /// running VM to change or, when stopped, for the record.
    pub async fn update_host_ports(
        &mut self,
        name: &str,
        add: Vec<v1::HostPortBinding>,
        remove: Vec<u32>,
    ) -> Result<v1::Environment, Status> {
        let operation = self
            .inner
            .update_host_ports(v1::UpdateHostPortsRequest {
                name: name.to_owned(),
                request_id: Uuid::new_v4().to_string(),
                environment_id: String::new(),
                add,
                remove,
            })
            .await?
            .into_inner();
        self.follow_environment_operation(operation, name, &mut |_| {})
            .await
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
        self.follow_operation(operation, &mut |_| {}).await
    }

    pub async fn delete(&mut self, name: &str) -> Result<v1::DeleteEnvironmentResponse, Status> {
        let operation = self
            .inner
            .delete_environment(mutation_selector(name))
            .await?
            .into_inner();
        let operation = self.follow_operation(operation, &mut |_| {}).await?;
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

    async fn runtime_client(
        &self,
    ) -> Result<
        v1::linux_cw_runtime_service_client::LinuxCwRuntimeServiceClient<tonic::transport::Channel>,
        Status,
    > {
        // Every connection keeps the original socket-derived pidfd/image pin.
        // Refusal cannot fall back to spawn, adoption or mutation replay.
        let channel = connect_supervisor_peer(self.peer_pin.clone())
            .await
            .map_err(|_| Status::failed_precondition("retained native supervisor changed"))?;
        let mut supervisor = LocalSupervisorServiceClient::new(channel.clone());
        query_supervisor_info(&mut supervisor, Some(self.expected_configuration_digest))
            .await
            .map_err(|_| {
                Status::failed_precondition(
                    "native runtime update requires exact Linux supervisor protocol9",
                )
            })?;
        Ok(v1::linux_cw_runtime_service_client::LinuxCwRuntimeServiceClient::new(channel))
    }

    pub async fn runtime_resolve(&self, selector: &str) -> Result<String, Status> {
        let resolved = self
            .runtime_client()
            .await?
            .resolve(v1::LinuxCwRuntimeSelector {
                selector: selector.to_owned(),
            })
            .await?
            .into_inner();
        let id = Uuid::parse_str(&resolved.environment_id)
            .ok()
            .filter(|id| !id.is_nil() && id.to_string() == resolved.environment_id)
            .ok_or_else(|| Status::failed_precondition("invalid resolved runtime environment"))?;
        if Uuid::parse_str(selector).is_ok_and(|selected| selected != id) {
            return Err(Status::failed_precondition(
                "runtime environment UUID changed",
            ));
        }
        Ok(resolved.environment_id)
    }

    pub async fn runtime_info(
        &self,
        environment_id: &str,
    ) -> Result<v1::LinuxCwRuntimeStatus, Status> {
        self.runtime_client()
            .await?
            .info(v1::LinuxCwRuntimeQuery {
                environment_id: environment_id.to_owned(),
                request_id: String::new(),
            })
            .await
            .map(|response| response.into_inner())
    }
    pub async fn runtime_update(
        &self,
        request: v1::LinuxCwRuntimeMutation,
    ) -> Result<v1::LinuxCwRuntimeStatus, Status> {
        self.runtime_client()
            .await?
            .update(request)
            .await
            .map(|response| response.into_inner())
    }
    pub async fn runtime_rollback(
        &self,
        request: v1::LinuxCwRuntimeMutation,
    ) -> Result<v1::LinuxCwRuntimeStatus, Status> {
        self.runtime_client()
            .await?
            .rollback(request)
            .await
            .map(|response| response.into_inner())
    }
    pub async fn runtime_observe(
        &self,
        environment_id: &str,
        request_id: &str,
    ) -> Result<v1::LinuxCwRuntimeStatus, Status> {
        self.runtime_client()
            .await?
            .observe(v1::LinuxCwRuntimeQuery {
                environment_id: environment_id.to_owned(),
                request_id: request_id.to_owned(),
            })
            .await
            .map(|response| response.into_inner())
    }
    pub async fn runtime_cancel(
        &self,
        environment_id: &str,
        request_id: &str,
    ) -> Result<v1::LinuxCwRuntimeStatus, Status> {
        self.runtime_client()
            .await?
            .cancel(v1::LinuxCwRuntimeQuery {
                environment_id: environment_id.to_owned(),
                request_id: request_id.to_owned(),
            })
            .await
            .map(|response| response.into_inner())
    }

    async fn follow_environment_operation(
        &mut self,
        operation: v1::Operation,
        name: &str,
        observe: &mut (dyn FnMut(&v1::Operation) + Send),
    ) -> Result<v1::Environment, Status> {
        self.follow_operation(operation, observe).await?;
        self.get(name).await
    }

    async fn follow_operation(
        &mut self,
        operation: v1::Operation,
        observe: &mut (dyn FnMut(&v1::Operation) + Send),
    ) -> Result<v1::Operation, Status> {
        let operation_id = operation.operation_id.clone();
        if operation_terminal(&operation)
            .map_err(|failure| operation_watch_failure(&operation_id, failure))?
        {
            return operation_outcome(operation);
        }
        observe(&operation);
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
                            Ok(Some(operation)) => observe(&operation),
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
                "local lifecycle operation {} failed: {error_code}{}",
                operation.operation_id,
                operation_error_hint(error_code)
            )))
        }
        _ => Err(Status::internal(
            "local lifecycle operation is not terminal",
        )),
    }
}

/// A plain-language reason for an operation error code, where the code alone
/// does not tell the user what to change.
fn operation_error_hint(error_code: &str) -> &'static str {
    match error_code {
        "create_guest_docker_tooling_missing" => {
            " (the image has no Docker tooling; create with --no-docker or choose an image that includes Docker)"
        }
        "delete_failed" | "delete_interrupted" => {
            " (nothing was removed and the environment was kept; see cw env info, then run cw env rm again)"
        }
        "create_direct_share_changed" | "start_direct_share_changed" => {
            " (a direct-mount source directory was moved, removed or replaced since it was admitted; put the original directory back at its path, or remove and recreate the environment)"
        }
        "create_host_port_unavailable" => {
            " (a host port this environment publishes on 127.0.0.1 is in use by another program or local environment; stop it, or change host_port in codewire.yaml)"
        }
        "start_host_port_unavailable" => {
            " (a host port this environment publishes on 127.0.0.1 is in use by another program or local environment; `cw env --local port ls` lists its ports: stop that program, or withdraw the port with `cw env --local port rm` and publish another)"
        }
        "host_port_unavailable" => {
            " (the host port is in use on 127.0.0.1 by another program or local environment; choose another with --host-port)"
        }
        #[cfg(target_os = "macos")]
        "create_registry_platform" => {
            " (the image has no linux/arm64 variant; macOS local environments run arm64 Linux, so pass --image with a multi-architecture or arm64 image, such as node:22-bookworm or ubuntu:24.04)"
        }
        #[cfg(not(target_os = "macos"))]
        "create_registry_platform" => {
            " (the image has no variant for this host's architecture; pass --image with one that has)"
        }
        "create_name_taken" => {
            " (an environment with this name already exists; remove it with cw env --local rm NAME or choose another --name)"
        }
        "create_interrupted" => {
            " (the local supervisor stopped during the create; create it again)"
        }
        #[cfg(target_os = "macos")]
        "create_vz_helper_missing" => {
            " (the Virtualization.framework helper named by the local VM artifact lock is missing; install the signed codewire-vz-runner at that path)"
        }
        #[cfg(target_os = "macos")]
        "create_vz_helper_unentitled" => {
            " (the Virtualization.framework helper is not signed with the com.apple.security.virtualization entitlement; sign it with codesign --entitlements and update its artifact lock entry)"
        }
        _ => "",
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
