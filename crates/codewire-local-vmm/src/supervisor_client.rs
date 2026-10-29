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
use crate::supervisor_config::{SupervisorConfigError, SupervisorFeature, admit_supervisor_info};
pub use crate::uds::{SupervisorRefusal, UdsError};
use crate::uds::{capture_supervisor_peer, connect_supervisor_peer};
use std::sync::Arc;

const SUPERVISOR_INFO_TIMEOUT: Duration = Duration::from_secs(3);
/// How long a failed create waits for its rollback delete to remove the
/// environment before it reports the environment as kept (#3329).
#[cfg(not(test))]
const CREATE_ROLLBACK_WAIT: Duration = Duration::from_secs(20);
#[cfg(test)]
const CREATE_ROLLBACK_WAIT: Duration = Duration::from_millis(500);
const CREATE_ROLLBACK_POLL: Duration = Duration::from_millis(100);

#[derive(Clone)]
pub struct NativeSupervisorClient {
    inner: LocalSupervisorServiceClient<tonic::transport::Channel>,
    pub(crate) peer_pin: Arc<SupervisorPeerPin>,
    pub(crate) expected_configuration_digest: [u8; 32],
    pub(crate) reconnect_enabled: bool,
    /// The admitted supervisor's protocol, in the supported range.
    protocol: u32,
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

    /// Admit the supervisor at `socket` for exactly this configuration: this
    /// root's socket, or the root's own socket a supervisor from before #2735
    /// listens on.
    pub(crate) async fn connect_configured_at(
        socket: &Path,
        config: &NativeRuntimeConfig,
    ) -> Result<Self, SupervisorClientError> {
        config.validate()?;
        let pin = capture_supervisor_peer(socket, Some(config)).await?;
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
        let (expected_configuration_digest, protocol) =
            query_supervisor_info(&mut inner, expected_configuration_digest).await?;
        Ok(Self {
            inner,
            peer_pin,
            expected_configuration_digest,
            reconnect_enabled,
            protocol,
        })
    }

    /// The protocol of the supervisor this client admitted. One older than
    /// this cw's still serves its VMs after a cw update.
    pub fn protocol(&self) -> u32 {
        self.protocol
    }

    /// Whether the admitted supervisor has `feature`.
    pub fn supports(&self, feature: SupervisorFeature) -> bool {
        self.protocol >= feature.since()
    }

    /// Ask this older supervisor to hand the state root to this cw's and
    /// exit (protocol 12 on, `SupervisorFeature::Retire`). It refuses while
    /// any environment may still run a VM.
    pub(crate) async fn retire(&mut self, successor_protocol: u32) -> Result<(), Status> {
        self.inner
            .retire_supervisor(v1::RetireSupervisorRequest { successor_protocol })
            .await?;
        Ok(())
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
                    "{} (remove it with `cw --local rm {name}` or choose another --name)",
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

    /// A failed create removes what it recorded (#2491); the image layers it
    /// downloaded stay as download cache (#2952). The supervisor publishes
    /// the failure as it begins that rollback delete, so the environment can
    /// still be listed for a moment: read it until it is gone, for a bounded
    /// time, so the message says only what is known: removed, kept, or
    /// unknown (#3329).
    async fn with_create_cleanup_outcome(&mut self, failure: Status, name: &str) -> Status {
        let deadline = tokio::time::Instant::now() + CREATE_ROLLBACK_WAIT;
        let outcome = loop {
            match self.get(name).await {
                Err(status) if status.code() == tonic::Code::NotFound => {
                    break " No environment was kept; the image layers it downloaded stay cached, so a retry resumes.".to_owned();
                }
                Ok(_) if tokio::time::Instant::now() < deadline => {
                    tokio::time::sleep(CREATE_ROLLBACK_POLL).await;
                }
                Ok(_) => {
                    break format!(
                        " The failed environment could not be removed; run `cw --local rm {name}`."
                    );
                }
                Err(_) => {
                    break format!(
                        " Whether the failed environment was removed is unknown; check `cw --local ls` and remove {name} if it is listed."
                    );
                }
            }
        };
        with_outcome(&failure, &outcome)
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

    /// Fails with `Unimplemented` before contacting a supervisor older than
    /// protocol 16, which has no network policies.
    fn require_network_policies(&self) -> Result<(), Status> {
        if self.supports(SupervisorFeature::NetworkPolicies) {
            Ok(())
        } else {
            Err(Status::unimplemented(
                "your local VMs run on an older cw's supervisor, which has no network policies; `cw upgrade --vms` moves them to this cw once they are idle",
            ))
        }
    }

    pub async fn create_network_policy(
        &mut self,
        request: v1::CreateNetworkPolicyRequest,
    ) -> Result<v1::NetworkPolicy, Status> {
        self.require_network_policies()?;
        Ok(self
            .inner
            .create_network_policy(request)
            .await?
            .into_inner())
    }

    pub async fn list_network_policies(&mut self) -> Result<Vec<v1::NetworkPolicy>, Status> {
        self.require_network_policies()?;
        Ok(self
            .inner
            .list_network_policies(v1::ListNetworkPoliciesRequest {})
            .await?
            .into_inner()
            .policies)
    }

    pub async fn get_network_policy(
        &mut self,
        request: v1::GetNetworkPolicyRequest,
    ) -> Result<v1::NetworkPolicy, Status> {
        self.require_network_policies()?;
        Ok(self.inner.get_network_policy(request).await?.into_inner())
    }

    pub async fn update_network_policy(
        &mut self,
        request: v1::UpdateNetworkPolicyRequest,
    ) -> Result<v1::NetworkPolicy, Status> {
        self.require_network_policies()?;
        Ok(self
            .inner
            .update_network_policy(request)
            .await?
            .into_inner())
    }

    /// Fails before contacting a supervisor older than protocol 17, which
    /// would ignore a selection and enforce `open`.
    pub fn require_network_policy_selection(&self) -> Result<(), Status> {
        if self.supports(SupervisorFeature::NetworkPolicySelection) {
            Ok(())
        } else {
            Err(Status::unimplemented(
                "your local VMs run on an older cw's supervisor, which cannot select a network policy; `cw upgrade --vms` moves them to this cw once they are idle",
            ))
        }
    }

    pub async fn update_environment_network_policy(
        &mut self,
        name: &str,
        network_policy: &str,
    ) -> Result<v1::Environment, Status> {
        self.require_network_policy_selection()?;
        Ok(self
            .inner
            .update_environment_network_policy(v1::UpdateEnvironmentNetworkPolicyRequest {
                name: name.to_owned(),
                network_policy: network_policy.to_owned(),
            })
            .await?
            .into_inner())
    }

    pub async fn delete_network_policy(
        &mut self,
        selector: v1::NetworkPolicySelector,
    ) -> Result<v1::NetworkPolicy, Status> {
        self.require_network_policies()?;
        Ok(self
            .inner
            .delete_network_policy(selector)
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

    /// SSH to a running environment over this owner-only socket (#3025):
    /// `input`'s bytes go to the supervisor's SSH server for the environment
    /// with this UUID, and its replies to `output`, until either side ends
    /// the connection. Supervisors before protocol 15 lack it; check
    /// [`Self::supports`] with [`SupervisorFeature::Ssh`] first. Errors:
    /// NotFound (no such environment), FailedPrecondition (not running),
    /// Unavailable (its daemon is not reachable yet), ResourceExhausted (too
    /// many SSH connections open).
    pub async fn pipe_ssh<R, W>(
        &mut self,
        environment_id: Uuid,
        mut input: R,
        mut output: W,
    ) -> Result<(), Status>
    where
        R: tokio::io::AsyncRead + Unpin + Send + 'static,
        W: tokio::io::AsyncWrite + Unpin,
    {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        use v1::ssh_stream_frame::Frame;

        const FRAME_BYTES: usize = 32 * 1024;
        let (frames, outbound) = tokio::sync::mpsc::channel(8);
        frames
            .send(v1::SshStreamFrame {
                frame: Some(Frame::Open(v1::SshStreamOpen {
                    environment_id: environment_id.to_string(),
                })),
            })
            .await
            .map_err(|_| Status::internal("local SSH stream closed"))?;
        let sender = tokio::spawn(async move {
            let mut buffer = vec![0; FRAME_BYTES];
            loop {
                match input.read(&mut buffer).await {
                    Ok(0) | Err(_) => break,
                    Ok(read) => {
                        let frame = v1::SshStreamFrame {
                            frame: Some(Frame::Data(buffer[..read].to_vec())),
                        };
                        if frames.send(frame).await.is_err() {
                            break;
                        }
                    }
                }
            }
        });
        let mut replies = self
            .inner
            .open_environment_ssh_stream(tokio_stream::wrappers::ReceiverStream::new(outbound))
            .await?
            .into_inner();
        let result = async {
            while let Some(frame) = replies.message().await? {
                if let Some(Frame::Data(bytes)) = frame.frame {
                    output
                        .write_all(&bytes)
                        .await
                        .map_err(|_| Status::cancelled("SSH output closed"))?;
                    output
                        .flush()
                        .await
                        .map_err(|_| Status::cancelled("SSH output closed"))?;
                }
            }
            Ok(())
        }
        .await;
        sender.abort();
        result
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

    /// Fails with `Unimplemented` before contacting a supervisor older than
    /// protocol 19, which has no local disk snapshots.
    pub fn require_local_snapshots(&self) -> Result<(), Status> {
        if self.supports(SupervisorFeature::LocalSnapshots) {
            Ok(())
        } else {
            Err(Status::unimplemented(
                "your local VMs run on an older cw's supervisor, which has no disk snapshots; `cw upgrade --vms` moves them to this cw once they are idle",
            ))
        }
    }

    async fn snapshot_client(
        &self,
    ) -> Result<
        v1::local_snapshot_service_client::LocalSnapshotServiceClient<tonic::transport::Channel>,
        Status,
    > {
        self.require_local_snapshots()?;
        // Every connection keeps the original socket-derived peer pin.
        let channel = connect_supervisor_peer(self.peer_pin.clone())
            .await
            .map_err(|_| Status::failed_precondition("retained native supervisor changed"))?;
        Ok(v1::local_snapshot_service_client::LocalSnapshotServiceClient::new(channel))
    }

    pub async fn create_snapshot(
        &self,
        environment: &str,
        name: &str,
        account: Option<v1::PlatformAccount>,
    ) -> Result<v1::Snapshot, Status> {
        Ok(self
            .snapshot_client()
            .await?
            .create_snapshot(v1::CreateSnapshotRequest {
                environment: environment.to_owned(),
                name: name.to_owned(),
                account,
            })
            .await?
            .into_inner())
    }

    pub async fn list_snapshots(&self) -> Result<Vec<v1::Snapshot>, Status> {
        Ok(self
            .snapshot_client()
            .await?
            .list_snapshots(v1::ListSnapshotsRequest {})
            .await?
            .into_inner()
            .snapshots)
    }

    pub async fn get_snapshot(&self, snapshot: &str) -> Result<v1::Snapshot, Status> {
        Ok(self
            .snapshot_client()
            .await?
            .get_snapshot(v1::SnapshotSelector {
                snapshot: snapshot.to_owned(),
            })
            .await?
            .into_inner())
    }

    pub async fn delete_snapshot(&self, snapshot: &str) -> Result<v1::Snapshot, Status> {
        Ok(self
            .snapshot_client()
            .await?
            .delete_snapshot(v1::SnapshotSelector {
                snapshot: snapshot.to_owned(),
            })
            .await?
            .into_inner())
    }

    /// Fails with `Unimplemented` before contacting a supervisor older than
    /// protocol 20, which has no VM checkpoints.
    pub fn require_local_checkpoints(&self) -> Result<(), Status> {
        if self.supports(SupervisorFeature::LocalCheckpoints) {
            Ok(())
        } else {
            Err(Status::unimplemented(
                "your local VMs run on an older cw's supervisor, which has no VM checkpoints; `cw upgrade --vms` moves them to this cw once they are idle",
            ))
        }
    }

    async fn checkpoint_client(
        &self,
    ) -> Result<
        v1::local_checkpoint_service_client::LocalCheckpointServiceClient<
            tonic::transport::Channel,
        >,
        Status,
    > {
        self.require_local_checkpoints()?;
        // Every connection keeps the original socket-derived peer pin.
        let channel = connect_supervisor_peer(self.peer_pin.clone())
            .await
            .map_err(|_| Status::failed_precondition("retained native supervisor changed"))?;
        Ok(v1::local_checkpoint_service_client::LocalCheckpointServiceClient::new(channel))
    }

    pub async fn create_checkpoint(
        &self,
        environment: &str,
        name: &str,
        account: Option<v1::PlatformAccount>,
    ) -> Result<v1::Checkpoint, Status> {
        Ok(self
            .checkpoint_client()
            .await?
            .create_checkpoint(v1::CreateCheckpointRequest {
                environment: environment.to_owned(),
                name: name.to_owned(),
                account,
            })
            .await?
            .into_inner())
    }

    pub async fn list_checkpoints(&self, environment: &str) -> Result<Vec<v1::Checkpoint>, Status> {
        Ok(self
            .checkpoint_client()
            .await?
            .list_checkpoints(v1::ListCheckpointsRequest {
                environment: environment.to_owned(),
            })
            .await?
            .into_inner()
            .checkpoints)
    }

    pub async fn get_checkpoint(&self, checkpoint: &str) -> Result<v1::Checkpoint, Status> {
        Ok(self
            .checkpoint_client()
            .await?
            .get_checkpoint(v1::CheckpointSelector {
                checkpoint: checkpoint.to_owned(),
            })
            .await?
            .into_inner())
    }

    pub async fn delete_checkpoint(&self, checkpoint: &str) -> Result<v1::Checkpoint, Status> {
        Ok(self
            .checkpoint_client()
            .await?
            .delete_checkpoint(v1::CheckpointSelector {
                checkpoint: checkpoint.to_owned(),
            })
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
        let (_, protocol) =
            query_supervisor_info(&mut supervisor, Some(self.expected_configuration_digest))
                .await
                .map_err(|_| {
                    Status::failed_precondition(
                        "native runtime update requires exact Linux supervisor protocol9",
                    )
                })?;
        // Only this cw's supervisor changes cw in a running VM; an older one
        // keeps serving its VMs until they stop.
        if protocol != crate::supervisor_config::NATIVE_SUPERVISOR_PROTOCOL_VERSION {
            return Err(Status::failed_precondition(
                "your local VMs run on an older cw's supervisor; changing cw in a running VM needs this cw's, which takes over once they stop",
            ));
        }
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

/// Where a failed operation's [`Status`] keeps its error code, for
/// [`operation_error_code`]. The status is made in this process from the
/// terminal operation; nothing reads it from the wire.
const OPERATION_ERROR_CODE_METADATA: &str = "codewire-operation-error-code";

pub(crate) fn operation_outcome(operation: v1::Operation) -> Result<v1::Operation, Status> {
    match v1::OperationPhase::try_from(operation.phase) {
        Ok(v1::OperationPhase::Completed) => Ok(operation),
        Ok(v1::OperationPhase::Failed | v1::OperationPhase::Interrupted) => {
            let error_code = if operation.error_code.is_empty() {
                "unknown"
            } else {
                operation.error_code.as_str()
            };
            let mut status = Status::failed_precondition(format!(
                "local lifecycle operation {} failed: {error_code}{}",
                operation.operation_id,
                operation_error_hint(error_code)
            ));
            if let Ok(value) = error_code.parse() {
                status
                    .metadata_mut()
                    .insert(OPERATION_ERROR_CODE_METADATA, value);
            }
            Err(status)
        }
        _ => Err(Status::internal(
            "local lifecycle operation is not terminal",
        )),
    }
}

/// `failure` with `outcome` appended to its message, keeping its metadata, so
/// the operation's error code still reaches `operation_error_code` (#3271).
fn with_outcome(failure: &Status, outcome: &str) -> Status {
    let mut status = Status::new(failure.code(), format!("{}{outcome}", failure.message()));
    *status.metadata_mut() = failure.metadata().clone();
    status
}

/// The error code of a failed lifecycle operation, when `status` reports one,
/// so a caller can name what failed (#3209).
pub fn operation_error_code(status: &Status) -> Option<&str> {
    status
        .metadata()
        .get(OPERATION_ERROR_CODE_METADATA)?
        .to_str()
        .ok()
}

/// The error code of an operation that met a runtime artifact store directory
/// that is not private (#3271). `NativeRuntimeConfig::
/// unsafe_runtime_artifact_store_directories` names each one.
pub const UNSAFE_RUNTIME_ARTIFACT_STORE_ERROR_CODE: &str = "runtime_artifact_store_unsafe";

/// A plain-language reason for an operation error code, where the code alone
/// does not tell the user what to change.
fn operation_error_hint(error_code: &str) -> &'static str {
    match error_code {
        UNSAFE_RUNTIME_ARTIFACT_STORE_ERROR_CODE => {
            " (a directory of the local VM runtime store is not private: each must be yours with mode 0700, and nothing was changed)"
        }
        "create_guest_docker_tooling_missing" => {
            " (the image has no Docker tooling; create with --no-docker or choose an image that includes Docker)"
        }
        "create_guest_setup_failed" => {
            " (the VM could not install the workspace image; try another image or a current release of it)"
        }
        "create_guest_workspace_failed" => " (the workspace could not start inside the VM)",
        "delete_failed" | "delete_interrupted" => {
            " (nothing was removed and the environment was kept; see cw info, then run cw rm again)"
        }
        "create_direct_share_changed" | "start_direct_share_changed" => {
            " (a direct-mount source directory was moved, removed or replaced since it was admitted; put the original directory back at its path, or remove and recreate the environment)"
        }
        "create_host_port_unavailable" => {
            " (a host port this environment publishes on 127.0.0.1 is in use by another program or local environment; stop it, or change host_port in codewire.yaml)"
        }
        "start_host_port_unavailable" => {
            " (a host port this environment publishes on 127.0.0.1 is in use by another program or local environment; `cw --local ports ENV` lists its ports: stop that program, or withdraw the port with `cw --local ports ENV --unpublish PORT` and publish another)"
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
            " (an environment with this name already exists; remove it with cw --local rm NAME or choose another --name)"
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
) -> Result<([u8; 32], u32), SupervisorClientError> {
    let info = tokio::time::timeout(
        SUPERVISOR_INFO_TIMEOUT,
        inner.get_supervisor_info(v1::GetSupervisorInfoRequest {}),
    )
    .await
    .map_err(|_| SupervisorClientError::SupervisorInfoUnavailable)?
    .map_err(supervisor_info_rpc_error)?
    .into_inner();
    admit_supervisor_info(&info, expected_configuration_digest.as_ref())?;
    let digest = info
        .configuration_sha256
        .as_slice()
        .try_into()
        .map_err(|_| SupervisorClientError::from(SupervisorConfigError::InvalidSupervisorInfo))?;
    Ok((digest, info.protocol_version))
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

/// The refusal of the supervisor serving the state root, when `error` is one
/// (directly, or through a supervisor, client or takeover error). Callers
/// walk an error chain with it to replace a retry with the steps that
/// recover (#3548).
pub fn supervisor_refusal<'a>(
    error: &'a (dyn std::error::Error + 'static),
) -> Option<&'a SupervisorRefusal> {
    use crate::supervisor::SupervisorError;
    use crate::supervisor_upgrade::TakeoverError;
    let uds = if let Some(error) = error.downcast_ref::<UdsError>() {
        error
    } else if let Some(SupervisorClientError::Uds(error)) = error.downcast_ref() {
        error
    } else if let Some(SupervisorError::Uds(error)) = error.downcast_ref() {
        error
    } else if let Some(TakeoverError::Supervisor(SupervisorError::Uds(error))) =
        error.downcast_ref()
    {
        error
    } else {
        return None;
    };
    match uds {
        UdsError::SupervisorPeerAdmission(refusal) => Some(refusal),
        _ => None,
    }
}

#[cfg(test)]
mod tests;
