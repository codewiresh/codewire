//! Exact environment-generation lease channel for an isolated local broker.
//!
//! The authority creates the Unix stream and gives its peer directly to the
//! broker process. This service is never registered on the owner control
//! socket. The wire carries only admitted metadata plus a material generation;
//! the broker reads the exact protected value from the OS store after the
//! authority has rederived and admitted the operation.

use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use std::task::{Context, Poll};

use codewire_access::{
    AccessProfileId, BrokerOperationId, BrokerRouteId,
    CREDENTIAL_REFRESH_EXECUTION_DEADLINE_SECONDS, CapabilitySlot, CredentialId, DerivedGrant,
    EnvironmentAccessBinding, EnvironmentId, GrantPermission,
};
use codewire_protected_store::{ProtectedStore, ProtectedValue};
use hyper_util::rt::TokioIo;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::UnixStream;
use tokio::sync::{Mutex, Notify, Semaphore, oneshot, watch};
use tokio_stream::{StreamExt as _, once, pending};
use tonic::transport::server::Connected;
use tonic::transport::{Channel, Endpoint, Server};
use tonic::{Request, Response, Status};
use uuid::Uuid;

use crate::client::{credential_from_proto, derived_grant_from_proto};
use crate::control::v1;
use crate::control::v1::local_credential_broker_lease_service_client::LocalCredentialBrokerLeaseServiceClient;
use crate::control::v1::local_credential_broker_lease_service_server::{
    LocalCredentialBrokerLeaseService, LocalCredentialBrokerLeaseServiceServer,
};
use crate::service::{credential_to_proto, derived_grant_to_proto};
use crate::{
    CredentialOperationLease, CredentialOperationLeaseRequest, CredentialRefreshAdmission,
    LocalCredentialAuthority, LocalCredentialError, PlatformCredentialBinding,
    PlatformCredentialConnector, deny_generic_ssh_lease, protected_entry_id,
};

mod delegation;
mod projection;
mod ssh;
pub use delegation::{LocalCredentialDelegationClient, LocalCredentialDelegationOutput};
pub use projection::LocalEnvironmentProjectionBinding;
pub(crate) use ssh::LocalSshOperationRuntime;
pub use ssh::{LocalSshSignError, LocalSshSignRequest, LocalSshSigner};

const BROKER_CHANNEL_REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(40);
const MAX_BROKER_LEASE_RPC_MESSAGE_BYTES: usize =
    codewire_workload_secrets::MAX_ENVIRONMENT_PROJECTION_BYTES + 64 * 1024;
const MAX_BROKER_DELEGATION_RPC_MESSAGE_BYTES: usize =
    codewire_gateway_proto::CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES + 8;
const MAX_BROKER_LEASE_RPC_CONCURRENCY: usize = 16;
const MAX_BROKER_PROTECTED_STORE_OPERATIONS: usize = 1;
pub(crate) const MAX_RECENT_BROKER_LEASE_AUDIT_EVENTS: usize = 4_096;
pub(crate) const MAX_BROKER_LEASE_AUDIT_LIST_LIMIT: usize = 256;
pub const BROKER_LEASE_PROTOCOL_VERSION: u32 = 8;

/// Result of exact refresh admission. Recovery completes durable bookkeeping;
/// it does not confer permission to consume material for an operation.
#[derive(Debug, PartialEq, Eq)]
pub enum BrokerCredentialRefreshAdmission {
    Reserved(BrokerCredentialRefreshReservation),
    Recovered,
}

/// Metadata-only reservation. It cannot be cloned or used to publish material;
/// the authority must durably start it before the provider request is sent.
#[derive(Debug, PartialEq, Eq)]
pub struct BrokerCredentialRefreshReservation {
    channel_binding: Uuid,
    refresh_id: Uuid,
    request_id: Uuid,
    grant: Box<DerivedGrant>,
    current_material_generation: u64,
    next_material_generation: u64,
}

/// Acknowledged durable Start for one exact request and channel. A lost Start
/// acknowledgement cannot be converted back into a retryable reservation.
#[derive(Debug, PartialEq, Eq)]
pub struct StartedBrokerCredentialRefresh {
    reservation: BrokerCredentialRefreshReservation,
    execution_deadline_unix_ms: u64,
}

/// Material-free result of one exact authority lease decision. This recent
/// local ring is intentionally bounded and process-lifetime; #1922 owns the
/// final durable local/platform audit persistence contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BrokerLeaseAuditDecision {
    Admitted,
    Denied,
    Unavailable,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BrokerLeaseAuditEvent {
    pub sequence: u64,
    pub observed_at_unix_ms: u64,
    pub environment_id: EnvironmentId,
    pub environment_generation: u64,
    pub request_id: Uuid,
    pub capability_slot: CapabilitySlot,
    pub operation: BrokerOperationId,
    pub route: BrokerRouteId,
    pub decision: BrokerLeaseAuditDecision,
    pub credential_id: Option<CredentialId>,
    pub profile_id: Option<AccessProfileId>,
    pub profile_revision: Option<u64>,
    pub credential_revocation_generation: Option<u64>,
}

#[derive(Default)]
pub(crate) struct BrokerLeaseAuditLog {
    state: Mutex<BrokerLeaseAuditState>,
}

#[derive(Default)]
struct BrokerLeaseAuditState {
    next_sequence: u64,
    events: VecDeque<BrokerLeaseAuditEvent>,
}

impl BrokerLeaseAuditLog {
    async fn record(&self, mut event: BrokerLeaseAuditEvent) {
        let mut state = self.state.lock().await;
        state.next_sequence = state.next_sequence.saturating_add(1).max(1);
        event.sequence = state.next_sequence;
        event.observed_at_unix_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|duration| u64::try_from(duration.as_millis()).ok())
            .unwrap_or(0);
        state.events.push_front(event);
        state.events.truncate(MAX_RECENT_BROKER_LEASE_AUDIT_EVENTS);
    }

    pub(crate) async fn recent(&self, limit: usize) -> Vec<BrokerLeaseAuditEvent> {
        self.state
            .lock()
            .await
            .events
            .iter()
            .take(limit.min(MAX_BROKER_LEASE_AUDIT_LIST_LIMIT))
            .cloned()
            .collect()
    }
}

/// Stable failures safe to retain outside the credential-bearing broker.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum BrokerLeaseChannelError {
    #[error("credential broker lease request is invalid")]
    InvalidRequest,
    #[error("credential broker lease was denied")]
    Denied,
    #[error("credential broker lease authority is unavailable")]
    Unavailable,
    #[error("credential broker lease authority returned invalid metadata")]
    InvalidResponse,
    #[error("credential refresh is already in progress")]
    RefreshInProgress,
    #[error("credential refresh generation changed")]
    StaleRefresh,
}

/// Client for one authority-created, environment-generation-bound channel.
///
/// Construction requires the connected inherited stream; there is no socket
/// path or general connector that another owner process can discover.
pub struct LocalCredentialBrokerLeaseClient<S> {
    inner: LocalCredentialBrokerLeaseServiceClient<Channel>,
    protected_store: S,
    protected_store_operations: Arc<Semaphore>,
    channel_binding: Uuid,
    environment_id: EnvironmentId,
    environment_generation: u64,
}

impl<S: Clone> Clone for LocalCredentialBrokerLeaseClient<S> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            protected_store: self.protected_store.clone(),
            protected_store_operations: Arc::clone(&self.protected_store_operations),
            channel_binding: self.channel_binding,
            environment_id: self.environment_id.clone(),
            environment_generation: self.environment_generation,
        }
    }
}

impl<S> std::fmt::Debug for LocalCredentialBrokerLeaseClient<S> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LocalCredentialBrokerLeaseClient")
            .field("environment_id", &self.environment_id)
            .field("environment_generation", &self.environment_generation)
            .field("protected_store", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl<S> LocalCredentialBrokerLeaseClient<S>
where
    S: ProtectedStore + Clone + 'static,
{
    /// Execute one typed, selected SSH operation on this channel's immutable
    /// environment generation. The unary call stays alive through the
    /// authority's bounded worker drain; no SSH material is read client-side.
    pub async fn ssh_operation(
        &mut self,
        request: codewire_gateway_proto::codewire::bridge::v1::CredentialSshRequest,
    ) -> Result<
        codewire_gateway_proto::codewire::bridge::v1::CredentialSshResponse,
        BrokerLeaseChannelError,
    > {
        use codewire_gateway_proto::codewire::bridge::v1::credential_ssh_response::Result as SshResult;
        let operation = codewire_gateway_proto::ssh::validate_request(&request)
            .map_err(|_| BrokerLeaseChannelError::InvalidRequest)?;
        let request_id = request.request_id.clone();
        let original_deadline = request.deadline_unix_ms;
        let remaining = codewire_gateway_proto::ssh::remaining_deadline(original_deadline)
            .map_err(|_| BrokerLeaseChannelError::InvalidRequest)?;
        let mut rpc_request = Request::new(v1::BrokerSshRequest {
            protocol_version: BROKER_LEASE_PROTOCOL_VERSION,
            request: Some(request),
        });
        rpc_request
            .set_timeout(ssh::transport_timeout(remaining).min(BROKER_CHANNEL_REQUEST_TIMEOUT));
        let response = self
            .inner
            .ssh_operation(rpc_request)
            .await
            .map_err(map_client_status)?
            .into_inner();
        if response.request_id != request_id
            || codewire_gateway_proto::ssh::validate_response(&response, operation).is_err()
        {
            return Err(BrokerLeaseChannelError::InvalidResponse);
        }
        if !matches!(response.result, Some(SshResult::Failure(_)))
            && codewire_gateway_proto::ssh::remaining_deadline(original_deadline).is_err()
        {
            return Err(BrokerLeaseChannelError::InvalidResponse);
        }
        Ok(response)
    }

    pub async fn connect(
        stream: UnixStream,
        protected_store: S,
        environment_id: EnvironmentId,
        environment_generation: u64,
    ) -> Result<Self, BrokerLeaseChannelError> {
        if environment_generation == 0 {
            return Err(BrokerLeaseChannelError::InvalidRequest);
        }
        let stream = Arc::new(Mutex::new(Some(stream)));
        let channel = Endpoint::from_static("http://codewire-local-credential-broker-lease")
            .timeout(BROKER_CHANNEL_REQUEST_TIMEOUT)
            .connect_with_connector(tower::service_fn(move |_| {
                let stream = Arc::clone(&stream);
                async move {
                    stream.lock().await.take().map(TokioIo::new).ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::NotConnected,
                            "broker lease channel already consumed",
                        )
                    })
                }
            }))
            .await
            .map_err(|_| BrokerLeaseChannelError::Unavailable)?;
        Ok(Self {
            inner: LocalCredentialBrokerLeaseServiceClient::new(channel)
                .max_decoding_message_size(MAX_BROKER_LEASE_RPC_MESSAGE_BYTES)
                .max_encoding_message_size(MAX_BROKER_LEASE_RPC_MESSAGE_BYTES),
            protected_store,
            protected_store_operations: Arc::new(Semaphore::new(
                MAX_BROKER_PROTECTED_STORE_OPERATIONS,
            )),
            channel_binding: Uuid::new_v4(),
            environment_id,
            environment_generation,
        })
    }

    /// Admit and resolve one exact operation. The protected-store call runs on
    /// a blocking worker and the resulting value is returned only as a
    /// non-cloneable, non-serializable operation lease.
    pub async fn lease_operation(
        &mut self,
        request_id: Uuid,
        capability_slot: CapabilitySlot,
        operation: BrokerOperationId,
        route: BrokerRouteId,
    ) -> Result<CredentialOperationLease, BrokerLeaseChannelError> {
        if request_id.is_nil() {
            return Err(BrokerLeaseChannelError::InvalidRequest);
        }
        let requested_permission = GrantPermission {
            operation: operation.clone(),
            route: route.clone(),
        };
        let response = self
            .inner
            .lease_credential_operation(v1::BrokerLeaseRequest {
                request_id: request_id.to_string(),
                capability_slot: capability_slot.to_string(),
                operation: operation.to_string(),
                route: route.to_string(),
            })
            .await
            .map_err(map_client_status)?
            .into_inner();
        let credential = response
            .credential
            .ok_or(BrokerLeaseChannelError::InvalidResponse)
            .and_then(|value| {
                credential_from_proto(value).map_err(|_| BrokerLeaseChannelError::InvalidResponse)
            })?;
        let grant = response
            .grant
            .ok_or(BrokerLeaseChannelError::InvalidResponse)
            .and_then(|value| {
                derived_grant_from_proto(value)
                    .map_err(|_| BrokerLeaseChannelError::InvalidResponse)
            })?;
        let permission = response
            .permission
            .ok_or(BrokerLeaseChannelError::InvalidResponse)
            .and_then(permission_from_proto)?;
        if response.material_generation == 0
            || credential.persistence != self.protected_store.persistence()
            || grant.environment_id != self.environment_id
            || grant.environment_generation != self.environment_generation
            || grant.capability_slot != capability_slot
            || grant.credential_id != credential.metadata.id
            || permission != requested_permission
            || !grant.permissions.contains(&permission)
            || grant.credential_revocation_generation != credential.metadata.revocation_generation
        {
            return Err(BrokerLeaseChannelError::InvalidResponse);
        }
        deny_generic_ssh_lease(&credential.metadata)
            .map_err(|_| BrokerLeaseChannelError::Denied)?;
        let entry_id = protected_entry_id(&credential.metadata.id, response.material_generation)
            .map_err(|_| BrokerLeaseChannelError::InvalidResponse)?;
        let operation_permit = Arc::clone(&self.protected_store_operations)
            .acquire_owned()
            .await
            .map_err(|_| BrokerLeaseChannelError::Unavailable)?;
        let store = self.protected_store.clone();
        let value = tokio::task::spawn_blocking(move || {
            // A blocking protected-store call cannot be cancelled by dropping
            // its async join handle. Keep the capacity permit inside the
            // closure so cancellation cannot admit unbounded replacement work.
            let _operation_permit = operation_permit;
            store.get(&entry_id)
        })
        .await
        .map_err(|_| BrokerLeaseChannelError::Unavailable)?
        .map_err(|_| BrokerLeaseChannelError::Unavailable)?
        .ok_or(BrokerLeaseChannelError::Unavailable)?;
        Ok(CredentialOperationLease {
            credential,
            grant,
            permission,
            material_generation: response.material_generation,
            value,
        })
    }

    /// Reserve one refresh for an already-admitted request. No provider value
    /// crosses this RPC and reservation does not permit a provider request.
    #[allow(clippy::too_many_arguments)]
    pub async fn begin_credential_refresh(
        &mut self,
        refresh_id: Uuid,
        request_id: Uuid,
        grant: DerivedGrant,
        operation: BrokerOperationId,
        route: BrokerRouteId,
        material_generation: u64,
    ) -> Result<BrokerCredentialRefreshAdmission, BrokerLeaseChannelError> {
        if refresh_id.is_nil()
            || request_id.is_nil()
            || grant.credential_revocation_generation == 0
            || material_generation == 0
            || grant.environment_id != self.environment_id
            || grant.environment_generation != self.environment_generation
            || !grant.permissions.contains(&GrantPermission {
                operation: operation.clone(),
                route: route.clone(),
            })
        {
            return Err(BrokerLeaseChannelError::InvalidRequest);
        }
        let response = self
            .inner
            .begin_credential_refresh(v1::BrokerCredentialRefreshRequest {
                refresh_id: refresh_id.to_string(),
                request_id: request_id.to_string(),
                operation: operation.to_string(),
                route: route.to_string(),
                grant: Some(derived_grant_to_proto(grant.clone())),
                expected_material_generation: material_generation,
            })
            .await
            .map_err(map_client_status)?
            .into_inner();
        use v1::broker_credential_refresh_admission::Outcome;
        let response = match response.outcome {
            Some(Outcome::Recovered(_)) => return Ok(BrokerCredentialRefreshAdmission::Recovered),
            Some(Outcome::Reserved(response)) => response,
            None => return Err(BrokerLeaseChannelError::InvalidResponse),
        };
        let expected_next = material_generation
            .checked_add(1)
            .ok_or(BrokerLeaseChannelError::InvalidRequest)?;
        if response.refresh_id != refresh_id.to_string()
            || response.request_id != request_id.to_string()
            || response.credential_id != grant.credential_id.as_str()
            || response.current_material_generation != material_generation
            || response.next_material_generation != expected_next
        {
            return Err(BrokerLeaseChannelError::InvalidResponse);
        }
        Ok(BrokerCredentialRefreshAdmission::Reserved(
            BrokerCredentialRefreshReservation {
                channel_binding: self.channel_binding,
                refresh_id,
                request_id,
                grant: Box::new(grant),
                current_material_generation: material_generation,
                next_material_generation: expected_next,
            },
        ))
    }

    /// Consume a reservation only after the authority acknowledges its durable
    /// Started transition. A failed or lost reply leaves recovery to the journal.
    pub async fn start_credential_refresh(
        &mut self,
        reservation: BrokerCredentialRefreshReservation,
    ) -> Result<StartedBrokerCredentialRefresh, BrokerLeaseChannelError> {
        self.validate_refresh_channel(&reservation)?;
        let earliest = crate::unix_millis().map_err(|_| BrokerLeaseChannelError::Unavailable)?;
        let response = self
            .inner
            .start_credential_refresh(v1::BrokerCredentialRefreshStartRequest {
                refresh_id: reservation.refresh_id.to_string(),
                request_id: reservation.request_id.to_string(),
            })
            .await
            .map_err(map_client_status)?
            .into_inner();
        let latest = crate::unix_millis().map_err(|_| BrokerLeaseChannelError::Unavailable)?;
        let lifetime = CREDENTIAL_REFRESH_EXECUTION_DEADLINE_SECONDS * 1_000;
        if response.execution_deadline_unix_ms < earliest.saturating_add(lifetime)
            || response.execution_deadline_unix_ms > latest.saturating_add(lifetime)
            || response.execution_deadline_unix_ms <= latest
        {
            return Err(BrokerLeaseChannelError::InvalidResponse);
        }
        Ok(StartedBrokerCredentialRefresh {
            reservation,
            execution_deadline_unix_ms: response.execution_deadline_unix_ms,
        })
    }

    fn validate_refresh_channel(
        &self,
        reservation: &BrokerCredentialRefreshReservation,
    ) -> Result<(), BrokerLeaseChannelError> {
        if reservation.channel_binding != self.channel_binding
            || reservation.grant.environment_id != self.environment_id
            || reservation.grant.environment_generation != self.environment_generation
        {
            return Err(BrokerLeaseChannelError::InvalidRequest);
        }
        Ok(())
    }

    /// Persist a validated refreshed bundle directly into the next exact OS
    /// protected-store generation, then ask the authority to promote metadata.
    /// An ambiguous commit is deliberately not rolled back: recovery promotes
    /// the durable next entry so a rotated refresh token cannot be lost.
    pub async fn commit_credential_refresh(
        &mut self,
        started: StartedBrokerCredentialRefresh,
        material: ProtectedValue,
    ) -> Result<(), BrokerLeaseChannelError> {
        let permit = started.reservation;
        self.validate_refresh_channel(&permit)?;
        if permit.next_material_generation != permit.current_material_generation.saturating_add(1) {
            return Err(BrokerLeaseChannelError::InvalidResponse);
        }
        let entry_id =
            protected_entry_id(&permit.grant.credential_id, permit.next_material_generation)
                .map_err(|_| BrokerLeaseChannelError::InvalidResponse)?;
        let operation_permit = Arc::clone(&self.protected_store_operations)
            .acquire_owned()
            .await
            .map_err(|_| BrokerLeaseChannelError::Unavailable)?;
        let store = self.protected_store.clone();
        let stored = tokio::task::spawn_blocking(move || {
            let _operation_permit = operation_permit;
            // Capacity waits cannot extend the bounded execution window. Once
            // the blocking write begins, shutdown drains it before recovery.
            if crate::unix_millis()
                .ok()
                .is_none_or(|now| now >= started.execution_deadline_unix_ms)
            {
                return Err(codewire_protected_store::ProtectedStoreError::Unavailable);
            }
            if store.get(&entry_id)?.is_some() {
                return Err(codewire_protected_store::ProtectedStoreError::AmbiguousEntry);
            }
            if crate::unix_millis()
                .ok()
                .is_none_or(|now| now >= started.execution_deadline_unix_ms)
            {
                return Err(codewire_protected_store::ProtectedStoreError::Unavailable);
            }
            store.put(&entry_id, &material)
        })
        .await
        .map_err(|_| BrokerLeaseChannelError::Unavailable)?;
        if stored.is_err() {
            // The provider has already returned a replacement refresh token.
            // A protected-store error may be reported after the write took
            // effect, so retain the journal and force this broker epoch to
            // end. The next broker reconciles an exact present generation by
            // promoting it, or invalidates Started when no value was written.
            return Err(BrokerLeaseChannelError::Unavailable);
        }
        let response = self
            .inner
            .commit_credential_refresh(v1::BrokerCredentialRefreshCommitRequest {
                refresh_id: permit.refresh_id.to_string(),
                request_id: permit.request_id.to_string(),
            })
            .await
            .map_err(map_client_status)?
            .into_inner();
        if response.revocation_generation
            != permit
                .grant
                .credential_revocation_generation
                .saturating_add(1)
            || response.material_generation != permit.next_material_generation
        {
            return Err(BrokerLeaseChannelError::InvalidResponse);
        }
        Ok(())
    }

    /// Cancel a reservation before Start. Started or ambiguous provider requests
    /// can never take this path or reopen the previous refresh token.
    pub async fn abort_credential_refresh(
        &mut self,
        permit: BrokerCredentialRefreshReservation,
    ) -> Result<(), BrokerLeaseChannelError> {
        self.validate_refresh_channel(&permit)?;
        self.inner
            .abort_credential_refresh(v1::BrokerCredentialRefreshAbortRequest {
                refresh_id: permit.refresh_id.to_string(),
                request_id: permit.request_id.to_string(),
            })
            .await
            .map_err(map_client_status)?;
        Ok(())
    }

    /// Invalidate the old generation after an unsuccessful Started attempt. The
    /// failure RPC contains no provider response body or credential value.
    pub async fn fail_credential_refresh(
        &mut self,
        started: StartedBrokerCredentialRefresh,
    ) -> Result<(), BrokerLeaseChannelError> {
        let permit = started.reservation;
        self.validate_refresh_channel(&permit)?;
        let response = self
            .inner
            .fail_credential_refresh(v1::BrokerCredentialRefreshFailureRequest {
                refresh_id: permit.refresh_id.to_string(),
                request_id: permit.request_id.to_string(),
            })
            .await
            .map_err(map_client_status)?
            .into_inner();
        if response.revocation_generation
            != permit
                .grant
                .credential_revocation_generation
                .saturating_add(1)
        {
            return Err(BrokerLeaseChannelError::InvalidResponse);
        }
        Ok(())
    }

    /// Wait for a protected-store operation whose blocking worker outlived a
    /// cancelled async request. Call this after request admission has stopped
    /// and before dropping the private authority channel, so channel-close
    /// recovery cannot race a late staged-generation write.
    pub async fn wait_for_protected_store_operations(&self) -> Result<(), BrokerLeaseChannelError> {
        let permits = u32::try_from(MAX_BROKER_PROTECTED_STORE_OPERATIONS)
            .map_err(|_| BrokerLeaseChannelError::Unavailable)?;
        let operation_barrier = Arc::clone(&self.protected_store_operations)
            .acquire_many_owned(permits)
            .await
            .map_err(|_| BrokerLeaseChannelError::Unavailable)?;
        drop(operation_barrier);
        Ok(())
    }

    /// Complete the authority-owned launch handshake only after the broker has
    /// authenticated and opened the matching guest-daemon bridge.
    pub async fn report_ready(
        &mut self,
        ready: codewire_gateway_proto::codewire::bridge::v1::CredentialBridgeReady,
    ) -> Result<(), BrokerLeaseChannelError> {
        if !delegation::ready_matches(&self.environment_id, self.environment_generation, &ready) {
            return Err(BrokerLeaseChannelError::InvalidRequest);
        }
        self.inner
            .report_broker_ready(v1::BrokerReadyRequest {
                protocol_version: BROKER_LEASE_PROTOCOL_VERSION,
                guest_ready: Some(ready),
            })
            .await
            .map_err(map_client_status)?;
        Ok(())
    }
}

/// Serve one preconnected broker peer, bound to exactly one environment
/// generation. Callers must create and transfer the peer stream without
/// exposing it through a filesystem socket.
pub async fn serve_broker_lease_channel<S>(
    authority: Arc<LocalCredentialAuthority<S>>,
    stream: UnixStream,
    environment_id: EnvironmentId,
    environment_generation: u64,
    local_profile: Option<EnvironmentAccessBinding>,
) -> Result<(), BrokerLeaseChannelError>
where
    S: ProtectedStore + 'static,
{
    serve_broker_lease_channel_with_ready(
        BrokerChannelRefreshLifetime::new(authority),
        stream,
        environment_id,
        environment_generation,
        Arc::new(BrokerLeaseAuditLog::default()),
        None,
        BrokerLeaseChannelControl {
            local_profile,
            ..Default::default()
        },
    )
    .await
}

#[derive(Default)]
pub(crate) struct BrokerLeaseChannelControl {
    pub local_profile: Option<EnvironmentAccessBinding>,
    pub ready: Option<oneshot::Sender<()>>,
    pub shutdown: Option<watch::Receiver<bool>>,
    pub platform: Option<(
        PlatformCredentialBinding,
        Arc<dyn PlatformCredentialConnector>,
    )>,
    pub platform_delegated: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum BrokerPlatformMode {
    Local,
    Delegated,
    SourcesOnly,
}

pub(crate) async fn serve_broker_lease_channel_with_ready<S>(
    refresh_lifetime: Arc<BrokerChannelRefreshLifetime<S>>,
    stream: UnixStream,
    environment_id: EnvironmentId,
    environment_generation: u64,
    audit: Arc<BrokerLeaseAuditLog>,
    projection: Option<LocalEnvironmentProjectionBinding>,
    control: BrokerLeaseChannelControl,
) -> Result<(), BrokerLeaseChannelError>
where
    S: ProtectedStore + 'static,
{
    let BrokerLeaseChannelControl {
        local_profile,
        ready,
        shutdown,
        platform,
        platform_delegated,
    } = control;
    if environment_generation == 0 {
        return Err(BrokerLeaseChannelError::InvalidRequest);
    }
    let channel_id = refresh_lifetime.channel_id;
    let authority = Arc::clone(&refresh_lifetime.authority);
    let _refresh_guard = BrokerChannelRefreshGuard {
        lifetime: Arc::clone(&refresh_lifetime),
    };
    let platform_mode = match (&platform, platform_delegated) {
        (None, false) => BrokerPlatformMode::Local,
        (Some(_), true) => BrokerPlatformMode::Delegated,
        (Some((binding, _)), false) if binding.selection.profile.is_none() => {
            BrokerPlatformMode::SourcesOnly
        }
        _ => return Err(BrokerLeaseChannelError::InvalidRequest),
    };
    let max_rpc_message_bytes = if platform_mode == BrokerPlatformMode::Delegated {
        MAX_BROKER_DELEGATION_RPC_MESSAGE_BYTES
    } else {
        MAX_BROKER_LEASE_RPC_MESSAGE_BYTES
    };
    let service = BrokerLeaseRpc {
        local_profile,
        authority,
        channel_id,
        refresh_lifetime: Arc::clone(&refresh_lifetime),
        environment_id,
        environment_generation,
        audit,
        ready: Mutex::new(ready),
        projection,
        projection_operations: Arc::new(Semaphore::new(1)),
        platform: Mutex::new(platform),
        platform_mode,
        platform_admitted: Arc::new(AtomicBool::new(false)),
        platform_sources: Mutex::new(None),
    };
    let (closed_tx, closed_rx) = oneshot::channel();
    let stream = ObservedBrokerStream {
        inner: stream,
        closed: Some(closed_tx),
    };
    // Keep the private one-connection accept stream open until Hyper drops the
    // actual peer. A one-item stream that ends immediately would make Tonic's
    // accept future complete before the connection's RPC lifetime ends.
    let incoming = once(Ok::<_, io::Error>(stream)).chain(pending());
    let closing_lifetime = Arc::clone(&refresh_lifetime);
    let result = Server::builder()
        .concurrency_limit_per_connection(MAX_BROKER_LEASE_RPC_CONCURRENCY)
        .add_service(
            LocalCredentialBrokerLeaseServiceServer::new(service)
                .max_decoding_message_size(max_rpc_message_bytes)
                .max_encoding_message_size(max_rpc_message_bytes),
        )
        .serve_with_incoming_shutdown(incoming, async move {
            tokio::select! {
                _ = closed_rx => {}
                _ = closing_lifetime.closed() => {}
                _ = async {
                    if let Some(mut shutdown) = shutdown {
                        if !*shutdown.borrow() { let _ = shutdown.changed().await; }
                    } else {
                        std::future::pending::<()>().await;
                    }
                } => {}
            }
            closing_lifetime.close();
        })
        .await
        .map_err(|_| BrokerLeaseChannelError::Unavailable);
    refresh_lifetime.close();
    refresh_lifetime.wait_for_operations().await;
    if refresh_lifetime.ssh_operations.cleanup_failed() {
        return Err(BrokerLeaseChannelError::Unavailable);
    }
    result
}

struct BrokerChannelRefreshGuard<S: ProtectedStore> {
    lifetime: Arc<BrokerChannelRefreshLifetime<S>>,
}

impl<S: ProtectedStore> Drop for BrokerChannelRefreshGuard<S> {
    fn drop(&mut self) {
        self.lifetime.close();
    }
}

pub(crate) struct BrokerChannelRefreshLifetime<S: ProtectedStore> {
    authority: Arc<LocalCredentialAuthority<S>>,
    channel_id: Uuid,
    closed: AtomicBool,
    active_operations: AtomicUsize,
    drained: Notify,
    close_notification: Notify,
    finalization: AtomicU8,
    ssh_operations: ssh::ChannelSshOperations,
}

impl<S: ProtectedStore> BrokerChannelRefreshLifetime<S> {
    pub(crate) fn new(authority: Arc<LocalCredentialAuthority<S>>) -> Arc<Self> {
        Self::new_with_ssh_runtime(authority, LocalSshOperationRuntime::new(None))
    }

    pub(crate) fn new_with_ssh_runtime(
        authority: Arc<LocalCredentialAuthority<S>>,
        ssh_runtime: Arc<LocalSshOperationRuntime>,
    ) -> Arc<Self> {
        Arc::new(Self {
            authority,
            channel_id: Uuid::new_v4(),
            closed: AtomicBool::new(false),
            active_operations: AtomicUsize::new(0),
            drained: Notify::new(),
            close_notification: Notify::new(),
            finalization: AtomicU8::new(0),
            ssh_operations: ssh::ChannelSshOperations::new(ssh_runtime),
        })
    }

    pub(crate) async fn close_and_wait(&self) {
        self.close();
        self.wait_for_operations().await;
    }

    fn acquire(self: &Arc<Self>) -> Option<BrokerChannelRefreshOperation<S>> {
        if self.closed.load(Ordering::Acquire) {
            return None;
        }
        self.active_operations
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                active.checked_add(1)
            })
            .ok()?;
        if self.closed.load(Ordering::Acquire) {
            self.release_operation();
            return None;
        }
        Some(BrokerChannelRefreshOperation {
            lifetime: Arc::clone(self),
        })
    }

    fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.close_notification.notify_waiters();
        self.ssh_operations.cancel_all();
        self.finalize_if_idle();
    }

    fn release_operation(&self) {
        let previous = self.active_operations.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous > 0);
        if previous == 1 {
            self.finalize_if_idle();
        }
    }

    fn finalize_if_idle(&self) {
        if self.closed.load(Ordering::Acquire)
            && self.active_operations.load(Ordering::Acquire) == 0
            && self
                .finalization
                .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            self.release_refreshes();
            self.finalization.store(2, Ordering::Release);
            self.drained.notify_waiters();
        }
    }

    async fn wait_for_operations(&self) {
        loop {
            let notified = self.drained.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.finalization.load(Ordering::Acquire) == 2 {
                return;
            }
            notified.await;
        }
    }

    async fn closed(&self) {
        loop {
            let notified = self.close_notification.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.closed.load(Ordering::Acquire) {
                return;
            }
            notified.await;
        }
    }

    fn release_refreshes(&self) {
        let _ = self
            .authority
            .release_channel_credential_refreshes(self.channel_id);
    }
}

struct BrokerChannelRefreshOperation<S: ProtectedStore> {
    lifetime: Arc<BrokerChannelRefreshLifetime<S>>,
}

impl<S: ProtectedStore> Drop for BrokerChannelRefreshOperation<S> {
    fn drop(&mut self) {
        self.lifetime.release_operation();
    }
}

struct ObservedBrokerStream {
    inner: UnixStream,
    closed: Option<oneshot::Sender<()>>,
}

impl Drop for ObservedBrokerStream {
    fn drop(&mut self) {
        if let Some(closed) = self.closed.take() {
            let _ = closed.send(());
        }
    }
}

impl AsyncRead for ObservedBrokerStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(context, buffer)
    }
}

impl AsyncWrite for ObservedBrokerStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.inner).poll_write(context, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

impl Connected for ObservedBrokerStream {
    type ConnectInfo = ();

    fn connect_info(&self) -> Self::ConnectInfo {}
}

struct BrokerLeaseRpc<S: ProtectedStore> {
    local_profile: Option<EnvironmentAccessBinding>,
    authority: Arc<LocalCredentialAuthority<S>>,
    channel_id: Uuid,
    refresh_lifetime: Arc<BrokerChannelRefreshLifetime<S>>,
    environment_id: EnvironmentId,
    environment_generation: u64,
    audit: Arc<BrokerLeaseAuditLog>,
    ready: Mutex<Option<oneshot::Sender<()>>>,
    projection: Option<LocalEnvironmentProjectionBinding>,
    projection_operations: Arc<Semaphore>,
    platform: Mutex<
        Option<(
            PlatformCredentialBinding,
            Arc<dyn PlatformCredentialConnector>,
        )>,
    >,
    platform_mode: BrokerPlatformMode,
    platform_admitted: Arc<AtomicBool>,
    platform_sources: Mutex<Option<delegation::sources_only::PlatformSourceConnection>>,
}

impl<S: ProtectedStore> BrokerLeaseRpc<S> {
    fn require_local_mode(&self) -> Result<(), Status> {
        if self.platform_mode == BrokerPlatformMode::Delegated {
            Err(Status::failed_precondition(
                "local credential operation is unavailable in platform mode",
            ))
        } else {
            Ok(())
        }
    }
}

#[tonic::async_trait]
impl<S> LocalCredentialBrokerLeaseService for BrokerLeaseRpc<S>
where
    S: ProtectedStore + 'static,
{
    type DelegateCredentialsStream = delegation::BrokerDelegationOutput;

    async fn delegate_credentials(
        &self,
        request: Request<
            tonic::Streaming<
                codewire_gateway_proto::codewire::bridge::v1::CredentialBridgeGuestMessage,
            >,
        >,
    ) -> Result<Response<Self::DelegateCredentialsStream>, Status> {
        self.delegate_platform_credentials(request).await
    }

    async fn ssh_operation(
        &self,
        request: Request<v1::BrokerSshRequest>,
    ) -> Result<Response<codewire_gateway_proto::codewire::bridge::v1::CredentialSshResponse>, Status>
    {
        self.require_local_mode()?;
        self.run_ssh_operation(request.into_inner()).await
    }

    async fn project_environment(
        &self,
        request: Request<v1::BrokerEnvironmentProjectionRequest>,
    ) -> Result<Response<v1::BrokerEnvironmentProjectionResponse>, Status> {
        self.require_local_mode()?;
        let request = request.into_inner();
        let response = if self.platform_mode == BrokerPlatformMode::SourcesOnly {
            self.project_platform_sources(request).await?
        } else {
            self.project_bound_environment(request).await?
        };
        Ok(Response::new(response))
    }

    async fn report_broker_ready(
        &self,
        request: Request<v1::BrokerReadyRequest>,
    ) -> Result<Response<v1::BrokerReadyResponse>, Status> {
        let request = request.into_inner();
        if request.protocol_version != BROKER_LEASE_PROTOCOL_VERSION {
            return Err(Status::failed_precondition(
                "credential broker lease protocol is incompatible",
            ));
        }
        if self.platform_mode == BrokerPlatformMode::Delegated
            && (!self.platform_admitted.load(Ordering::Acquire) || request.guest_ready.is_some())
        {
            return Err(Status::failed_precondition(
                "platform credential delegation is not admitted",
            ));
        }
        let ready = self
            .ready
            .lock()
            .await
            .take()
            .ok_or_else(|| Status::failed_precondition("credential broker is already ready"))?;
        if self.platform_mode != BrokerPlatformMode::Delegated {
            let guest_ready = request
                .guest_ready
                .ok_or_else(|| Status::permission_denied("credential broker Ready is missing"))?;
            if !delegation::ready_matches(
                &self.environment_id,
                self.environment_generation,
                &guest_ready,
            ) {
                return Err(Status::permission_denied(
                    "credential broker Ready is invalid",
                ));
            }
            if self.platform_mode == BrokerPlatformMode::SourcesOnly {
                self.admit_platform_sources(guest_ready).await?;
            }
        }
        let authority = Arc::clone(&self.authority);
        let environment_id = self.environment_id.clone();
        let generation = self.environment_generation;
        let selected = self.local_profile.clone();
        let checked = tokio::task::spawn_blocking(move || {
            authority.evaluate_selected_environment_grants(
                &environment_id,
                generation,
                selected.as_ref(),
            )
        })
        .await
        .map_err(|_| Status::unavailable("credential broker authority is unavailable"))
        .and_then(|result| result.map_err(map_server_error));
        if let Err(error) = checked {
            self.refresh_lifetime.close();
            return Err(error);
        }
        ready
            .send(())
            .map_err(|_| Status::unavailable("credential broker launch was cancelled"))?;
        Ok(Response::new(v1::BrokerReadyResponse {}))
    }

    async fn lease_credential_operation(
        &self,
        request: Request<v1::BrokerLeaseRequest>,
    ) -> Result<Response<v1::BrokerLeaseResponse>, Status> {
        self.require_local_mode()?;
        let request = request.into_inner();
        let request_id = Uuid::parse_str(&request.request_id)
            .map_err(|_| Status::invalid_argument("invalid broker lease request"))?;
        if request_id.is_nil() || request_id.to_string() != request.request_id {
            return Err(Status::invalid_argument("invalid broker lease request"));
        }
        let capability_slot = CapabilitySlot::parse(request.capability_slot)
            .map_err(|_| Status::invalid_argument("invalid broker lease request"))?;
        let operation = BrokerOperationId::parse(request.operation)
            .map_err(|_| Status::invalid_argument("invalid broker lease request"))?;
        let route = BrokerRouteId::parse(request.route)
            .map_err(|_| Status::invalid_argument("invalid broker lease request"))?;
        let admission_request = CredentialOperationLeaseRequest {
            environment_id: self.environment_id.clone(),
            environment_generation: self.environment_generation,
            capability_slot: capability_slot.clone(),
            operation: operation.clone(),
            route: route.clone(),
        };
        let authority = Arc::clone(&self.authority);
        let selected = self.local_profile.clone();
        let admission = match tokio::task::spawn_blocking(move || {
            authority.admit_selected_environment_credential_operation(
                &admission_request,
                selected.as_ref(),
            )
        })
        .await
        {
            Ok(admission) => admission,
            Err(_) => {
                self.audit
                    .record(BrokerLeaseAuditEvent {
                        sequence: 0,
                        observed_at_unix_ms: 0,
                        environment_id: self.environment_id.clone(),
                        environment_generation: self.environment_generation,
                        request_id,
                        capability_slot,
                        operation,
                        route,
                        decision: BrokerLeaseAuditDecision::Unavailable,
                        credential_id: None,
                        profile_id: None,
                        profile_revision: None,
                        credential_revocation_generation: None,
                    })
                    .await;
                return Err(Status::unavailable(
                    "credential broker lease authority is unavailable",
                ));
            }
        };
        let admission = match admission {
            Ok(admission) => {
                if deny_generic_ssh_lease(&admission.credential.metadata).is_err() {
                    self.audit
                        .record(BrokerLeaseAuditEvent {
                            sequence: 0,
                            observed_at_unix_ms: 0,
                            environment_id: self.environment_id.clone(),
                            environment_generation: self.environment_generation,
                            request_id,
                            capability_slot,
                            operation,
                            route,
                            decision: BrokerLeaseAuditDecision::Denied,
                            credential_id: None,
                            profile_id: None,
                            profile_revision: None,
                            credential_revocation_generation: None,
                        })
                        .await;
                    return Err(Status::permission_denied(
                        "SSH credentials require the typed SSH operation",
                    ));
                }
                self.audit
                    .record(BrokerLeaseAuditEvent {
                        sequence: 0,
                        observed_at_unix_ms: 0,
                        environment_id: self.environment_id.clone(),
                        environment_generation: self.environment_generation,
                        request_id,
                        capability_slot,
                        operation,
                        route,
                        decision: BrokerLeaseAuditDecision::Admitted,
                        credential_id: Some(admission.credential.metadata.id.clone()),
                        profile_id: Some(admission.grant.profile_id.clone()),
                        profile_revision: Some(admission.grant.profile_revision),
                        credential_revocation_generation: Some(
                            admission.grant.credential_revocation_generation,
                        ),
                    })
                    .await;
                admission
            }
            Err(error) => {
                self.audit
                    .record(BrokerLeaseAuditEvent {
                        sequence: 0,
                        observed_at_unix_ms: 0,
                        environment_id: self.environment_id.clone(),
                        environment_generation: self.environment_generation,
                        request_id,
                        capability_slot,
                        operation,
                        route,
                        decision: audit_decision_for_error(&error),
                        credential_id: None,
                        profile_id: None,
                        profile_revision: None,
                        credential_revocation_generation: None,
                    })
                    .await;
                return Err(map_server_error(error));
            }
        };
        Ok(Response::new(v1::BrokerLeaseResponse {
            credential: Some(credential_to_proto(admission.credential)),
            grant: Some(derived_grant_to_proto(admission.grant)),
            permission: Some(v1::GrantPermission {
                operation: admission.permission.operation.to_string(),
                route: admission.permission.route.to_string(),
            }),
            material_generation: admission.material_generation,
        }))
    }

    async fn begin_credential_refresh(
        &self,
        request: Request<v1::BrokerCredentialRefreshRequest>,
    ) -> Result<Response<v1::BrokerCredentialRefreshAdmission>, Status> {
        self.require_local_mode()?;
        let request = request.into_inner();
        let refresh_id = parse_canonical_uuid(&request.refresh_id, "credential refresh")?;
        let request_id = parse_canonical_uuid(&request.request_id, "credential refresh")?;
        let grant = request
            .grant
            .and_then(|value| derived_grant_from_proto(value).ok())
            .ok_or_else(|| Status::invalid_argument("invalid credential refresh request"))?;
        let operation = BrokerOperationId::parse(request.operation)
            .map_err(|_| Status::invalid_argument("invalid credential refresh request"))?;
        let route = BrokerRouteId::parse(request.route)
            .map_err(|_| Status::invalid_argument("invalid credential refresh request"))?;
        if request.expected_material_generation == 0
            || grant.environment_id != self.environment_id
            || grant.environment_generation != self.environment_generation
        {
            return Err(Status::invalid_argument(
                "invalid credential refresh request",
            ));
        }
        // The caller's grant is untrusted, but must name this channel's exact
        // selection before the authority atomically rederives it. The retained
        // refresh permit then carries that same profile through Start/recovery.
        if !self.local_profile.as_ref().is_some_and(|selected| {
            selected.environment_id == grant.environment_id
                && selected.profile_id == grant.profile_id
                && selected.profile_revision == grant.profile_revision
        }) {
            return Err(Status::permission_denied(
                "credential refresh profile changed",
            ));
        }
        let admission_request = CredentialOperationLeaseRequest {
            environment_id: self.environment_id.clone(),
            environment_generation: self.environment_generation,
            capability_slot: grant.capability_slot.clone(),
            operation,
            route,
        };
        let authority = Arc::clone(&self.authority);
        let channel_id = self.channel_id;
        let operation = self
            .refresh_lifetime
            .acquire()
            .ok_or_else(|| Status::unavailable("credential broker lease channel is unavailable"))?;
        let admission = tokio::task::spawn_blocking(move || {
            let _operation = operation;
            authority.begin_environment_credential_refresh(
                channel_id,
                refresh_id,
                request_id,
                &admission_request,
                &grant,
                request.expected_material_generation,
            )
        })
        .await
        .map_err(|_| Status::unavailable("credential refresh authority is unavailable"))?
        .map_err(map_server_error)?;
        use v1::broker_credential_refresh_admission::Outcome;
        let outcome = match admission {
            CredentialRefreshAdmission::Reserved(permit) => {
                Outcome::Reserved(v1::BrokerCredentialRefreshReservation {
                    refresh_id: permit.refresh_id.to_string(),
                    request_id: permit.request_id.to_string(),
                    credential_id: permit.grant.credential_id.to_string(),
                    current_material_generation: permit.current_material_generation,
                    next_material_generation: permit.next_material_generation,
                })
            }
            CredentialRefreshAdmission::Recovered => {
                Outcome::Recovered(v1::BrokerCredentialRefreshRecovered {})
            }
        };
        Ok(Response::new(v1::BrokerCredentialRefreshAdmission {
            outcome: Some(outcome),
        }))
    }

    async fn start_credential_refresh(
        &self,
        request: Request<v1::BrokerCredentialRefreshStartRequest>,
    ) -> Result<Response<v1::BrokerCredentialRefreshStartResponse>, Status> {
        self.require_local_mode()?;
        let request = request.into_inner();
        let refresh_id = parse_canonical_uuid(&request.refresh_id, "credential refresh start")?;
        let request_id = parse_canonical_uuid(&request.request_id, "credential refresh start")?;
        let authority = Arc::clone(&self.authority);
        let channel_id = self.channel_id;
        let operation = self
            .refresh_lifetime
            .acquire()
            .ok_or_else(|| Status::unavailable("credential broker lease channel is unavailable"))?;
        let execution_deadline_unix_ms = tokio::task::spawn_blocking(move || {
            let _operation = operation;
            authority.start_environment_credential_refresh(channel_id, refresh_id, request_id)
        })
        .await
        .map_err(|_| Status::unavailable("credential refresh authority is unavailable"))?
        .map_err(map_server_error)?;
        Ok(Response::new(v1::BrokerCredentialRefreshStartResponse {
            execution_deadline_unix_ms,
        }))
    }

    async fn commit_credential_refresh(
        &self,
        request: Request<v1::BrokerCredentialRefreshCommitRequest>,
    ) -> Result<Response<v1::BrokerCredentialRefreshCommitResponse>, Status> {
        self.require_local_mode()?;
        let request = request.into_inner();
        let refresh_id = parse_canonical_uuid(&request.refresh_id, "credential refresh commit")?;
        let request_id = parse_canonical_uuid(&request.request_id, "credential refresh commit")?;
        let authority = Arc::clone(&self.authority);
        let channel_id = self.channel_id;
        let operation = self
            .refresh_lifetime
            .acquire()
            .ok_or_else(|| Status::unavailable("credential broker lease channel is unavailable"))?;
        let (record, material_generation) = tokio::task::spawn_blocking(move || {
            let _operation = operation;
            authority.commit_environment_credential_refresh(channel_id, refresh_id, request_id)
        })
        .await
        .map_err(|_| Status::unavailable("credential refresh authority is unavailable"))?
        .map_err(map_server_error)?;
        Ok(Response::new(v1::BrokerCredentialRefreshCommitResponse {
            revocation_generation: record.metadata.revocation_generation,
            material_generation,
        }))
    }

    async fn abort_credential_refresh(
        &self,
        request: Request<v1::BrokerCredentialRefreshAbortRequest>,
    ) -> Result<Response<v1::BrokerCredentialRefreshAbortResponse>, Status> {
        self.require_local_mode()?;
        let request = request.into_inner();
        let refresh_id = parse_canonical_uuid(&request.refresh_id, "credential refresh abort")?;
        let request_id = parse_canonical_uuid(&request.request_id, "credential refresh abort")?;
        let authority = Arc::clone(&self.authority);
        let channel_id = self.channel_id;
        let operation = self
            .refresh_lifetime
            .acquire()
            .ok_or_else(|| Status::unavailable("credential broker lease channel is unavailable"))?;
        tokio::task::spawn_blocking(move || {
            let _operation = operation;
            authority.abort_environment_credential_refresh(channel_id, refresh_id, request_id)
        })
        .await
        .map_err(|_| Status::unavailable("credential refresh authority is unavailable"))?
        .map_err(map_server_error)?;
        Ok(Response::new(v1::BrokerCredentialRefreshAbortResponse {}))
    }

    async fn fail_credential_refresh(
        &self,
        request: Request<v1::BrokerCredentialRefreshFailureRequest>,
    ) -> Result<Response<v1::BrokerCredentialRefreshFailureResponse>, Status> {
        self.require_local_mode()?;
        let request = request.into_inner();
        let refresh_id = parse_canonical_uuid(&request.refresh_id, "credential refresh failure")?;
        let request_id = parse_canonical_uuid(&request.request_id, "credential refresh failure")?;
        let authority = Arc::clone(&self.authority);
        let channel_id = self.channel_id;
        let operation = self
            .refresh_lifetime
            .acquire()
            .ok_or_else(|| Status::unavailable("credential broker lease channel is unavailable"))?;
        let record = tokio::task::spawn_blocking(move || {
            let _operation = operation;
            authority.fail_environment_credential_refresh(channel_id, refresh_id, request_id)
        })
        .await
        .map_err(|_| Status::unavailable("credential refresh authority is unavailable"))?
        .map_err(map_server_error)?;
        Ok(Response::new(v1::BrokerCredentialRefreshFailureResponse {
            revocation_generation: record.metadata.revocation_generation,
        }))
    }
}

fn parse_canonical_uuid(value: &str, operation: &'static str) -> Result<Uuid, Status> {
    let parsed = Uuid::parse_str(value)
        .map_err(|_| Status::invalid_argument(format!("invalid {operation} request")))?;
    if parsed.is_nil() || parsed.to_string() != value {
        return Err(Status::invalid_argument(format!(
            "invalid {operation} request"
        )));
    }
    Ok(parsed)
}

fn audit_decision_for_error(error: &LocalCredentialError) -> BrokerLeaseAuditDecision {
    match error {
        LocalCredentialError::DatabaseUnavailable
        | LocalCredentialError::InvalidDatabase
        | LocalCredentialError::UnsupportedSchema
        | LocalCredentialError::CorruptMetadata
        | LocalCredentialError::OwnerMismatch
        | LocalCredentialError::ProtectedStoreMismatch
        | LocalCredentialError::UnsupportedPlatform
        | LocalCredentialError::InvalidTime
        | LocalCredentialError::ProtectedStore(_) => BrokerLeaseAuditDecision::Unavailable,
        _ => BrokerLeaseAuditDecision::Denied,
    }
}

fn permission_from_proto(
    value: v1::GrantPermission,
) -> Result<GrantPermission, BrokerLeaseChannelError> {
    Ok(GrantPermission {
        operation: BrokerOperationId::parse(value.operation)
            .map_err(|_| BrokerLeaseChannelError::InvalidResponse)?,
        route: BrokerRouteId::parse(value.route)
            .map_err(|_| BrokerLeaseChannelError::InvalidResponse)?,
    })
}

fn map_client_status(status: Status) -> BrokerLeaseChannelError {
    match status.code() {
        tonic::Code::InvalidArgument => BrokerLeaseChannelError::InvalidRequest,
        tonic::Code::Aborted => BrokerLeaseChannelError::RefreshInProgress,
        tonic::Code::OutOfRange => BrokerLeaseChannelError::StaleRefresh,
        tonic::Code::FailedPrecondition | tonic::Code::PermissionDenied => {
            BrokerLeaseChannelError::Denied
        }
        _ => BrokerLeaseChannelError::Unavailable,
    }
}

fn map_server_error(error: LocalCredentialError) -> Status {
    match error {
        LocalCredentialError::StaleCredentialRefresh => {
            Status::out_of_range("credential refresh generation changed")
        }
        LocalCredentialError::CredentialOperationLeaseDenied
        | LocalCredentialError::CredentialInactive
        | LocalCredentialError::CredentialUnavailable
        | LocalCredentialError::CredentialMaterialMissing
        | LocalCredentialError::CredentialNotFound
        | LocalCredentialError::EnvironmentBindingNotFound
        | LocalCredentialError::StaleEnvironmentBinding
        | LocalCredentialError::ProfileNotFound
        | LocalCredentialError::ProfileRevisionNotFound
        | LocalCredentialError::StaleProfileRevision
        | LocalCredentialError::StaleCredentialRevision
        | LocalCredentialError::Access(_) => {
            Status::failed_precondition("credential broker lease was denied")
        }
        LocalCredentialError::CredentialRefreshInProgress => {
            Status::aborted("credential refresh is already in progress")
        }
        _ => Status::unavailable("credential broker lease authority is unavailable"),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Condvar, Mutex as StdMutex};

    use codewire_access::{
        AccessProfileName, CapabilityPolicy, CredentialAuthKind, EnvironmentAccessBinding,
        ProviderCatalog, ProviderDefinition, ProviderId,
    };
    use codewire_protected_store::{
        ProtectedEntryId, ProtectedStoreError, ProtectedStorePersistence, ProtectedValue,
    };

    use super::*;
    use crate::NewCredential;

    #[derive(Clone, Default)]
    struct TestProtectedStore {
        entries: Arc<StdMutex<BTreeMap<ProtectedEntryId, Vec<u8>>>>,
        get_control: Option<Arc<BlockingGetControl>>,
        fail_next_put_after_effect: Arc<AtomicBool>,
    }

    #[derive(Default)]
    struct BlockingGetControl {
        state: StdMutex<BlockingGetState>,
        released: Condvar,
    }

    #[derive(Default)]
    struct BlockingGetState {
        blocked: bool,
        active: usize,
        maximum_active: usize,
    }

    struct BlockingGetGuard {
        control: Arc<BlockingGetControl>,
    }

    impl BlockingGetControl {
        fn blocked() -> Arc<Self> {
            Arc::new(Self {
                state: StdMutex::new(BlockingGetState {
                    blocked: true,
                    ..BlockingGetState::default()
                }),
                released: Condvar::new(),
            })
        }

        fn enter(self: &Arc<Self>) -> Result<BlockingGetGuard, ProtectedStoreError> {
            let mut state = self
                .state
                .lock()
                .map_err(|_| ProtectedStoreError::Unavailable)?;
            state.active += 1;
            state.maximum_active = state.maximum_active.max(state.active);
            while state.blocked {
                state = self
                    .released
                    .wait(state)
                    .map_err(|_| ProtectedStoreError::Unavailable)?;
            }
            drop(state);
            Ok(BlockingGetGuard {
                control: Arc::clone(self),
            })
        }

        fn counts(&self) -> (usize, usize) {
            let state = self.state.lock().unwrap();
            (state.active, state.maximum_active)
        }

        fn block(&self) {
            let mut state = self.state.lock().unwrap();
            state.blocked = true;
        }

        fn release(&self) {
            let mut state = self.state.lock().unwrap();
            state.blocked = false;
            self.released.notify_all();
        }
    }

    impl Drop for BlockingGetGuard {
        fn drop(&mut self) {
            let mut state = self.control.state.lock().unwrap();
            state.active -= 1;
        }
    }

    impl TestProtectedStore {
        fn with_blocked_gets(&self, control: Arc<BlockingGetControl>) -> Self {
            Self {
                entries: Arc::clone(&self.entries),
                get_control: Some(control),
                fail_next_put_after_effect: Arc::clone(&self.fail_next_put_after_effect),
            }
        }

        fn fail_next_put_after_effect(&self) {
            self.fail_next_put_after_effect
                .store(true, Ordering::Release);
        }
    }

    impl ProtectedStore for TestProtectedStore {
        fn persistence(&self) -> ProtectedStorePersistence {
            ProtectedStorePersistence::ProcessLifetime
        }

        fn get(
            &self,
            id: &ProtectedEntryId,
        ) -> Result<Option<ProtectedValue>, ProtectedStoreError> {
            let _get_guard = self
                .get_control
                .as_ref()
                .map(BlockingGetControl::enter)
                .transpose()?;
            self.entries
                .lock()
                .map_err(|_| ProtectedStoreError::Unavailable)?
                .get(id)
                .map(|value| ProtectedValue::from_slice(value))
                .transpose()
        }

        fn put(
            &self,
            id: &ProtectedEntryId,
            value: &ProtectedValue,
        ) -> Result<(), ProtectedStoreError> {
            self.entries
                .lock()
                .map_err(|_| ProtectedStoreError::Unavailable)?
                .insert(id.clone(), value.expose_secret().to_vec());
            if self
                .fail_next_put_after_effect
                .swap(false, Ordering::AcqRel)
            {
                Err(ProtectedStoreError::Unavailable)
            } else {
                Ok(())
            }
        }

        fn delete(&self, id: &ProtectedEntryId) -> Result<(), ProtectedStoreError> {
            self.entries
                .lock()
                .map_err(|_| ProtectedStoreError::Unavailable)?
                .remove(id);
            Ok(())
        }
    }

    fn catalog() -> ProviderCatalog {
        catalog_with_authentication(CredentialAuthKind::ApiKey)
    }

    fn catalog_with_authentication(authentication_kind: CredentialAuthKind) -> ProviderCatalog {
        ProviderCatalog::from_definitions([ProviderDefinition {
            id: ProviderId::parse("openai").unwrap(),
            authentication_kinds: BTreeSet::from([authentication_kind]),
            capabilities: BTreeMap::from([(
                CapabilitySlot::codex(),
                CapabilityPolicy {
                    authentication_kinds: BTreeSet::from([authentication_kind]),
                    permissions: BTreeSet::from([GrantPermission {
                        operation: BrokerOperationId::parse("responses").unwrap(),
                        route: BrokerRouteId::parse("openai-api").unwrap(),
                    }]),
                },
            )]),
        }])
        .unwrap()
    }

    #[tokio::test]
    async fn channel_admits_only_the_bound_generation_and_exact_operation() {
        let temp = tempfile::tempdir().unwrap();
        let store = TestProtectedStore::default();
        let authority = Arc::new(
            LocalCredentialAuthority::open(
                &temp.path().join("authority"),
                store.clone(),
                catalog(),
            )
            .unwrap(),
        );
        let credential = authority
            .add_credential(
                NewCredential {
                    provider: ProviderId::parse("openai").unwrap(),
                    authentication_kind: CredentialAuthKind::ApiKey,
                    display_name: "synthetic".into(),
                    account_hint: None,
                    expires_at_unix: None,
                },
                ProtectedValue::from_slice(b"synthetic-openai-material").unwrap(),
            )
            .unwrap();
        let profile = authority
            .create_profile(
                AccessProfileName::parse("synthetic").unwrap(),
                BTreeMap::from([(CapabilitySlot::codex(), credential.metadata.id.clone())]),
            )
            .unwrap();
        let environment_id = EnvironmentId::parse(uuid::Uuid::new_v4().to_string()).unwrap();
        authority
            .create_environment_access_binding(EnvironmentAccessBinding {
                environment_id: environment_id.clone(),
                profile_id: profile.profile.id,
                profile_revision: profile.profile.revision,
            })
            .unwrap();

        let (server_stream, client_stream) = UnixStream::pair().unwrap();
        let audit = Arc::new(BrokerLeaseAuditLog::default());
        let server = tokio::spawn(serve_broker_lease_channel_with_ready(
            BrokerChannelRefreshLifetime::new(Arc::clone(&authority)),
            server_stream,
            environment_id.clone(),
            7,
            Arc::clone(&audit),
            None,
            BrokerLeaseChannelControl {
                local_profile: Some(
                    authority
                        .get_environment_access_binding(&environment_id)
                        .unwrap()
                        .binding,
                ),
                ..Default::default()
            },
        ));
        let mut client = LocalCredentialBrokerLeaseClient::connect(
            client_stream,
            store.clone(),
            environment_id.clone(),
            7,
        )
        .await
        .unwrap();
        let lease = client
            .lease_operation(
                Uuid::new_v4(),
                CapabilitySlot::codex(),
                BrokerOperationId::parse("responses").unwrap(),
                BrokerRouteId::parse("openai-api").unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            lease.with_material(|value| value.to_vec()),
            b"synthetic-openai-material"
        );
        assert!(matches!(
            client
                .lease_operation(
                    Uuid::new_v4(),
                    CapabilitySlot::codex(),
                    BrokerOperationId::parse("responses").unwrap(),
                    BrokerRouteId::parse("other-route").unwrap(),
                )
                .await,
            Err(BrokerLeaseChannelError::Denied)
        ));

        authority
            .revoke_credential(&credential.metadata.id)
            .unwrap();
        assert!(matches!(
            client
                .lease_operation(
                    Uuid::new_v4(),
                    CapabilitySlot::codex(),
                    BrokerOperationId::parse("responses").unwrap(),
                    BrokerRouteId::parse("openai-api").unwrap(),
                )
                .await,
            Err(BrokerLeaseChannelError::Denied)
        ));
        let events = audit.recent(8).await;
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].decision, BrokerLeaseAuditDecision::Denied);
        assert_eq!(events[1].decision, BrokerLeaseAuditDecision::Denied);
        assert_eq!(events[2].decision, BrokerLeaseAuditDecision::Admitted);
        assert!(events[2].credential_id.is_some());
        assert!(!format!("{events:?}").contains("synthetic-openai-material"));
        drop(client);
        server.abort();
    }

    #[tokio::test]
    async fn channel_commits_or_invalidates_serialized_oauth_refresh_without_material_on_wire() {
        let temp = tempfile::tempdir().unwrap();
        let store = TestProtectedStore::default();
        let authority = Arc::new(
            LocalCredentialAuthority::open(
                &temp.path().join("authority"),
                store.clone(),
                catalog_with_authentication(CredentialAuthKind::OAuth),
            )
            .unwrap(),
        );
        let credential = authority
            .add_credential(
                NewCredential {
                    provider: ProviderId::parse("openai").unwrap(),
                    authentication_kind: CredentialAuthKind::OAuth,
                    display_name: "synthetic-oauth".into(),
                    account_hint: None,
                    expires_at_unix: None,
                },
                ProtectedValue::from_slice(b"synthetic-old-oauth-bundle").unwrap(),
            )
            .unwrap();
        let profile = authority
            .create_profile(
                AccessProfileName::parse("synthetic-oauth").unwrap(),
                BTreeMap::from([(CapabilitySlot::codex(), credential.metadata.id.clone())]),
            )
            .unwrap();
        let environment_id = EnvironmentId::parse(Uuid::new_v4().to_string()).unwrap();
        authority
            .create_environment_access_binding(EnvironmentAccessBinding {
                environment_id: environment_id.clone(),
                profile_id: profile.profile.id,
                profile_revision: profile.profile.revision,
            })
            .unwrap();

        let (server_stream, client_stream) = UnixStream::pair().unwrap();
        let server = tokio::spawn(serve_broker_lease_channel(
            Arc::clone(&authority),
            server_stream,
            environment_id.clone(),
            7,
            Some(
                authority
                    .get_environment_access_binding(&environment_id)
                    .unwrap()
                    .binding,
            ),
        ));
        let mut client = LocalCredentialBrokerLeaseClient::connect(
            client_stream,
            store.clone(),
            environment_id.clone(),
            7,
        )
        .await
        .unwrap();
        let lease = client
            .lease_operation(
                Uuid::new_v4(),
                CapabilitySlot::codex(),
                BrokerOperationId::parse("responses").unwrap(),
                BrokerRouteId::parse("openai-api").unwrap(),
            )
            .await
            .unwrap();
        let credential_id = lease.credential.metadata.id.clone();
        let revocation_generation = lease.credential.metadata.revocation_generation;
        let material_generation = lease.material_generation();
        let grant = lease.grant.clone();
        assert_eq!(
            lease.with_material(|value| value.to_vec()),
            b"synthetic-old-oauth-bundle"
        );

        let refresh_id = Uuid::new_v4();
        let BrokerCredentialRefreshAdmission::Reserved(permit) = client
            .begin_credential_refresh(
                refresh_id,
                Uuid::new_v4(),
                grant.clone(),
                BrokerOperationId::parse("responses").unwrap(),
                BrokerRouteId::parse("openai-api").unwrap(),
                material_generation,
            )
            .await
            .unwrap()
        else {
            panic!("expected reservation");
        };
        let mut concurrent = client.clone();
        assert_eq!(
            concurrent
                .begin_credential_refresh(
                    Uuid::new_v4(),
                    Uuid::new_v4(),
                    grant.clone(),
                    BrokerOperationId::parse("responses").unwrap(),
                    BrokerRouteId::parse("openai-api").unwrap(),
                    material_generation,
                )
                .await,
            Err(BrokerLeaseChannelError::RefreshInProgress)
        );
        let premature_commit = client
            .inner
            .commit_credential_refresh(v1::BrokerCredentialRefreshCommitRequest {
                refresh_id: permit.refresh_id.to_string(),
                request_id: permit.request_id.to_string(),
            })
            .await
            .unwrap_err();
        assert_eq!(premature_commit.code(), tonic::Code::OutOfRange);
        let missing_request = client
            .inner
            .start_credential_refresh(v1::BrokerCredentialRefreshStartRequest {
                refresh_id: permit.refresh_id.to_string(),
                request_id: String::new(),
            })
            .await
            .unwrap_err();
        assert_eq!(missing_request.code(), tonic::Code::InvalidArgument);
        let permit = client.start_credential_refresh(permit).await.unwrap();
        let marker =
            crate::load_credential_refresh_marker(&authority.connection().unwrap(), &credential_id)
                .unwrap()
                .unwrap();
        assert!(matches!(
            marker.phase,
            crate::CredentialRefreshPhase::Started { .. }
        ));
        client
            .commit_credential_refresh(
                permit,
                ProtectedValue::from_slice(b"synthetic-new-oauth-bundle").unwrap(),
            )
            .await
            .unwrap();

        let refreshed = client
            .lease_operation(
                Uuid::new_v4(),
                CapabilitySlot::codex(),
                BrokerOperationId::parse("responses").unwrap(),
                BrokerRouteId::parse("openai-api").unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(refreshed.material_generation(), material_generation + 1);
        assert_eq!(
            refreshed.credential.metadata.revocation_generation,
            revocation_generation + 1
        );
        let refreshed_revocation_generation = refreshed.credential.metadata.revocation_generation;
        let refreshed_material_generation = refreshed.material_generation();
        let refreshed_grant = refreshed.grant.clone();
        assert_eq!(
            refreshed.with_material(|value| value.to_vec()),
            b"synthetic-new-oauth-bundle"
        );

        let BrokerCredentialRefreshAdmission::Reserved(interrupted_permit) = client
            .begin_credential_refresh(
                Uuid::new_v4(),
                Uuid::new_v4(),
                refreshed_grant.clone(),
                BrokerOperationId::parse("responses").unwrap(),
                BrokerRouteId::parse("openai-api").unwrap(),
                refreshed_material_generation,
            )
            .await
            .unwrap()
        else {
            panic!("expected reservation");
        };
        let interrupted_permit = client
            .start_credential_refresh(interrupted_permit)
            .await
            .unwrap();
        store.fail_next_put_after_effect();
        assert_eq!(
            client
                .commit_credential_refresh(
                    interrupted_permit,
                    ProtectedValue::from_slice(b"synthetic-recovered-oauth-bundle").unwrap(),
                )
                .await,
            Err(BrokerLeaseChannelError::Unavailable)
        );
        drop(client);
        drop(concurrent);
        tokio::time::timeout(std::time::Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap()
            .unwrap();

        let (server_stream, client_stream) = UnixStream::pair().unwrap();
        let server = tokio::spawn(serve_broker_lease_channel(
            Arc::clone(&authority),
            server_stream,
            environment_id.clone(),
            7,
            Some(
                authority
                    .get_environment_access_binding(&environment_id)
                    .unwrap()
                    .binding,
            ),
        ));
        let mut client = LocalCredentialBrokerLeaseClient::connect(
            client_stream,
            store.clone(),
            environment_id,
            7,
        )
        .await
        .unwrap();
        assert_eq!(
            client
                .begin_credential_refresh(
                    Uuid::new_v4(),
                    Uuid::new_v4(),
                    refreshed_grant.clone(),
                    BrokerOperationId::parse("responses").unwrap(),
                    BrokerRouteId::parse("openai-api").unwrap(),
                    refreshed_material_generation,
                )
                .await,
            Ok(BrokerCredentialRefreshAdmission::Recovered)
        );
        let recovered = client
            .lease_operation(
                Uuid::new_v4(),
                CapabilitySlot::codex(),
                BrokerOperationId::parse("responses").unwrap(),
                BrokerRouteId::parse("openai-api").unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            recovered.material_generation(),
            refreshed_material_generation + 1
        );
        assert_eq!(
            recovered.credential.metadata.revocation_generation,
            refreshed_revocation_generation + 1
        );
        let recovered_revocation_generation = recovered.credential.metadata.revocation_generation;
        let recovered_material_generation = recovered.material_generation();
        let recovered_grant = recovered.grant.clone();
        assert_eq!(
            recovered.with_material(|value| value.to_vec()),
            b"synthetic-recovered-oauth-bundle"
        );
        let BrokerCredentialRefreshAdmission::Reserved(failed_permit) = client
            .begin_credential_refresh(
                Uuid::new_v4(),
                Uuid::new_v4(),
                recovered_grant,
                BrokerOperationId::parse("responses").unwrap(),
                BrokerRouteId::parse("openai-api").unwrap(),
                recovered_material_generation,
            )
            .await
            .unwrap()
        else {
            panic!("expected reservation");
        };
        let failed_permit = client
            .start_credential_refresh(failed_permit)
            .await
            .unwrap();
        client.fail_credential_refresh(failed_permit).await.unwrap();
        let failed = authority.get_credential(&credential_id).unwrap();
        assert_eq!(
            failed.metadata.status,
            codewire_access::CredentialStatus::RefreshFailed
        );
        assert_eq!(
            failed.metadata.revocation_generation,
            recovered_revocation_generation + 1
        );
        assert!(matches!(
            client
                .lease_operation(
                    Uuid::new_v4(),
                    CapabilitySlot::codex(),
                    BrokerOperationId::parse("responses").unwrap(),
                    BrokerRouteId::parse("openai-api").unwrap(),
                )
                .await,
            Err(BrokerLeaseChannelError::Denied)
        ));
        let observed = authority.get_credential(&credential_id).unwrap();
        let recovered = authority
            .rotate_credential_material(
                &credential_id,
                observed.metadata.revocation_generation,
                ProtectedValue::from_slice(b"synthetic-reconnected-oauth-bundle").unwrap(),
                None,
                observed.metadata.account_hint,
            )
            .unwrap();
        assert_eq!(
            recovered.metadata.status,
            codewire_access::CredentialStatus::Active
        );
        assert_eq!(
            recovered.metadata.revocation_generation,
            recovered_revocation_generation + 2
        );
        drop(client);
        server.abort();
    }

    #[tokio::test]
    async fn manual_rotation_excludes_refresh_until_its_store_mutation_finishes() {
        let temp = tempfile::tempdir().unwrap();
        let store = TestProtectedStore::default();
        let get_control = Arc::new(BlockingGetControl::default());
        let authority = Arc::new(
            LocalCredentialAuthority::open(
                &temp.path().join("authority"),
                store.with_blocked_gets(Arc::clone(&get_control)),
                catalog_with_authentication(CredentialAuthKind::OAuth),
            )
            .unwrap(),
        );
        let credential = authority
            .add_credential(
                NewCredential {
                    provider: ProviderId::parse("openai").unwrap(),
                    authentication_kind: CredentialAuthKind::OAuth,
                    display_name: "synthetic-oauth".into(),
                    account_hint: None,
                    expires_at_unix: None,
                },
                ProtectedValue::from_slice(b"synthetic-old-oauth-bundle").unwrap(),
            )
            .unwrap();
        let profile = authority
            .create_profile(
                AccessProfileName::parse("synthetic-oauth").unwrap(),
                BTreeMap::from([(CapabilitySlot::codex(), credential.metadata.id.clone())]),
            )
            .unwrap();
        let environment_id = EnvironmentId::parse(Uuid::new_v4().to_string()).unwrap();
        authority
            .create_environment_access_binding(EnvironmentAccessBinding {
                environment_id: environment_id.clone(),
                profile_id: profile.profile.id,
                profile_revision: profile.profile.revision,
            })
            .unwrap();
        let request = CredentialOperationLeaseRequest {
            environment_id,
            environment_generation: 7,
            capability_slot: CapabilitySlot::codex(),
            operation: BrokerOperationId::parse("responses").unwrap(),
            route: BrokerRouteId::parse("openai-api").unwrap(),
        };
        let grant = authority
            .admit_environment_credential_operation(&request)
            .unwrap()
            .grant;

        get_control.block();
        let rotating_authority = Arc::clone(&authority);
        let rotating_id = credential.metadata.id.clone();
        let rotating_revision = credential.metadata.revocation_generation;
        let rotating_hint = credential.metadata.account_hint.clone();
        let rotation = tokio::task::spawn_blocking(move || {
            rotating_authority.rotate_credential_material(
                &rotating_id,
                rotating_revision,
                ProtectedValue::from_slice(b"synthetic-manual-rotation").unwrap(),
                None,
                rotating_hint,
            )
        });
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while get_control.counts().0 != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();

        let refreshing_authority = Arc::clone(&authority);
        let mut refresh = tokio::task::spawn_blocking(move || {
            refreshing_authority.begin_environment_credential_refresh(
                Uuid::new_v4(),
                Uuid::new_v4(),
                Uuid::new_v4(),
                &request,
                &grant,
                1,
            )
        });
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), &mut refresh)
                .await
                .is_err()
        );

        get_control.release();
        let rotated = rotation.await.unwrap().unwrap();
        assert_eq!(rotated.metadata.revocation_generation, 2);
        assert_eq!(
            refresh.await.unwrap(),
            Err(LocalCredentialError::StaleCredentialRefresh)
        );
    }

    #[tokio::test]
    async fn channel_close_defers_refresh_release_until_blocking_operation_finishes() {
        let temp = tempfile::tempdir().unwrap();
        let store = TestProtectedStore::default();
        let get_control = Arc::new(BlockingGetControl::default());
        let authority = Arc::new(
            LocalCredentialAuthority::open(
                &temp.path().join("authority"),
                store.with_blocked_gets(Arc::clone(&get_control)),
                catalog_with_authentication(CredentialAuthKind::OAuth),
            )
            .unwrap(),
        );
        let credential = authority
            .add_credential(
                NewCredential {
                    provider: ProviderId::parse("openai").unwrap(),
                    authentication_kind: CredentialAuthKind::OAuth,
                    display_name: "synthetic-oauth".into(),
                    account_hint: None,
                    expires_at_unix: None,
                },
                ProtectedValue::from_slice(b"synthetic-old-oauth-bundle").unwrap(),
            )
            .unwrap();
        let profile = authority
            .create_profile(
                AccessProfileName::parse("synthetic-oauth").unwrap(),
                BTreeMap::from([(CapabilitySlot::codex(), credential.metadata.id.clone())]),
            )
            .unwrap();
        let environment_id = EnvironmentId::parse(Uuid::new_v4().to_string()).unwrap();
        authority
            .create_environment_access_binding(EnvironmentAccessBinding {
                environment_id: environment_id.clone(),
                profile_id: profile.profile.id,
                profile_revision: profile.profile.revision,
            })
            .unwrap();
        get_control.block();
        let request = CredentialOperationLeaseRequest {
            environment_id,
            environment_generation: 7,
            capability_slot: CapabilitySlot::codex(),
            operation: BrokerOperationId::parse("responses").unwrap(),
            route: BrokerRouteId::parse("openai-api").unwrap(),
        };
        let grant = authority
            .admit_environment_credential_operation(&request)
            .unwrap()
            .grant;
        let lifetime = BrokerChannelRefreshLifetime::new(Arc::clone(&authority));
        let channel_id = lifetime.channel_id;
        let refresh_id = Uuid::new_v4();
        let operation = lifetime.acquire().unwrap();
        let blocking_authority = Arc::clone(&authority);
        let credential_id = credential.metadata.id.clone();
        let refresh = tokio::task::spawn_blocking(move || {
            let _operation = operation;
            blocking_authority.begin_environment_credential_refresh(
                channel_id,
                refresh_id,
                Uuid::new_v4(),
                &request,
                &grant,
                1,
            )
        });
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while get_control.counts().0 != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();

        lifetime.close();
        assert!(lifetime.acquire().is_none());
        assert!(matches!(
            authority.rotate_credential_material(
                &credential_id,
                credential.metadata.revocation_generation,
                ProtectedValue::from_slice(b"must-not-win").unwrap(),
                None,
                credential.metadata.account_hint.clone(),
            ),
            Err(LocalCredentialError::CredentialRefreshInProgress)
        ));

        get_control.release();
        refresh.await.unwrap().unwrap();
        let observed = authority.get_credential(&credential_id).unwrap();
        let rotated = authority
            .rotate_credential_material(
                &credential_id,
                observed.metadata.revocation_generation,
                ProtectedValue::from_slice(b"synthetic-reconnected-oauth-bundle").unwrap(),
                None,
                observed.metadata.account_hint,
            )
            .unwrap();
        assert_eq!(rotated.metadata.revocation_generation, 2);
    }

    #[tokio::test]
    async fn shutdown_barrier_waits_for_cancelled_refresh_staging_and_fences_late_writes() {
        let temp = tempfile::tempdir().unwrap();
        let store = TestProtectedStore::default();
        let authority = Arc::new(
            LocalCredentialAuthority::open(
                &temp.path().join("authority"),
                store.clone(),
                catalog_with_authentication(CredentialAuthKind::OAuth),
            )
            .unwrap(),
        );
        let credential = authority
            .add_credential(
                NewCredential {
                    provider: ProviderId::parse("openai").unwrap(),
                    authentication_kind: CredentialAuthKind::OAuth,
                    display_name: "synthetic-oauth".into(),
                    account_hint: None,
                    expires_at_unix: None,
                },
                ProtectedValue::from_slice(b"synthetic-old-oauth-bundle").unwrap(),
            )
            .unwrap();
        let profile = authority
            .create_profile(
                AccessProfileName::parse("synthetic-oauth").unwrap(),
                BTreeMap::from([(CapabilitySlot::codex(), credential.metadata.id.clone())]),
            )
            .unwrap();
        let environment_id = EnvironmentId::parse(Uuid::new_v4().to_string()).unwrap();
        authority
            .create_environment_access_binding(EnvironmentAccessBinding {
                environment_id: environment_id.clone(),
                profile_id: profile.profile.id,
                profile_revision: profile.profile.revision,
            })
            .unwrap();

        let (server_stream, client_stream) = UnixStream::pair().unwrap();
        let server = tokio::spawn(serve_broker_lease_channel(
            Arc::clone(&authority),
            server_stream,
            environment_id.clone(),
            7,
            Some(
                authority
                    .get_environment_access_binding(&environment_id)
                    .unwrap()
                    .binding,
            ),
        ));
        let get_control = Arc::new(BlockingGetControl::default());
        let mut client = LocalCredentialBrokerLeaseClient::connect(
            client_stream,
            store.with_blocked_gets(Arc::clone(&get_control)),
            environment_id.clone(),
            7,
        )
        .await
        .unwrap();
        let lease = client
            .lease_operation(
                Uuid::new_v4(),
                CapabilitySlot::codex(),
                BrokerOperationId::parse("responses").unwrap(),
                BrokerRouteId::parse("openai-api").unwrap(),
            )
            .await
            .unwrap();
        let credential_id = lease.credential.metadata.id.clone();
        let grant = lease.grant.clone();
        let BrokerCredentialRefreshAdmission::Reserved(permit) = client
            .begin_credential_refresh(
                Uuid::new_v4(),
                Uuid::new_v4(),
                grant.clone(),
                BrokerOperationId::parse("responses").unwrap(),
                BrokerRouteId::parse("openai-api").unwrap(),
                lease.material_generation(),
            )
            .await
            .unwrap()
        else {
            panic!("expected reservation");
        };
        let permit = client.start_credential_refresh(permit).await.unwrap();

        get_control.block();
        let mut staging_client = client.clone();
        let staging = tokio::spawn(async move {
            staging_client
                .commit_credential_refresh(
                    permit,
                    ProtectedValue::from_slice(b"synthetic-staged-oauth-bundle").unwrap(),
                )
                .await
        });
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while get_control.counts().0 != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        staging.abort();
        assert!(staging.await.unwrap_err().is_cancelled());

        let barrier_client = client.clone();
        let mut barrier =
            tokio::spawn(async move { barrier_client.wait_for_protected_store_operations().await });
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), &mut barrier)
                .await
                .is_err()
        );
        assert!(matches!(
            authority.rotate_credential_material(
                &credential_id,
                credential.metadata.revocation_generation,
                ProtectedValue::from_slice(b"must-not-win").unwrap(),
                None,
                credential.metadata.account_hint.clone(),
            ),
            Err(LocalCredentialError::CredentialRefreshInProgress)
        ));

        get_control.release();
        barrier.await.unwrap().unwrap();
        drop(client);
        tokio::time::timeout(std::time::Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap()
            .unwrap();

        let (server_stream, client_stream) = UnixStream::pair().unwrap();
        let server = tokio::spawn(serve_broker_lease_channel(
            Arc::clone(&authority),
            server_stream,
            environment_id.clone(),
            7,
            Some(
                authority
                    .get_environment_access_binding(&environment_id)
                    .unwrap()
                    .binding,
            ),
        ));
        let mut client = LocalCredentialBrokerLeaseClient::connect(
            client_stream,
            store.with_blocked_gets(Arc::clone(&get_control)),
            environment_id,
            7,
        )
        .await
        .unwrap();
        assert_eq!(
            client
                .begin_credential_refresh(
                    Uuid::new_v4(),
                    Uuid::new_v4(),
                    grant,
                    BrokerOperationId::parse("responses").unwrap(),
                    BrokerRouteId::parse("openai-api").unwrap(),
                    1,
                )
                .await,
            Ok(BrokerCredentialRefreshAdmission::Recovered)
        );
        let recovered = client
            .lease_operation(
                Uuid::new_v4(),
                CapabilitySlot::codex(),
                BrokerOperationId::parse("responses").unwrap(),
                BrokerRouteId::parse("openai-api").unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(recovered.material_generation(), 2);
        let recovered_grant = recovered.grant.clone();
        assert_eq!(
            recovered.with_material(|value| value.to_vec()),
            b"synthetic-staged-oauth-bundle"
        );
        let BrokerCredentialRefreshAdmission::Reserved(reservation) = client
            .begin_credential_refresh(
                Uuid::new_v4(),
                Uuid::new_v4(),
                recovered_grant.clone(),
                BrokerOperationId::parse("responses").unwrap(),
                BrokerRouteId::parse("openai-api").unwrap(),
                2,
            )
            .await
            .unwrap()
        else {
            panic!("expected reservation");
        };
        let mut started = client.start_credential_refresh(reservation).await.unwrap();
        // Shorten only this synthetic client's fence. The real authority
        // persists the shared 90s bound; no production clock hook is needed.
        started.execution_deadline_unix_ms = crate::unix_millis().unwrap() + 1_000;
        let deadline = started.execution_deadline_unix_ms;
        get_control.block();
        let mut late_client = client.clone();
        let late_write = tokio::spawn(async move {
            late_client
                .commit_credential_refresh(
                    started,
                    ProtectedValue::from_slice(b"must-not-stage-after-deadline").unwrap(),
                )
                .await
        });
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while get_control.counts().0 != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(
            deadline.saturating_sub(crate::unix_millis().unwrap()) + 1,
        ))
        .await;
        get_control.release();
        assert_eq!(
            late_write.await.unwrap(),
            Err(BrokerLeaseChannelError::Unavailable)
        );
        client.wait_for_protected_store_operations().await.unwrap();
        assert!(
            authority
                .protected_store
                .get(&protected_entry_id(&credential_id, 3).unwrap())
                .unwrap()
                .is_none()
        );
        drop(client);
        tokio::time::timeout(std::time::Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let request = CredentialOperationLeaseRequest {
            environment_id: recovered_grant.environment_id.clone(),
            environment_generation: recovered_grant.environment_generation,
            capability_slot: recovered_grant.capability_slot.clone(),
            operation: BrokerOperationId::parse("responses").unwrap(),
            route: BrokerRouteId::parse("openai-api").unwrap(),
        };
        assert!(
            authority
                .begin_environment_credential_refresh(
                    Uuid::new_v4(),
                    Uuid::new_v4(),
                    Uuid::new_v4(),
                    &request,
                    &recovered_grant,
                    2
                )
                .is_err()
        );
        assert_eq!(
            authority
                .get_credential(&credential_id)
                .unwrap()
                .metadata
                .status,
            codewire_access::CredentialStatus::RefreshFailed
        );
    }

    #[tokio::test]
    async fn cancelled_leases_do_not_release_blocking_store_capacity_early() {
        let temp = tempfile::tempdir().unwrap();
        let store = TestProtectedStore::default();
        let authority = Arc::new(
            LocalCredentialAuthority::open(
                &temp.path().join("authority"),
                store.clone(),
                catalog(),
            )
            .unwrap(),
        );
        let credential = authority
            .add_credential(
                NewCredential {
                    provider: ProviderId::parse("openai").unwrap(),
                    authentication_kind: CredentialAuthKind::ApiKey,
                    display_name: "synthetic".into(),
                    account_hint: None,
                    expires_at_unix: None,
                },
                ProtectedValue::from_slice(b"synthetic-openai-material").unwrap(),
            )
            .unwrap();
        let profile = authority
            .create_profile(
                AccessProfileName::parse("synthetic").unwrap(),
                BTreeMap::from([(CapabilitySlot::codex(), credential.metadata.id)]),
            )
            .unwrap();
        let environment_id = EnvironmentId::parse(Uuid::new_v4().to_string()).unwrap();
        authority
            .create_environment_access_binding(EnvironmentAccessBinding {
                environment_id: environment_id.clone(),
                profile_id: profile.profile.id,
                profile_revision: profile.profile.revision,
            })
            .unwrap();

        let (server_stream, client_stream) = UnixStream::pair().unwrap();
        let server = tokio::spawn(serve_broker_lease_channel(
            Arc::clone(&authority),
            server_stream,
            environment_id.clone(),
            7,
            Some(
                authority
                    .get_environment_access_binding(&environment_id)
                    .unwrap()
                    .binding,
            ),
        ));
        let get_control = BlockingGetControl::blocked();
        let client_store = store.with_blocked_gets(Arc::clone(&get_control));
        let client = LocalCredentialBrokerLeaseClient::connect(
            client_stream,
            client_store,
            environment_id,
            7,
        )
        .await
        .unwrap();

        let spawn_lease = |mut client: LocalCredentialBrokerLeaseClient<TestProtectedStore>| {
            tokio::spawn(async move {
                client
                    .lease_operation(
                        Uuid::new_v4(),
                        CapabilitySlot::codex(),
                        BrokerOperationId::parse("responses").unwrap(),
                        BrokerRouteId::parse("openai-api").unwrap(),
                    )
                    .await
            })
        };
        let first = (0..MAX_BROKER_PROTECTED_STORE_OPERATIONS)
            .map(|_| spawn_lease(client.clone()))
            .collect::<Vec<_>>();
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while get_control.counts().0 != MAX_BROKER_PROTECTED_STORE_OPERATIONS {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        for task in &first {
            task.abort();
        }
        for task in first {
            assert!(task.await.unwrap_err().is_cancelled());
        }

        let second = (0..MAX_BROKER_PROTECTED_STORE_OPERATIONS)
            .map(|_| spawn_lease(client.clone()))
            .collect::<Vec<_>>();
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), async {
                while get_control.counts().1 <= MAX_BROKER_PROTECTED_STORE_OPERATIONS {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .is_err()
        );
        assert_eq!(
            get_control.counts(),
            (
                MAX_BROKER_PROTECTED_STORE_OPERATIONS,
                MAX_BROKER_PROTECTED_STORE_OPERATIONS
            )
        );

        get_control.release();
        for task in second {
            assert!(task.await.unwrap().is_ok());
        }
        assert_eq!(
            get_control.counts(),
            (0, MAX_BROKER_PROTECTED_STORE_OPERATIONS)
        );
        drop(client);
        server.abort();
    }

    #[tokio::test]
    async fn recent_lease_audit_ring_is_bounded_and_newest_first() {
        let audit = BrokerLeaseAuditLog::default();
        for _ in 0..(MAX_RECENT_BROKER_LEASE_AUDIT_EVENTS + 3) {
            audit
                .record(BrokerLeaseAuditEvent {
                    sequence: 0,
                    observed_at_unix_ms: 0,
                    environment_id: EnvironmentId::parse("environment").unwrap(),
                    environment_generation: 1,
                    request_id: Uuid::new_v4(),
                    capability_slot: CapabilitySlot::codex(),
                    operation: BrokerOperationId::parse("responses").unwrap(),
                    route: BrokerRouteId::parse("openai-api").unwrap(),
                    decision: BrokerLeaseAuditDecision::Denied,
                    credential_id: None,
                    profile_id: None,
                    profile_revision: None,
                    credential_revocation_generation: None,
                })
                .await;
        }
        assert_eq!(
            audit.state.lock().await.events.len(),
            MAX_RECENT_BROKER_LEASE_AUDIT_EVENTS
        );
        let recent = audit.recent(16).await;
        assert_eq!(recent.len(), 16);
        assert!(
            recent
                .windows(2)
                .all(|pair| pair[0].sequence > pair[1].sequence)
        );
    }
}
