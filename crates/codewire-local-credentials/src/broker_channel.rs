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
use std::task::{Context, Poll};

use codewire_access::{
    AccessProfileId, BrokerOperationId, BrokerRouteId, CapabilitySlot, CredentialId, EnvironmentId,
    GrantPermission,
};
use codewire_protected_store::ProtectedStore;
use hyper_util::rt::TokioIo;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::UnixStream;
use tokio::sync::{Mutex, Semaphore, oneshot};
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
    CredentialOperationLease, CredentialOperationLeaseRequest, LocalCredentialAuthority,
    LocalCredentialError, protected_entry_id,
};

const BROKER_CHANNEL_REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
const MAX_BROKER_LEASE_RPC_MESSAGE_BYTES: usize = 64 * 1024;
const MAX_BROKER_LEASE_RPC_CONCURRENCY: usize = 16;
const MAX_BROKER_PROTECTED_STORE_OPERATIONS: usize = 1;
pub(crate) const MAX_RECENT_BROKER_LEASE_AUDIT_EVENTS: usize = 4_096;
pub(crate) const MAX_BROKER_LEASE_AUDIT_LIST_LIMIT: usize = 256;
pub const BROKER_LEASE_PROTOCOL_VERSION: u32 = 2;

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
}

/// Client for one authority-created, environment-generation-bound channel.
///
/// Construction requires the connected inherited stream; there is no socket
/// path or general connector that another owner process can discover.
pub struct LocalCredentialBrokerLeaseClient<S> {
    inner: LocalCredentialBrokerLeaseServiceClient<Channel>,
    protected_store: S,
    protected_store_operations: Arc<Semaphore>,
    environment_id: EnvironmentId,
    environment_generation: u64,
}

impl<S: Clone> Clone for LocalCredentialBrokerLeaseClient<S> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            protected_store: self.protected_store.clone(),
            protected_store_operations: Arc::clone(&self.protected_store_operations),
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
            value,
        })
    }

    /// Complete the authority-owned launch handshake only after the broker has
    /// authenticated and opened the matching guest-daemon bridge.
    pub async fn report_ready(&mut self) -> Result<(), BrokerLeaseChannelError> {
        self.inner
            .report_broker_ready(v1::BrokerReadyRequest {
                protocol_version: BROKER_LEASE_PROTOCOL_VERSION,
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
) -> Result<(), BrokerLeaseChannelError>
where
    S: ProtectedStore + 'static,
{
    serve_broker_lease_channel_with_ready(
        authority,
        stream,
        environment_id,
        environment_generation,
        Arc::new(BrokerLeaseAuditLog::default()),
        None,
    )
    .await
}

pub(crate) async fn serve_broker_lease_channel_with_ready<S>(
    authority: Arc<LocalCredentialAuthority<S>>,
    stream: UnixStream,
    environment_id: EnvironmentId,
    environment_generation: u64,
    audit: Arc<BrokerLeaseAuditLog>,
    ready: Option<oneshot::Sender<()>>,
) -> Result<(), BrokerLeaseChannelError>
where
    S: ProtectedStore + 'static,
{
    if environment_generation == 0 {
        return Err(BrokerLeaseChannelError::InvalidRequest);
    }
    let service = BrokerLeaseRpc {
        authority,
        environment_id,
        environment_generation,
        audit,
        ready: Mutex::new(ready),
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
    Server::builder()
        .concurrency_limit_per_connection(MAX_BROKER_LEASE_RPC_CONCURRENCY)
        .add_service(
            LocalCredentialBrokerLeaseServiceServer::new(service)
                .max_decoding_message_size(MAX_BROKER_LEASE_RPC_MESSAGE_BYTES)
                .max_encoding_message_size(MAX_BROKER_LEASE_RPC_MESSAGE_BYTES),
        )
        .serve_with_incoming_shutdown(incoming, async move {
            let _ = closed_rx.await;
        })
        .await
        .map_err(|_| BrokerLeaseChannelError::Unavailable)
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
    authority: Arc<LocalCredentialAuthority<S>>,
    environment_id: EnvironmentId,
    environment_generation: u64,
    audit: Arc<BrokerLeaseAuditLog>,
    ready: Mutex<Option<oneshot::Sender<()>>>,
}

#[tonic::async_trait]
impl<S> LocalCredentialBrokerLeaseService for BrokerLeaseRpc<S>
where
    S: ProtectedStore + 'static,
{
    async fn report_broker_ready(
        &self,
        request: Request<v1::BrokerReadyRequest>,
    ) -> Result<Response<v1::BrokerReadyResponse>, Status> {
        if request.into_inner().protocol_version != BROKER_LEASE_PROTOCOL_VERSION {
            return Err(Status::failed_precondition(
                "credential broker lease protocol is incompatible",
            ));
        }
        let ready = self
            .ready
            .lock()
            .await
            .take()
            .ok_or_else(|| Status::failed_precondition("credential broker is already ready"))?;
        ready
            .send(())
            .map_err(|_| Status::unavailable("credential broker launch was cancelled"))?;
        Ok(Response::new(v1::BrokerReadyResponse {}))
    }

    async fn lease_credential_operation(
        &self,
        request: Request<v1::BrokerLeaseRequest>,
    ) -> Result<Response<v1::BrokerLeaseResponse>, Status> {
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
        let admission = match tokio::task::spawn_blocking(move || {
            authority.admit_environment_credential_operation(&admission_request)
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
        tonic::Code::FailedPrecondition | tonic::Code::PermissionDenied => {
            BrokerLeaseChannelError::Denied
        }
        _ => BrokerLeaseChannelError::Unavailable,
    }
}

fn map_server_error(error: LocalCredentialError) -> Status {
    match error {
        LocalCredentialError::CredentialOperationLeaseDenied
        | LocalCredentialError::CredentialInactive
        | LocalCredentialError::CredentialUnavailable
        | LocalCredentialError::CredentialMaterialMissing
        | LocalCredentialError::CredentialNotFound
        | LocalCredentialError::EnvironmentBindingNotFound
        | LocalCredentialError::ProfileNotFound
        | LocalCredentialError::ProfileRevisionNotFound
        | LocalCredentialError::StaleProfileRevision
        | LocalCredentialError::Access(_) => {
            Status::failed_precondition("credential broker lease was denied")
        }
        _ => Status::unavailable("credential broker lease authority is unavailable"),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
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
            }
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
            Ok(())
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
        ProviderCatalog::from_definitions([ProviderDefinition {
            id: ProviderId::parse("openai").unwrap(),
            capabilities: BTreeMap::from([(
                CapabilitySlot::codex(),
                CapabilityPolicy {
                    authentication_kinds: BTreeSet::from([CredentialAuthKind::ApiKey]),
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
            Arc::clone(&authority),
            server_stream,
            environment_id.clone(),
            7,
            Arc::clone(&audit),
            None,
        ));
        let mut client =
            LocalCredentialBrokerLeaseClient::connect(client_stream, store, environment_id, 7)
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
            authority,
            server_stream,
            environment_id.clone(),
            7,
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
