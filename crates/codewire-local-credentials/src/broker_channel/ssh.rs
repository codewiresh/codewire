use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};

use codewire_access::{
    BrokerOperationId, BrokerRouteId, CapabilitySlot, CredentialAuthKind, GrantPermission,
};
use codewire_daemon_proto::codewire::bridge::v1 as daemon_v1;
use codewire_daemon_proto::ssh::{
    SshOperation, remaining_deadline, validate_request, validate_response,
};
use codewire_protected_store::ssh_material::{
    SshAgentMaterial, SshKeyAlgorithm, decode_protected_material, parse_public_key,
};
use thiserror::Error;
use tokio::sync::{OwnedSemaphorePermit, oneshot, watch};
use tokio::time::Instant;
use tonic::{Response, Status};
use uuid::Uuid;
use zeroize::Zeroizing;

#[cfg(test)]
mod tests;

use super::{
    BROKER_LEASE_PROTOCOL_VERSION, BrokerChannelRefreshLifetime, BrokerChannelRefreshOperation,
    BrokerLeaseAuditDecision, BrokerLeaseAuditEvent, BrokerLeaseAuditLog, BrokerLeaseRpc,
};
use crate::control::v1;
use crate::{
    CredentialOperationAdmission, CredentialOperationLeaseRequest, LocalCredentialAuthority,
    LocalCredentialError,
};

const MAX_ACTIVE_SSH_OPERATIONS: usize = 8;
const SSH_OPERATION_CLEANUP_TAIL: std::time::Duration = std::time::Duration::from_secs(10);

/// Closed typed input to one selected-key signer. It contains no route,
/// credential selector, environment coordinate, or arbitrary agent frame.
pub struct LocalSshSignRequest {
    pub public_key_blob: Vec<u8>,
    pub data: Zeroizing<Vec<u8>>,
    pub flags: u32,
}

impl std::fmt::Debug for LocalSshSignRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LocalSshSignRequest")
            .field("public_key_blob", &self.public_key_blob)
            .field("data", &"[REDACTED]")
            .field("flags", &self.flags)
            .finish()
    }
}

/// Stable failures from the injected signer. No OpenSSH output or material
/// parser detail may cross this boundary.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum LocalSshSignError {
    #[error("local SSH signing is unavailable")]
    Unavailable,
    #[error("local SSH signing was denied")]
    Denied,
    #[error("local SSH signing deadline elapsed")]
    Expired,
    #[error("local SSH signing cleanup failed")]
    Cleanup,
}

/// Process-composed selected-key signer. A call must start at most one agent
/// and return only after that exact worker has been cancelled and drained.
#[tonic::async_trait]
pub trait LocalSshSigner: Send + Sync + 'static {
    async fn sign_once(
        &self,
        material: SshAgentMaterial,
        request: LocalSshSignRequest,
        deadline: Instant,
        cancellation: watch::Receiver<bool>,
    ) -> Result<Vec<u8>, LocalSshSignError>;
}

pub(crate) struct LocalSshOperationRuntime {
    signer: Option<Arc<dyn LocalSshSigner>>,
    permits: Arc<tokio::sync::Semaphore>,
    unhealthy: AtomicBool,
}

impl LocalSshOperationRuntime {
    pub(crate) fn new(signer: Option<Arc<dyn LocalSshSigner>>) -> Arc<Self> {
        Arc::new(Self {
            signer,
            permits: Arc::new(tokio::sync::Semaphore::new(MAX_ACTIVE_SSH_OPERATIONS)),
            unhealthy: AtomicBool::new(false),
        })
    }

    pub(crate) fn signer(&self) -> Result<Arc<dyn LocalSshSigner>, LocalSshSignError> {
        if self.unhealthy.load(Ordering::Acquire) {
            return Err(LocalSshSignError::Cleanup);
        }
        self.signer
            .as_ref()
            .cloned()
            .ok_or(LocalSshSignError::Unavailable)
    }

    pub(crate) fn acquire(&self) -> Result<OwnedSemaphorePermit, LocalSshSignError> {
        if self.unhealthy.load(Ordering::Acquire) {
            return Err(LocalSshSignError::Cleanup);
        }
        let permit = Arc::clone(&self.permits)
            .try_acquire_owned()
            .map_err(|_| LocalSshSignError::Unavailable)?;
        if self.unhealthy.load(Ordering::Acquire) {
            return Err(LocalSshSignError::Cleanup);
        }
        Ok(permit)
    }

    pub(crate) fn is_unhealthy(&self) -> bool {
        self.unhealthy.load(Ordering::Acquire)
    }

    pub(crate) fn ensure_healthy(&self) -> Result<(), LocalSshSignError> {
        if self.unhealthy.load(Ordering::Acquire) {
            Err(LocalSshSignError::Cleanup)
        } else {
            Ok(())
        }
    }

    pub(crate) fn latch_cleanup_failure(&self) {
        self.unhealthy.store(true, Ordering::Release);
    }
}

pub(super) struct ChannelSshOperations {
    active: StdMutex<HashMap<Uuid, watch::Sender<bool>>>,
    runtime: Arc<LocalSshOperationRuntime>,
    cleanup_failed: AtomicBool,
}

impl ChannelSshOperations {
    pub(super) fn new(runtime: Arc<LocalSshOperationRuntime>) -> Self {
        Self {
            active: StdMutex::new(HashMap::new()),
            runtime,
            cleanup_failed: AtomicBool::new(false),
        }
    }

    pub(super) fn cancel_all(&self) {
        let active = self
            .active
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        for cancellation in active.values() {
            cancellation.send_replace(true);
        }
    }

    pub(super) fn cleanup_failed(&self) -> bool {
        self.cleanup_failed.load(Ordering::Acquire)
    }

    fn latch_cleanup_failure(&self) {
        self.cleanup_failed.store(true, Ordering::Release);
        self.runtime.latch_cleanup_failure();
    }
}

pub(super) struct ChannelSshOperation<S: codewire_protected_store::ProtectedStore> {
    lifetime: Arc<BrokerChannelRefreshLifetime<S>>,
    permit: Option<OwnedSemaphorePermit>,
    channel_operation: Option<BrokerChannelRefreshOperation<S>>,
    request_id: Uuid,
    cancellation: watch::Sender<bool>,
}

impl<S: codewire_protected_store::ProtectedStore> ChannelSshOperation<S> {
    fn cancellation(&self) -> watch::Receiver<bool> {
        self.cancellation.subscribe()
    }

    fn ensure_live(
        &self,
        deadline: Instant,
        deadline_unix_ms: u64,
    ) -> Result<(), LocalSshSignError> {
        self.lifetime.ssh_operations.runtime.ensure_healthy()?;
        if *self.cancellation.borrow()
            || self.lifetime.closed.load(Ordering::Acquire)
            || Instant::now() >= deadline
            || remaining_deadline(deadline_unix_ms).is_err()
        {
            return Err(LocalSshSignError::Expired);
        }
        Ok(())
    }
}

impl<S: codewire_protected_store::ProtectedStore> Drop for ChannelSshOperation<S> {
    fn drop(&mut self) {
        self.cancellation.send_replace(true);
        drop(self.permit.take());
        self.lifetime
            .ssh_operations
            .active
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .remove(&self.request_id);
        // This decrement may wake channel drain, so it must be last.
        drop(self.channel_operation.take());
    }
}

struct OperationCompletionGuard<S: codewire_protected_store::ProtectedStore> {
    operation: Option<ChannelSshOperation<S>>,
    completed: bool,
}

impl<S: codewire_protected_store::ProtectedStore> OperationCompletionGuard<S> {
    fn new(operation: ChannelSshOperation<S>) -> Self {
        Self {
            operation: Some(operation),
            completed: false,
        }
    }

    fn operation(&self) -> &ChannelSshOperation<S> {
        self.operation
            .as_ref()
            .expect("SSH operation remains owned until completion")
    }

    fn complete(mut self) {
        self.completed = true;
        drop(self.operation.take());
    }
}

impl<S: codewire_protected_store::ProtectedStore> Drop for OperationCompletionGuard<S> {
    fn drop(&mut self) {
        if !self.completed
            && let Some(operation) = self.operation.as_ref()
        {
            operation.lifetime.ssh_operations.latch_cleanup_failure();
        }
        drop(self.operation.take());
    }
}

struct RequestCancellationGuard(watch::Sender<bool>);

impl Drop for RequestCancellationGuard {
    fn drop(&mut self) {
        self.0.send_replace(true);
    }
}

impl<S: codewire_protected_store::ProtectedStore> BrokerChannelRefreshLifetime<S> {
    fn acquire_ssh_operation(
        self: &Arc<Self>,
        request_id: Uuid,
        signing: bool,
    ) -> Result<ChannelSshOperation<S>, Status> {
        self.ssh_operations
            .runtime
            .ensure_healthy()
            .map_err(sign_error_status)?;
        let channel_operation = self.acquire().ok_or_else(unavailable)?;
        let permit = signing
            .then(|| self.ssh_operations.runtime.acquire())
            .transpose()
            .map_err(sign_error_status)?;
        let (cancellation, _) = watch::channel(false);
        let mut active = self
            .ssh_operations
            .active
            .lock()
            .map_err(|_| unavailable())?;
        if self.closed.load(Ordering::Acquire) {
            return Err(unavailable());
        }
        match active.entry(request_id) {
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(cancellation.clone());
            }
            std::collections::hash_map::Entry::Occupied(_) => {
                return Err(Status::invalid_argument("duplicate local SSH request ID"));
            }
        }
        drop(active);
        Ok(ChannelSshOperation {
            lifetime: Arc::clone(self),
            permit,
            channel_operation: Some(channel_operation),
            request_id,
            cancellation,
        })
    }
}

impl<S> BrokerLeaseRpc<S>
where
    S: codewire_protected_store::ProtectedStore + 'static,
{
    pub(super) async fn run_ssh_operation(
        &self,
        request: v1::BrokerSshRequest,
    ) -> Result<Response<daemon_v1::CredentialSshResponse>, Status> {
        if request.protocol_version != BROKER_LEASE_PROTOCOL_VERSION {
            return Err(Status::failed_precondition(
                "credential broker lease protocol is incompatible",
            ));
        }
        let request = request
            .request
            .ok_or_else(|| Status::invalid_argument("invalid local SSH operation"))?;
        let operation = validate_request(&request)?;
        let request_id = Uuid::parse_str(&request.request_id)
            .map_err(|_| Status::invalid_argument("invalid local SSH operation"))?;
        let deadline_unix_ms = request.deadline_unix_ms;
        let remaining = remaining_deadline(deadline_unix_ms)?;
        let deadline = Instant::now()
            .checked_add(remaining)
            .ok_or_else(unavailable)?;
        let operation_guard = self
            .refresh_lifetime
            .acquire_ssh_operation(request_id, operation == SshOperation::Sign)?;
        let request_cancel = operation_guard.cancellation.clone();
        let _request_guard = RequestCancellationGuard(request_cancel);
        let authority = Arc::clone(&self.authority);
        let audit = Arc::clone(&self.audit);
        let lifetime = Arc::clone(&self.refresh_lifetime);
        let selected = self.local_profile.clone();
        let lease_request = CredentialOperationLeaseRequest {
            environment_id: self.environment_id.clone(),
            environment_generation: self.environment_generation,
            capability_slot: CapabilitySlot::parse("ssh").expect("canonical SSH capability slot"),
            operation: BrokerOperationId::parse(match operation {
                SshOperation::Identities => "ssh-identities",
                SshOperation::Sign => "ssh-sign",
            })
            .expect("canonical SSH operation"),
            route: BrokerRouteId::parse("ssh-agent").expect("canonical SSH agent route"),
        };
        let (response_tx, receiver) = oneshot::channel();
        tokio::spawn(async move {
            let completion = OperationCompletionGuard::new(operation_guard);
            let mut release_deadline = deadline;
            let result = execute_operation(
                authority,
                audit,
                completion.operation(),
                lease_request,
                selected,
                request,
                operation,
                &mut release_deadline,
            )
            .await;
            if matches!(result, Err(LocalSshSignError::Cleanup)) {
                lifetime.ssh_operations.latch_cleanup_failure();
            }
            let request_id = completion.operation().request_id;
            let response = operation_response(request_id, operation, result);
            // The terminal response proves both signer drain and release of the
            // authority's global operation capacity/active-ID reservation.
            completion.complete();
            let _ = response_tx.send((response, release_deadline));
        });
        let (response, release_deadline) = receiver.await.map_err(|_| unavailable())?;
        let response = response?;
        if Instant::now() >= release_deadline || remaining_deadline(deadline_unix_ms).is_err() {
            return Ok(Response::new(operation_response(
                request_id,
                operation,
                Err(LocalSshSignError::Expired),
            )?));
        }
        Ok(Response::new(response))
    }
}

// Keep the immutable parent selection separate from the guest operation.
#[allow(clippy::too_many_arguments)]
async fn execute_operation<S: codewire_protected_store::ProtectedStore + 'static>(
    authority: Arc<LocalCredentialAuthority<S>>,
    audit: Arc<BrokerLeaseAuditLog>,
    operation_guard: &ChannelSshOperation<S>,
    lease_request: CredentialOperationLeaseRequest,
    selected: Option<codewire_access::EnvironmentAccessBinding>,
    request: daemon_v1::CredentialSshRequest,
    operation: SshOperation,
    deadline: &mut Instant,
) -> Result<daemon_v1::credential_ssh_response::Result, LocalSshSignError> {
    let deadline_unix_ms = request.deadline_unix_ms;
    operation_guard.ensure_live(*deadline, deadline_unix_ms)?;
    let admission = revalidate(
        Arc::clone(&authority),
        lease_request.clone(),
        selected.clone(),
        None,
        operation_guard,
        *deadline,
        deadline_unix_ms,
    )
    .await;
    record_admission(
        &audit,
        operation_guard.request_id,
        &lease_request,
        admission.as_ref().ok(),
        admission.as_ref().err().copied(),
    )
    .await;
    let admission = admission?;
    let public = admitted_public_key(&admission, operation)?;
    *deadline = clamp_admitted_deadline(&admission, *deadline)?;
    if operation == SshOperation::Identities {
        operation_guard.ensure_live(*deadline, deadline_unix_ms)?;
        revalidate(
            authority,
            lease_request,
            selected,
            Some(admission),
            operation_guard,
            *deadline,
            deadline_unix_ms,
        )
        .await?;
        return Ok(daemon_v1::credential_ssh_response::Result::Identity(
            daemon_v1::CredentialSshIdentity {
                public_key_blob: public.key_blob().to_vec(),
            },
        ));
    }

    let daemon_v1::credential_ssh_request::Operation::Sign(sign) =
        request.operation.ok_or(LocalSshSignError::Denied)?
    else {
        return Err(LocalSshSignError::Denied);
    };
    if sign.public_key_blob != public.key_blob() {
        return Err(LocalSshSignError::Denied);
    }
    match (public.algorithm(), sign.flags) {
        (SshKeyAlgorithm::Ed25519, 0) | (SshKeyAlgorithm::Rsa { .. }, 2 | 4) => {}
        _ => return Err(LocalSshSignError::Denied),
    }
    operation_guard.ensure_live(*deadline, deadline_unix_ms)?;
    let material_admission = admission.clone();
    let material_authority = Arc::clone(&authority);
    let material = tokio::task::spawn_blocking(move || {
        material_authority
            .read_admitted_credential_material(&material_admission)
            .map_err(|_| LocalSshSignError::Unavailable)
            .and_then(|value| {
                decode_protected_material(value).map_err(|_| LocalSshSignError::Unavailable)
            })
    })
    .await
    .map_err(|_| LocalSshSignError::Unavailable)??;
    operation_guard.ensure_live(*deadline, deadline_unix_ms)?;
    if material.public_key() != &public {
        return Err(LocalSshSignError::Unavailable);
    }
    revalidate(
        Arc::clone(&authority),
        lease_request.clone(),
        selected.clone(),
        Some(admission.clone()),
        operation_guard,
        *deadline,
        deadline_unix_ms,
    )
    .await?;
    let signer = operation_guard.lifetime.ssh_operations.runtime.signer()?;
    let signature = signer
        .sign_once(
            material,
            LocalSshSignRequest {
                public_key_blob: sign.public_key_blob,
                data: Zeroizing::new(sign.data),
                flags: sign.flags,
            },
            *deadline,
            operation_guard.cancellation(),
        )
        .await?;
    operation_guard.ensure_live(*deadline, deadline_unix_ms)?;
    revalidate(
        authority,
        lease_request,
        selected,
        Some(admission),
        operation_guard,
        *deadline,
        deadline_unix_ms,
    )
    .await?;
    Ok(daemon_v1::credential_ssh_response::Result::Signature(
        daemon_v1::CredentialSshSignature {
            signature_blob: signature,
        },
    ))
}

async fn record_admission(
    audit: &BrokerLeaseAuditLog,
    request_id: Uuid,
    request: &CredentialOperationLeaseRequest,
    admission: Option<&CredentialOperationAdmission>,
    error: Option<LocalSshSignError>,
) {
    audit
        .record(BrokerLeaseAuditEvent {
            sequence: 0,
            observed_at_unix_ms: 0,
            environment_id: request.environment_id.clone(),
            environment_generation: request.environment_generation,
            request_id,
            capability_slot: request.capability_slot.clone(),
            operation: request.operation.clone(),
            route: request.route.clone(),
            decision: match error {
                None => BrokerLeaseAuditDecision::Admitted,
                Some(LocalSshSignError::Denied | LocalSshSignError::Expired) => {
                    BrokerLeaseAuditDecision::Denied
                }
                Some(LocalSshSignError::Unavailable | LocalSshSignError::Cleanup) => {
                    BrokerLeaseAuditDecision::Unavailable
                }
            },
            credential_id: admission.map(|value| value.credential.metadata.id.clone()),
            profile_id: admission.and_then(|value| {
                value
                    .grant
                    .profile
                    .as_ref()
                    .map(|profile| profile.id.clone())
            }),
            profile_revision: admission
                .and_then(|value| value.grant.profile.as_ref().map(|profile| profile.revision)),
            credential_revocation_generation: admission
                .map(|value| value.grant.credential_revocation_generation),
        })
        .await;
}

async fn revalidate<S: codewire_protected_store::ProtectedStore + 'static>(
    authority: Arc<LocalCredentialAuthority<S>>,
    request: CredentialOperationLeaseRequest,
    selected: Option<codewire_access::EnvironmentAccessBinding>,
    captured: Option<CredentialOperationAdmission>,
    operation: &ChannelSshOperation<S>,
    deadline: Instant,
    deadline_unix_ms: u64,
) -> Result<CredentialOperationAdmission, LocalSshSignError> {
    operation.ensure_live(deadline, deadline_unix_ms)?;
    let result = tokio::task::spawn_blocking(move || match captured {
        Some(captured) => authority
            .revalidate_credential_operation(&request, &captured)
            .map(|()| captured),
        None => {
            authority.admit_selected_environment_credential_operation(&request, selected.as_ref())
        }
    })
    .await
    .map_err(|_| LocalSshSignError::Unavailable)?
    .map_err(map_authority_error)?;
    operation.ensure_live(deadline, deadline_unix_ms)?;
    Ok(result)
}

fn admitted_public_key(
    admission: &CredentialOperationAdmission,
    operation: SshOperation,
) -> Result<codewire_protected_store::ssh_material::SshPublicKey, LocalSshSignError> {
    let metadata = &admission.credential.metadata;
    if metadata.provider.as_str() != "ssh"
        || metadata.authentication_kind != CredentialAuthKind::SshKey
        || admission.permission
            != (GrantPermission {
                operation: BrokerOperationId::parse(match operation {
                    SshOperation::Identities => "ssh-identities",
                    SshOperation::Sign => "ssh-sign",
                })
                .expect("canonical SSH operation"),
                route: BrokerRouteId::parse("ssh-agent").expect("canonical SSH agent route"),
            })
    {
        return Err(LocalSshSignError::Denied);
    }
    let public = metadata
        .ssh_public_key
        .as_ref()
        .ok_or(LocalSshSignError::Unavailable)?;
    parse_public_key(&public.openssh, &public.fingerprint)
        .map_err(|_| LocalSshSignError::Unavailable)
}

fn clamp_admitted_deadline(
    admission: &CredentialOperationAdmission,
    request_deadline: Instant,
) -> Result<Instant, LocalSshSignError> {
    let expiration = [
        admission.grant.expires_at_unix,
        admission.credential.metadata.expires_at_unix,
    ]
    .into_iter()
    .flatten()
    .min();
    let Some(expiration) = expiration else {
        return Ok(request_deadline);
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| LocalSshSignError::Unavailable)?;
    let remaining = std::time::Duration::from_secs(expiration)
        .checked_sub(now)
        .filter(|remaining| !remaining.is_zero())
        .ok_or(LocalSshSignError::Expired)?;
    let expiration_deadline = Instant::now()
        .checked_add(remaining)
        .ok_or(LocalSshSignError::Unavailable)?;
    Ok(request_deadline.min(expiration_deadline))
}

fn operation_response(
    request_id: Uuid,
    operation: SshOperation,
    result: Result<daemon_v1::credential_ssh_response::Result, LocalSshSignError>,
) -> Result<daemon_v1::CredentialSshResponse, Status> {
    let result = match result {
        Ok(result) => result,
        Err(LocalSshSignError::Denied) => daemon_v1::credential_ssh_response::Result::Failure(
            daemon_v1::CredentialBridgeFailureReason::Denied as i32,
        ),
        Err(LocalSshSignError::Expired) => daemon_v1::credential_ssh_response::Result::Failure(
            daemon_v1::CredentialBridgeFailureReason::Unavailable as i32,
        ),
        Err(LocalSshSignError::Unavailable | LocalSshSignError::Cleanup) => {
            return Err(unavailable());
        }
    };
    let response = daemon_v1::CredentialSshResponse {
        request_id: request_id.to_string(),
        result: Some(result),
    };
    validate_response(&response, operation).map_err(|_| unavailable())?;
    Ok(response)
}

fn map_authority_error(error: LocalCredentialError) -> LocalSshSignError {
    match error {
        LocalCredentialError::CredentialOperationLeaseDenied
        | LocalCredentialError::CredentialInactive
        | LocalCredentialError::EnvironmentBindingNotFound
        | LocalCredentialError::StaleEnvironmentBinding
        | LocalCredentialError::ProfileNotFound
        | LocalCredentialError::ProfileRevisionNotFound
        // Grant derivation reports inactive/revoked identities through the
        // shared policy error, not only CredentialInactive. Preserve denial
        // (and its audit decision), just like the HTTP lease boundary.
        | LocalCredentialError::Access(_) => LocalSshSignError::Denied,
        _ => LocalSshSignError::Unavailable,
    }
}

fn sign_error_status(error: LocalSshSignError) -> Status {
    match error {
        LocalSshSignError::Denied => Status::permission_denied("local SSH operation was denied"),
        LocalSshSignError::Unavailable
        | LocalSshSignError::Expired
        | LocalSshSignError::Cleanup => unavailable(),
    }
}

fn unavailable() -> Status {
    Status::unavailable("local SSH operation is unavailable")
}

pub(super) fn transport_timeout(remaining: std::time::Duration) -> std::time::Duration {
    remaining.saturating_add(SSH_OPERATION_CLEANUP_TAIL)
}
