//! Public-only SSH checkout intent and selected-key repository operations.

use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex as StdMutex};

use codewire_access::{AccessProfileId, CredentialAuthKind};
use codewire_gateway_proto::codewire::bridge::v1 as daemon_v1;
use codewire_gateway_proto::ssh::{
    SshOperation, remaining_deadline, validate_request, validate_response,
};
use codewire_protected_store::ssh_material::{SshKeyAlgorithm, SshPublicKey, parse_public_key};
use tokio::sync::{OwnedSemaphorePermit, oneshot, watch};
use tokio::time::Instant;
use tonic::{Response, Status};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{
    LocalCredentialRepositoryLeaseClient, REPOSITORY_LEASE_PROTOCOL_VERSION,
    RepositoryLeaseLifetime, RepositoryLeaseOperation, RepositoryLeaseRpc, map_client_status,
    map_server_error, parse_canonical_uuid, validate_repository_lease_request,
};
use crate::broker_channel::LocalSshOperationRuntime;
use crate::control::v1;
use crate::{
    LocalCredentialAuthority, LocalSshSignError, LocalSshSignRequest,
    RepositoryCredentialAdmission, RepositoryCredentialLeaseRequest,
    RepositorySshCredentialAdmission,
};

/// Canonical, public-only SSH checkout coordinates returned by the inherited
/// authority channel. It carries neither material nor a protected-store key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepositorySshCheckoutIntent {
    pub preparation_request_id: Uuid,
    pub profile_id: AccessProfileId,
    pub profile_revision: u64,
    pub source: String,
    pub branch: String,
    pub revision: String,
    pub known_hosts: Vec<String>,
}

impl LocalCredentialRepositoryLeaseClient {
    pub async fn ssh_checkout(
        &mut self,
    ) -> Result<RepositorySshCheckoutIntent, super::RepositoryLeaseChannelError> {
        let response = self
            .inner
            .get_repository_ssh_checkout(v1::RepositorySshCheckoutRequest {
                protocol_version: REPOSITORY_LEASE_PROTOCOL_VERSION,
                preparation_request_id: self.request_id.to_string(),
            })
            .await
            .map_err(map_client_status)?
            .into_inner();
        checkout_intent_from_proto(response, self.request_id)
    }

    pub async fn ssh_operation(
        &mut self,
        request: daemon_v1::CredentialSshRequest,
    ) -> Result<daemon_v1::CredentialSshResponse, super::RepositoryLeaseChannelError> {
        let operation = validate_request(&request)
            .map_err(|_| super::RepositoryLeaseChannelError::InvalidRequest)?;
        let deadline_unix_ms = request.deadline_unix_ms;
        remaining_deadline(deadline_unix_ms)
            .map_err(|_| super::RepositoryLeaseChannelError::InvalidRequest)?;
        let request_id = parse_canonical_uuid(&request.request_id)
            .map_err(|_| super::RepositoryLeaseChannelError::InvalidRequest)?;
        let response = self
            .inner
            .repository_ssh_operation(v1::RepositorySshOperationRequest {
                protocol_version: REPOSITORY_LEASE_PROTOCOL_VERSION,
                preparation_request_id: self.request_id.to_string(),
                request: Some(request),
            })
            .await
            .map_err(map_client_status)?
            .into_inner();
        if response.request_id != request_id.to_string()
            || validate_response(&response, operation).is_err()
            || remaining_deadline(deadline_unix_ms).is_err()
        {
            return Err(super::RepositoryLeaseChannelError::InvalidResponse);
        }
        Ok(response)
    }
}

fn checkout_intent_from_proto(
    response: v1::RepositorySshCheckoutResponse,
    expected_request_id: Uuid,
) -> Result<RepositorySshCheckoutIntent, super::RepositoryLeaseChannelError> {
    let preparation_request_id = parse_canonical_uuid(&response.preparation_request_id)
        .map_err(|_| super::RepositoryLeaseChannelError::InvalidResponse)?;
    let profile_id = AccessProfileId::parse(response.profile_id)
        .map_err(|_| super::RepositoryLeaseChannelError::InvalidResponse)?;
    let request = RepositoryCredentialLeaseRequest {
        request_id: preparation_request_id,
        profile_id: profile_id.clone(),
        profile_revision: response.profile_revision,
        source: response.source,
        branch: response.branch,
        revision: response.revision,
        known_hosts: response.known_hosts,
    };
    if preparation_request_id != expected_request_id
        || validate_repository_lease_request(&request) != Ok(super::LocalRepositoryTransport::Ssh)
    {
        return Err(super::RepositoryLeaseChannelError::InvalidResponse);
    }
    Ok(RepositorySshCheckoutIntent {
        preparation_request_id,
        profile_id,
        profile_revision: request.profile_revision,
        source: request.source,
        branch: request.branch,
        revision: request.revision,
        known_hosts: request.known_hosts,
    })
}

pub(super) struct RepositorySshOperations {
    active: StdMutex<HashMap<Uuid, watch::Sender<bool>>>,
    runtime: Arc<LocalSshOperationRuntime>,
    cleanup_failed: std::sync::atomic::AtomicBool,
}

impl RepositorySshOperations {
    pub(super) fn new(runtime: Arc<LocalSshOperationRuntime>) -> Self {
        Self {
            active: StdMutex::new(HashMap::new()),
            runtime,
            cleanup_failed: std::sync::atomic::AtomicBool::new(false),
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

    pub(super) fn failed(&self) -> bool {
        self.cleanup_failed.load(Ordering::Acquire) || self.runtime.is_unhealthy()
    }

    fn latch_cleanup_failure(&self) {
        self.cleanup_failed.store(true, Ordering::Release);
        self.runtime.latch_cleanup_failure();
    }
}

pub(super) struct RepositorySshOperation {
    lifetime: Arc<RepositoryLeaseLifetime>,
    permit: Option<OwnedSemaphorePermit>,
    channel_operation: Option<RepositoryLeaseOperation>,
    request_id: Uuid,
    cancellation: watch::Sender<bool>,
}

impl RepositorySshOperation {
    fn cancellation(&self) -> watch::Receiver<bool> {
        self.cancellation.subscribe()
    }

    fn ensure_live(
        &self,
        deadline: Instant,
        deadline_unix_ms: u64,
    ) -> Result<(), LocalSshSignError> {
        self.lifetime.ssh.runtime.ensure_healthy()?;
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

impl Drop for RepositorySshOperation {
    fn drop(&mut self) {
        self.cancellation.send_replace(true);
        drop(self.permit.take());
        self.lifetime
            .ssh
            .active
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .remove(&self.request_id);
        drop(self.channel_operation.take());
    }
}

pub(super) struct RepositorySshCompletion {
    operation: Option<RepositorySshOperation>,
    completed: bool,
}

impl RepositorySshCompletion {
    pub(super) fn new(operation: RepositorySshOperation) -> Self {
        Self {
            operation: Some(operation),
            completed: false,
        }
    }

    pub(super) fn operation(&self) -> &RepositorySshOperation {
        self.operation
            .as_ref()
            .expect("repository SSH operation remains owned")
    }

    pub(super) fn complete(mut self) {
        self.completed = true;
        drop(self.operation.take());
    }
}

impl Drop for RepositorySshCompletion {
    fn drop(&mut self) {
        if !self.completed
            && let Some(operation) = self.operation.as_ref()
        {
            operation.lifetime.ssh.latch_cleanup_failure();
        }
        drop(self.operation.take());
    }
}

pub(super) struct RequestCancellationGuard(pub(super) watch::Sender<bool>);

impl Drop for RequestCancellationGuard {
    fn drop(&mut self) {
        self.0.send_replace(true);
    }
}

impl RepositoryLeaseLifetime {
    pub(super) fn acquire_ssh(
        self: &Arc<Self>,
        request_id: Uuid,
        signing: bool,
    ) -> Result<RepositorySshOperation, Status> {
        self.ssh
            .runtime
            .ensure_healthy()
            .map_err(sign_error_status)?;
        let channel_operation = self.acquire()?;
        let permit = signing
            .then(|| self.ssh.runtime.acquire())
            .transpose()
            .map_err(sign_error_status)?;
        let (cancellation, _) = watch::channel(false);
        let mut active = self.ssh.active.lock().map_err(|_| unavailable())?;
        self.ensure_open()?;
        match active.entry(request_id) {
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(cancellation.clone());
            }
            std::collections::hash_map::Entry::Occupied(_) => {
                return Err(Status::invalid_argument(
                    "duplicate repository SSH request ID",
                ));
            }
        }
        drop(active);
        Ok(RepositorySshOperation {
            lifetime: Arc::clone(self),
            permit,
            channel_operation: Some(channel_operation),
            request_id,
            cancellation,
        })
    }
}

impl<S> RepositoryLeaseRpc<S>
where
    S: codewire_protected_store::ProtectedStore + 'static,
{
    pub(super) async fn run_ssh_checkout(
        &self,
        request: v1::RepositorySshCheckoutRequest,
    ) -> Result<Response<v1::RepositorySshCheckoutResponse>, Status> {
        let preparation_request_id = parse_canonical_uuid(&request.preparation_request_id)?;
        if request.protocol_version != REPOSITORY_LEASE_PROTOCOL_VERSION {
            return Err(Status::failed_precondition(
                "repository executor lease protocol is incompatible",
            ));
        }
        if !self.ready_reported.load(Ordering::Acquire)
            || preparation_request_id != self.authorization.request_id
            || validate_repository_lease_request(&self.authorization)
                != Ok(super::LocalRepositoryTransport::Ssh)
            || self.ssh_intent_issued.load(Ordering::Acquire)
        {
            return Err(Status::permission_denied(
                "repository SSH checkout intent was denied",
            ));
        }
        if let Some(platform) = &self.platform {
            if !matches!(
                platform.as_ref(),
                super::RepositoryPlatformCheckout::Ssh { .. }
            ) {
                return Err(Status::permission_denied("repository transport mismatch"));
            }
            let _operation = self.lifetime.acquire()?;
            self.ssh_intent_issued
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .map_err(|_| {
                    Status::permission_denied("repository SSH intent was already issued")
                })?;
            // The already admitted platform profile owns authorization. This
            // response is only the parent's canonical public checkout intent;
            // every identity/sign request is authorized again by the platform.
            self.lifetime.ensure_open()?;
            return Ok(Response::new(v1::RepositorySshCheckoutResponse {
                preparation_request_id: self.authorization.request_id.to_string(),
                profile_id: self.authorization.profile_id.to_string(),
                profile_revision: self.authorization.profile_revision,
                source: self.authorization.source.clone(),
                branch: self.authorization.branch.clone(),
                revision: self.authorization.revision.clone(),
                known_hosts: self.authorization.known_hosts.clone(),
            }));
        }
        let authority = Arc::clone(&self.authority);
        let authorization = self.authorization.clone();
        let operation = self.lifetime.acquire()?;
        let admission = tokio::task::spawn_blocking(move || {
            let _operation = operation;
            let admission = authority.admit_repository_credential_operation(&authorization)?;
            let RepositoryCredentialAdmission::Ssh(admission) = admission else {
                return Err(crate::LocalCredentialError::CredentialOperationLeaseDenied);
            };
            admitted_public_key(&admission)
                .map_err(|_| crate::LocalCredentialError::CredentialUnavailable)?;
            authority.revalidate_repository_credential_operation(
                &authorization,
                &RepositoryCredentialAdmission::Ssh(admission.clone()),
            )?;
            Ok::<_, crate::LocalCredentialError>(admission)
        })
        .await
        .map_err(|_| unavailable())?
        .map_err(map_server_error)?;
        self.lifetime.ensure_open()?;
        self.ssh_intent_issued
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| Status::permission_denied("repository SSH checkout intent was denied"))?;
        Ok(Response::new(v1::RepositorySshCheckoutResponse {
            preparation_request_id: self.authorization.request_id.to_string(),
            profile_id: admission.profile_id.to_string(),
            profile_revision: admission.profile_revision,
            source: self.authorization.source.clone(),
            branch: self.authorization.branch.clone(),
            revision: self.authorization.revision.clone(),
            known_hosts: self.authorization.known_hosts.clone(),
        }))
    }

    pub(super) async fn run_ssh_operation(
        &self,
        request: v1::RepositorySshOperationRequest,
    ) -> Result<Response<daemon_v1::CredentialSshResponse>, Status> {
        if request.protocol_version != REPOSITORY_LEASE_PROTOCOL_VERSION {
            return Err(Status::failed_precondition(
                "repository executor lease protocol is incompatible",
            ));
        }
        let preparation_request_id = parse_canonical_uuid(&request.preparation_request_id)?;
        if !self.ready_reported.load(Ordering::Acquire)
            || !self.ssh_intent_issued.load(Ordering::Acquire)
            || preparation_request_id != self.authorization.request_id
            || validate_repository_lease_request(&self.authorization)
                != Ok(super::LocalRepositoryTransport::Ssh)
        {
            return Err(Status::permission_denied(
                "repository SSH operation was denied",
            ));
        }
        let request = request
            .request
            .ok_or_else(|| Status::invalid_argument("invalid repository SSH operation"))?;
        let operation = validate_request(&request)?;
        let request_id = parse_canonical_uuid(&request.request_id)?;
        let deadline_unix_ms = request.deadline_unix_ms;
        let remaining = remaining_deadline(deadline_unix_ms)?;
        let deadline = Instant::now()
            .checked_add(remaining)
            .ok_or_else(unavailable)?;
        if let Some(platform) = &self.platform {
            let super::RepositoryPlatformCheckout::Ssh { bridge } = platform.as_ref() else {
                return Err(Status::permission_denied("repository transport mismatch"));
            };
            // Reuse this channel's cancellation and operation permit, without
            // acquiring a local signer permit or consulting local credentials.
            // Cancellation tombstones the shared bridge request. Retained
            // signer work stays owned and drained by the platform broker.
            let guard = self.lifetime.acquire_ssh(request_id, false)?;
            let mut cancellation = guard.cancellation();
            let response = tokio::select! {
                biased;
                () = async {
                    if !*cancellation.borrow() { let _ = cancellation.changed().await; }
                } => return Err(Status::cancelled("repository SSH channel closed")),
                result = tokio::time::timeout_at(deadline, bridge.relay_ssh(request)) => {
                    result.map_err(|_| Status::deadline_exceeded("repository SSH request expired"))??
                }
            };
            guard
                .ensure_live(deadline, deadline_unix_ms)
                .map_err(sign_error_status)?;
            return Ok(Response::new(response));
        }
        let operation_guard = self
            .lifetime
            .acquire_ssh(request_id, operation == SshOperation::Sign)?;
        let request_cancel = operation_guard.cancellation.clone();
        let _request_guard = RequestCancellationGuard(request_cancel);
        let authority = Arc::clone(&self.authority);
        let authorization = self.authorization.clone();
        let lifetime = Arc::clone(&self.lifetime);
        let (sender, receiver) = oneshot::channel();
        tokio::spawn(async move {
            let completion = RepositorySshCompletion::new(operation_guard);
            let mut release_deadline = deadline;
            let result = execute_repository_ssh_operation(
                authority,
                authorization,
                completion.operation(),
                request,
                operation,
                &mut release_deadline,
            )
            .await;
            if matches!(result, Err(LocalSshSignError::Cleanup)) {
                lifetime.ssh.latch_cleanup_failure();
            }
            let response = operation_response(request_id, operation, result);
            completion.complete();
            let _ = sender.send((response, release_deadline));
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

pub(super) async fn execute_repository_ssh_operation<S>(
    authority: Arc<LocalCredentialAuthority<S>>,
    authorization: RepositoryCredentialLeaseRequest,
    operation_guard: &RepositorySshOperation,
    request: daemon_v1::CredentialSshRequest,
    operation: SshOperation,
    deadline: &mut Instant,
) -> Result<daemon_v1::credential_ssh_response::Result, LocalSshSignError>
where
    S: codewire_protected_store::ProtectedStore + 'static,
{
    let deadline_unix_ms = request.deadline_unix_ms;
    operation_guard.ensure_live(*deadline, deadline_unix_ms)?;
    let admission = revalidate(
        Arc::clone(&authority),
        authorization.clone(),
        None,
        operation_guard,
        *deadline,
        deadline_unix_ms,
    )
    .await?;
    let public = admitted_public_key(&admission)?;
    *deadline = clamp_admitted_deadline(&admission, *deadline)?;
    if operation == SshOperation::Identities {
        operation_guard.ensure_live(*deadline, deadline_unix_ms)?;
        revalidate(
            authority,
            authorization,
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
    validate_sign_request(&public, &sign)?;
    operation_guard.ensure_live(*deadline, deadline_unix_ms)?;
    let material_admission = admission.clone();
    let material_authority = Arc::clone(&authority);
    let material = tokio::task::spawn_blocking(move || {
        material_authority
            .read_repository_ssh_material(&material_admission)
            .map_err(|_| LocalSshSignError::Unavailable)
    })
    .await
    .map_err(|_| LocalSshSignError::Unavailable)??;
    operation_guard.ensure_live(*deadline, deadline_unix_ms)?;
    if material.public_key() != &public {
        return Err(LocalSshSignError::Unavailable);
    }
    revalidate(
        Arc::clone(&authority),
        authorization.clone(),
        Some(admission.clone()),
        operation_guard,
        *deadline,
        deadline_unix_ms,
    )
    .await?;
    let signer = operation_guard.lifetime.ssh.runtime.signer()?;
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
        authorization,
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

async fn revalidate<S>(
    authority: Arc<LocalCredentialAuthority<S>>,
    request: RepositoryCredentialLeaseRequest,
    captured: Option<RepositorySshCredentialAdmission>,
    operation: &RepositorySshOperation,
    deadline: Instant,
    deadline_unix_ms: u64,
) -> Result<RepositorySshCredentialAdmission, LocalSshSignError>
where
    S: codewire_protected_store::ProtectedStore + 'static,
{
    operation.ensure_live(deadline, deadline_unix_ms)?;
    let admission = tokio::task::spawn_blocking(move || match captured {
        Some(captured) => authority
            .revalidate_repository_credential_operation(
                &request,
                &RepositoryCredentialAdmission::Ssh(captured.clone()),
            )
            .map(|()| captured),
        None => authority
            .admit_repository_credential_operation(&request)
            .and_then(|admission| match admission {
                RepositoryCredentialAdmission::Ssh(admission) => Ok(admission),
                RepositoryCredentialAdmission::GitHubOAuth(_) => {
                    Err(crate::LocalCredentialError::CredentialOperationLeaseDenied)
                }
            }),
    })
    .await
    .map_err(|_| LocalSshSignError::Unavailable)?
    .map_err(map_authority_error)?;
    operation.ensure_live(deadline, deadline_unix_ms)?;
    Ok(admission)
}

pub(super) fn admitted_public_key(
    admission: &RepositorySshCredentialAdmission,
) -> Result<SshPublicKey, LocalSshSignError> {
    let metadata = &admission.credential.metadata;
    if metadata.provider.as_str() != "ssh"
        || metadata.authentication_kind != CredentialAuthKind::SshKey
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

fn validate_sign_request(
    public: &SshPublicKey,
    sign: &daemon_v1::CredentialSshSignRequest,
) -> Result<(), LocalSshSignError> {
    if sign.public_key_blob != public.key_blob() {
        return Err(LocalSshSignError::Denied);
    }
    match (public.algorithm(), sign.flags) {
        (SshKeyAlgorithm::Ed25519, 0) | (SshKeyAlgorithm::Rsa { .. }, 2 | 4) => Ok(()),
        _ => Err(LocalSshSignError::Denied),
    }
}

fn clamp_admitted_deadline(
    admission: &RepositorySshCredentialAdmission,
    request_deadline: Instant,
) -> Result<Instant, LocalSshSignError> {
    let Some(expiration) = admission.credential.metadata.expires_at_unix else {
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

pub(super) fn operation_response(
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

pub(super) fn sign_error_status(error: LocalSshSignError) -> Status {
    match error {
        LocalSshSignError::Denied => Status::permission_denied("repository SSH operation denied"),
        LocalSshSignError::Expired => {
            Status::deadline_exceeded("repository SSH operation deadline elapsed")
        }
        LocalSshSignError::Unavailable | LocalSshSignError::Cleanup => unavailable(),
    }
}

fn map_authority_error(error: crate::LocalCredentialError) -> LocalSshSignError {
    match error {
        crate::LocalCredentialError::CredentialOperationLeaseDenied
        | crate::LocalCredentialError::CredentialInactive
        | crate::LocalCredentialError::CredentialNotFound
        | crate::LocalCredentialError::ProfileNotFound
        | crate::LocalCredentialError::ProfileRevisionNotFound => LocalSshSignError::Denied,
        _ => LocalSshSignError::Unavailable,
    }
}

pub(super) fn unavailable() -> Status {
    Status::unavailable("repository SSH authority is unavailable")
}

#[cfg(test)]
mod inherited_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message as _;

    #[test]
    fn inherited_transport_envelope_covers_maximum_typed_ssh_payloads() {
        let checkout = v1::RepositorySshCheckoutResponse {
            preparation_request_id: Uuid::new_v4().to_string(),
            profile_id: Uuid::new_v4().to_string(),
            profile_revision: u64::MAX,
            source: "s".repeat(1024),
            branch: "b".repeat(1024),
            revision: String::new(),
            known_hosts: vec!["k".repeat(2047); 32],
        };
        assert!(checkout.encoded_len() < super::super::MAX_REPOSITORY_LEASE_RPC_MESSAGE_BYTES);

        let operation = v1::RepositorySshOperationRequest {
            protocol_version: REPOSITORY_LEASE_PROTOCOL_VERSION,
            preparation_request_id: Uuid::new_v4().to_string(),
            request: Some(daemon_v1::CredentialSshRequest {
                request_id: Uuid::new_v4().to_string(),
                deadline_unix_ms: u64::MAX,
                operation: Some(daemon_v1::credential_ssh_request::Operation::Sign(
                    daemon_v1::CredentialSshSignRequest {
                        public_key_blob: vec![0; codewire_gateway_proto::ssh::MAX_PUBLIC_KEY_BYTES],
                        data: vec![0; codewire_gateway_proto::ssh::MAX_SIGNING_DATA_BYTES],
                        flags: 4,
                    },
                )),
            }),
        };
        assert!(operation.encoded_len() < super::super::MAX_REPOSITORY_LEASE_RPC_MESSAGE_BYTES);
    }
}
