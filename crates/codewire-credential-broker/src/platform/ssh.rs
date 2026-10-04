//! Selected-only SSH work retained by the existing private service owner.
//! No key cache: identities reads public metadata; each sign loads one exact
//! version, owns one agent, and proves its drain before releasing a signature.

use std::future::Future;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use codewire_gateway_proto::{
    codewire::bridge::v1,
    ssh::{SshOperation, remaining_deadline, validate_request},
};
use codewire_protected_store::ssh_material::{
    SshAgentMaterial, SshMaterialError, SshPublicKey, decode_protected_material, parse_public_key,
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, oneshot};
use tokio::time::Instant;
use tokio_util::{sync::CancellationToken, task::TaskTracker};

use super::*;
use crate::ssh_agent::{SshAgentError, SshAgentOwner, sign_once};

const MAX_OPERATIONS: u32 = 8;

/// Shares the bridge's existing admission mutex/tracker. The additional eight
/// permits bound unwrap and CPU preparation, not just already-started agents.
pub(super) struct Service {
    owner: Arc<SshAgentOwner>,
    permits: Arc<Semaphore>,
    accepting: Arc<Mutex<bool>>,
    workers: TaskTracker,
    stop: CancellationToken,
    failed: AtomicBool,
}

impl Service {
    pub(super) fn new(
        owner: Arc<SshAgentOwner>,
        accepting: Arc<Mutex<bool>>,
        workers: TaskTracker,
        stop: CancellationToken,
    ) -> Arc<Self> {
        Arc::new(Self {
            owner,
            permits: Arc::new(Semaphore::new(MAX_OPERATIONS as usize)),
            accepting,
            workers,
            stop,
            failed: AtomicBool::new(false),
        })
    }

    pub(super) fn epoch(self: &Arc<Self>) -> Epoch {
        Epoch {
            service: self.clone(),
            cancel: self.stop.child_token(),
            // Drain accounting only; the shared service permits are the budget.
            active: Arc::new(Semaphore::new(MAX_OPERATIONS as usize)),
            failed: Arc::new(AtomicBool::new(false)),
        }
    }

    pub(super) async fn shutdown(&self) -> Result<(), PlatformRuntimeError> {
        // The containing service has closed admission and joined its tracker.
        let result = self.owner.shutdown().await;
        if result.is_err() || self.failed.load(Ordering::Acquire) {
            Err(PlatformRuntimeError::Unavailable)
        } else {
            Ok(())
        }
    }

    fn spawn<T: Send + 'static>(
        self: &Arc<Self>,
        epoch: &Epoch,
        scope: &Scope,
        work: impl Future<Output = Result<T, BrokerLeaseError>> + Send + 'static,
    ) -> Result<oneshot::Receiver<Result<T, BrokerLeaseError>>, BrokerLeaseError> {
        let accepting = self
            .accepting
            .lock()
            .map_err(|_| BrokerLeaseError::Unavailable)?;
        scope.check()?;
        if !*accepting
            || self.stop.is_cancelled()
            || epoch.cancel.is_cancelled()
            || self.failed.load(Ordering::Acquire)
        {
            return Err(BrokerLeaseError::Unavailable);
        }
        let global = self
            .permits
            .clone()
            .try_acquire_owned()
            .map_err(|_| BrokerLeaseError::Unavailable)?;
        let active = epoch
            .active
            .clone()
            .try_acquire_owned()
            .map_err(|_| BrokerLeaseError::Unavailable)?;
        let mut completion = Completion {
            service: self.clone(),
            epoch_failed: epoch.failed.clone(),
            finished: false,
            _global: global,
            _active: active,
        };
        let (sender, receiver) = oneshot::channel();
        drop(self.workers.spawn(async move {
            let result = work.await;
            if completion.service.failed.load(Ordering::Acquire) {
                completion.epoch_failed.store(true, Ordering::Release);
            }
            completion.finished = true;
            drop(completion);
            let _ = sender.send(result);
        }));
        Ok(receiver)
    }
}

pub(super) struct Epoch {
    service: Arc<Service>,
    cancel: CancellationToken,
    active: Arc<Semaphore>,
    failed: Arc<AtomicBool>,
}

impl Epoch {
    pub(super) async fn drain(&self) -> Result<(), BrokerLeaseError> {
        {
            // Serialize retirement with check + permit acquisition + spawn.
            // A zero-active observation cannot precede a late registration.
            let _admission = self
                .service
                .accepting
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            self.cancel.cancel();
        }
        let _drained = self
            .active
            .acquire_many(MAX_OPERATIONS)
            .await
            .map_err(|_| BrokerLeaseError::Unavailable)?;
        if self.failed.load(Ordering::Acquire) {
            Err(BrokerLeaseError::Unavailable)
        } else {
            Ok(())
        }
    }
}

impl Drop for Epoch {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

#[derive(Clone)]
struct Scope {
    cancel: CancellationToken,
    epoch: CancellationToken,
    deadline: Instant,
    deadline_unix_ms: u64,
}

impl Scope {
    fn check(&self) -> Result<(), BrokerLeaseError> {
        if self.cancel.is_cancelled()
            || self.epoch.is_cancelled()
            || Instant::now() >= self.deadline
            || remaining_deadline(self.deadline_unix_ms).is_err()
        {
            Err(BrokerLeaseError::Denied)
        } else {
            Ok(())
        }
    }

    async fn cancelled(&self) {
        tokio::select! { _ = self.cancel.cancelled() => {}, _ = self.epoch.cancelled() => {} }
    }

    async fn wait<T>(
        &self,
        work: impl Future<Output = Result<T, BrokerLeaseError>>,
    ) -> Result<T, BrokerLeaseError> {
        self.check()?;
        let result = tokio::select! {
            biased;
            _ = self.cancelled() => return Err(BrokerLeaseError::Denied),
            _ = tokio::time::sleep_until(self.deadline) => return Err(BrokerLeaseError::Denied),
            result = work => result,
        };
        self.check()?;
        result
    }

    fn clamp_expiry(&mut self, expiry: u64) -> Result<(), BrokerLeaseError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| BrokerLeaseError::Unavailable)?;
        let remaining = Duration::from_secs(expiry)
            .checked_sub(now)
            .filter(|value| !value.is_zero())
            .ok_or(BrokerLeaseError::Denied)?;
        // An arbitrarily distant metadata expiry cannot overflow the clock or
        // extend the already bounded request deadline.
        self.deadline = self.deadline.min(
            Instant::now()
                .checked_add(remaining)
                .unwrap_or(self.deadline),
        );
        self.deadline_unix_ms = self
            .deadline_unix_ms
            .min(expiry.checked_mul(1000).ok_or(BrokerLeaseError::Denied)?);
        self.check()
    }
}

/// An unwind must never be acknowledged as successful owner cleanup.
struct Completion {
    service: Arc<Service>,
    epoch_failed: Arc<AtomicBool>,
    finished: bool,
    // Drop::drop latches an unwind before field destruction returns capacity.
    _global: OwnedSemaphorePermit,
    _active: OwnedSemaphorePermit,
}
impl Drop for Completion {
    fn drop(&mut self) {
        if !self.finished {
            self.service.failed.store(true, Ordering::Release);
            self.epoch_failed.store(true, Ordering::Release);
        }
    }
}

impl<A: PlatformRuntimeAuthority + 'static> PlatformBrokerLeaseProvider<A> {
    pub(super) async fn retained_ssh_operation(
        &self,
        request: v1::CredentialSshRequest,
        cancellation: CancellationToken,
    ) -> Result<v1::credential_ssh_response::Result, BrokerLeaseError> {
        let operation = validate_request(&request).map_err(|_| BrokerLeaseError::InvalidRequest)?;
        let remaining = remaining_deadline(request.deadline_unix_ms)
            .map_err(|_| BrokerLeaseError::InvalidRequest)?;
        let epoch = self.ssh.as_ref().ok_or(BrokerLeaseError::Denied)?;
        let cancel = cancellation.child_token();
        let _request_drop = cancel.clone().drop_guard();
        let mut scope = Scope {
            cancel: cancel.clone(),
            epoch: epoch.cancel.clone(),
            deadline: Instant::now() + remaining,
            deadline_unix_ms: request.deadline_unix_ms,
        };
        scope.clamp_expiry(self.session.identity_expires_at_unix)?;
        let provider = Self {
            authority: self.authority.clone(),
            session: self.session.clone(),
            instance_id: self.instance_id,
            credentials: self.credentials.clone(),
            profiles: self.profiles.clone(),
            leases: self.leases.clone(),
            // The signer reads through the store for every signature.
            material: None,
            ssh: None,
        };
        let admission = scope.clone();
        let service = epoch.service.clone();
        // Shared admission occurs before the future can read private material.
        let receiver = epoch.service.spawn(epoch, &admission, async move {
            let result = provider
                .ssh_admitted(request, operation, &mut scope, &service)
                .await;
            Ok((result, scope))
        })?;
        // Cancellation revokes release, not cleanup ownership. A live caller
        // waits for the retained driver's terminal result; a dropped caller
        // signals its child token while the epoch/service still owns the task.
        let (result, scope) = receiver
            .await
            .map_err(|_| BrokerLeaseError::Unavailable)??;
        if epoch.service.failed.load(Ordering::Acquire) {
            return Err(BrokerLeaseError::Unavailable);
        }
        // Preserve credential/grant narrowing across scheduling after worker
        // completion as well as the original request/session deadline.
        scope.check()?;
        result
    }

    async fn ssh_admitted(
        &self,
        request: v1::CredentialSshRequest,
        operation: SshOperation,
        scope: &mut Scope,
        service: &Service,
    ) -> Result<v1::credential_ssh_response::Result, BrokerLeaseError> {
        let slot = CapabilitySlot::parse("ssh").map_err(|_| BrokerLeaseError::InvalidRequest)?;
        let permission = GrantPermission {
            operation: BrokerOperationId::parse(match operation {
                SshOperation::Identities => "ssh-identities",
                SshOperation::Sign => "ssh-sign",
            })
            .map_err(|_| BrokerLeaseError::InvalidRequest)?,
            route: BrokerRouteId::parse("ssh-agent")
                .map_err(|_| BrokerLeaseError::InvalidRequest)?,
        };
        let before = scope.wait(self.admit(&slot, permission.clone())).await?;
        let public = public_identity(&before)?;
        scope.clamp_expiry(
            before
                .grant
                .expires_at_unix
                .ok_or(BrokerLeaseError::Denied)?,
        )?;
        let result = match request.operation.ok_or(BrokerLeaseError::InvalidRequest)? {
            v1::credential_ssh_request::Operation::Identities(_) => {
                v1::credential_ssh_response::Result::Identity(v1::CredentialSshIdentity {
                    public_key_blob: public.key_blob().to_vec(),
                })
            }
            v1::credential_ssh_request::Operation::Sign(sign) => {
                // Wrong keys/flags fail before OpenBao or private material work.
                if sign.public_key_blob != public.key_blob() || !allowed_flags(&public, sign.flags)
                {
                    return Err(BrokerLeaseError::Denied);
                }
                let protected = scope
                    .wait(async {
                        self.credentials
                            .read_for_broker(
                                &before.record.metadata.owner,
                                &before.record.metadata.id,
                                before.record.version,
                            )
                            .await
                            .map_err(credential_error)
                    })
                    .await?;
                let material =
                    prepare_retained(scope, move || decode_protected_material(protected)).await?;
                if material.public_key() != &public {
                    return Err(BrokerLeaseError::Denied);
                }
                self.recheck_ssh(scope, &slot, &permission, &before).await?;
                // sign_once always joins/reaps/removes staging before returning.
                let signed = sign_once(
                    &service.owner,
                    material,
                    sign,
                    scope.deadline,
                    scope.cancelled(),
                )
                .await;
                if signed == Err(SshAgentError::Cleanup) {
                    service.failed.store(true, Ordering::Release);
                    return Err(BrokerLeaseError::Unavailable);
                }
                let signature = signed.map_err(agent_error)?;
                scope.check()?;
                v1::credential_ssh_response::Result::Signature(v1::CredentialSshSignature {
                    signature_blob: signature,
                })
            }
        };
        // Metadata-only identities and completed signatures share the same
        // final live Pod/profile/full-version/expiry fence before release.
        self.recheck_ssh(scope, &slot, &permission, &before).await?;
        Ok(result)
    }

    async fn recheck_ssh(
        &self,
        scope: &mut Scope,
        slot: &CapabilitySlot,
        permission: &GrantPermission,
        before: &Admission,
    ) -> Result<(), BrokerLeaseError> {
        let after = scope.wait(self.admit(slot, permission.clone())).await?;
        revalidate_admission(scope, before, &after)
    }
}

fn revalidate_admission(
    scope: &mut Scope,
    before: &Admission,
    after: &Admission,
) -> Result<(), BrokerLeaseError> {
    if before.record != after.record
        || before.permission != after.permission
        || !same_grant_binding(&before.grant, &after.grant)
    {
        return Err(BrokerLeaseError::Denied);
    }
    ensure_live(&before.record.metadata, &before.grant)?;
    // A session can retain the exact binding while shortening its expiry.
    // Carry every newer restriction through signing and the result queue;
    // a subsequent read with a later expiry cannot extend this deadline.
    scope.clamp_expiry(
        after
            .grant
            .expires_at_unix
            .ok_or(BrokerLeaseError::Denied)?,
    )
}

fn public_identity(admission: &Admission) -> Result<SshPublicKey, BrokerLeaseError> {
    public_identity_metadata(&admission.record.metadata)
}

fn public_identity_metadata(
    metadata: &CredentialMetadata,
) -> Result<SshPublicKey, BrokerLeaseError> {
    if metadata.provider.as_str() != "ssh"
        || metadata.authentication_kind != CredentialAuthKind::SshKey
    {
        return Err(BrokerLeaseError::Denied);
    }
    let public = metadata
        .ssh_public_key
        .as_ref()
        .ok_or(BrokerLeaseError::InvalidResponse)?;
    parse_public_key(&public.openssh, &public.fingerprint)
        .map_err(|_| BrokerLeaseError::InvalidResponse)
}

fn allowed_flags(key: &SshPublicKey, flags: u32) -> bool {
    use codewire_protected_store::ssh_material::SshKeyAlgorithm;
    matches!(
        (key.algorithm(), flags),
        (SshKeyAlgorithm::Ed25519, 0) | (SshKeyAlgorithm::Rsa { .. }, 2 | 4)
    )
}

async fn prepare_retained(
    scope: &Scope,
    operation: impl FnOnce() -> Result<SshAgentMaterial, SshMaterialError> + Send + 'static,
) -> Result<SshAgentMaterial, BrokerLeaseError> {
    scope.check()?;
    let mut worker = tokio::task::spawn_blocking(operation);
    let result = tokio::select! {
        biased;
        _ = scope.cancelled() => None,
        _ = tokio::time::sleep_until(scope.deadline) => None,
        result = &mut worker => Some(result),
    };
    let result = match result {
        Some(result) => result,
        None => {
            drop(worker.await);
            return Err(BrokerLeaseError::Denied);
        }
    };
    // Timer readiness is not proof that the original deadline remains live.
    scope.check()?;
    result
        .map_err(|_| BrokerLeaseError::Unavailable)?
        .map_err(|_| BrokerLeaseError::InvalidResponse)
}

fn agent_error(error: SshAgentError) -> BrokerLeaseError {
    match error {
        SshAgentError::Denied | SshAgentError::Cancelled | SshAgentError::Expired => {
            BrokerLeaseError::Denied
        }
        SshAgentError::InvalidKey => BrokerLeaseError::InvalidResponse,
        _ => BrokerLeaseError::Unavailable,
    }
}

#[cfg(test)]
mod tests;
