//! Personal OAuth-only credential mutation inside the isolated authority.
//!
//! Constructing this owner or its generated router binds no listener. Runtime
//! integration must mount it with the shared OAuth-only policy and await
//! shutdown before terminating Tokio. Provider material never enters DTOs.

mod publication;
#[cfg(test)]
pub(crate) mod tests;
mod wire;

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use codewire_access::{CredentialId, CredentialMetadata, Owner, OwnerId};
use codewire_credential_broker::codex_enrollment::{CodexEnrollmentError, CodexEnrollmentOwner};
use codewire_platform_credentials::{PlatformCredentialError, PlatformCredentialStore};
use codewire_proto::codewire::v1::{EnrollCodexResponse, enroll_codex_response};
use codewire_server_core::auth::{OAuthBearerAuthority, OAuthBearerAuthorityError};
use sqlx::PgPool;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot};
use tokio::time::Instant;
use tokio_util::sync::{CancellationToken, DropGuard};
use tokio_util::task::TaskTracker;

const MAX_OPERATIONS: usize = 8;
const ENROLLMENT_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const MUTATION_TIMEOUT: Duration = Duration::from_secs(5);

/// Closed service failures. No raw provider/SQL error or source is retained.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialMutationError {
    InvalidInput,
    Denied,
    Unavailable,
    Cancelled,
    Expired,
    AlreadyExists,
    NotFound,
    StaleRevision,
    InUse,
    MustBeRevoked,
    EnrollmentFailed,
    CleanupFailed,
    PublicationUnknown,
}

type Error = CredentialMutationError;

struct Shared {
    pool: PgPool,
    store: Arc<PlatformCredentialStore>,
    enrollment: Arc<CodexEnrollmentOwner>,
}

/// Bounded owner of request drivers as well as the shared enrollment workers.
/// A response disappearing signals cancellation; it never aborts SQL cleanup.
pub struct CredentialMutationOwner {
    shared: Arc<Shared>,
    accepting: Mutex<bool>,
    capacity: Arc<Semaphore>,
    workers: TaskTracker,
    stop: CancellationToken,
}

impl CredentialMutationOwner {
    /// All inputs are administrator-owned isolated service dependencies.
    /// Neither this store nor its KEK provider belongs in orchestration.
    pub fn new(
        pool: PgPool,
        store: Arc<PlatformCredentialStore>,
        enrollment: CodexEnrollmentOwner,
    ) -> Self {
        Self {
            shared: Arc::new(Shared {
                pool,
                store,
                enrollment: Arc::new(enrollment),
            }),
            accepting: Mutex::new(true),
            capacity: Arc::new(Semaphore::new(MAX_OPERATIONS)),
            workers: TaskTracker::new(),
            stop: CancellationToken::new(),
        }
    }

    /// Generated handlers only. The caller must use the shared OAuth-only
    /// Connect mount; handlers independently require its opaque authority.
    pub fn router(self: &Arc<Self>) -> connectrpc::Router {
        wire::router(self.clone())
    }

    /// Stop admission and cancel drivers synchronously. No issued mutation
    /// task is aborted; the caller must still await `shutdown` to prove drain.
    pub fn start_shutdown(&self) {
        {
            let mut accepting = self.accepting.lock().unwrap_or_else(|p| p.into_inner());
            *accepting = false;
            self.workers.close();
            self.stop.cancel();
        }
    }

    /// Signal cancellation and await every disposition and provider child.
    /// Runtime owners may call `start_shutdown` first to close sibling
    /// services before beginning any transport grace period.
    /// Local drain cannot guarantee a remote COMMIT stopped; uncertain
    /// outcomes retain the possibly published provider credential.
    pub async fn shutdown(&self) -> Result<(), Error> {
        self.start_shutdown();
        self.workers.wait().await;
        self.shared
            .enrollment
            .shutdown()
            .await
            .map_err(enrollment_error)
    }

    fn enroll(&self, authority: OAuthBearerAuthority, name: String) -> Result<Events, Error> {
        validate_name(&name)?;
        let scope = Scope::new(authority, self.stop.child_token(), ENROLLMENT_TIMEOUT)?;
        let accepting = self.accepting.lock().map_err(|_| Error::Unavailable)?;
        let permit = self.admit(*accepting)?;
        let cancel = scope.cancel.clone().drop_guard();
        // One challenge and one terminal result: a slow consumer must not
        // cause a known failure to be silently replaced by successful EOF.
        let (sender, receiver) = mpsc::channel(2);
        let shared = self.shared.clone();
        self.workers.spawn(async move {
            let _permit = permit;
            if let Err(error) = run_enrollment(shared, &scope, name, &sender).await {
                // Never hold admission waiting for a disconnected or slow
                // response consumer; at most one closed error is buffered.
                let _ = sender.try_send(Err(error));
            }
        });
        drop(accepting);
        Ok(Events {
            receiver,
            _cancel: cancel,
        })
    }

    async fn lifecycle(
        &self,
        authority: OAuthBearerAuthority,
        id: String,
        revision: u64,
        delete: bool,
    ) -> Result<Option<CredentialMetadata>, Error> {
        let id = CredentialId::parse(id).map_err(|_| Error::InvalidInput)?;
        if revision == 0 || i64::try_from(revision).is_err() {
            return Err(Error::InvalidInput);
        }
        let scope = Scope::new(authority, self.stop.child_token(), MUTATION_TIMEOUT)?;
        let deadline = scope.deadline;
        let cancelled = scope.cancel.clone();
        let _guard = cancelled.clone().drop_guard();
        let (sender, receiver) = oneshot::channel();
        {
            let accepting = self.accepting.lock().map_err(|_| Error::Unavailable)?;
            let permit = self.admit(*accepting)?;
            let shared = self.shared.clone();
            self.workers.spawn(async move {
                let _permit = permit;
                let result = publication::lifecycle(&shared, &scope, id, revision, delete).await;
                let _ = sender.send(result);
            });
        }
        tokio::select! {
            biased;
            _ = cancelled.cancelled() => Err(Error::Cancelled),
            _ = tokio::time::sleep_until(deadline) => Err(Error::PublicationUnknown),
            result = receiver => result.map_err(|_| Error::PublicationUnknown)?,
        }
    }

    fn admit(&self, accepting: bool) -> Result<OwnedSemaphorePermit, Error> {
        if !accepting {
            return Err(Error::Unavailable);
        }
        self.capacity
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::Unavailable)
    }
}

impl Drop for CredentialMutationOwner {
    fn drop(&mut self) {
        self.stop.cancel();
        self.workers.close();
    }
}

struct Scope {
    authority: OAuthBearerAuthority,
    owner: Owner,
    deadline: Instant,
    expires_at_unix: u64,
    cancel: CancellationToken,
}

impl Scope {
    fn new(
        authority: OAuthBearerAuthority,
        cancel: CancellationToken,
        limit: Duration,
    ) -> Result<Self, Error> {
        let started = Instant::now();
        let captured_wall = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::Unavailable)?
            .as_secs();
        let lifetime = authority
            .remaining_lifetime()
            .map_err(authority_error)?
            .min(limit);
        let owner = Owner::User(OwnerId::parse(authority.user_id()).map_err(|_| Error::Denied)?);
        let expires_at_unix = captured_wall
            .checked_add(lifetime.as_secs())
            .ok_or(Error::Unavailable)?
            .min(authority.expires_at().timestamp().max(0) as u64);
        Ok(Self {
            authority,
            owner,
            deadline: started + lifetime,
            expires_at_unix,
            cancel,
        })
    }

    fn check(&self) -> Result<(), Error> {
        if self.cancel.is_cancelled() {
            return Err(Error::Cancelled);
        }
        if Instant::now() >= self.deadline {
            return Err(Error::Expired);
        }
        self.authority
            .remaining_lifetime()
            .map_err(authority_error)?;
        Ok(())
    }

    async fn wait<T>(&self, operation: impl std::future::Future<Output = T>) -> Result<T, Error> {
        self.check()?;
        tokio::select! {
            biased;
            _ = self.cancel.cancelled() => Err(Error::Cancelled),
            _ = tokio::time::sleep_until(self.deadline) => Err(Error::Expired),
            result = operation => { self.check()?; Ok(result) }
        }
    }
}

struct Events {
    receiver: mpsc::Receiver<Result<EnrollCodexResponse, Error>>,
    _cancel: DropGuard,
}

async fn run_enrollment(
    shared: Arc<Shared>,
    scope: &Scope,
    name: String,
    sender: &mpsc::Sender<Result<EnrollCodexResponse, Error>>,
) -> Result<(), Error> {
    scope.check()?;
    let mut pending = shared.enrollment.start().map_err(enrollment_error)?;
    let challenge = scope
        .wait(pending.challenge())
        .await?
        .map_err(enrollment_error)?;
    let response = EnrollCodexResponse {
        event: Some(enroll_codex_response::Event::Challenge(Box::new(
            codewire_proto::codewire::v1::CodexDeviceChallenge {
                verification_url: challenge.verification_url().to_owned(),
                user_code: challenge.user_code().to_owned(),
                expires_at_unix: challenge.expires_at_unix().min(scope.expires_at_unix),
                ..Default::default()
            },
        ))),
        ..Default::default()
    };
    drop(challenge);
    scope
        .wait(sender.send(Ok(response)))
        .await?
        .map_err(|_| Error::Cancelled)?;
    let mut completed = scope
        .wait(pending.complete())
        .await?
        .map_err(enrollment_error)?;
    let result = publication::enroll(&shared, scope, &mut completed, name).await;
    // An issued COMMIT is never followed by NotPublished, even when its
    // acknowledgement was lost. Cleanup never revokes possibly stored tokens.
    completed
        .finish(result.outcome)
        .await
        .map_err(|_| Error::CleanupFailed)?;
    let credential = result.result?;
    scope
        .wait(sender.send(Ok(EnrollCodexResponse {
            event: Some(enroll_codex_response::Event::Credential(Box::new(
                wire::credential(credential),
            ))),
            ..Default::default()
        })))
        .await?
        .map_err(|_| Error::PublicationUnknown)?;
    Ok(())
}

fn validate_name(name: &str) -> Result<(), Error> {
    if name.is_empty()
        || name.len() > 256
        || name.trim() != name
        || name.chars().any(char::is_control)
    {
        Err(Error::InvalidInput)
    } else {
        Ok(())
    }
}

fn enrollment_error(error: CodexEnrollmentError) -> Error {
    match error {
        CodexEnrollmentError::Cancelled => Error::Cancelled,
        CodexEnrollmentError::Expired => Error::Expired,
        CodexEnrollmentError::Unavailable | CodexEnrollmentError::Configuration => {
            Error::Unavailable
        }
        CodexEnrollmentError::Cleanup => Error::CleanupFailed,
        _ => Error::EnrollmentFailed,
    }
}

fn authority_error(error: OAuthBearerAuthorityError) -> Error {
    match error {
        OAuthBearerAuthorityError::Denied => Error::Denied,
        OAuthBearerAuthorityError::Unavailable => Error::Unavailable,
    }
}

fn store_error(error: PlatformCredentialError) -> Error {
    match error {
        PlatformCredentialError::InvalidInput | PlatformCredentialError::UnsupportedCredential => {
            Error::InvalidInput
        }
        PlatformCredentialError::NotFound => Error::NotFound,
        PlatformCredentialError::AlreadyExists => Error::AlreadyExists,
        PlatformCredentialError::StaleVersion => Error::StaleRevision,
        PlatformCredentialError::CredentialInUse => Error::InUse,
        PlatformCredentialError::Inactive => Error::MustBeRevoked,
        _ => Error::Unavailable,
    }
}
