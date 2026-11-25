//! Personal session-or-OAuth credential mutation inside the isolated authority.
//!
//! Constructing this owner or its generated router binds no listener. Runtime
//! integration must mount it with the dedicated credential-mutation policy and await
//! shutdown before terminating Tokio. Only typed import accepts write-only
//! API keys and explicitly imported SSH keys; provider material
//! never enters response DTOs.

mod claude;
mod enrollment;
mod github;
mod github_app;
mod keys;
mod provider_revocation;
mod publication;
mod ssh;
#[cfg(test)]
pub(crate) mod tests;
mod wire;

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use codewire_access::{
    CredentialAuthKind, CredentialId, CredentialMetadata, Owner, OwnerId, ProviderId,
    reserves_provider_prefix,
};
use codewire_credential_broker::provider_oauth::DeviceLoginError;
use codewire_credential_broker::provider_oauth::claude::ClaudeSignIn;
use codewire_credential_broker::provider_oauth::codex::CodexDeviceLogin;
use codewire_credential_broker::provider_oauth::github::GitHubDeviceLogin;
use codewire_credential_broker::{
    CodexOAuthImport, GitHubAppAuthorizationImport, GitHubAppAuthorizationOwner,
};
use codewire_platform_credentials::{
    CredentialRecord, CredentialRegistration, PlatformCredentialError, PlatformCredentialStore,
};
use codewire_protected_store::ProtectedValue;
use codewire_proto::codewire::v1::{EnrollCodexResponse, enroll_codex_response};
use codewire_server_core::auth::{CredentialMutationAuthority, CredentialMutationAuthorityError};
use sqlx::PgPool;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot};
use tokio::time::Instant;
use tokio_util::sync::{CancellationToken, DropGuard};
use tokio_util::task::TaskTracker;

const MAX_OPERATIONS: usize = 8;
pub(crate) use codewire_access::CLAUDE_SUBSCRIPTION_TOKEN_LIFETIME_SECONDS;
const ENROLLMENT_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const MUTATION_TIMEOUT: Duration = Duration::from_secs(5);
/// The longest drain worth waiting for: a whole device enrollment and a
/// margin for its publication (#6535).
pub const LONGEST_DRAIN: Duration = Duration::from_secs(15 * 60 + 30);

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
    EnrollmentUnsupported,
    EnrollmentNotPublished,
    /// The device code or the enrollment's deadline ran out before approval;
    /// nothing was stored (#6535).
    EnrollmentExpired,
    GitHubInstallationRequired,
    GitHubAlreadyConnected,
    GitHubAppNotConfigured,
    CleanupFailed,
    PublicationUnknown,
    /// The pasted Claude code is malformed or from another sign-in.
    ClaudeSignInCodeInvalid,
    /// The Claude sign-in was started too long ago.
    ClaudeSignInExpired,
    /// A new or renamed credential's name starts with a provider id and `/`.
    NameReservesProvider,
}

type Error = CredentialMutationError;

struct Shared {
    pool: PgPool,
    store: Arc<PlatformCredentialStore>,
    codex_login: CodexDeviceLogin,
    claude_sign_in: ClaudeSignIn,
    /// Present exactly when the GitHub App is configured.
    github_login: Option<GitHubDeviceLogin>,
    github_app_authorization: Option<Arc<GitHubAppAuthorizationOwner>>,
    /// Present when a revoke also asks the credential's provider (#4717).
    revocation: Option<RevocationTransports>,
    /// Bounds a mutation and every publication: [`MUTATION_TIMEOUT`] in the
    /// product.
    mutation_timeout: Duration,
    /// The owner's workers, for work that outlives its request (#4904).
    workers: TaskTracker,
}

pub use provider_revocation::RevocationTransports;

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
        codex_login: CodexDeviceLogin,
        claude_sign_in: ClaudeSignIn,
        github_login: Option<GitHubDeviceLogin>,
        github_app_authorization: Option<Arc<GitHubAppAuthorizationOwner>>,
    ) -> Self {
        let workers = TaskTracker::new();
        Self {
            shared: Arc::new(Shared {
                pool,
                store,
                codex_login,
                claude_sign_in,
                github_login,
                github_app_authorization,
                revocation: None,
                mutation_timeout: MUTATION_TIMEOUT,
                workers: workers.clone(),
            }),
            accepting: Mutex::new(true),
            capacity: Arc::new(Semaphore::new(MAX_OPERATIONS)),
            workers,
            stop: CancellationToken::new(),
        }
    }

    /// The same owner, revoking each credential's token at its provider too
    /// (#4717). Call it before serving.
    pub fn with_provider_revocation(mut self, transports: RevocationTransports) -> Self {
        Arc::get_mut(&mut self.shared)
            .expect("an owner that has not served is not shared")
            .revocation = Some(transports);
        self
    }

    /// The same owner with `bound` in place of every mutation's and
    /// publication's five-second bound. A test whose subject is not that
    /// bound lengthens it into a hang guard, so a stalled database on a
    /// loaded CI slot cannot spend it. Call it before serving.
    #[cfg(test)]
    pub(crate) fn with_mutation_timeout(mut self, bound: Duration) -> Self {
        Arc::get_mut(&mut self.shared)
            .expect("an owner that has not served is not shared")
            .mutation_timeout = bound;
        self
    }

    /// Generated handlers only. The caller must use the session-or-OAuth
    /// Connect mount; handlers independently require its opaque authority.
    pub fn router(self: &Arc<Self>) -> connectrpc::Router {
        wire::router(self.clone())
    }

    /// The configured GitHub App's install page, which the wire attaches to
    /// `CREDENTIAL_GITHUB_INSTALLATION_REQUIRED` (#5479).
    fn github_app_install_url(&self) -> Option<String> {
        self.shared
            .github_login
            .as_ref()
            .map(GitHubDeviceLogin::install_url)
    }

    /// Stop admission and cancel drivers synchronously. No issued mutation
    /// task is aborted; the caller must still await `shutdown` to prove drain.
    pub fn start_shutdown(&self) {
        self.start_drain();
        self.stop.cancel();
    }

    /// Stop admission without cancelling what was admitted: a pending device
    /// approval can still be given and published (#6535).
    pub fn start_drain(&self) {
        let mut accepting = self.accepting.lock().unwrap_or_else(|p| p.into_inner());
        *accepting = false;
        self.workers.close();
    }

    /// A process stopping for a roll: admit nothing new, let every admitted
    /// mutation reach its own deadline, and cancel whatever is left after
    /// `limit`, as `shutdown` does. The runtime sets `limit` to fit inside
    /// the Pod's termination grace.
    pub async fn drain(&self, limit: Duration) -> Result<(), Error> {
        self.start_drain();
        if tokio::time::timeout(limit, self.workers.wait())
            .await
            .is_err()
        {
            tracing::warn!("credential mutations outlived the drain; cancelling them");
        }
        self.shutdown().await
    }

    /// Signal cancellation and await every disposition. Runtime owners may
    /// call `start_shutdown` first to close sibling services before beginning
    /// any transport grace period. Local drain cannot guarantee a remote
    /// COMMIT stopped; uncertain outcomes retain the possibly published
    /// provider credential.
    pub async fn shutdown(&self) -> Result<(), Error> {
        self.start_shutdown();
        self.workers.wait().await;
        Ok(())
    }

    fn enroll(
        &self,
        authority: CredentialMutationAuthority,
        name: String,
        credential_id: Option<String>,
        expected_revision: Option<u64>,
    ) -> Result<Events, Error> {
        let replacement = replacement_selector(credential_id, expected_revision)?;
        validate_target_name(&name, replacement.is_some())?;
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
            if let Err(error) = run_enrollment(shared, &scope, name, replacement, &sender).await {
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

    async fn add_api_key(
        &self,
        authority: CredentialMutationAuthority,
        provider: String,
        name: String,
        material: ProtectedValue,
        expires_at_unix: Option<u64>,
    ) -> Result<CredentialMetadata, Error> {
        validate_api_key(&provider, &name, material.expose_secret(), expires_at_unix)?;
        validate_new_name(&name)?;
        let registration = CredentialRegistration {
            provider: ProviderId::parse(provider).map_err(|_| Error::InvalidInput)?,
            authentication_kind: CredentialAuthKind::ApiKey,
            display_name: name,
            account_hint: None,
            expires_at_unix,
        };
        let scope = Scope::new(
            authority,
            self.stop.child_token(),
            self.shared.mutation_timeout,
        )?;
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
                let result =
                    publication::add_api_key(&shared, &scope, registration, material).await;
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

    /// Store a pasted Claude subscription token as the anthropic provider's
    /// OAuth kind, or replace the exact named existing one. The owner ran
    /// `claude setup-token`; no provider call is made here.
    async fn add_claude_subscription_token(
        &self,
        authority: CredentialMutationAuthority,
        name: String,
        material: ProtectedValue,
        credential_id: Option<String>,
        expected_revision: Option<u64>,
    ) -> Result<CredentialMetadata, Error> {
        validate_name(&name)?;
        validate_claude_subscription_token(material.expose_secret())?;
        let replacement = replacement_selector(credential_id, expected_revision)?;
        validate_target_name(&name, replacement.is_some())?;
        let expires_at_unix = unix_now()?
            .checked_add(CLAUDE_SUBSCRIPTION_TOKEN_LIFETIME_SECONDS)
            .ok_or(Error::Unavailable)?;
        let scope = Scope::new(
            authority,
            self.stop.child_token(),
            self.shared.mutation_timeout,
        )?;
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
                let result = publication::add_claude_subscription_token(
                    &shared,
                    &scope,
                    name,
                    material,
                    replacement,
                    expires_at_unix,
                )
                .await;
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

    async fn lifecycle(
        &self,
        authority: CredentialMutationAuthority,
        id: String,
        revision: u64,
        delete: bool,
    ) -> Result<Option<CredentialMetadata>, Error> {
        let id = CredentialId::parse(id).map_err(|_| Error::InvalidInput)?;
        if revision == 0 || i64::try_from(revision).is_err() {
            return Err(Error::InvalidInput);
        }
        let scope = Scope::new(
            authority,
            self.stop.child_token(),
            self.shared.mutation_timeout,
        )?;
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
    authority: CredentialMutationAuthority,
    owner: Owner,
    deadline: Instant,
    expires_at_unix: u64,
    cancel: CancellationToken,
}

impl Scope {
    fn new(
        authority: CredentialMutationAuthority,
        cancel: CancellationToken,
        limit: Duration,
    ) -> Result<Self, Error> {
        let started = Instant::now();
        let captured_wall = unix_now()?;
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

struct Events<T = EnrollCodexResponse> {
    receiver: mpsc::Receiver<Result<T, Error>>,
    _cancel: DropGuard,
}

enum EnrollmentTarget {
    Create(String),
    CreateGithubAccount,
    Reconnect(CredentialRecord),
}

fn replacement_selector(
    id: Option<String>,
    revision: Option<u64>,
) -> Result<Option<(CredentialId, u64)>, Error> {
    match (id, revision) {
        (None, None) => Ok(None),
        (Some(id), Some(revision)) if revision > 0 && revision <= i64::MAX as u64 => Ok(Some((
            CredentialId::parse(id).map_err(|_| Error::InvalidInput)?,
            revision,
        ))),
        _ => Err(Error::InvalidInput),
    }
}

async fn run_enrollment(
    shared: Arc<Shared>,
    scope: &Scope,
    name: String,
    replacement: Option<(CredentialId, u64)>,
    sender: &mpsc::Sender<Result<EnrollCodexResponse, Error>>,
) -> Result<(), Error> {
    let (target, import) = codex_approved(&shared, scope, name, replacement, sender)
        .await
        .map_err(enrollment::before_publication)?;
    let mut completed = enrollment::Completed::Codex(Some(import));
    let result = publication::enroll(&shared, scope, &mut completed, target).await;
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

/// Everything before publication: the target, the challenge and the person's
/// approval. Nothing is stored yet.
async fn codex_approved(
    shared: &Shared,
    scope: &Scope,
    name: String,
    replacement: Option<(CredentialId, u64)>,
    sender: &mpsc::Sender<Result<EnrollCodexResponse, Error>>,
) -> Result<(EnrollmentTarget, CodexOAuthImport), Error> {
    let target = enrollment_target(
        shared,
        scope,
        "openai",
        CredentialAuthKind::OAuth,
        name,
        replacement,
    )
    .await?;
    let pending = scope
        .wait(shared.codex_login.start())
        .await?
        .map_err(device_login_error)?;
    let challenge = pending.challenge();
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
    scope
        .wait(sender.send(Ok(response)))
        .await?
        .map_err(|_| Error::Cancelled)?;
    let import = scope
        .wait(shared.codex_login.complete(pending))
        .await?
        .map_err(device_login_error)?;
    Ok((target, import))
}

async fn enrollment_target(
    shared: &Shared,
    scope: &Scope,
    provider: &str,
    authentication_kind: CredentialAuthKind,
    name: String,
    replacement: Option<(CredentialId, u64)>,
) -> Result<EnrollmentTarget, Error> {
    scope.check()?;
    // Validate the exact owner/name/kind/full version before starting a device
    // login or emitting its challenge. Keep this record through publication;
    // neither a concurrent refresh nor revoke can be silently overwritten.
    let target = if let Some((id, revision)) = replacement {
        let record = scope
            .wait(shared.store.record(&scope.owner, &id))
            .await?
            .map_err(store_error)?;
        if record.metadata.display_name != name
            || record.metadata.provider.as_str() != provider
            || record.metadata.authentication_kind != authentication_kind
        {
            return Err(Error::InvalidInput);
        }
        if record.version.revocation_generation != revision {
            return Err(Error::StaleRevision);
        }
        EnrollmentTarget::Reconnect(record)
    } else {
        EnrollmentTarget::Create(name)
    };
    Ok(target)
}

/// Refuse to start a second GitHub connection before any provider challenge
/// or code exchange. Publication still relies on the database's singleton
/// index, so a concurrent enrollment cannot slip past this early answer.
async fn ensure_github_unconnected(shared: &Shared, scope: &Scope) -> Result<(), Error> {
    scope.check()?;
    // GitHub is a per-user connection; organizations cannot hold one.
    let Owner::User(user_id) = &scope.owner else {
        return Err(Error::InvalidInput);
    };
    let exists: bool = scope
        .wait(
            sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM platform_credentials \
                  WHERE user_id=$1 AND provider='github' AND authentication_kind='oauth')",
            )
            .bind(user_id.as_str())
            .fetch_one(&shared.pool),
        )
        .await?
        .map_err(|_| Error::Unavailable)?;
    if exists {
        Err(Error::GitHubAlreadyConnected)
    } else {
        Ok(())
    }
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

/// A name a credential is created with or renamed to. `PROVIDER/NAME` would
/// read a name that starts with a provider id and `/` as another credential,
/// so no new name may (docs/dev/SECRETS-AND-CREDENTIALS.md, "Credential
/// names"). A credential that already has one keeps it: reconnecting,
/// rotating or naming it as the expected name checks only [`validate_name`].
fn validate_new_name(name: &str) -> Result<(), Error> {
    validate_name(name)?;
    if reserves_provider_prefix(name) {
        Err(Error::NameReservesProvider)
    } else {
        Ok(())
    }
}

/// An enrollment's name: new unless it reconnects an existing credential,
/// whose name must then match exactly.
fn validate_target_name(name: &str, reconnect: bool) -> Result<(), Error> {
    if reconnect {
        validate_name(name)
    } else {
        validate_new_name(name)
    }
}

fn unix_now() -> Result<u64, Error> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .map_err(|_| Error::Unavailable)
}

fn validate_api_key(
    provider: &str,
    name: &str,
    material: &[u8],
    expiry: Option<u64>,
) -> Result<(), Error> {
    validate_name(name)?;
    if material.is_empty()
        || material.len() > 1024
        || expiry.is_some_and(|value| value > i64::MAX as u64)
    {
        return Err(Error::InvalidInput);
    }
    let valid = match provider {
        "openai" => {
            let token = material
                .iter()
                .position(|byte| *byte == b'=')
                .unwrap_or(material.len());
            token > 0
                && material[..token].iter().all(|byte| {
                    byte.is_ascii_alphanumeric()
                        || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'+' | b'/')
                })
                && material[token..].iter().all(|byte| *byte == b'=')
        }
        "anthropic" => material.iter().all(u8::is_ascii_graphic),
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(Error::InvalidInput)
    }
}

fn validate_claude_subscription_token(material: &[u8]) -> Result<(), Error> {
    if codewire_access::is_claude_subscription_token_shape(material) {
        Ok(())
    } else {
        Err(Error::InvalidInput)
    }
}

/// The provider's device-login outcome. No provider text survives.
fn device_login_error(error: DeviceLoginError) -> Error {
    match error {
        DeviceLoginError::Expired => Error::Expired,
        DeviceLoginError::Unavailable => Error::Unavailable,
        DeviceLoginError::InstallationRequired => Error::GitHubInstallationRequired,
        // A malformed provider answer is a failed attempt; only a disabled
        // device login is something the user must change before retrying.
        DeviceLoginError::AccessDenied | DeviceLoginError::InvalidResponse => {
            Error::EnrollmentFailed
        }
        DeviceLoginError::DeviceLoginDisabled => Error::EnrollmentUnsupported,
    }
}

fn authority_error(error: CredentialMutationAuthorityError) -> Error {
    match error {
        CredentialMutationAuthorityError::Denied => Error::Denied,
        CredentialMutationAuthorityError::Unavailable => Error::Unavailable,
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
