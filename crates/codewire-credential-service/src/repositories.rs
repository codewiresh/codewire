//! Account-scoped finite GitHub discovery, never a fabricated runtime grant.
//! All protected handles and provider traffic stay in the isolated authority.

#[cfg(test)]
mod tests;
mod wire;

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use codewire_access::{
    AccessProfileId, CapabilitySlot, CredentialAuthKind, CredentialMetadata, CredentialStatus,
    Owner, OwnerId, PROVIDER_REFRESH_TIMEOUT_SECONDS, builtin_provider_catalog,
};
use codewire_credential_broker::github::repositories::{
    self as github, GithubRepositoryAccountLease, RepositoryDiscoveryError,
};
use codewire_credential_broker::{
    BrokerUpstreamTransport, GitHubAppAuthorizationOwner, GitHubAppRefreshError,
    GitHubAppUserOAuthBundle,
};
use codewire_platform_credentials::{
    CredentialRecord, OAuthRefreshState, PlatformAccessProfileStore, PlatformCredentialError,
    PlatformCredentialStore, PlatformProfileError,
};
use codewire_protected_store::ProtectedValue;
use codewire_proto::codewire::v1::{
    GithubRepository, ListGithubRepositoriesRequest, ListGithubRepositoriesResponse,
};
use codewire_server_core::auth::{CredentialMutationAuthority, CredentialMutationAuthorityError};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, oneshot};
use tokio::time::Instant;
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use uuid::Uuid;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_OPERATIONS: usize = 8;
const DEFAULT_PAGE_SIZE: u16 = 50;
const MAX_PAGE_TOKEN_BYTES: usize = 128;
const REFRESH_WAIT_ATTEMPTS: usize = 64;
const REFRESH_WAIT_INTERVAL: Duration = Duration::from_millis(500);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Error {
    InvalidInput,
    Denied,
    NotFound,
    ProfileChanged,
    NotConnected,
    CredentialChanged,
    ProviderDenied,
    RateLimited,
    Unavailable,
    Cancelled,
    Expired,
}

pub(crate) struct GithubRepositoryOwner {
    pool: PgPool,
    store: Arc<PlatformCredentialStore>,
    upstream: Arc<dyn BrokerUpstreamTransport>,
    github_app_authorization: Option<Arc<GitHubAppAuthorizationOwner>>,
    capacity: Arc<Semaphore>,
    workers: TaskTracker,
    stop: CancellationToken,
}

impl GithubRepositoryOwner {
    pub(crate) fn new(
        pool: PgPool,
        store: Arc<PlatformCredentialStore>,
        upstream: Arc<dyn BrokerUpstreamTransport>,
        github_app_authorization: Option<Arc<GitHubAppAuthorizationOwner>>,
    ) -> Self {
        Self {
            pool,
            store,
            upstream,
            github_app_authorization,
            capacity: Arc::new(Semaphore::new(MAX_OPERATIONS)),
            workers: TaskTracker::new(),
            stop: CancellationToken::new(),
        }
    }

    pub(crate) fn router(self: &Arc<Self>) -> connectrpc::Router {
        wire::router(self.clone())
    }

    pub(crate) fn start_shutdown(&self) {
        self.capacity.close();
        self.workers.close();
        self.stop.cancel();
    }

    /// Preserve a started rotating-token exchange through service shutdown, so
    /// its durable outcome is either staged and promoted or explicitly failed.
    pub(crate) async fn shutdown(&self) {
        self.start_shutdown();
        self.workers.wait().await;
    }

    async fn list(
        &self,
        authority: CredentialMutationAuthority,
        request: ListGithubRepositoriesRequest,
    ) -> Result<ListGithubRepositoriesResponse, Error> {
        let selection = Selection::parse(request)?;
        let permit = Arc::clone(&self.capacity)
            .try_acquire_owned()
            .map_err(|_| Error::Unavailable)?;
        let owner = Owner::User(OwnerId::parse(authority.user_id()).map_err(|_| Error::Denied)?);
        let deadline = Instant::now()
            + authority
                .remaining_lifetime()
                .map_err(authority_error)?
                .min(REQUEST_TIMEOUT);
        let operation = async {
            let before = self.resolve(&authority, &owner, &selection).await?;
            selection.check_cursor(&owner, &before)?;
            let (mut record, mut material) = self
                .load_account(&authority, &owner, &selection, &before)
                .await?;
            let mut app_bundle = github_app_bundle(&material)?;
            let mut refreshed = false;
            let mut permit = Some(permit);

            let refresh_early = match app_bundle.as_ref() {
                Some(bundle) => bundle
                    .should_refresh(unix_now()?)
                    .map_err(app_bundle_error)?,
                None => false,
            };
            if refresh_early {
                self.refresh_github_app(
                    authority.clone(),
                    owner.clone(),
                    selection.clone(),
                    before.clone(),
                    app_bundle.take().ok_or(Error::Unavailable)?,
                    permit.take().ok_or(Error::Unavailable)?,
                )
                .await?;
                permit = Some(self.acquire_capacity()?);
                // A continuation binds the old revocation generation. Do not
                // silently rebind it after rotating user credentials.
                if !selection.page_token.is_empty() {
                    return Err(Error::CredentialChanged);
                }
                record = self.resolve(&authority, &owner, &selection).await?;
                same_refreshed_record(&before, &record)?;
                (record, material) = self
                    .load_account(&authority, &owner, &selection, &record)
                    .await?;
                same_refreshed_record(&before, &record)?;
                app_bundle = github_app_bundle(&material)?;
                refreshed = true;
            }

            let first = github::list_repositories(
                self.upstream.as_ref(),
                AccountLease { record, material },
                selection.page,
                selection.page_size,
            )
            .await;
            let page = match first {
                // An early renewal already consumed this discovery request's
                // one App rotation/replay budget. A 401 from its direct
                // successor is a provider denial, not authority to rotate
                // again and replay under a third token generation.
                Err(RepositoryDiscoveryError::Unauthorized)
                    if app_bundle.is_some() && !refreshed =>
                {
                    self.refresh_github_app(
                        authority.clone(),
                        owner.clone(),
                        selection.clone(),
                        before.clone(),
                        app_bundle.take().ok_or(Error::Unavailable)?,
                        permit.take().ok_or(Error::Unavailable)?,
                    )
                    .await?;
                    let _retry_permit = self.acquire_capacity()?;
                    if !selection.page_token.is_empty() {
                        return Err(Error::CredentialChanged);
                    }
                    let successor = self.resolve(&authority, &owner, &selection).await?;
                    same_refreshed_record(&before, &successor)?;
                    let (successor, successor_material) = self
                        .load_account(&authority, &owner, &selection, &successor)
                        .await?;
                    same_refreshed_record(&before, &successor)?;
                    refreshed = true;
                    // A 401 is retried once only after a durable, re-admitted
                    // App successor. Any second 401 is a provider denial.
                    github::list_repositories(
                        self.upstream.as_ref(),
                        AccountLease {
                            record: successor,
                            material: successor_material,
                        },
                        selection.page,
                        selection.page_size,
                    )
                    .await
                    .map_err(provider_error)?
                }
                result => result.map_err(provider_error)?,
            };
            // No locks span KEK/provider I/O. Recheck original session/OAuth,
            // exact current profile and credential before releasing metadata.
            let after_response = self.resolve(&authority, &owner, &selection).await?;
            if refreshed {
                same_refreshed_record(&before, &after_response)?;
            } else {
                same_record(&before, &after_response)?;
            }
            let next_page_token = if page.has_more {
                if selection.page >= github::MAX_PAGE {
                    return Err(Error::Unavailable);
                }
                selection.cursor(&owner, &after_response, selection.page + 1)
            } else {
                String::new()
            };
            Ok(ListGithubRepositoriesResponse {
                repositories: page
                    .repositories
                    .into_iter()
                    .map(|repository| GithubRepository {
                        repository_id: repository.repository_id,
                        full_name: repository.full_name,
                        default_branch: repository.default_branch,
                        clone_url: repository.clone_url,
                        is_private: repository.is_private,
                        archived: repository.archived,
                        disabled: repository.disabled,
                        ..Default::default()
                    })
                    .collect(),
                next_page_token,
                ..Default::default()
            })
        };
        // Ordinary discovery is request-owned. A rotating App refresh transfers
        // only its started durable exchange to the tracked service owner.
        tokio::select! {
            biased;
            _ = self.stop.cancelled() => Err(Error::Cancelled),
            _ = tokio::time::sleep_until(deadline) => Err(Error::Expired),
            result = operation => result,
        }
    }

    async fn resolve(
        &self,
        authority: &CredentialMutationAuthority,
        owner: &Owner,
        selection: &Selection,
    ) -> Result<CredentialRecord, Error> {
        resolve_record(&self.pool, self.store.as_ref(), authority, owner, selection).await
    }

    async fn load_account(
        &self,
        authority: &CredentialMutationAuthority,
        owner: &Owner,
        selection: &Selection,
        expected: &CredentialRecord,
    ) -> Result<(CredentialRecord, ProtectedValue), Error> {
        let material = self
            .store
            .read_for_broker(owner, &expected.metadata.id, expected.version)
            .await
            .map_err(credential_error)?;
        let current = self.resolve(authority, owner, selection).await?;
        same_record(expected, &current)?;
        Ok((current, material))
    }

    fn acquire_capacity(&self) -> Result<OwnedSemaphorePermit, Error> {
        Arc::clone(&self.capacity)
            .try_acquire_owned()
            .map_err(|_| Error::Unavailable)
    }

    async fn refresh_github_app(
        &self,
        authority: CredentialMutationAuthority,
        owner: Owner,
        selection: Selection,
        before: CredentialRecord,
        bundle: GitHubAppUserOAuthBundle,
        permit: OwnedSemaphorePermit,
    ) -> Result<(), Error> {
        let authorization = self
            .github_app_authorization
            .as_ref()
            .cloned()
            .ok_or(Error::Unavailable)?;
        let (sender, receiver) = oneshot::channel();
        let pool = self.pool.clone();
        let store = Arc::clone(&self.store);
        // The worker takes the current capacity permit before any async step.
        // If the browser disconnects after a reserve/start, it keeps the full
        // provider exchange and durable publication alive through shutdown.
        self.workers.spawn(async move {
            let _permit = permit;
            let result = refresh_github_app_record(GitHubAppRefreshContext {
                pool,
                store,
                authority,
                owner,
                selection,
                before,
                bundle,
                authorization,
            })
            .await;
            let _ = sender.send(result);
        });
        receiver.await.map_err(|_| Error::Unavailable)?
    }
}

async fn resolve_record(
    pool: &PgPool,
    store: &PlatformCredentialStore,
    authority: &CredentialMutationAuthority,
    owner: &Owner,
    selection: &Selection,
) -> Result<CredentialRecord, Error> {
    let profiles = PlatformAccessProfileStore::new(pool.clone(), builtin_provider_catalog());
    let mut tx = pool.begin().await.map_err(|_| Error::Unavailable)?;
    // Existing restricted security-definer helper rechecks the original exact
    // session row or OAuth subject/client/token, never just expiry.
    authority
        .lock_for_publication(&mut tx)
        .await
        .map_err(authority_error)?;
    let profile = profiles
        .get_in(&mut tx, owner, &selection.profile_id, None)
        .await
        .map_err(profile_error)?;
    if profile.revision != selection.profile_revision {
        return Err(Error::ProfileChanged);
    }
    let credential_id = profile
        .entries
        .get(&CapabilitySlot::github())
        .ok_or(Error::NotConnected)?;
    let record = store
        .record_for_update_in(&mut tx, owner, credential_id)
        .await
        .map_err(credential_error)?;
    let now = unix_now()?;
    if record.metadata.provider.as_str() != "github"
        || record.metadata.authentication_kind != CredentialAuthKind::OAuth
        || record.metadata.status != CredentialStatus::Active
        || record
            .metadata
            .expires_at_unix
            .is_some_and(|expiry| expiry <= now)
    {
        return Err(Error::NotConnected);
    }
    authority.remaining_lifetime().map_err(authority_error)?;
    tx.commit().await.map_err(|_| Error::Unavailable)?;
    Ok(record)
}

fn github_app_bundle(material: &ProtectedValue) -> Result<Option<GitHubAppUserOAuthBundle>, Error> {
    let bytes = material.expose_secret();
    if !GitHubAppUserOAuthBundle::is_tagged(bytes) {
        return Ok(None);
    }
    GitHubAppUserOAuthBundle::parse(bytes)
        .map(Some)
        .map_err(app_bundle_error)
}

/// State that is immutable for one durable GitHub App refresh. It is carried
/// intact into promotion so the successor is re-admitted against precisely
/// the same owner, profile revision, and original record.
struct GitHubAppRefreshContext {
    pool: PgPool,
    store: Arc<PlatformCredentialStore>,
    authority: CredentialMutationAuthority,
    owner: Owner,
    selection: Selection,
    before: CredentialRecord,
    bundle: GitHubAppUserOAuthBundle,
    authorization: Arc<GitHubAppAuthorizationOwner>,
}

async fn refresh_github_app_record(context: GitHubAppRefreshContext) -> Result<(), Error> {
    let GitHubAppRefreshContext {
        pool,
        store,
        authority,
        owner,
        selection,
        before,
        bundle,
        authorization,
    } = context;
    let current = resolve_record(&pool, store.as_ref(), &authority, &owner, &selection).await?;
    same_record(&before, &current)?;
    let credential_id = current.metadata.id.clone();
    let expected = current.version;

    for refresh_waits in 0..=REFRESH_WAIT_ATTEMPTS {
        let attempt = store
            .current_oauth_refresh_attempt(&owner, &credential_id)
            .await
            .map_err(refresh_error)?;
        if let Some(attempt) = attempt {
            if attempt.expected != expected {
                return Err(Error::CredentialChanged);
            }
            match attempt.state {
                OAuthRefreshState::Staged => {
                    store
                        .promote_oauth_refresh(&owner, &credential_id, expected, attempt.attempt_id)
                        .await
                        .map_err(refresh_error)?;
                    return require_refreshed_record(
                        &pool,
                        store.as_ref(),
                        &authority,
                        &owner,
                        &selection,
                        &before,
                    )
                    .await;
                }
                OAuthRefreshState::Committed => {
                    return require_refreshed_record(
                        &pool,
                        store.as_ref(),
                        &authority,
                        &owner,
                        &selection,
                        &before,
                    )
                    .await;
                }
                state
                    if (state == OAuthRefreshState::Reserved && attempt.reservation_live)
                        || (state == OAuthRefreshState::Started && attempt.execution_live) =>
                {
                    if refresh_waits == REFRESH_WAIT_ATTEMPTS {
                        return Err(Error::Unavailable);
                    }
                    tokio::time::sleep(REFRESH_WAIT_INTERVAL).await;
                    let after =
                        resolve_record(&pool, store.as_ref(), &authority, &owner, &selection)
                            .await?;
                    if after != before {
                        return same_refreshed_record(&before, &after);
                    }
                    continue;
                }
                OAuthRefreshState::Started => {
                    store
                        .fail_abandoned_oauth_refresh(
                            &owner,
                            &credential_id,
                            expected,
                            attempt.attempt_id,
                        )
                        .await
                        .map_err(refresh_error)?;
                    return Err(Error::ProviderDenied);
                }
                OAuthRefreshState::Unknown => return Err(Error::Unavailable),
                OAuthRefreshState::Reserved | OAuthRefreshState::Cancelled => {}
            }
        }

        let attempt_id = Uuid::new_v4();
        let prepared = match store
            .begin_oauth_refresh(&owner, &credential_id, expected, attempt_id)
            .await
        {
            Ok(prepared) => prepared,
            // Another process can reserve the same record between our read of
            // the journal and this begin. Observe its durable outcome instead
            // of treating that race as permission to issue a second exchange.
            Err(PlatformCredentialError::RefreshInProgress)
                if refresh_waits < REFRESH_WAIT_ATTEMPTS =>
            {
                tokio::time::sleep(REFRESH_WAIT_INTERVAL).await;
                let after =
                    resolve_record(&pool, store.as_ref(), &authority, &owner, &selection).await?;
                if after != before {
                    return same_refreshed_record(&before, &after);
                }
                continue;
            }
            Err(PlatformCredentialError::RefreshInProgress) => return Err(Error::Unavailable),
            Err(error) => return Err(refresh_error(error)),
        };
        if let Err(error) = resolve_record(&pool, store.as_ref(), &authority, &owner, &selection)
            .await
            .and_then(|current| same_record(&before, &current))
        {
            return match store
                .cancel_oauth_refresh(&owner, &credential_id, expected, attempt_id)
                .await
            {
                Ok(()) => Err(error),
                Err(_) => Err(Error::Unavailable),
            };
        }
        let started = store
            .start_oauth_refresh(prepared)
            .await
            .map_err(refresh_error)?;
        return complete_github_app_refresh(
            GitHubAppRefreshContext {
                pool,
                store,
                authority,
                owner,
                selection,
                before,
                bundle,
                authorization,
            },
            credential_id,
            expected,
            attempt_id,
            started,
        )
        .await;
    }
    Err(Error::Unavailable)
}

async fn complete_github_app_refresh(
    context: GitHubAppRefreshContext,
    credential_id: codewire_access::CredentialId,
    expected: codewire_platform_credentials::CredentialVersion,
    attempt_id: Uuid,
    started: codewire_platform_credentials::StartedOAuthRefresh,
) -> Result<(), Error> {
    let GitHubAppRefreshContext {
        pool,
        store,
        authority,
        owner,
        selection,
        before,
        bundle,
        authorization,
    } = context;
    let exchange = tokio::time::timeout(
        Duration::from_secs(PROVIDER_REFRESH_TIMEOUT_SECONDS),
        authorization.refresh(bundle),
    )
    .await;
    let bundle = match exchange {
        Ok(Ok(bundle)) => bundle,
        Ok(Err(GitHubAppRefreshError::Permanent)) => {
            return fail_started_refresh(store.as_ref(), started, Error::ProviderDenied).await;
        }
        Ok(Err(GitHubAppRefreshError::Uncertain)) | Err(_) => {
            return fail_started_refresh(store.as_ref(), started, Error::Unavailable).await;
        }
    };
    let mut bytes = bundle.into_bytes();
    let value = match ProtectedValue::new(std::mem::take(&mut *bytes)) {
        Ok(value) => value,
        Err(_) => return fail_started_refresh(store.as_ref(), started, Error::Unavailable).await,
    };
    let result = match started.prepare_result(&value) {
        Ok(result) => result,
        Err(_) => return fail_started_refresh(store.as_ref(), started, Error::Unavailable).await,
    };
    drop(value);
    if let Err(error) = store.stage_oauth_refresh(&result).await {
        // Stage acknowledgement can be lost. Discover only this immutable
        // attempt; never repeat a provider exchange after Start.
        let current = store
            .current_oauth_refresh_attempt(&owner, &credential_id)
            .await
            .map_err(refresh_error)?;
        if !current.is_some_and(|attempt| {
            attempt.attempt_id == attempt_id
                && attempt.expected == expected
                && matches!(
                    attempt.state,
                    OAuthRefreshState::Staged | OAuthRefreshState::Committed
                )
        }) {
            return Err(refresh_error(error));
        }
    }
    store
        .promote_oauth_refresh(&owner, &credential_id, expected, attempt_id)
        .await
        .map_err(refresh_error)?;
    require_refreshed_record(
        &pool,
        store.as_ref(),
        &authority,
        &owner,
        &selection,
        &before,
    )
    .await
}

async fn fail_started_refresh(
    store: &PlatformCredentialStore,
    started: codewire_platform_credentials::StartedOAuthRefresh,
    error: Error,
) -> Result<(), Error> {
    match store.fail_oauth_refresh(started).await {
        Ok(()) => Err(error),
        Err(_) => Err(Error::Unavailable),
    }
}

async fn require_refreshed_record(
    pool: &PgPool,
    store: &PlatformCredentialStore,
    authority: &CredentialMutationAuthority,
    owner: &Owner,
    selection: &Selection,
    before: &CredentialRecord,
) -> Result<(), Error> {
    let after = resolve_record(pool, store, authority, owner, selection).await?;
    same_refreshed_record(before, &after)
}

struct AccountLease {
    record: CredentialRecord,
    material: ProtectedValue,
}

impl GithubRepositoryAccountLease for AccountLease {
    fn metadata(&self) -> &CredentialMetadata {
        &self.record.metadata
    }
    fn with_material<T>(self, operation: impl FnOnce(&[u8]) -> T) -> T {
        operation(self.material.expose_secret())
    }
}

#[derive(Clone)]
struct Selection {
    profile_id: AccessProfileId,
    profile_revision: u64,
    page_size: u16,
    page: u32,
    page_token: String,
}

impl Selection {
    fn parse(request: ListGithubRepositoriesRequest) -> Result<Self, Error> {
        let profile_id = uuid::Uuid::parse_str(&request.profile_id)
            .ok()
            .filter(|id| !id.is_nil() && id.to_string() == request.profile_id)
            .and_then(|_| AccessProfileId::parse(request.profile_id).ok())
            .ok_or(Error::InvalidInput)?;
        if request.profile_revision == 0
            || request.profile_revision > i64::MAX as u64
            || request.page_size < 0
            || request.page_size > i32::from(github::MAX_PAGE_SIZE)
            || request.page_token.len() > MAX_PAGE_TOKEN_BYTES
        {
            return Err(Error::InvalidInput);
        }
        let page_size = if request.page_size == 0 {
            DEFAULT_PAGE_SIZE
        } else {
            request.page_size as u16
        };
        let page = if request.page_token.is_empty() {
            1
        } else {
            let fields: Vec<_> = request.page_token.split('.').collect();
            if fields.len() != 4
                || fields[0] != "v1"
                || fields[2] != page_size.to_string()
                || fields[3].len() != 64
                || !fields[3]
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err(Error::InvalidInput);
            }
            let page = fields[1].parse::<u32>().map_err(|_| Error::InvalidInput)?;
            if !(2..=github::MAX_PAGE).contains(&page) || fields[1] != page.to_string() {
                return Err(Error::InvalidInput);
            }
            page
        };
        Ok(Self {
            profile_id,
            profile_revision: request.profile_revision,
            page_size,
            page,
            page_token: request.page_token,
        })
    }

    fn cursor(&self, owner: &Owner, record: &CredentialRecord, page: u32) -> String {
        let mut hash = Sha256::new();
        hash.update(b"codewire-github-repositories-v1");
        for value in [
            owner.id().as_str(),
            self.profile_id.as_str(),
            record.metadata.id.as_str(),
        ] {
            hash.update((value.len() as u64).to_be_bytes());
            hash.update(value.as_bytes());
        }
        hash.update(self.profile_revision.to_be_bytes());
        hash.update(record.metadata.revocation_generation.to_be_bytes());
        let binding = hash
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        // This opaque continuation is not a grant or a secret. Recompute its
        // binding from current authorized records on EVERY request. It contains
        // no provider cursor, internal material version or protected-store path.
        format!("v1.{page}.{}.{binding}", self.page_size)
    }

    fn check_cursor(&self, owner: &Owner, record: &CredentialRecord) -> Result<(), Error> {
        if !self.page_token.is_empty() && self.page_token != self.cursor(owner, record, self.page) {
            return Err(Error::CredentialChanged);
        }
        Ok(())
    }
}

fn same_record(before: &CredentialRecord, after: &CredentialRecord) -> Result<(), Error> {
    if before != after {
        Err(Error::CredentialChanged)
    } else {
        Ok(())
    }
}

/// A successful refresh replaces exactly one material/revocation generation.
/// It must not turn an account, profile binding, display identity, or hard
/// lifetime change into permission to retry the original discovery request.
fn same_refreshed_record(before: &CredentialRecord, after: &CredentialRecord) -> Result<(), Error> {
    let revocation_generation = before
        .version
        .revocation_generation
        .checked_add(1)
        .ok_or(Error::CredentialChanged)?;
    let material_generation = before
        .version
        .material_generation
        .checked_add(1)
        .ok_or(Error::CredentialChanged)?;
    let mut expected = before.clone();
    expected.version.revocation_generation = revocation_generation;
    expected.version.material_generation = material_generation;
    expected.metadata.revocation_generation = revocation_generation;
    same_record(&expected, after)
}

fn unix_now() -> Result<u64, Error> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| Error::Unavailable)
}

fn app_bundle_error(_: codewire_credential_broker::GitHubAppAuthorizationError) -> Error {
    // Tagged material is never reinterpreted as a legacy CLI token. A malformed
    // or expired App bundle requires reconnecting the provider account.
    Error::NotConnected
}

fn authority_error(error: CredentialMutationAuthorityError) -> Error {
    match error {
        CredentialMutationAuthorityError::Denied => Error::Denied,
        CredentialMutationAuthorityError::Unavailable => Error::Unavailable,
    }
}

fn profile_error(error: PlatformProfileError) -> Error {
    match error {
        PlatformProfileError::NotFound => Error::NotFound,
        PlatformProfileError::StaleRevision => Error::ProfileChanged,
        _ => Error::Unavailable,
    }
}

fn credential_error(error: PlatformCredentialError) -> Error {
    match error {
        PlatformCredentialError::NotFound => Error::NotConnected,
        PlatformCredentialError::StaleVersion => Error::CredentialChanged,
        PlatformCredentialError::Inactive | PlatformCredentialError::Expired => Error::NotConnected,
        _ => Error::Unavailable,
    }
}

fn refresh_error(error: PlatformCredentialError) -> Error {
    match error {
        PlatformCredentialError::NotFound
        | PlatformCredentialError::Inactive
        | PlatformCredentialError::Expired => Error::NotConnected,
        PlatformCredentialError::StaleVersion | PlatformCredentialError::StaleRefresh => {
            Error::CredentialChanged
        }
        PlatformCredentialError::RefreshInProgress
        | PlatformCredentialError::RefreshOutcomeUnknown
        | PlatformCredentialError::InvalidInput
        | PlatformCredentialError::UnsupportedCredential
        | PlatformCredentialError::AlreadyExists
        | PlatformCredentialError::CredentialInUse
        | PlatformCredentialError::CorruptRecord
        | PlatformCredentialError::DatabaseUnavailable
        | PlatformCredentialError::ProviderUnavailable
        | PlatformCredentialError::ProviderTimedOut
        | PlatformCredentialError::ClockUnavailable => Error::Unavailable,
    }
}

fn provider_error(error: RepositoryDiscoveryError) -> Error {
    match error {
        RepositoryDiscoveryError::Unauthorized | RepositoryDiscoveryError::Denied => {
            Error::ProviderDenied
        }
        RepositoryDiscoveryError::RateLimited => Error::RateLimited,
        _ => Error::Unavailable,
    }
}
