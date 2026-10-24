//! Account-scoped finite GitHub discovery, never a fabricated runtime grant.
//! All protected handles and provider traffic stay in the isolated authority.

#[cfg(test)]
mod tests;
mod wire;

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use codewire_access::{
    CredentialAuthKind, CredentialId, CredentialMetadata, CredentialStatus, Owner, OwnerId,
    PROVIDER_REFRESH_TIMEOUT_SECONDS,
};
use codewire_credential_broker::github::repositories::{
    self as github, GithubRepositoryAccountLease, RepositoryDiscoveryError,
};
use codewire_credential_broker::{
    BrokerUpstreamTransport, GitHubAccountKind, GitHubAppAuthorizationOwner,
    GitHubAppInstallationReach, GitHubAppRefreshError, GitHubAppStatusError,
    GitHubAppUserOAuthBundle,
};
use codewire_platform_credentials::{
    CredentialRecord, OAuthRefreshAttemptInfo, OAuthRefreshState, PlatformCredentialError,
    PlatformCredentialStore,
};
use codewire_protected_store::ProtectedValue;
use codewire_proto::codewire::v1::{
    GithubAppAccountKind, GithubAppPendingPermissions, GithubRepository,
    ListGithubPendingPermissionsResponse, ListGithubRepositoriesRequest,
    ListGithubRepositoriesResponse,
};
use codewire_server_core::auth::{CredentialMutationAuthority, CredentialMutationAuthorityError};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, oneshot};
use tokio::time::Instant;
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use uuid::Uuid;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// The live permission status is advisory: a page renders without it, so it
/// gets its callers' own budget and a few slots of its own, never discovery's.
const STATUS_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_STATUS_OPERATIONS: usize = 3;
const MAX_PENDING_PERMISSIONS: usize = 16;
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
    NotConnected,
    CredentialChanged,
    ProviderDenied,
    RateLimited,
    Unavailable,
    Cancelled,
    Expired,
    /// An advisory read found its slots full or another renewal of the same
    /// credential running, and does not wait (#2712).
    Busy,
}

pub(crate) struct GithubRepositoryOwner {
    pool: PgPool,
    store: Arc<PlatformCredentialStore>,
    upstream: Arc<dyn BrokerUpstreamTransport>,
    github_app_authorization: Option<Arc<GitHubAppAuthorizationOwner>>,
    capacity: Arc<Semaphore>,
    status_capacity: Arc<Semaphore>,
    /// The advisory status's own budget: `STATUS_TIMEOUT`, except in tests
    /// whose subject is not that deadline (#3304).
    status_timeout: Duration,
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
            status_capacity: Arc::new(Semaphore::new(MAX_STATUS_OPERATIONS)),
            status_timeout: STATUS_TIMEOUT,
            workers: TaskTracker::new(),
            stop: CancellationToken::new(),
        }
    }

    /// A test owner whose advisory status gets `timeout` instead of
    /// `STATUS_TIMEOUT`.
    #[cfg(test)]
    fn with_status_timeout(mut self, timeout: Duration) -> Self {
        self.status_timeout = timeout;
        self
    }

    pub(crate) fn router(self: &Arc<Self>) -> connectrpc::Router {
        wire::router(self.clone())
    }

    pub(crate) fn start_shutdown(&self) {
        self.capacity.close();
        self.status_capacity.close();
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
        let permit = acquire(&self.capacity)?;
        let operation = async {
            let (output, after_response) = self
                .read(&authority, &selection, Read::Repositories, permit)
                .await?;
            let ReadOutput::Repositories(page) = output else {
                return Err(Error::Unavailable);
            };
            let owner = owner_of(&authority)?;
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
        self.bounded(&authority, REQUEST_TIMEOUT, operation).await
    }

    /// The installations of the owner's GitHub App connection that have not
    /// yet granted what Codewire needs (#2712), read live with that same
    /// connection under discovery's authority, renewal and recheck. Only a
    /// validated login, the installation ID and its account kind leave.
    ///
    /// Advisory, so it never holds anyone up: it has its own few slots and
    /// answers nothing at once when they are full or when another renewal
    /// of this credential is running. It may start a renewal itself; that
    /// moves to the tracked worker and completes durably for the next read.
    async fn pending_permissions(
        &self,
        authority: CredentialMutationAuthority,
    ) -> Result<ListGithubPendingPermissionsResponse, Error> {
        let selection = Selection::first_page();
        let Ok(permit) = acquire(&self.status_capacity) else {
            return Ok(ListGithubPendingPermissionsResponse::default());
        };
        let operation = async {
            let (output, _) = match self
                .read(&authority, &selection, Read::PendingPermissions, permit)
                .await
            {
                Err(Error::Busy) => return Ok(ListGithubPendingPermissionsResponse::default()),
                result => result?,
            };
            let ReadOutput::PendingPermissions(pending) = output else {
                return Err(Error::Unavailable);
            };
            Ok(ListGithubPendingPermissionsResponse {
                pending_permissions: pending
                    .into_iter()
                    .take(MAX_PENDING_PERMISSIONS)
                    .filter_map(|reach| {
                        let pending = reach.pending_permissions?;
                        Some(GithubAppPendingPermissions {
                            account: reach.account,
                            installation_id: pending.installation_id,
                            account_kind: match pending.account_kind {
                                GitHubAccountKind::User => GithubAppAccountKind::User,
                                GitHubAccountKind::Organization => {
                                    GithubAppAccountKind::Organization
                                }
                                GitHubAccountKind::Enterprise => GithubAppAccountKind::Enterprise,
                            }
                            .into(),
                            ..Default::default()
                        })
                    })
                    .collect(),
                ..Default::default()
            })
        };
        self.bounded(&authority, self.status_timeout, operation)
            .await
    }

    /// Run one request-owned operation within the original authority's
    /// remaining lifetime and `timeout`. A rotating App refresh it starts
    /// is transferred to the tracked service owner and outlives it.
    async fn bounded<T>(
        &self,
        authority: &CredentialMutationAuthority,
        timeout: Duration,
        operation: impl std::future::Future<Output = Result<T, Error>>,
    ) -> Result<T, Error> {
        let deadline = Instant::now()
            + authority
                .remaining_lifetime()
                .map_err(authority_error)?
                .min(timeout);
        tokio::select! {
            biased;
            _ = self.stop.cancelled() => Err(Error::Cancelled),
            _ = tokio::time::sleep_until(deadline) => Err(Error::Expired),
            result = operation => result,
        }
    }

    /// One provider read with the owner's current GitHub connection. For
    /// discovery an App token about to expire is renewed first; for either
    /// read a 401 renews once and asks again. No locks span KEK or provider I/O: the original session or
    /// OAuth authority and the exact credential record are checked again
    /// after the answer, before anything from it is released.
    async fn read(
        &self,
        authority: &CredentialMutationAuthority,
        selection: &Selection,
        read: Read,
        permit: OwnedSemaphorePermit,
    ) -> Result<(ReadOutput, CredentialRecord), Error> {
        // Discovery waits for another renewal and takes discovery's slots;
        // the advisory status does neither.
        let (capacity, wait) = match read {
            Read::Repositories => (&self.capacity, true),
            Read::PendingPermissions => (&self.status_capacity, false),
        };
        let reacquire =
            || acquire(capacity).map_err(|error| if wait { error } else { Error::Busy });
        let owner = owner_of(authority)?;
        let before = self.resolve(authority, &owner, selection).await?;
        selection.check_cursor(&owner, &before)?;
        let (mut record, mut material) = self
            .load_account(authority, &owner, selection, &before)
            .await?;
        let mut app_bundle = github_app_bundle(&material)?;
        let mut refreshed = false;
        let mut permit = Some(permit);

        let due = match app_bundle.as_ref() {
            Some(bundle) => bundle
                .should_refresh(unix_now()?)
                .map_err(app_bundle_error)?,
            None => false,
        };
        // The advisory status never renews ahead of time: a token GitHub
        // still accepts is used as it is, and only one GitHub refuses renews,
        // once, below. Page renders therefore never rotate a working token.
        let refresh_early = due && matches!(read, Read::Repositories);
        if refresh_early {
            self.refresh_github_app(
                Renewal {
                    authority: authority.clone(),
                    owner: owner.clone(),
                    selection: selection.clone(),
                    before: before.clone(),
                    bundle: app_bundle.take().ok_or(Error::Unavailable)?,
                    wait,
                },
                permit.take().ok_or(Error::Unavailable)?,
            )
            .await?;
            permit = Some(reacquire()?);
            // A continuation binds the old revocation generation. Do not
            // silently rebind it after rotating user credentials.
            if !selection.page_token.is_empty() {
                return Err(Error::CredentialChanged);
            }
            record = self.resolve(authority, &owner, selection).await?;
            same_refreshed_record(&before, &record)?;
            (record, material) = self
                .load_account(authority, &owner, selection, &record)
                .await?;
            same_refreshed_record(&before, &record)?;
            app_bundle = github_app_bundle(&material)?;
            refreshed = true;
        }

        let first = self
            .call(&read, selection, AccountLease { record, material })
            .await;
        let output = match first {
            // An early renewal already consumed this request's one App
            // rotation/replay budget. A 401 from its direct successor is a
            // provider denial, not authority to rotate again and replay under
            // a third token generation.
            Err(Call::Unauthorized) if app_bundle.is_some() && !refreshed => {
                self.refresh_github_app(
                    Renewal {
                        authority: authority.clone(),
                        owner: owner.clone(),
                        selection: selection.clone(),
                        before: before.clone(),
                        bundle: app_bundle.take().ok_or(Error::Unavailable)?,
                        wait,
                    },
                    permit.take().ok_or(Error::Unavailable)?,
                )
                .await?;
                let _retry_permit = reacquire()?;
                if !selection.page_token.is_empty() {
                    return Err(Error::CredentialChanged);
                }
                let successor = self.resolve(authority, &owner, selection).await?;
                same_refreshed_record(&before, &successor)?;
                let (successor, successor_material) = self
                    .load_account(authority, &owner, selection, &successor)
                    .await?;
                same_refreshed_record(&before, &successor)?;
                refreshed = true;
                // A 401 is retried once only after a durable, re-admitted
                // App successor. Any second 401 is a provider denial.
                self.call(
                    &read,
                    selection,
                    AccountLease {
                        record: successor,
                        material: successor_material,
                    },
                )
                .await
                .map_err(Call::into_error)?
            }
            result => result.map_err(Call::into_error)?,
        };
        let after_response = self.resolve(authority, &owner, selection).await?;
        if refreshed {
            same_refreshed_record(&before, &after_response)?;
        } else {
            same_record(&before, &after_response)?;
        }
        Ok((output, after_response))
    }

    async fn call(
        &self,
        read: &Read,
        selection: &Selection,
        lease: AccountLease,
    ) -> Result<ReadOutput, Call> {
        match read {
            Read::Repositories => github::list_repositories(
                self.upstream.as_ref(),
                lease,
                selection.page,
                selection.page_size,
            )
            .await
            .map(ReadOutput::Repositories)
            .map_err(|error| match error {
                RepositoryDiscoveryError::Unauthorized => Call::Unauthorized,
                error => Call::Failed(provider_error(error)),
            }),
            Read::PendingPermissions => {
                let authorization = self
                    .github_app_authorization
                    .as_ref()
                    .ok_or(Call::Failed(Error::Unavailable))?;
                authorization
                    .pending_permissions(lease.material.expose_secret())
                    .await
                    .map(ReadOutput::PendingPermissions)
                    .map_err(|error| match error {
                        GitHubAppStatusError::Unauthorized => Call::Unauthorized,
                        GitHubAppStatusError::Unavailable => Call::Failed(Error::Unavailable),
                    })
            }
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

    async fn refresh_github_app(
        &self,
        renewal: Renewal,
        permit: OwnedSemaphorePermit,
    ) -> Result<(), Error> {
        let Renewal {
            authority,
            owner,
            selection,
            before,
            bundle,
            wait,
        } = renewal;
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
                wait,
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
    _selection: &Selection,
) -> Result<CredentialRecord, Error> {
    let mut tx = pool.begin().await.map_err(|_| Error::Unavailable)?;
    // Existing restricted security-definer helper rechecks the original exact
    // session row or OAuth subject/client/token, never just expiry.
    authority
        .lock_for_publication(&mut tx)
        .await
        .map_err(authority_error)?;
    let Owner::User(user_id) = owner else {
        return Err(Error::NotConnected);
    };
    let singleton_ids: Vec<String> = sqlx::query_scalar(
        "SELECT id FROM platform_credentials \
         WHERE user_id=$1 AND provider='github' AND authentication_kind='oauth' \
           AND status='active' ORDER BY id",
    )
    .bind(user_id.as_str())
    .fetch_all(&mut *tx)
    .await
    .map_err(|_| Error::Unavailable)?;
    let [credential_id] = singleton_ids.as_slice() else {
        return Err(Error::NotConnected);
    };
    let credential_id = CredentialId::parse(credential_id).map_err(|_| Error::NotConnected)?;
    let record = store
        .record_for_update_in(&mut tx, owner, &credential_id)
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

/// What one read asks a renewal for: the exact record it read and whether it
/// waits for another renewal of the same credential.
struct Renewal {
    authority: CredentialMutationAuthority,
    owner: Owner,
    selection: Selection,
    before: CredentialRecord,
    bundle: GitHubAppUserOAuthBundle,
    wait: bool,
}

/// State that is immutable for one durable GitHub App refresh. It is carried
/// intact into promotion so the successor is re-admitted against precisely
/// the same owner, credential, and original record.
struct GitHubAppRefreshContext {
    pool: PgPool,
    store: Arc<PlatformCredentialStore>,
    authority: CredentialMutationAuthority,
    owner: Owner,
    selection: Selection,
    before: CredentialRecord,
    bundle: GitHubAppUserOAuthBundle,
    authorization: Arc<GitHubAppAuthorizationOwner>,
    /// Whether this read waits for another renewal of the same credential to
    /// finish; an advisory read returns at once instead.
    wait: bool,
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
        wait,
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
        // A finished attempt against an earlier generation is history that
        // begin replaces, not a concurrent change. Without this, the first
        // committed renewal would block every later one.
        let attempt =
            attempt.filter(|attempt| attempt.expected == expected || !finished_attempt(attempt));
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
                    if !wait {
                        return Err(Error::Busy);
                    }
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
                    tracing::warn!(
                        provider = "github",
                        failure = "abandoned",
                        "started credential refresh passed its execution deadline without an outcome"
                    );
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
            Err(PlatformCredentialError::RefreshInProgress) if !wait => return Err(Error::Busy),
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
                wait,
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
        wait: _,
    } = context;
    let exchange = tokio::time::timeout(
        Duration::from_secs(PROVIDER_REFRESH_TIMEOUT_SECONDS),
        authorization.refresh(bundle),
    )
    .await;
    let bundle = match exchange {
        Ok(Ok(bundle)) => bundle,
        Ok(Err(GitHubAppRefreshError::Permanent)) => {
            return fail_started_refresh(
                store.as_ref(),
                started,
                "provider_rejected",
                Error::ProviderDenied,
            )
            .await;
        }
        Ok(Err(GitHubAppRefreshError::Uncertain)) => {
            return fail_started_refresh(
                store.as_ref(),
                started,
                "provider_uncertain",
                Error::Unavailable,
            )
            .await;
        }
        Err(_) => {
            return fail_started_refresh(store.as_ref(), started, "timeout", Error::Unavailable)
                .await;
        }
    };
    let mut bytes = bundle.into_bytes();
    let value = match ProtectedValue::new(std::mem::take(&mut *bytes)) {
        Ok(value) => value,
        Err(_) => {
            return fail_started_refresh(store.as_ref(), started, "material", Error::Unavailable)
                .await;
        }
    };
    let result = match started.prepare_result(&value) {
        Ok(result) => result,
        Err(_) => {
            return fail_started_refresh(store.as_ref(), started, "material", Error::Unavailable)
                .await;
        }
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

/// `failure` is a fixed class name; no provider or storage detail is logged.
async fn fail_started_refresh(
    store: &PlatformCredentialStore,
    started: codewire_platform_credentials::StartedOAuthRefresh,
    failure: &'static str,
    error: Error,
) -> Result<(), Error> {
    tracing::warn!(
        provider = "github",
        failure,
        "provider credential refresh failed"
    );
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

/// What one account read asks GitHub for.
enum Read {
    Repositories,
    PendingPermissions,
}

enum ReadOutput {
    Repositories(github::RepositoryPage),
    PendingPermissions(Vec<GitHubAppInstallationReach>),
}

/// A provider call's outcome before the one permitted renewal.
enum Call {
    Unauthorized,
    Failed(Error),
}

impl Call {
    fn into_error(self) -> Error {
        match self {
            Self::Unauthorized => Error::ProviderDenied,
            Self::Failed(error) => error,
        }
    }
}

fn acquire(capacity: &Arc<Semaphore>) -> Result<OwnedSemaphorePermit, Error> {
    Arc::clone(capacity)
        .try_acquire_owned()
        .map_err(|_| Error::Unavailable)
}

fn owner_of(authority: &CredentialMutationAuthority) -> Result<Owner, Error> {
    Ok(Owner::User(
        OwnerId::parse(authority.user_id()).map_err(|_| Error::Denied)?,
    ))
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
    page_size: u16,
    page: u32,
    page_token: String,
}

impl Selection {
    /// The selection of a read that has no pages of its own.
    fn first_page() -> Self {
        Self {
            page_size: DEFAULT_PAGE_SIZE,
            page: 1,
            page_token: String::new(),
        }
    }

    fn parse(request: ListGithubRepositoriesRequest) -> Result<Self, Error> {
        if request.page_size < 0
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
                || fields[0] != "v2"
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
            page_size,
            page,
            page_token: request.page_token,
        })
    }

    fn cursor(&self, owner: &Owner, record: &CredentialRecord, page: u32) -> String {
        let mut hash = Sha256::new();
        hash.update(b"codewire-github-repositories-v2");
        for value in [owner.id().as_str(), record.metadata.id.as_str()] {
            hash.update((value.len() as u64).to_be_bytes());
            hash.update(value.as_bytes());
        }
        hash.update(record.metadata.revocation_generation.to_be_bytes());
        hash.update(record.version.revocation_generation.to_be_bytes());
        hash.update(record.version.material_generation.to_be_bytes());
        let binding = hash
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        // This opaque continuation is not a grant or a secret. Recompute its
        // binding from current authorized records on EVERY request. It contains
        // no provider cursor, internal material version or protected-store path.
        format!("v2.{page}.{}.{binding}", self.page_size)
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
/// It must not turn an account, display identity, or hard
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

/// The states `begin_oauth_refresh` may replace: no provider request is
/// outstanding and no result waits to be promoted.
fn finished_attempt(attempt: &OAuthRefreshAttemptInfo) -> bool {
    matches!(
        attempt.state,
        OAuthRefreshState::Committed | OAuthRefreshState::Cancelled
    ) || (attempt.state == OAuthRefreshState::Reserved && !attempt.reservation_live)
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

fn credential_error(error: PlatformCredentialError) -> Error {
    match error {
        PlatformCredentialError::NotFound => Error::NotFound,
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
