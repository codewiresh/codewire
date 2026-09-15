//! Account-scoped finite GitHub discovery, never a fabricated runtime grant.
//! All protected handles and provider traffic stay in the isolated authority.

#[cfg(test)]
mod tests;
mod wire;

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use codewire_access::{
    AccessProfileId, CapabilitySlot, CredentialAuthKind, CredentialMetadata, CredentialStatus,
    Owner, OwnerId, builtin_provider_catalog,
};
use codewire_credential_broker::BrokerUpstreamTransport;
use codewire_credential_broker::github::repositories::{
    self as github, GithubRepositoryAccountLease, RepositoryDiscoveryError,
};
use codewire_platform_credentials::{
    CredentialRecord, PlatformAccessProfileStore, PlatformCredentialError, PlatformCredentialStore,
    PlatformProfileError,
};
use codewire_protected_store::ProtectedValue;
use codewire_proto::codewire::v1::{
    GithubRepository, ListGithubRepositoriesRequest, ListGithubRepositoriesResponse,
};
use codewire_server_core::auth::{CredentialMutationAuthority, CredentialMutationAuthorityError};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tokio::sync::Semaphore;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_OPERATIONS: usize = 8;
const DEFAULT_PAGE_SIZE: u16 = 50;
const MAX_PAGE_TOKEN_BYTES: usize = 128;

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
    profiles: PlatformAccessProfileStore,
    store: Arc<PlatformCredentialStore>,
    upstream: Arc<dyn BrokerUpstreamTransport>,
    capacity: Semaphore,
    stop: CancellationToken,
}

impl GithubRepositoryOwner {
    pub(crate) fn new(
        pool: PgPool,
        store: Arc<PlatformCredentialStore>,
        upstream: Arc<dyn BrokerUpstreamTransport>,
    ) -> Self {
        Self {
            profiles: PlatformAccessProfileStore::new(pool.clone(), builtin_provider_catalog()),
            pool,
            store,
            upstream,
            capacity: Semaphore::new(MAX_OPERATIONS),
            stop: CancellationToken::new(),
        }
    }

    pub(crate) fn router(self: &Arc<Self>) -> connectrpc::Router {
        wire::router(self.clone())
    }

    pub(crate) fn start_shutdown(&self) {
        self.capacity.close();
        self.stop.cancel();
    }

    async fn list(
        &self,
        authority: CredentialMutationAuthority,
        request: ListGithubRepositoriesRequest,
    ) -> Result<ListGithubRepositoriesResponse, Error> {
        let selection = Selection::parse(request)?;
        let _permit = self
            .capacity
            .try_acquire()
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
            let material = self
                .store
                .read_for_broker(&owner, &before.metadata.id, before.version)
                .await
                .map_err(credential_error)?;
            let after_unwrap = self.resolve(&authority, &owner, &selection).await?;
            same_record(&before, &after_unwrap)?;
            let page = github::list_repositories(
                self.upstream.as_ref(),
                AccountLease {
                    record: after_unwrap,
                    material,
                },
                selection.page,
                selection.page_size,
            )
            .await
            .map_err(provider_error)?;
            // No locks span KEK/provider I/O. Recheck original session/OAuth,
            // exact current profile and credential before releasing metadata.
            let after_response = self.resolve(&authority, &owner, &selection).await?;
            same_record(&before, &after_response)?;
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
        // This read-only request owns every future and response stream. Dropping
        // it cancels its I/O; it launches no child or background publication.
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
        let mut tx = self.pool.begin().await.map_err(|_| Error::Unavailable)?;
        // Existing restricted security-definer helper rechecks the original
        // exact session row or OAuth subject/client/token, never just expiry.
        authority
            .lock_for_publication(&mut tx)
            .await
            .map_err(authority_error)?;
        let profile = self
            .profiles
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
        let record = self
            .store
            .record_for_update_in(&mut tx, owner, credential_id)
            .await
            .map_err(credential_error)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::Unavailable)?
            .as_secs();
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

fn provider_error(error: RepositoryDiscoveryError) -> Error {
    match error {
        RepositoryDiscoveryError::Denied => Error::ProviderDenied,
        RepositoryDiscoveryError::RateLimited => Error::RateLimited,
        _ => Error::Unavailable,
    }
}
