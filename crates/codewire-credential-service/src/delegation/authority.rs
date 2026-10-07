//! Original owner-OAuth authority for an exact platform selection targeting one
//! local environment operation. This module owns no listener or transport.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use codewire_access::{
    AccessProfileId, DerivedGrant, EnvironmentAccessBinding, EnvironmentId, GrantContext,
    GrantPlacement, HttpProvider, Owner, OwnerId, Placement,
};
use codewire_credential_broker::platform::{
    PlatformRuntimeAuthority, PlatformRuntimeError as Error, PlatformRuntimeSession,
};
use codewire_daemon_proto::codewire::bridge::v1;
use codewire_platform_credentials::{PlatformAccessProfileStore, PlatformProfileError};
use codewire_project::{PlatformProjectionSelection, platform_projection_reserved_keys};
use codewire_protected_store::secret_envelope::KekProvider;
use codewire_server_core::auth::{OAuthBearerAuthority, OAuthBearerAuthorityError};
use codewire_workload_secrets::{
    ProjectionContext, ProjectionContributor, seal_environment_projection,
    seal_environment_projection_fragment, validate_projection_recipient,
};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::projection::{capture_in, composition};

const MAX_OWNER_LOCAL_LIFETIME: Duration = Duration::from_secs(600);
const OWNER_LOCAL_ADMISSION_TIMEOUT: Duration = Duration::from_secs(5);
const NATIVE_CODEX_HOME_KEY: &str = "CODEX_HOME";

/// Names-only platform source/profile selection bound to one existing local
/// environment operation and its canonical native ProjectSpec digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnerLocalSelection {
    local_environment_id: Uuid,
    local_environment_generation: u64,
    platform: PlatformProjectionSelection,
    selection_sha256: [u8; 32],
}

impl OwnerLocalSelection {
    pub fn new(
        local_environment_id: Uuid,
        local_environment_generation: u64,
        platform: PlatformProjectionSelection,
        selection_sha256: [u8; 32],
    ) -> Result<Self, Error> {
        platform.validate().map_err(|_| Error::Denied)?;
        let _ = platform.sha256().map_err(|_| Error::Denied)?;
        if local_environment_id.is_nil()
            || local_environment_generation == 0
            || local_environment_generation > i64::MAX as u64
            || selection_sha256 == [0; 32]
        {
            return Err(Error::Denied);
        }
        validate_reserved_keys(&platform, [])?;
        Ok(Self {
            local_environment_id,
            local_environment_generation,
            platform,
            selection_sha256,
        })
    }
}

/// Process-local authority retaining the exact original OAuth token reference.
/// It does not attest the local host, create a Pod identity, or persist a
/// delegation. The eventual transport owner must authenticate the local caller.
pub struct OwnerLocalRuntimeAuthority {
    source: OwnerLocalSource,
    initial: Admission,
}

struct OwnerLocalSource {
    pool: PgPool,
    provider: Arc<dyn KekProvider>,
    profiles: PlatformAccessProfileStore,
    oauth: OAuthBearerAuthority,
    selection: OwnerLocalSelection,
    expires_at_unix: u64,
    deadline: Instant,
}

#[derive(Clone, PartialEq, Eq)]
struct Admission {
    session: PlatformRuntimeSession,
    grants: Vec<DerivedGrant>,
}

impl OwnerLocalRuntimeAuthority {
    pub async fn new(
        pool: PgPool,
        provider: Arc<dyn KekProvider>,
        profiles: PlatformAccessProfileStore,
        oauth: OAuthBearerAuthority,
        selection: OwnerLocalSelection,
        connected_expires_at_unix: u64,
    ) -> Result<Arc<Self>, Error> {
        if selection.platform.creator != oauth.user_id() {
            return Err(Error::Denied);
        }
        let captured_monotonic = Instant::now();
        let now_wall = unix_time()?;
        let now = now_wall.as_secs();
        let oauth_expires_at = u64::try_from(oauth.expires_at().timestamp())
            .ok()
            .filter(|expires| *expires > now)
            .ok_or(Error::Denied)?;
        let expires_at_unix = connected_expires_at_unix.min(oauth_expires_at).min(
            now.checked_add(MAX_OWNER_LOCAL_LIFETIME.as_secs())
                .ok_or(Error::Denied)?,
        );
        let wall_remaining = Duration::from_secs(expires_at_unix)
            .checked_sub(now_wall)
            .filter(|remaining| !remaining.is_zero())
            .ok_or(Error::Denied)?;
        let remaining = oauth
            .remaining_lifetime()
            .map_err(oauth_error)?
            .min(wall_remaining);
        let deadline = captured_monotonic
            .checked_add(remaining)
            .ok_or(Error::Denied)?;
        let source = OwnerLocalSource {
            pool,
            provider,
            profiles,
            oauth,
            selection,
            expires_at_unix,
            deadline,
        };
        let initial = source.admit().await?;
        Ok(Arc::new(Self { source, initial }))
    }
}

impl OwnerLocalSource {
    async fn admit(&self) -> Result<Admission, Error> {
        self.ensure_live()?;
        let timeout = Instant::now()
            .checked_add(OWNER_LOCAL_ADMISSION_TIMEOUT)
            .ok_or(Error::Denied)?;
        let deadline = self.deadline.min(timeout);
        let result = tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), async {
            let mut tx = self.pool.begin().await.map_err(|_| Error::Unavailable)?;
            let admission = self.admit_in(&mut tx).await?;
            tx.commit().await.map_err(|_| Error::Unavailable)?;
            self.ensure_live()?;
            Ok(admission)
        })
        .await;
        match result {
            Ok(result) => result,
            Err(_) => match self.ensure_live() {
                Ok(()) => Err(Error::Unavailable),
                Err(error) => Err(error),
            },
        }
    }

    async fn admit_in(&self, tx: &mut Transaction<'_, Postgres>) -> Result<Admission, Error> {
        self.ensure_live()?;
        self.oauth
            .lock_for_publication(tx)
            .await
            .map_err(oauth_error)?;
        let user = OwnerId::parse(self.oauth.user_id()).map_err(|_| Error::Denied)?;
        let organization =
            OwnerId::parse(&self.selection.platform.organization).map_err(|_| Error::Denied)?;
        let source_locked: bool = sqlx::query_scalar(
            "SELECT public.codewire_platform_lock_owner_source_authority($1::text,$2::text,$3::text)",
        )
        .bind(user.as_str())
        .bind(organization.as_str())
        .bind(self.selection.platform.project_id.as_deref())
        .fetch_one(&mut **tx)
        .await
        .map_err(|_| Error::Unavailable)?;
        if !source_locked || self.selection.platform.creator != user.as_str() {
            return Err(Error::Denied);
        }

        let mut context = GrantContext {
            environment_id: EnvironmentId::parse(self.selection.local_environment_id.to_string())
                .map_err(|_| Error::Denied)?,
            environment_generation: self.selection.local_environment_generation,
            placement: GrantPlacement::PlatformToLocal,
            user_id: user.clone(),
            organization_id: Some(organization.clone()),
            allow_personal_credentials: true,
            authorized_credentials: BTreeSet::new(),
        };
        let (credential_owner, profile, grants) = match &self.selection.platform.profile {
            None => (Owner::User(user), None, Vec::new()),
            Some((profile_id, revision)) => {
                let profile_id = AccessProfileId::parse(profile_id).map_err(|_| Error::Denied)?;
                let owner = resolve_profile_owner(tx, &profile_id, &user, &organization).await?;
                let selected = self
                    .profiles
                    .get_in(tx, &owner, &profile_id, Some(*revision))
                    .await
                    .map_err(profile_error)?;
                if selected.owner != owner
                    || selected.id != profile_id
                    || selected.revision != *revision
                    || selected.placement != Placement::Platform
                {
                    return Err(Error::Denied);
                }
                let mut authorized: BTreeSet<_> = selected.entries.values().cloned().collect();
                // Every personal profile includes the account's current GitHub
                // connection; a missing one is omitted instead of fabricated.
                // The environment's slots were captured when it was created,
                // so GitHub is authorized only when that capture selected it
                // and the connection is still active now.
                let github_captured = HttpProvider::GitHubOAuth
                    .reserved_environment_keys()
                    .iter()
                    .all(|key| self.selection.platform.reserved_keys.contains(*key));
                let mut github_connected = false;
                if selected.includes_github()
                    && github_captured
                    && let Some(github) =
                        codewire_platform_credentials::active_github_connection(&mut **tx, &owner)
                            .await
                            .map_err(|_| Error::Unavailable)?
                {
                    authorized.insert(github);
                    github_connected = true;
                }
                validate_reserved_keys(
                    &self.selection.platform,
                    selected.launch_slots(github_connected),
                )?;
                context.authorized_credentials = authorized;
                let binding = EnvironmentAccessBinding {
                    environment_id: context.environment_id.clone(),
                    profile_id,
                    profile_revision: *revision,
                };
                let confirmation = match &owner {
                    Owner::User(personal) => Some(personal),
                    Owner::Organization(_) => None,
                };
                let grants = self
                    .profiles
                    .evaluate_owner_selection_in(tx, &context, &binding, confirmation)
                    .await
                    .map_err(profile_error)?;
                (owner, Some(binding), grants)
            }
        };
        let session = PlatformRuntimeSession::owner_local(
            context,
            credential_owner,
            profile,
            self.selection.selection_sha256,
            self.expires_at_unix,
        )?;
        self.ensure_live()?;
        Ok(Admission { session, grants })
    }

    async fn project(
        &self,
        request: v1::EnvironmentProjectionRequest,
        expected: &Admission,
    ) -> Result<Vec<u8>, Error> {
        if !request.local_inventories.is_empty() {
            return Err(Error::Denied);
        }
        let request_id = Uuid::parse_str(&request.request_id).map_err(|_| Error::Denied)?;
        if request_id.is_nil()
            || request_id.to_string() != request.request_id
            || request.selection_sha256.as_slice() != self.selection.selection_sha256
        {
            return Err(Error::Denied);
        }
        let recipient: [u8; 32] = request
            .recipient_public_key
            .try_into()
            .map_err(|_| Error::Denied)?;
        validate_projection_recipient(recipient).map_err(|_| Error::Denied)?;
        let context = ProjectionContext {
            environment_id: *self.selection.local_environment_id.as_bytes(),
            operation_generation: self.selection.local_environment_generation,
            selection_sha256: self.selection.selection_sha256,
            deadline_unix_ms: request.deadline_unix_ms,
        };
        ensure_request_live(&context, self)?;
        let request_deadline = request_deadline(&context, self)?;
        tokio::time::timeout_at(tokio::time::Instant::from_std(request_deadline), async {
            let mut first_tx = self.pool.begin().await.map_err(|_| Error::Unavailable)?;
            let first = self.admit_in(&mut first_tx).await?;
            if &first != expected {
                return Err(Error::Denied);
            }
            let captured = capture_in(&mut first_tx, &self.selection.platform).await?;
            ensure_request_live(&context, self)?;
            first_tx.commit().await.map_err(|_| Error::Unavailable)?;

            let values = captured.decrypt(self.provider.as_ref(), &context).await?;
            ensure_request_live(&context, self)?;

            let mut final_tx = self.pool.begin().await.map_err(|_| Error::Unavailable)?;
            let current = self.admit_in(&mut final_tx).await?;
            let current_capture = capture_in(&mut final_tx, &self.selection.platform).await?;
            if &current != expected || current != first || current_capture != captured {
                return Err(Error::Denied);
            }
            ensure_request_live(&context, self)?;
            let sealed = seal_environment_projection(values, &context, recipient, unix_millis()?)
                .map_err(|_| Error::Denied)?;
            final_tx.commit().await.map_err(|_| Error::Unavailable)?;
            ensure_request_live(&context, self)?;
            Ok(sealed)
        })
        .await
        .map_err(|_| Error::Denied)?
    }

    async fn project_fragment(
        &self,
        request: v1::EnvironmentProjectionRequest,
        expected: &Admission,
    ) -> Result<v1::EnvironmentProjectionComposition, Error> {
        let request_id = Uuid::parse_str(&request.request_id).map_err(|_| Error::Denied)?;
        if request_id.is_nil()
            || request_id.to_string() != request.request_id
            || request.selection_sha256.as_slice() != self.selection.selection_sha256
        {
            return Err(Error::Denied);
        }
        let recipient: [u8; 32] = request
            .recipient_public_key
            .as_slice()
            .try_into()
            .map_err(|_| Error::Denied)?;
        validate_projection_recipient(recipient).map_err(|_| Error::Denied)?;
        let local_inventories = composition::decode_local(&request.local_inventories)?;
        let context = ProjectionContext {
            environment_id: *self.selection.local_environment_id.as_bytes(),
            operation_generation: self.selection.local_environment_generation,
            selection_sha256: self.selection.selection_sha256,
            deadline_unix_ms: request.deadline_unix_ms,
        };
        ensure_request_live(&context, self)?;
        let request_deadline = request_deadline(&context, self)?;
        tokio::time::timeout_at(tokio::time::Instant::from_std(request_deadline), async {
            let mut first_tx = self.pool.begin().await.map_err(|_| Error::Unavailable)?;
            let first_admission = self.admit_in(&mut first_tx).await?;
            if &first_admission != expected {
                return Err(Error::Denied);
            }
            let first = composition::capture_in(
                &mut first_tx,
                &self.selection.platform,
                &local_inventories,
                &context,
                *request_id.as_bytes(),
                recipient,
                unix_millis()?,
            )
            .await?;
            ensure_request_live(&context, self)?;
            first_tx.commit().await.map_err(|_| Error::Unavailable)?;

            let values = first
                .captured
                .decrypt(self.provider.as_ref(), &context)
                .await?;
            ensure_request_live(&context, self)?;

            let mut final_tx = self.pool.begin().await.map_err(|_| Error::Unavailable)?;
            let final_admission = self.admit_in(&mut final_tx).await?;
            let current = composition::capture_in(
                &mut final_tx,
                &self.selection.platform,
                &local_inventories,
                &context,
                *request_id.as_bytes(),
                recipient,
                unix_millis()?,
            )
            .await?;
            if &final_admission != expected
                || final_admission != first_admission
                || current != first
            {
                return Err(Error::Denied);
            }
            ensure_request_live(&context, self)?;
            let sealed_platform_fragment = seal_environment_projection_fragment(
                values,
                &context,
                recipient,
                ProjectionContributor::Platform,
                &first.plan,
                unix_millis()?,
            )
            .map_err(|_| Error::Denied)?;
            let platform_inventories = composition::encode_platform(&first.platform_inventories)?;
            final_tx.commit().await.map_err(|_| Error::Unavailable)?;
            ensure_request_live(&context, self)?;
            Ok(v1::EnvironmentProjectionComposition {
                sealed_platform_fragment,
                platform_inventories,
            })
        })
        .await
        .map_err(|_| Error::Denied)?
    }

    fn ensure_live(&self) -> Result<(), Error> {
        if Instant::now() >= self.deadline || unix_seconds()? >= self.expires_at_unix {
            return Err(Error::Denied);
        }
        self.oauth.remaining_lifetime().map_err(oauth_error)?;
        Ok(())
    }
}

#[async_trait]
impl PlatformRuntimeAuthority for OwnerLocalRuntimeAuthority {
    async fn current_session(&self) -> Result<PlatformRuntimeSession, Error> {
        let current = self.source.admit().await?;
        if current != self.initial {
            return Err(Error::Denied);
        }
        Ok(current.session)
    }

    async fn owner_local_grants(
        &self,
        expected: &PlatformRuntimeSession,
    ) -> Result<Vec<DerivedGrant>, Error> {
        if &self.initial.session != expected {
            return Err(Error::Denied);
        }
        let current = self.source.admit().await?;
        if current != self.initial {
            return Err(Error::Denied);
        }
        Ok(current.grants)
    }

    async fn project_environment(
        &self,
        request: v1::EnvironmentProjectionRequest,
    ) -> Result<Vec<u8>, Error> {
        self.source.project(request, &self.initial).await
    }

    async fn project_environment_fragment(
        &self,
        request: v1::EnvironmentProjectionRequest,
    ) -> Result<v1::EnvironmentProjectionComposition, Error> {
        self.source.project_fragment(request, &self.initial).await
    }
}

fn validate_reserved_keys<'a>(
    selection: &PlatformProjectionSelection,
    platform_slots: impl IntoIterator<Item = &'a str>,
) -> Result<(), Error> {
    let mut required =
        platform_projection_reserved_keys(platform_slots).map_err(|_| Error::Denied)?;
    required.insert(NATIVE_CODEX_HOME_KEY.to_owned());
    if selection
        .ordinary_keys
        .is_disjoint(&selection.reserved_keys)
        && selection.reserved_keys.is_superset(&required)
    {
        Ok(())
    } else {
        Err(Error::Denied)
    }
}

async fn resolve_profile_owner(
    tx: &mut Transaction<'_, Postgres>,
    profile_id: &AccessProfileId,
    user: &OwnerId,
    organization: &OwnerId,
) -> Result<Owner, Error> {
    let row: Option<(Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT user_id,organization_id FROM \
         public.codewire_platform_lock_profile($1::text,$2::text,$3::text)",
    )
    .bind(profile_id.as_str())
    .bind(user.as_str())
    .bind(organization.as_str())
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| Error::Unavailable)?;
    match row {
        Some((Some(selected), None)) if selected == user.as_str() => Ok(Owner::User(user.clone())),
        Some((None, Some(selected))) if selected == organization.as_str() => {
            Ok(Owner::Organization(organization.clone()))
        }
        _ => Err(Error::Denied),
    }
}

fn request_deadline(
    context: &ProjectionContext,
    authority: &OwnerLocalSource,
) -> Result<Instant, Error> {
    let monotonic_now = Instant::now();
    let remaining_ms = context
        .deadline_unix_ms
        .checked_sub(unix_millis()?)
        .filter(|remaining| *remaining > 0)
        .ok_or(Error::Denied)?;
    let wall_deadline = monotonic_now
        .checked_add(Duration::from_millis(remaining_ms))
        .ok_or(Error::Denied)?;
    Ok(authority.deadline.min(wall_deadline))
}

fn ensure_request_live(
    context: &ProjectionContext,
    authority: &OwnerLocalSource,
) -> Result<(), Error> {
    authority.ensure_live()?;
    context
        .validate_at(unix_millis()?)
        .map_err(|_| Error::Denied)
}

fn profile_error(error: PlatformProfileError) -> Error {
    match error {
        PlatformProfileError::DatabaseUnavailable | PlatformProfileError::ClockUnavailable => {
            Error::Unavailable
        }
        _ => Error::Denied,
    }
}

fn oauth_error(error: OAuthBearerAuthorityError) -> Error {
    match error {
        OAuthBearerAuthorityError::Denied => Error::Denied,
        OAuthBearerAuthorityError::Unavailable => Error::Unavailable,
    }
}

fn unix_seconds() -> Result<u64, Error> {
    Ok(unix_time()?.as_secs())
}

fn unix_time() -> Result<Duration, Error> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::Unavailable)
}

fn unix_millis() -> Result<u64, Error> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::Unavailable)?
            .as_millis(),
    )
    .map_err(|_| Error::Unavailable)
}

#[cfg(test)]
mod tests;
