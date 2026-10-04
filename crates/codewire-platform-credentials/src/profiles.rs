//! Material-free profile revisions and explicitly pinned environment bindings.
//!
//! Owners and grant contexts must come from an authenticated, authorized caller,
//! not unchecked request fields. This store fences their exact database scope;
//! it does not authenticate a user or establish original OAuth/client authority.
//! Authorized credential identities still come from that trusted caller.
//! Only same-owner entries are supported. Profile edits publish a new immutable
//! revision; an existing environment keeps its explicitly selected revision.
//! A rename relabels the profile row and publishes no revision.

use std::collections::{BTreeMap, BTreeSet};
use std::time::{SystemTime, UNIX_EPOCH};

use codewire_access::{
    AccessError, AccessProfile, AccessProfileId, AccessProfileName, AvailableGrants,
    CapabilitySlot, CredentialId, CredentialMetadata, DerivedGrant, EnvironmentAccessBinding,
    GrantContext, GrantPlacement, Owner, OwnerId, Placement, ProviderCatalog, ProviderId,
    derive_account_github_grant, derive_available_grants, derive_grants, validate_profile_entries,
};
use sqlx::{PgPool, Postgres, Row, Transaction};
use uuid::Uuid;

use crate::model::{parse_auth_kind, parse_ssh_public_key, parse_status};

/// Closed errors: database messages, catalog input and source chains never escape.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PlatformProfileError {
    #[error("invalid profile, binding or environment context")]
    InvalidInput,
    #[error("profile, credential, environment or active owner not found")]
    NotFound,
    #[error("profile or environment binding already exists")]
    AlreadyExists,
    #[error("profile revision changed")]
    StaleRevision,
    #[error("environment binding changed")]
    StaleBinding,
    #[error("environment operation or lifecycle authority changed")]
    StaleEnvironment,
    #[error("profile entry is unsupported or unauthorized")]
    UnsupportedEntry,
    #[error("selected credential is not active")]
    InactiveCredential,
    #[error("selected credential is expired")]
    ExpiredCredential,
    #[error("profile is bound to an environment")]
    ProfileInUse,
    #[error("stored profile or credential metadata is corrupt")]
    CorruptRecord,
    #[error("profile database is unavailable")]
    DatabaseUnavailable,
    #[error("profile clock is unavailable")]
    ClockUnavailable,
}

type Error = PlatformProfileError;

const PROFILE_STATEMENT_TIMEOUT_MILLIS: i64 = 5_000;

/// Material-free selection and personal-owner confirmation read from one row.
///
/// This is inspectable even when confirmation is absent. It is not an access
/// grant: runtime must use `evaluate_grants` with current authenticated scope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlatformBindingMetadata {
    pub binding: EnvironmentAccessBinding,
    pub personal_owner_confirmed_by: Option<OwnerId>,
}

/// Profile authority with no KEK provider or protected-material read path.
#[derive(Clone)]
pub struct PlatformAccessProfileStore {
    pool: PgPool,
    catalog: ProviderCatalog,
}

impl PlatformAccessProfileStore {
    pub fn new(pool: PgPool, catalog: ProviderCatalog) -> Self {
        Self { pool, catalog }
    }

    /// Begin a short profile transaction, including caller-composed binding
    /// authorization. All profile-owned transactions use this same initializer.
    ///
    /// Statement and idle-in-transaction timeouts are transaction-local and
    /// capped at five seconds without increasing an existing nonzero shorter
    /// setting. Existing lock_timeout is untouched. These bounds prevent a
    /// dropped SQLx future from leaving an indefinitely blocked server query or
    /// idle transaction; callers must still bound overall admission and retain
    /// every authorization/CAS fence through commit or rollback.
    ///
    /// The statement ceiling is not a total transaction-duration promise.
    /// Network loss can prevent observing cleanup or a COMMIT acknowledgement;
    /// an unknown publication outcome must never cause a blind CAS retry.
    pub async fn begin_transaction(&self) -> Result<Transaction<'static, Postgres>, Error> {
        let mut tx = self.pool.begin().await.map_err(database_error)?;
        // A separate command installs the server timeout before any domain row
        // lock. pg_settings exposes these two settings in milliseconds, where
        // zero means unlimited. SET LOCAL cannot leak through a pooled session.
        let settings: Vec<String> = sqlx::query_scalar(
            "SELECT pg_catalog.set_config(name, \
             LEAST($1::bigint, CASE WHEN setting::bigint=0 THEN $1::bigint ELSE setting::bigint END)::text, true) \
             FROM pg_catalog.pg_settings \
             WHERE name IN ('statement_timeout','idle_in_transaction_session_timeout') AND unit='ms'",
        )
        .bind(PROFILE_STATEMENT_TIMEOUT_MILLIS)
        .fetch_all(&mut *tx)
        .await
        .map_err(database_error)?;
        if settings.len() != 2 {
            return Err(Error::DatabaseUnavailable);
        }
        Ok(tx)
    }

    pub async fn create(
        &self,
        owner: &Owner,
        name: AccessProfileName,
        entries: BTreeMap<CapabilitySlot, CredentialId>,
    ) -> Result<AccessProfile, Error> {
        let profile = AccessProfile {
            id: AccessProfileId::parse(Uuid::new_v4().to_string())
                .map_err(|_| Error::InvalidInput)?,
            placement: Placement::Platform,
            owner: owner.clone(),
            name,
            revision: 1,
            entries,
        };
        let mut tx = self.begin_transaction().await?;
        lock_owner(&mut tx, owner).await?;
        let credentials = load_credentials(&mut tx, &profile).await?;
        validate_profile_entries(&profile, &credentials, &self.catalog).map_err(access_error)?;
        let (user_id, organization_id) = owner_columns(owner);
        sqlx::query(
            "INSERT INTO platform_access_profiles \
             (id,user_id,organization_id,name,current_revision) VALUES ($1,$2,$3,$4,1)",
        )
        .bind(profile.id.as_str())
        .bind(user_id)
        .bind(organization_id)
        .bind(profile.name.as_str())
        .execute(&mut *tx)
        .await
        .map_err(database_error)?;
        insert_revision(&mut tx, &profile).await?;
        tx.commit().await.map_err(database_error)?;
        Ok(profile)
    }

    pub async fn get(&self, owner: &Owner, id: &AccessProfileId) -> Result<AccessProfile, Error> {
        self.read_revision(owner, id, None).await
    }

    /// Resolve metadata without a second pooled connection. The caller retains
    /// owner/environment authorization locks through publication. A requested
    /// revision is immutable history, not an assertion that it is still current.
    pub async fn get_in(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        owner: &Owner,
        id: &AccessProfileId,
        revision: Option<u64>,
    ) -> Result<AccessProfile, Error> {
        lock_owner(tx, owner).await?;
        load_profile(tx, owner, id, revision, false).await
    }

    /// Transaction-composable exact-owner name resolution; there is no fallback
    /// to another owner or placement when the requested name is absent.
    pub async fn resolve_in(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        owner: &Owner,
        name: &AccessProfileName,
    ) -> Result<AccessProfile, Error> {
        lock_owner(tx, owner).await?;
        let (user_id, organization_id) = owner_columns(owner);
        let id: String = sqlx::query_scalar(
            "SELECT id FROM platform_access_profiles WHERE \
             (user_id=$1 OR organization_id=$2) AND lower(name)=lower($3) FOR SHARE",
        )
        .bind(user_id)
        .bind(organization_id)
        .bind(name.as_str())
        .fetch_optional(&mut **tx)
        .await
        .map_err(database_error)?
        .ok_or(Error::NotFound)?;
        let id = AccessProfileId::parse(id).map_err(|_| Error::CorruptRecord)?;
        load_profile(tx, owner, &id, None, false).await
    }

    /// Historical entries remain metadata-only references, even after an unbound
    /// retired credential is deleted. Runtime admission revalidates every entry.
    pub async fn get_revision(
        &self,
        owner: &Owner,
        id: &AccessProfileId,
        revision: u64,
    ) -> Result<AccessProfile, Error> {
        generation(revision)?;
        self.read_revision(owner, id, Some(revision)).await
    }

    async fn read_revision(
        &self,
        owner: &Owner,
        id: &AccessProfileId,
        revision: Option<u64>,
    ) -> Result<AccessProfile, Error> {
        let mut tx = self.begin_transaction().await?;
        lock_owner(&mut tx, owner).await?;
        let profile = load_profile(&mut tx, owner, id, revision, false).await?;
        tx.commit().await.map_err(database_error)?;
        Ok(profile)
    }

    pub async fn resolve(
        &self,
        owner: &Owner,
        name: &AccessProfileName,
    ) -> Result<AccessProfile, Error> {
        let mut tx = self.begin_transaction().await?;
        lock_owner(&mut tx, owner).await?;
        let (user_id, organization_id) = owner_columns(owner);
        let id: String = sqlx::query_scalar(
            "SELECT id FROM platform_access_profiles WHERE \
             (user_id=$1 OR organization_id=$2) AND lower(name)=lower($3) FOR SHARE",
        )
        .bind(user_id)
        .bind(organization_id)
        .bind(name.as_str())
        .fetch_optional(&mut *tx)
        .await
        .map_err(database_error)?
        .ok_or(Error::NotFound)?;
        let id = AccessProfileId::parse(id).map_err(|_| Error::CorruptRecord)?;
        let profile = load_profile(&mut tx, owner, &id, None, false).await?;
        tx.commit().await.map_err(database_error)?;
        Ok(profile)
    }

    /// Bounded, ID-ordered pagination scoped to exactly one authorized owner.
    pub async fn list(
        &self,
        owner: &Owner,
        after: Option<&AccessProfileId>,
        limit: u32,
    ) -> Result<Vec<AccessProfile>, Error> {
        if limit == 0 || limit > 1000 {
            return Err(Error::InvalidInput);
        }
        let mut tx = self.begin_transaction().await?;
        lock_owner(&mut tx, owner).await?;
        let (user_id, organization_id) = owner_columns(owner);
        let ids: Vec<String> = sqlx::query_scalar(
            "SELECT id FROM platform_access_profiles WHERE \
             (user_id=$1 OR organization_id=$2) AND ($3::text IS NULL OR id>$3) \
             ORDER BY id LIMIT $4 FOR SHARE",
        )
        .bind(user_id)
        .bind(organization_id)
        .bind(after.map(AccessProfileId::as_str))
        .bind(i64::from(limit))
        .fetch_all(&mut *tx)
        .await
        .map_err(database_error)?;
        let mut profiles = Vec::with_capacity(ids.len());
        for id in ids {
            let id = AccessProfileId::parse(id).map_err(|_| Error::CorruptRecord)?;
            profiles.push(load_profile(&mut tx, owner, &id, None, false).await?);
        }
        tx.commit().await.map_err(database_error)?;
        Ok(profiles)
    }

    /// CAS advances the current pointer without editing any existing revision
    /// or binding. Slot removal, including removal of the final slot, is explicit.
    pub async fn update(
        &self,
        owner: &Owner,
        id: &AccessProfileId,
        expected_revision: u64,
        entries: BTreeMap<CapabilitySlot, CredentialId>,
    ) -> Result<AccessProfile, Error> {
        let expected = generation(expected_revision)?;
        let next = expected.checked_add(1).ok_or(Error::InvalidInput)?;
        let mut tx = self.begin_transaction().await?;
        lock_owner(&mut tx, owner).await?;
        let current = load_profile(&mut tx, owner, id, None, true).await?;
        if current.revision != expected_revision {
            return Err(Error::StaleRevision);
        }
        let profile = AccessProfile {
            revision: next as u64,
            entries,
            ..current
        };
        let credentials = load_credentials(&mut tx, &profile).await?;
        validate_profile_entries(&profile, &credentials, &self.catalog).map_err(access_error)?;
        insert_revision(&mut tx, &profile).await?;
        let changed = sqlx::query(
            "UPDATE platform_access_profiles SET current_revision=$3,updated_at=now() \
             WHERE id=$1 AND current_revision=$2",
        )
        .bind(id.as_str())
        .bind(expected)
        .bind(next)
        .execute(&mut *tx)
        .await
        .map_err(database_error)?;
        if changed.rows_affected() != 1 {
            return Err(Error::StaleRevision);
        }
        tx.commit().await.map_err(database_error)?;
        Ok(profile)
    }

    /// Relabel the profile without publishing a revision. The name lives on
    /// the profile row, not in its immutable revisions, so entries, history
    /// and every environment binding are untouched. The expected revision and
    /// name must both still be current under the row lock, rejecting a rename
    /// prepared from a stale view, including one that raced another rename.
    /// Renaming to the current name is a no-op. A name another profile of the
    /// same owner already uses is `AlreadyExists`, exactly as on create.
    pub async fn rename(
        &self,
        owner: &Owner,
        id: &AccessProfileId,
        expected_revision: u64,
        expected_name: &AccessProfileName,
        name: AccessProfileName,
    ) -> Result<AccessProfile, Error> {
        let expected = generation(expected_revision)?;
        let mut tx = self.begin_transaction().await?;
        lock_owner(&mut tx, owner).await?;
        let current = load_profile(&mut tx, owner, id, None, true).await?;
        if current.revision != expected_revision || current.name != *expected_name {
            return Err(Error::StaleRevision);
        }
        if current.name == name {
            tx.commit().await.map_err(database_error)?;
            return Ok(current);
        }
        let changed = sqlx::query(
            "UPDATE platform_access_profiles SET name=$4,updated_at=now() \
             WHERE id=$1 AND current_revision=$2 AND name=$3",
        )
        .bind(id.as_str())
        .bind(expected)
        .bind(expected_name.as_str())
        .bind(name.as_str())
        .execute(&mut *tx)
        .await
        .map_err(database_error)?;
        if changed.rows_affected() != 1 {
            return Err(Error::StaleRevision);
        }
        tx.commit().await.map_err(database_error)?;
        Ok(AccessProfile { name, ..current })
    }

    pub async fn delete(
        &self,
        owner: &Owner,
        id: &AccessProfileId,
        expected_revision: u64,
    ) -> Result<(), Error> {
        generation(expected_revision)?;
        let mut tx = self.begin_transaction().await?;
        lock_owner(&mut tx, owner).await?;
        let current = load_profile(&mut tx, owner, id, None, true).await?;
        if current.revision != expected_revision {
            return Err(Error::StaleRevision);
        }
        let bound: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM platform_environment_access_bindings WHERE profile_id=$1)",
        )
        .bind(id.as_str())
        .fetch_one(&mut *tx)
        .await
        .map_err(database_error)?;
        if bound {
            return Err(Error::ProfileInUse);
        }
        sqlx::query("DELETE FROM platform_access_profiles WHERE id=$1")
            .bind(id.as_str())
            .execute(&mut *tx)
            .await
            .map_err(database_error)?;
        tx.commit().await.map_err(database_error)
    }

    /// The context must already authorize this exact environment and selection.
    /// This does not increment or invent an environment operation generation.
    /// Personal confirmation is an explicit per-call choice attributed to the
    /// authenticated creator, not identity proof from an unchecked request ID.
    /// Organization selections supply `None`; personal selections must supply
    /// the exact profile owner and remain permitted by current context policy.
    pub async fn create_binding(
        &self,
        context: &GrantContext,
        binding: EnvironmentAccessBinding,
        personal_owner_confirmation: Option<&OwnerId>,
    ) -> Result<EnvironmentAccessBinding, Error> {
        let mut tx = self.begin_transaction().await?;
        let binding = self
            .create_binding_in(&mut tx, context, binding, personal_owner_confirmation)
            .await?;
        tx.commit().await.map_err(database_error)?;
        Ok(binding)
    }

    /// Compose a binding write with the caller's authorization row locks in one
    /// transaction. The caller owns commit/rollback; all store fences still run.
    pub async fn create_binding_in(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        context: &GrantContext,
        binding: EnvironmentAccessBinding,
        personal_owner_confirmation: Option<&OwnerId>,
    ) -> Result<EnvironmentAccessBinding, Error> {
        validate_binding(context, &binding)?;
        lock_environment(tx, context, false, true).await?;
        self.admit_binding(tx, context, &binding, personal_owner_confirmation)
            .await?;
        sqlx::query(
            "INSERT INTO platform_environment_access_bindings \
             (environment_id,profile_id,profile_revision,personal_owner_confirmed_by) \
             VALUES ($1,$2,$3,$4)",
        )
        .bind(binding.environment_id.as_str())
        .bind(binding.profile_id.as_str())
        .bind(generation(binding.profile_revision)?)
        .bind(personal_owner_confirmation.map(OwnerId::as_str))
        .execute(&mut **tx)
        .await
        .map_err(database_error)?;
        Ok(binding)
    }

    /// Admit only metadata for a newly inserted pending environment at operation
    /// generation zero. This never derives a grant or invents a future operation.
    /// The caller must authorize creator/membership and compose the new row and
    /// creator ACL in this same transaction. Runtime APIs still require a
    /// positive, admitted operation generation and a running environment.
    pub async fn create_pending_binding_in(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        context: &GrantContext,
        binding: EnvironmentAccessBinding,
        personal_owner_confirmation: Option<&OwnerId>,
    ) -> Result<EnvironmentAccessBinding, Error> {
        validate_binding(context, &binding)?;
        if context.environment_generation != 0 || context.placement != GrantPlacement::Platform {
            return Err(Error::InvalidInput);
        }
        let organization = context
            .organization_id
            .as_ref()
            .ok_or(Error::InvalidInput)?;
        lock_owner(tx, &Owner::User(context.user_id.clone())).await?;
        lock_owner(tx, &Owner::Organization(organization.clone())).await?;
        let pending: Option<bool> = sqlx::query_scalar(
            "SELECT environment_operation_generation=0 AND state='pending' AND desired_state='started' \
             AND deletion_requested_at IS NULL AND type='sandbox' FROM environments \
             WHERE id=$1 AND created_by=$2 AND org_id=$3 FOR UPDATE",
        )
        .bind(context.environment_id.as_str())
        .bind(context.user_id.as_str())
        .bind(organization.as_str())
        .fetch_optional(&mut **tx)
        .await
        .map_err(database_error)?;
        match pending {
            None => return Err(Error::NotFound),
            Some(false) => return Err(Error::StaleEnvironment),
            Some(true) => {}
        }
        let profile = profile_for_context(tx, context, &binding).await?;
        validate_personal_confirmation(context, &profile, personal_owner_confirmation)?;
        let credentials = load_credentials(tx, &profile).await?;
        validate_profile_entries(&profile, &credentials, &self.catalog).map_err(access_error)?;
        // A credential that needs Reconnect does not block the Sandbox: like a
        // missing GitHub connection, only its capability is unavailable until
        // the owner reconnects it. Runtime admission withholds it per slot.
        for credential in credentials.values() {
            if !context.authorized_credentials.contains(&credential.id) {
                return Err(Error::UnsupportedEntry);
            }
        }
        sqlx::query(
            "INSERT INTO platform_environment_access_bindings \
             (environment_id,profile_id,profile_revision,personal_owner_confirmed_by) \
             VALUES ($1,$2,$3,$4)",
        )
        .bind(binding.environment_id.as_str())
        .bind(binding.profile_id.as_str())
        .bind(generation(binding.profile_revision)?)
        .bind(personal_owner_confirmation.map(OwnerId::as_str))
        .execute(&mut **tx)
        .await
        .map_err(database_error)?;
        Ok(binding)
    }

    /// Rebinding never inherits prior consent, including rebinding the same
    /// immutable revision. The caller must explicitly confirm it again.
    pub async fn replace_binding(
        &self,
        context: &GrantContext,
        expected: &EnvironmentAccessBinding,
        replacement: EnvironmentAccessBinding,
        personal_owner_confirmation: Option<&OwnerId>,
    ) -> Result<EnvironmentAccessBinding, Error> {
        let mut tx = self.begin_transaction().await?;
        let binding = self
            .replace_binding_in(
                &mut tx,
                context,
                expected,
                replacement,
                personal_owner_confirmation,
            )
            .await?;
        tx.commit().await.map_err(database_error)?;
        Ok(binding)
    }

    /// Transaction-composable exact CAS, retaining every revision/owner fence.
    pub async fn replace_binding_in(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        context: &GrantContext,
        expected: &EnvironmentAccessBinding,
        replacement: EnvironmentAccessBinding,
        personal_owner_confirmation: Option<&OwnerId>,
    ) -> Result<EnvironmentAccessBinding, Error> {
        validate_binding(context, expected)?;
        validate_binding(context, &replacement)?;
        lock_environment(tx, context, false, true).await?;
        if load_binding(tx, context).await?.binding != *expected {
            return Err(Error::StaleBinding);
        }
        self.admit_binding(tx, context, &replacement, personal_owner_confirmation)
            .await?;
        sqlx::query(
            "UPDATE platform_environment_access_bindings SET profile_id=$2,profile_revision=$3, \
             personal_owner_confirmed_by=$4,updated_at=now() WHERE environment_id=$1",
        )
        .bind(replacement.environment_id.as_str())
        .bind(replacement.profile_id.as_str())
        .bind(generation(replacement.profile_revision)?)
        .bind(personal_owner_confirmation.map(OwnerId::as_str))
        .execute(&mut **tx)
        .await
        .map_err(database_error)?;
        Ok(replacement)
    }

    pub async fn get_binding(
        &self,
        context: &GrantContext,
    ) -> Result<EnvironmentAccessBinding, Error> {
        Ok(self.get_binding_metadata(context).await?.binding)
    }

    /// Atomically inspect exact binding metadata, including missing consent.
    /// Neither this result nor an enrollment/membership decision grants use.
    pub async fn get_binding_metadata(
        &self,
        context: &GrantContext,
    ) -> Result<PlatformBindingMetadata, Error> {
        let mut tx = self.begin_transaction().await?;
        let binding = self.get_binding_metadata_in(&mut tx, context).await?;
        tx.commit().await.map_err(database_error)?;
        Ok(binding)
    }

    /// Compose a metadata-only read with the caller's current authority locks.
    pub async fn get_binding_metadata_in(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        context: &GrantContext,
    ) -> Result<PlatformBindingMetadata, Error> {
        lock_environment(tx, context, false, false).await?;
        let binding = load_binding(tx, context).await?;
        profile_for_context(tx, context, &binding.binding).await?;
        Ok(binding)
    }

    /// `get_binding_metadata`, then `get_revision(owner, bound profile, bound
    /// revision)`, in one transaction: the two profile reads of runtime
    /// authority. The outer error is the binding read's. The inner result is
    /// the revision read's, which a caller consults only after it has compared
    /// the binding with its own scope, as when the reads were separate.
    ///
    /// `owner` must be the context's user or organization. Both are already
    /// locked by the binding read, so the revision read takes no new lock: it
    /// re-locks rows this transaction holds and reads the same immutable
    /// revision, which is the separate reads when nothing commits between them.
    ///
    /// Runtime authority calls this on every resolve, so it uses the merged
    /// statements `ENVIRONMENT_FENCE` and `BOUND_PROFILE`, whose residual
    /// differences from the separate statements are documented there. Every
    /// other caller keeps `get_binding_metadata` and `get_revision`.
    pub async fn get_binding_metadata_and_revision(
        &self,
        context: &GrantContext,
        owner: &Owner,
    ) -> Result<(PlatformBindingMetadata, Result<AccessProfile, Error>), Error> {
        let context_owner = match owner {
            Owner::User(id) => *id == context.user_id,
            Owner::Organization(id) => context.organization_id.as_ref() == Some(id),
        };
        if !context_owner {
            return Err(Error::InvalidInput);
        }
        let mut tx = self.begin_transaction().await?;
        lock_runtime_environment(&mut tx, context, false).await?;
        let bound = load_bound_profile(&mut tx, context, Some(owner))
            .await?
            .ok_or(Error::NotFound)?;
        tx.commit().await.map_err(database_error)?;
        let revision = bound.owner_revision.ok_or(Error::InvalidInput)?;
        Ok((bound.binding, revision))
    }

    pub async fn delete_binding(
        &self,
        context: &GrantContext,
        expected: &EnvironmentAccessBinding,
    ) -> Result<(), Error> {
        let mut tx = self.begin_transaction().await?;
        self.delete_binding_in(&mut tx, context, expected).await?;
        tx.commit().await.map_err(database_error)
    }

    /// Compose clearing an exact binding with the caller's authorization locks.
    pub async fn delete_binding_in(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        context: &GrantContext,
        expected: &EnvironmentAccessBinding,
    ) -> Result<(), Error> {
        validate_binding(context, expected)?;
        lock_environment(tx, context, false, true).await?;
        if load_binding(tx, context).await?.binding != *expected {
            return Err(Error::StaleBinding);
        }
        profile_for_context(tx, context, expected).await?;
        sqlx::query("DELETE FROM platform_environment_access_bindings WHERE environment_id=$1")
            .bind(context.environment_id.as_str())
            .execute(&mut **tx)
            .await
            .map_err(database_error)?;
        Ok(())
    }

    /// One metadata admission point, not an irrevocable lease. The broker must
    /// repeat its operation, runtime identity, expiry and revocation fences when
    /// consuming material. A stopped or superseded runtime cannot derive grants.
    /// Each capability is admitted separately: a selected credential that needs
    /// Reconnect is reported, without a grant, and never withholds the others.
    ///
    /// It runs twice per proxied request, so it uses the merged statements
    /// `ENVIRONMENT_FENCE`, `BOUND_PROFILE` and `LOCK_CREDENTIALS_IN_ORDER`,
    /// whose residual differences from one statement per lock and read are
    /// documented there. Binding writes and owner-local admission keep
    /// `bound_profile` and its one statement per lock.
    pub async fn evaluate_grants(&self, context: &GrantContext) -> Result<AvailableGrants, Error> {
        let mut tx = self.begin_transaction().await?;
        lock_runtime_environment(&mut tx, context, true).await?;
        let grants = match load_bound_profile(&mut tx, context, None).await? {
            // Hosted runtime admission. A selected credential that needs
            // Reconnect withholds only its own capability; every other fence
            // still rejects the whole binding.
            Some(bound) => {
                validate_personal_confirmation(
                    context,
                    &bound.profile,
                    bound.binding.personal_owner_confirmed_by.as_ref(),
                )?;
                let credentials = lock_profile_credentials(&mut tx, &bound.profile).await?;
                derive_available_grants(
                    context,
                    &bound.binding.binding,
                    &bound.profile,
                    &credentials,
                    &self.catalog,
                    unix_now()?,
                )
                .map_err(access_error)?
            }
            // Selecting a GitHub repository needs no profile: without a
            // binding, the creator's one GitHub connection is the only grant.
            None => AvailableGrants {
                grants: self.admit_account_github(&mut tx, context).await?,
                reconnect_required: BTreeSet::new(),
            },
        };
        tx.commit().await.map_err(database_error)?;
        Ok(grants)
    }

    async fn admit_account_github(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        context: &GrantContext,
    ) -> Result<Vec<DerivedGrant>, Error> {
        let mut credentials = BTreeMap::new();
        if let Some((id, metadata)) = lock_github_connection(tx, &context.user_id).await? {
            credentials.insert(id, metadata);
        }
        Ok(
            derive_account_github_grant(context, &credentials, &self.catalog, unix_now()?)
                .map_err(access_error)?
                .into_iter()
                .collect(),
        )
    }

    /// Admit an explicit platform credential selection for owner-authenticated
    /// local execution without reading or creating a platform environment row.
    /// This is material-free admission, not an irrevocable lease or VM proof.
    ///
    /// The caller MUST first retain the ORIGINAL `OAuthBearerAuthority` fence
    /// through `lock_for_publication` on this same transaction, and bind its
    /// authenticated user to `context.user_id`. This helper does not authenticate
    /// caller-supplied IDs. The caller separately owns the exact local environment
    /// operation, original cancellation/expiry deadline and authorized selection.
    /// Retain all fences through consumption/publication; recheck current profile,
    /// credential and runtime authority before releasing a result. Never obtain
    /// another pooled connection while this transaction is held, and roll back
    /// on every error. The caller owns commit/rollback and unknown-outcome handling.
    ///
    /// The supplied revision remains immutable even when a newer revision exists.
    /// Personal confirmation is explicit for this selection and must name the
    /// authenticated personal owner; organization selections require `None`.
    /// No environment, stored binding or durable delegation is inserted here.
    pub async fn evaluate_owner_selection_in(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        context: &GrantContext,
        binding: &EnvironmentAccessBinding,
        personal_owner_confirmation: Option<&OwnerId>,
    ) -> Result<Vec<DerivedGrant>, Error> {
        if context.placement != GrantPlacement::PlatformToLocal {
            return Err(Error::InvalidInput);
        }
        generation(context.environment_generation)?;
        validate_binding(context, binding)?;
        let organization = context
            .organization_id
            .as_ref()
            .ok_or(Error::InvalidInput)?;
        let found: bool = sqlx::query_scalar(
            "SELECT public.codewire_platform_lock_owner_source_authority($1::text,$2::text,NULL::text)",
        )
        .bind(context.user_id.as_str())
        .bind(organization.as_str())
        .fetch_one(&mut **tx)
        .await
        .map_err(database_error)?;
        if !found {
            return Err(Error::NotFound);
        }
        // An owner-local launch admits its exact selection as a whole.
        let (profile, credentials) = self
            .bound_profile(tx, context, binding, personal_owner_confirmation)
            .await?;
        derive_grants(
            context,
            binding,
            &profile,
            &credentials,
            &self.catalog,
            unix_now()?,
        )
        .map_err(access_error)
    }

    /// Hosted binding writes. A selected credential that needs Reconnect
    /// withholds only its own capability; every other fence still rejects the
    /// whole binding. Runtime admission composes the same checks in
    /// `evaluate_grants`.
    async fn admit_binding(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        context: &GrantContext,
        binding: &EnvironmentAccessBinding,
        personal_owner_confirmation: Option<&OwnerId>,
    ) -> Result<AvailableGrants, Error> {
        let (profile, credentials) = self
            .bound_profile(tx, context, binding, personal_owner_confirmation)
            .await?;
        derive_available_grants(
            context,
            binding,
            &profile,
            &credentials,
            &self.catalog,
            unix_now()?,
        )
        .map_err(access_error)
    }

    /// The bound revision and its SHARE-locked credential metadata, after the
    /// personal confirmation fence. Material-free; this grants nothing.
    async fn bound_profile(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        context: &GrantContext,
        binding: &EnvironmentAccessBinding,
        personal_owner_confirmation: Option<&OwnerId>,
    ) -> Result<(AccessProfile, BTreeMap<CredentialId, CredentialMetadata>), Error> {
        let profile = profile_for_context(tx, context, binding).await?;
        validate_personal_confirmation(context, &profile, personal_owner_confirmation)?;
        let credentials = load_credentials(tx, &profile).await?;
        Ok((profile, credentials))
    }
}

fn validate_personal_confirmation(
    context: &GrantContext,
    profile: &AccessProfile,
    confirmation: Option<&OwnerId>,
) -> Result<(), Error> {
    match &profile.owner {
        Owner::User(owner)
            if context.allow_personal_credentials
                && owner == &context.user_id
                && confirmation == Some(owner) =>
        {
            Ok(())
        }
        Owner::Organization(owner)
            if context.organization_id.as_ref() == Some(owner) && confirmation.is_none() =>
        {
            Ok(())
        }
        _ => Err(Error::UnsupportedEntry),
    }
}

async fn load_profile(
    tx: &mut Transaction<'_, Postgres>,
    owner: &Owner,
    id: &AccessProfileId,
    revision: Option<u64>,
    write: bool,
) -> Result<AccessProfile, Error> {
    let (user_id, organization_id) = owner_columns(owner);
    // Profile management retains its ordinary DML authority. Runtime exact
    // reads use only the fixed metadata-lock helper, not profile UPDATE rights.
    let sql = if write {
        "SELECT name,current_revision FROM platform_access_profiles \
         WHERE id=$1 AND (user_id=$2 OR organization_id=$3) FOR UPDATE"
    } else {
        "SELECT name,current_revision FROM \
         public.codewire_platform_lock_profile($1::text,$2::text,$3::text)"
    };
    let row = sqlx::query(sql)
        .bind(id.as_str())
        .bind(user_id)
        .bind(organization_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(database_error)?
        .ok_or(Error::NotFound)?;
    let current: i64 = row.try_get("current_revision").map_err(database_error)?;
    let revision = revision.unwrap_or(positive(current)?);
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM platform_access_profile_revisions \
         WHERE profile_id=$1 AND revision=$2)",
    )
    .bind(id.as_str())
    .bind(generation(revision)?)
    .fetch_one(&mut **tx)
    .await
    .map_err(database_error)?;
    if !exists {
        return Err(Error::NotFound);
    }
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT capability_slot,credential_id FROM platform_access_profile_entries \
         WHERE profile_id=$1 AND revision=$2 ORDER BY capability_slot",
    )
    .bind(id.as_str())
    .bind(generation(revision)?)
    .fetch_all(&mut **tx)
    .await
    .map_err(database_error)?;
    let mut entries = BTreeMap::new();
    for (slot, credential) in rows {
        entries.insert(
            CapabilitySlot::parse(slot).map_err(|_| Error::CorruptRecord)?,
            CredentialId::parse(credential).map_err(|_| Error::CorruptRecord)?,
        );
    }
    Ok(AccessProfile {
        id: id.clone(),
        placement: Placement::Platform,
        owner: owner.clone(),
        name: AccessProfileName::parse(row.try_get::<String, _>("name").map_err(database_error)?)
            .map_err(|_| Error::CorruptRecord)?,
        revision,
        entries,
    })
}

async fn insert_revision(
    tx: &mut Transaction<'_, Postgres>,
    profile: &AccessProfile,
) -> Result<(), Error> {
    sqlx::query(
        "INSERT INTO platform_access_profile_revisions(profile_id,revision) VALUES ($1,$2)",
    )
    .bind(profile.id.as_str())
    .bind(generation(profile.revision)?)
    .execute(&mut **tx)
    .await
    .map_err(database_error)?;
    for (slot, credential) in &profile.entries {
        sqlx::query(
            "INSERT INTO platform_access_profile_entries \
             (profile_id,revision,capability_slot,credential_id) VALUES ($1,$2,$3,$4)",
        )
        .bind(profile.id.as_str())
        .bind(generation(profile.revision)?)
        .bind(slot.as_str())
        .bind(credential.as_str())
        .execute(&mut **tx)
        .await
        .map_err(database_error)?;
    }
    Ok(())
}

/// One statement per credential: each is locked and fully validated before
/// the next is locked, so the first missing or corrupt credential returns its
/// error with no later credential locked, and every lock wait has its own
/// statement timeout. Profile writes, binding writes and owner-local admission
/// use this. Runtime grant evaluation, which runs twice per proxied request,
/// uses `lock_profile_credentials` instead and accepts the residual
/// differences documented at `LOCK_CREDENTIALS_IN_ORDER`.
async fn load_credentials(
    tx: &mut Transaction<'_, Postgres>,
    profile: &AccessProfile,
) -> Result<BTreeMap<CredentialId, CredentialMetadata>, Error> {
    let mut credentials = BTreeMap::new();
    // A shared lock fences replacement/revocation/deletion through admission.
    // Deterministic order avoids opposite-order locks across multi-slot profiles.
    for id in profile.entries.values().collect::<BTreeSet<_>>() {
        let metadata = lock_credential(tx, &profile.owner, id).await?;
        credentials.insert(id.clone(), metadata);
    }
    // Every personal profile includes the owner's one GitHub connection when
    // it can be used now; a missing connection is omitted.
    if profile.includes_github()
        && let Some(id) = crate::store::active_github_connection(&mut **tx, &profile.owner)
            .await
            .map_err(credential_error)?
    {
        let metadata = lock_credential(tx, &profile.owner, &id).await?;
        credentials.insert(id, metadata);
    }
    Ok(credentials)
}

async fn lock_credential(
    tx: &mut Transaction<'_, Postgres>,
    owner: &Owner,
    id: &CredentialId,
) -> Result<CredentialMetadata, Error> {
    let (user_id, organization_id) = owner_columns(owner);
    let row: CredentialMetadataRow = sqlx::query_as(
        "SELECT provider,authentication_kind,display_name,account_hint,status, \
             expires_at_unix,revocation_generation FROM \
             public.codewire_platform_lock_credential($1::text,$2::text,$3::text)",
    )
    .bind(id.as_str())
    .bind(user_id)
    .bind(organization_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(database_error)?
    .ok_or(Error::NotFound)?;
    // Retain the applied helper's exact signature and SHARE fence. Only
    // after it has locked this owner-scoped identity may the existing
    // metadata SELECT authority read the additive public fields.
    let (ssh_public_key, ssh_fingerprint): (Option<String>, Option<String>) = sqlx::query_as(
        "SELECT ssh_public_key,ssh_fingerprint FROM public.platform_credentials \
                 WHERE id=$1 AND (user_id=$2 OR organization_id=$3)",
    )
    .bind(id.as_str())
    .bind(user_id)
    .bind(organization_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(database_error)?
    .ok_or(Error::NotFound)?;
    credential_metadata(owner, id, row, ssh_public_key, ssh_fingerprint)
}

/// The columns `codewire_platform_lock_credential` returns for a locked row.
#[derive(sqlx::FromRow)]
struct CredentialMetadataRow {
    provider: String,
    authentication_kind: String,
    display_name: String,
    account_hint: Option<String>,
    status: String,
    expires_at_unix: Option<i64>,
    revocation_generation: i64,
}

/// Validated metadata of one locked credential row and its public SSH key.
fn credential_metadata(
    owner: &Owner,
    id: &CredentialId,
    row: CredentialMetadataRow,
    ssh_public_key: Option<String>,
    ssh_fingerprint: Option<String>,
) -> Result<CredentialMetadata, Error> {
    let metadata = CredentialMetadata {
        id: id.clone(),
        placement: Placement::Platform,
        owner: owner.clone(),
        provider: ProviderId::parse(row.provider).map_err(|_| Error::CorruptRecord)?,
        authentication_kind: parse_auth_kind(&row.authentication_kind)
            .map_err(|_| Error::CorruptRecord)?,
        display_name: row.display_name,
        account_hint: row.account_hint,
        ssh_public_key: parse_ssh_public_key(ssh_public_key, ssh_fingerprint)
            .map_err(|_| Error::CorruptRecord)?,
        status: parse_status(&row.status).map_err(|_| Error::CorruptRecord)?,
        expires_at_unix: row
            .expires_at_unix
            .map(|value| u64::try_from(value).map_err(|_| Error::CorruptRecord))
            .transpose()?,
        revocation_generation: positive(row.revocation_generation)?,
    };
    metadata.validate().map_err(|_| Error::CorruptRecord)?;
    Ok(metadata)
}

async fn lock_owner(tx: &mut Transaction<'_, Postgres>, owner: &Owner) -> Result<(), Error> {
    let kind = match owner {
        Owner::User(_) => "user",
        Owner::Organization(_) => "organization",
    };
    let found: bool =
        sqlx::query_scalar("SELECT public.codewire_platform_lock_owner($1::text,$2::text)")
            .bind(kind)
            .bind(owner.id().as_str())
            .fetch_one(&mut **tx)
            .await
            .map_err(database_error)?;
    if found { Ok(()) } else { Err(Error::NotFound) }
}

async fn lock_environment(
    tx: &mut Transaction<'_, Postgres>,
    context: &GrantContext,
    runtime: bool,
    write: bool,
) -> Result<(), Error> {
    let org = environment_organization(context)?;
    lock_owner(tx, &Owner::User(context.user_id.clone())).await?;
    lock_owner(tx, &Owner::Organization(org.clone())).await?;
    // Only orchestration's binding writers need the UPDATE branch. The broker
    // cannot mutate an environment and needs only the SHARE helper.
    let sql = if write {
        "SELECT environment_operation_generation,desired_state,state FROM environments \
         WHERE id=$1 AND created_by=$2 AND org_id=$3 FOR UPDATE"
    } else {
        "SELECT environment_operation_generation,desired_state,state FROM \
         public.codewire_platform_lock_environment($1::text,$2::text,$3::text)"
    };
    let row: Option<(i64, String, String)> = sqlx::query_as(sql)
        .bind(context.environment_id.as_str())
        .bind(context.user_id.as_str())
        .bind(org.as_str())
        .fetch_optional(&mut **tx)
        .await
        .map_err(database_error)?;
    current_environment(context, row, runtime)
}

/// `lock_environment(tx, context, runtime, false)` for the two runtime
/// authority paths, with its three locks in the one statement
/// `ENVIRONMENT_FENCE`.
async fn lock_runtime_environment(
    tx: &mut Transaction<'_, Postgres>,
    context: &GrantContext,
    runtime: bool,
) -> Result<(), Error> {
    let org = environment_organization(context)?;
    let fence: EnvironmentFenceRow = sqlx::query_as(ENVIRONMENT_FENCE)
        .bind(context.environment_id.as_str())
        .bind(context.user_id.as_str())
        .bind(org.as_str())
        .fetch_one(&mut **tx)
        .await
        .map_err(database_error)?;
    if !fence.user_found || !fence.organization_found {
        return Err(Error::NotFound);
    }
    let row = if fence.environment_found == Some(true) {
        Some((
            fence
                .environment_operation_generation
                .ok_or(Error::DatabaseUnavailable)?,
            fence.desired_state.ok_or(Error::DatabaseUnavailable)?,
            fence.state.ok_or(Error::DatabaseUnavailable)?,
        ))
    } else {
        None
    };
    current_environment(context, row, runtime)
}

/// The checks `lock_environment` makes before it locks anything.
fn environment_organization(context: &GrantContext) -> Result<&OwnerId, Error> {
    generation(context.environment_generation)?;
    let org = context
        .organization_id
        .as_ref()
        .ok_or(Error::InvalidInput)?;
    if context.placement != GrantPlacement::Platform {
        return Err(Error::InvalidInput);
    }
    Ok(org)
}

/// The checks `lock_environment` makes on the locked environment row.
fn current_environment(
    context: &GrantContext,
    row: Option<(i64, String, String)>,
    runtime: bool,
) -> Result<(), Error> {
    let (current, desired, state) = row.ok_or(Error::NotFound)?;
    if current != generation(context.environment_generation)?
        || desired == "destroyed"
        || state == "destroyed"
        || (runtime && (desired != "started" || state != "running"))
    {
        return Err(Error::StaleEnvironment);
    }
    Ok(())
}

async fn load_binding(
    tx: &mut Transaction<'_, Postgres>,
    context: &GrantContext,
) -> Result<PlatformBindingMetadata, Error> {
    let row: Option<(String, i64, Option<String>)> = sqlx::query_as(
        "SELECT profile_id,profile_revision,personal_owner_confirmed_by FROM platform_environment_access_bindings \
         WHERE environment_id=$1",
    )
    .bind(context.environment_id.as_str())
    .fetch_optional(&mut **tx)
    .await
    .map_err(database_error)?;
    let (id, revision, confirmed_by) = row.ok_or(Error::NotFound)?;
    binding_metadata(context, id, revision, confirmed_by)
}

fn binding_metadata(
    context: &GrantContext,
    id: String,
    revision: i64,
    confirmed_by: Option<String>,
) -> Result<PlatformBindingMetadata, Error> {
    Ok(PlatformBindingMetadata {
        binding: EnvironmentAccessBinding {
            environment_id: context.environment_id.clone(),
            profile_id: AccessProfileId::parse(id).map_err(|_| Error::CorruptRecord)?,
            profile_revision: positive(revision)?,
        },
        personal_owner_confirmed_by: confirmed_by
            .map(|id| OwnerId::parse(id).map_err(|_| Error::CorruptRecord))
            .transpose()?,
    })
}

async fn profile_for_context(
    tx: &mut Transaction<'_, Postgres>,
    context: &GrantContext,
    binding: &EnvironmentAccessBinding,
) -> Result<AccessProfile, Error> {
    let row: Option<(Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT user_id,organization_id FROM \
         public.codewire_platform_lock_profile($1::text,$2::text,$3::text)",
    )
    .bind(binding.profile_id.as_str())
    .bind(context.user_id.as_str())
    .bind(context.organization_id.as_ref().map(OwnerId::as_str))
    .fetch_optional(&mut **tx)
    .await
    .map_err(database_error)?;
    let owner = match row.ok_or(Error::NotFound)? {
        (Some(user), None) => Owner::User(OwnerId::parse(user).map_err(|_| Error::CorruptRecord)?),
        (None, Some(org)) => {
            Owner::Organization(OwnerId::parse(org).map_err(|_| Error::CorruptRecord)?)
        }
        _ => return Err(Error::CorruptRecord),
    };
    load_profile(
        tx,
        &owner,
        &binding.profile_id,
        Some(binding.profile_revision),
        false,
    )
    .await
}

/// The broker's environment fence in one statement: `lock_owner` for the
/// user, then for the organization, then `codewire_platform_lock_environment`,
/// in the order three statements took them. Each helper is VOLATILE, so each
/// of its queries reads a fresh snapshot, as a separate statement did. A
/// LATERAL argument orders every call after the one before it, and a failed
/// owner lock passes NULL to the next call, which then matches and locks no
/// row. Both owner results are booleans that SQL decides, so no lock here is
/// taken after the point where the separate statements stopped.
///
/// Residual difference, which fails closed: `statement_timeout` (at most 5 s,
/// set by `begin_transaction`) now bounds all three lock waits together, where
/// each statement had its own. Under lock contention this returns
/// DatabaseUnavailable (Unavailable) sooner than before; it never admits more.
///
/// Each table-returning helper is read through `LIMIT 1`, as here and in the
/// statements below. That changes nothing that runs: a function in FROM runs
/// to completion before its first row is returned, and every helper matches
/// at most one row by primary key, which `fetch_optional` read before. It only
/// keeps the planner's estimate at one row instead of the default 1000 per
/// function, so nested calls are not planned as billions of rows, which made
/// PostgreSQL JIT-compile every execution.
const ENVIRONMENT_FENCE: &str = "SELECT u.found AS user_found, o.found AS organization_found, \
    e.found AS environment_found, e.environment_operation_generation, e.desired_state, e.state \
    FROM public.codewire_platform_lock_owner('user', $2::text) AS u(found) \
    CROSS JOIN LATERAL public.codewire_platform_lock_owner( \
        'organization', CASE WHEN u.found THEN $3::text END) AS o(found) \
    LEFT JOIN LATERAL (SELECT true AS found, f.* FROM public.codewire_platform_lock_environment( \
        CASE WHEN o.found THEN $1::text END, $2::text, $3::text) AS f LIMIT 1) AS e ON true";

#[derive(sqlx::FromRow)]
struct EnvironmentFenceRow {
    user_found: bool,
    organization_found: bool,
    environment_found: Option<bool>,
    environment_operation_generation: Option<i64>,
    desired_state: Option<String>,
    state: Option<String>,
}

/// The binding read, then `profile_for_context` of the bound revision, and,
/// for runtime authority's owner (`$4` kind, `$5` id), `get_revision` of it,
/// in one statement. It runs after `ENVIRONMENT_FENCE`, so the binding is read
/// in a snapshot taken after binding writers were fenced, as before.
///
/// Every call is ordered by a LATERAL argument and gated by NULL on the SQL
/// result before it, as in `ENVIRONMENT_FENCE`. The first profile lock is the
/// only lock that can wait: the second re-locks that same row with its own
/// owner, and the owner and profile locks for `$4`/`$5` re-lock rows this
/// transaction already holds. The revision and entries are read in the
/// statement's snapshot. That is the same data: a binding names its revision
/// through a RESTRICT foreign key, so the revision exists in any snapshot
/// where the binding does, and a revision and its entries are never changed
/// after they are inserted.
///
/// Residual difference, which fails closed: the binding row's values are
/// validated in Rust (`binding_metadata`: profile ID, positive revision,
/// confirming owner ID), after this statement returns, where the separate code
/// validated them before it locked the profile. A binding row that fails that
/// validation now has its profile SHARE-locked first, and the statement may
/// wait for a profile writer within its `statement_timeout`, turning that
/// CorruptRecord (Denied) into DatabaseUnavailable (Unavailable). The same
/// holds for the profile's owner IDs, name and entries, which are parsed after
/// the re-locks; those take no new lock. Every such value is constrained by
/// the schema or written only by validated code.
const BOUND_PROFILE: &str = "SELECT b.profile_id, b.profile_revision, b.personal_owner_confirmed_by, \
    p.found AS profile_found, p.user_id AS profile_user, p.organization_id AS profile_organization, \
    q.found AS revision_profile_found, q.name AS profile_name, \
    q.current_revision AS profile_current_revision, \
    r.revision_exists, r.slots, r.credentials, \
    o.found AS owner_found, s.found AS owner_profile_found, s.name AS owner_profile_name, \
    s.current_revision AS owner_profile_current_revision \
    FROM public.platform_environment_access_bindings AS b \
    LEFT JOIN LATERAL (SELECT true AS found, f.* FROM public.codewire_platform_lock_profile( \
        b.profile_id, $2::text, $3::text) AS f LIMIT 1) AS p ON true \
    LEFT JOIN LATERAL (SELECT true AS found, f.* FROM public.codewire_platform_lock_profile( \
        CASE WHEN p.found AND (p.user_id IS NULL) <> (p.organization_id IS NULL) \
             THEN b.profile_id END, p.user_id, p.organization_id) AS f LIMIT 1) AS q ON true \
    LEFT JOIN LATERAL (SELECT EXISTS (SELECT 1 FROM public.platform_access_profile_revisions AS v \
            WHERE v.profile_id=b.profile_id AND v.revision=b.profile_revision) AS revision_exists, \
        n.slots, n.credentials \
        FROM (SELECT coalesce(array_agg(e.capability_slot ORDER BY e.capability_slot), '{}') AS slots, \
            coalesce(array_agg(e.credential_id ORDER BY e.capability_slot), '{}') AS credentials \
            FROM public.platform_access_profile_entries AS e \
            WHERE e.profile_id=b.profile_id AND e.revision=b.profile_revision) AS n \
        WHERE q.found) AS r ON true \
    LEFT JOIN LATERAL public.codewire_platform_lock_owner( \
        $4::text, CASE WHEN r.revision_exists THEN $5::text END) AS o(found) ON true \
    LEFT JOIN LATERAL (SELECT true AS found, f.* FROM public.codewire_platform_lock_profile( \
        CASE WHEN o.found THEN b.profile_id END, \
        CASE WHEN $4::text = 'user' THEN $5::text END, \
        CASE WHEN $4::text = 'organization' THEN $5::text END) AS f LIMIT 1) AS s ON true \
    WHERE b.environment_id=$1::text";

#[derive(sqlx::FromRow)]
struct BoundProfileRow {
    profile_id: String,
    profile_revision: i64,
    personal_owner_confirmed_by: Option<String>,
    profile_found: Option<bool>,
    profile_user: Option<String>,
    profile_organization: Option<String>,
    revision_profile_found: Option<bool>,
    profile_name: Option<String>,
    profile_current_revision: Option<i64>,
    revision_exists: Option<bool>,
    slots: Option<Vec<String>>,
    credentials: Option<Vec<String>>,
    owner_found: Option<bool>,
    owner_profile_found: Option<bool>,
    owner_profile_name: Option<String>,
    owner_profile_current_revision: Option<i64>,
}

struct BoundProfile {
    binding: PlatformBindingMetadata,
    /// `profile_for_context` of the bound revision.
    profile: AccessProfile,
    /// `get_revision` of the bound revision for the requested owner.
    owner_revision: Option<Result<AccessProfile, Error>>,
}

/// The binding read, then `profile_for_context`, with their errors in their
/// order; `None` when the environment has no binding.
async fn load_bound_profile(
    tx: &mut Transaction<'_, Postgres>,
    context: &GrantContext,
    owner: Option<&Owner>,
) -> Result<Option<BoundProfile>, Error> {
    let (owner_kind, owner_id) = match owner {
        Some(Owner::User(id)) => (Some("user"), Some(id.as_str())),
        Some(Owner::Organization(id)) => (Some("organization"), Some(id.as_str())),
        None => (None, None),
    };
    let Some(row): Option<BoundProfileRow> = sqlx::query_as(BOUND_PROFILE)
        .bind(context.environment_id.as_str())
        .bind(context.user_id.as_str())
        .bind(context.organization_id.as_ref().map(OwnerId::as_str))
        .bind(owner_kind)
        .bind(owner_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(database_error)?
    else {
        return Ok(None);
    };
    let binding = binding_metadata(
        context,
        row.profile_id,
        row.profile_revision,
        row.personal_owner_confirmed_by,
    )?;
    if row.profile_found != Some(true) {
        return Err(Error::NotFound);
    }
    let profile_owner = match (row.profile_user, row.profile_organization) {
        (Some(user), None) => Owner::User(OwnerId::parse(user).map_err(|_| Error::CorruptRecord)?),
        (None, Some(org)) => {
            Owner::Organization(OwnerId::parse(org).map_err(|_| Error::CorruptRecord)?)
        }
        _ => return Err(Error::CorruptRecord),
    };
    let revision = PinnedRevision {
        binding: &binding.binding,
        exists: row.revision_exists,
        slots: row.slots.unwrap_or_default(),
        credentials: row.credentials.unwrap_or_default(),
    };
    let profile = revision.profile(
        &profile_owner,
        row.revision_profile_found,
        row.profile_name,
        row.profile_current_revision,
    )?;
    let owner_revision = owner.map(|owner| {
        // `get_revision` checks the revision before it opens its transaction.
        generation(binding.binding.profile_revision)?;
        if row.owner_found != Some(true) {
            return Err(Error::NotFound);
        }
        revision.profile(
            owner,
            row.owner_profile_found,
            row.owner_profile_name,
            row.owner_profile_current_revision,
        )
    });
    Ok(Some(BoundProfile {
        binding,
        profile,
        owner_revision,
    }))
}

/// One bound revision as `load_profile` reads it after its profile lock.
struct PinnedRevision<'a> {
    binding: &'a EnvironmentAccessBinding,
    exists: Option<bool>,
    slots: Vec<String>,
    credentials: Vec<String>,
}

impl PinnedRevision<'_> {
    /// `load_profile(owner, id, Some(revision))` from its profile lock's row,
    /// with its checks in its order.
    fn profile(
        &self,
        owner: &Owner,
        found: Option<bool>,
        name: Option<String>,
        current_revision: Option<i64>,
    ) -> Result<AccessProfile, Error> {
        if found != Some(true) {
            return Err(Error::NotFound);
        }
        let current = current_revision.ok_or(Error::DatabaseUnavailable)?;
        positive(current)?;
        let revision = self.binding.profile_revision;
        generation(revision)?;
        if self.exists != Some(true) {
            return Err(Error::NotFound);
        }
        // Both arrays aggregate the same scan of entries, each ordered by
        // capability slot, which the primary key makes unique per revision,
        // so the Nth slot and the Nth credential come from the same entry.
        if self.slots.len() != self.credentials.len() {
            return Err(Error::DatabaseUnavailable);
        }
        let mut entries = BTreeMap::new();
        for (slot, credential) in self.slots.iter().zip(&self.credentials) {
            entries.insert(
                CapabilitySlot::parse(slot.as_str()).map_err(|_| Error::CorruptRecord)?,
                CredentialId::parse(credential.as_str()).map_err(|_| Error::CorruptRecord)?,
            );
        }
        Ok(AccessProfile {
            id: self.binding.profile_id.clone(),
            placement: Placement::Platform,
            owner: owner.clone(),
            name: AccessProfileName::parse(name.ok_or(Error::DatabaseUnavailable)?)
                .map_err(|_| Error::CorruptRecord)?,
            revision,
            entries,
        })
    }
}

/// `lock_credential` for each ID of `$1` in array order: each recursion step
/// makes the next call, strictly in sequence, and the recursion stops at the
/// first ID the helper does not find, so no later credential is locked after
/// a missing one, as in `load_credentials`. Each call reads a fresh snapshot
/// and takes the same SHARE lock. The public SSH key of each row is read in the
/// statement's snapshot. That is the same data: the key is written only when a
/// credential is inserted, and every ID here was read by an earlier statement
/// (a profile entry or the GitHub connection), so its row was already
/// committed when this statement began.
///
/// Residual differences from `load_credentials`, which all fail closed:
/// - Each row is validated in Rust (`credential_metadata`: provider,
///   authentication kind, status, expiry, revocation generation, SSH key)
///   after the statement returns. `load_credentials` stopped at the first
///   corrupt credential before locking the next; here the later credentials
///   are already SHARE-locked, and the statement may have waited for a writer
///   holding one, turning that CorruptRecord (Denied) into DatabaseUnavailable
///   (Unavailable). The checked values are constrained by the schema or
///   written only by validated code.
/// - `statement_timeout` (at most 5 s) bounds all the lock waits together (one
///   per entry; a profile has one entry per catalog slot, four today), where
///   each credential's statement had its own. Under contention this returns
///   Unavailable sooner.
///
/// Exact parity is cheap to restore if it is wanted: one statement per
/// credential, each this lock and SSH key read for one ID, validated in Rust
/// before the next. That is one round trip per entry (most profiles have one),
/// where `load_credentials` takes two and this statement takes one in all.
const LOCK_CREDENTIALS_IN_ORDER: &str = "WITH RECURSIVE locked AS ( \
    SELECT 1 AS ordinal, l.provider, l.authentication_kind, l.display_name, l.account_hint, \
        l.status, l.expires_at_unix, l.revocation_generation \
    FROM (SELECT f.* FROM public.codewire_platform_lock_credential( \
        ($1::text[])[1], $2::text, $3::text) AS f LIMIT 1) AS l \
    UNION ALL \
    SELECT previous.ordinal + 1, l.provider, l.authentication_kind, l.display_name, \
        l.account_hint, l.status, l.expires_at_unix, l.revocation_generation \
    FROM locked AS previous \
    CROSS JOIN LATERAL (SELECT f.* FROM public.codewire_platform_lock_credential( \
        ($1::text[])[previous.ordinal + 1], $2::text, $3::text) AS f LIMIT 1) AS l \
    WHERE previous.ordinal < cardinality($1::text[])) \
    SELECT locked.*, k.found AS public_key_found, k.ssh_public_key, k.ssh_fingerprint \
    FROM locked \
    LEFT JOIN LATERAL (SELECT true AS found, c.ssh_public_key, c.ssh_fingerprint \
        FROM public.platform_credentials AS c \
        WHERE c.id=($1::text[])[locked.ordinal] \
        AND (c.user_id=$2::text OR c.organization_id=$3::text)) AS k ON true \
    ORDER BY locked.ordinal";

/// One `lock_credential` outcome: no locked row, no public key row, or both.
#[derive(sqlx::FromRow)]
struct LockedCredentialRow {
    provider: Option<String>,
    authentication_kind: Option<String>,
    display_name: Option<String>,
    account_hint: Option<String>,
    status: Option<String>,
    expires_at_unix: Option<i64>,
    revocation_generation: Option<i64>,
    public_key_found: Option<bool>,
    ssh_public_key: Option<String>,
    ssh_fingerprint: Option<String>,
}

impl LockedCredentialRow {
    /// `lock_credential`'s result for `id`, with its checks in its order.
    fn metadata(self, owner: &Owner, id: &CredentialId) -> Result<CredentialMetadata, Error> {
        let Some(provider) = self.provider else {
            return Err(Error::NotFound);
        };
        if self.public_key_found != Some(true) {
            return Err(Error::NotFound);
        }
        let row = CredentialMetadataRow {
            provider,
            authentication_kind: self.authentication_kind.ok_or(Error::DatabaseUnavailable)?,
            display_name: self.display_name.ok_or(Error::DatabaseUnavailable)?,
            account_hint: self.account_hint,
            status: self.status.ok_or(Error::DatabaseUnavailable)?,
            expires_at_unix: self.expires_at_unix,
            revocation_generation: self
                .revocation_generation
                .ok_or(Error::DatabaseUnavailable)?,
        };
        credential_metadata(owner, id, row, self.ssh_public_key, self.ssh_fingerprint)
    }
}

#[derive(sqlx::FromRow)]
struct OrderedCredentialRow {
    ordinal: i32,
    #[sqlx(flatten)]
    credential: LockedCredentialRow,
}

/// `load_credentials` for an admitted profile: its credentials locked in one
/// statement, then its owner's GitHub connection read and, when there is one,
/// locked in another.
async fn lock_profile_credentials(
    tx: &mut Transaction<'_, Postgres>,
    profile: &AccessProfile,
) -> Result<BTreeMap<CredentialId, CredentialMetadata>, Error> {
    // A shared lock fences replacement/revocation/deletion through admission.
    // Deterministic order avoids opposite-order locks across multi-slot profiles.
    let ids: Vec<&CredentialId> = profile
        .entries
        .values()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let mut credentials: BTreeMap<_, _> = lock_credentials_in_order(tx, &profile.owner, &ids)
        .await?
        .into_iter()
        .collect();
    // Every personal profile includes the owner's one GitHub connection when
    // it can be used now; a missing connection is omitted.
    if profile.includes_github()
        && let Owner::User(user) = &profile.owner
        && let Some((id, metadata)) = lock_github_connection(tx, user).await?
    {
        credentials.insert(id, metadata);
    }
    Ok(credentials)
}

/// `active_github_connection` for `user`, then, when there is a connection,
/// `lock_credential` of it. Two statements, as before, so a role reads only
/// what it read before when the account has no connection.
async fn lock_github_connection(
    tx: &mut Transaction<'_, Postgres>,
    user: &OwnerId,
) -> Result<Option<(CredentialId, CredentialMetadata)>, Error> {
    let owner = Owner::User(user.clone());
    let Some(id) = crate::store::active_github_connection(&mut **tx, &owner)
        .await
        .map_err(credential_error)?
    else {
        return Ok(None);
    };
    Ok(lock_credentials_in_order(tx, &owner, &[&id]).await?.pop())
}

/// `lock_credential` of each of `ids` in order, in one statement. An empty
/// list runs no statement.
async fn lock_credentials_in_order(
    tx: &mut Transaction<'_, Postgres>,
    owner: &Owner,
    ids: &[&CredentialId],
) -> Result<Vec<(CredentialId, CredentialMetadata)>, Error> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    let (user_id, organization_id) = owner_columns(owner);
    let rows: Vec<OrderedCredentialRow> = sqlx::query_as(LOCK_CREDENTIALS_IN_ORDER)
        .bind(ids.iter().map(|id| id.as_str()).collect::<Vec<_>>())
        .bind(user_id)
        .bind(organization_id)
        .fetch_all(&mut **tx)
        .await
        .map_err(database_error)?;
    let mut rows = rows.into_iter();
    let mut locked = Vec::with_capacity(ids.len());
    for (index, id) in ids.iter().enumerate() {
        // The recursion stops at the first ID it does not find.
        let Some(row) = rows.next() else {
            return Err(Error::NotFound);
        };
        if usize::try_from(row.ordinal).ok() != Some(index + 1) {
            return Err(Error::DatabaseUnavailable);
        }
        locked.push(((*id).clone(), row.credential.metadata(owner, id)?));
    }
    Ok(locked)
}

fn validate_binding(
    context: &GrantContext,
    binding: &EnvironmentAccessBinding,
) -> Result<(), Error> {
    generation(binding.profile_revision)?;
    if binding.environment_id != context.environment_id {
        return Err(Error::InvalidInput);
    }
    Ok(())
}

fn owner_columns(owner: &Owner) -> (Option<&str>, Option<&str>) {
    match owner {
        Owner::User(id) => (Some(id.as_str()), None),
        Owner::Organization(id) => (None, Some(id.as_str())),
    }
}

fn generation(value: u64) -> Result<i64, Error> {
    if value == 0 {
        return Err(Error::InvalidInput);
    }
    i64::try_from(value).map_err(|_| Error::InvalidInput)
}

fn positive(value: i64) -> Result<u64, Error> {
    if value <= 0 {
        return Err(Error::CorruptRecord);
    }
    Ok(value as u64)
}

fn unix_now() -> Result<u64, Error> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| Error::ClockUnavailable)
}

fn database_error(error: sqlx::Error) -> Error {
    if error
        .as_database_error()
        .and_then(|error| error.code())
        .as_deref()
        == Some("23505")
    {
        Error::AlreadyExists
    } else {
        Error::DatabaseUnavailable
    }
}

fn credential_error(error: crate::PlatformCredentialError) -> Error {
    match error {
        crate::PlatformCredentialError::CorruptRecord => Error::CorruptRecord,
        _ => Error::DatabaseUnavailable,
    }
}

fn access_error(error: AccessError) -> Error {
    match error {
        AccessError::CredentialInactive { .. } => Error::InactiveCredential,
        AccessError::CredentialExpired { .. } => Error::ExpiredCredential,
        AccessError::CredentialMissing { .. } => Error::NotFound,
        AccessError::BindingMismatch => Error::StaleBinding,
        _ => Error::UnsupportedEntry,
    }
}
