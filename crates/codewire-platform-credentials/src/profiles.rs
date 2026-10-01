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
    AccessError, AccessProfile, AccessProfileId, AccessProfileName, CapabilitySlot, CredentialId,
    CredentialMetadata, CredentialStatus, DerivedGrant, EnvironmentAccessBinding, GrantContext,
    GrantPlacement, Owner, OwnerId, Placement, ProviderCatalog, ProviderId,
    derive_account_github_grant, derive_grants, validate_profile_entries,
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
        let now = unix_now()?;
        for credential in credentials.values() {
            if !context.authorized_credentials.contains(&credential.id) {
                return Err(Error::UnsupportedEntry);
            }
            match credential.status {
                CredentialStatus::Active => {}
                CredentialStatus::Expired => return Err(Error::ExpiredCredential),
                CredentialStatus::RefreshFailed | CredentialStatus::Revoked => {
                    return Err(Error::InactiveCredential);
                }
            }
            if credential
                .expires_at_unix
                .is_some_and(|expires| expires <= now)
            {
                return Err(Error::ExpiredCredential);
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
    pub async fn evaluate_grants(
        &self,
        context: &GrantContext,
    ) -> Result<Vec<DerivedGrant>, Error> {
        let mut tx = self.begin_transaction().await?;
        lock_environment(&mut tx, context, true, false).await?;
        let grants = match find_binding(&mut tx, context).await? {
            Some(binding) => {
                self.admit_binding(
                    &mut tx,
                    context,
                    &binding.binding,
                    binding.personal_owner_confirmed_by.as_ref(),
                )
                .await?
            }
            // Selecting a GitHub repository needs no profile: without a
            // binding, the creator's one GitHub connection is the only grant.
            None => self.admit_account_github(&mut tx, context).await?,
        };
        tx.commit().await.map_err(database_error)?;
        Ok(grants)
    }

    async fn admit_account_github(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        context: &GrantContext,
    ) -> Result<Vec<DerivedGrant>, Error> {
        let owner = Owner::User(context.user_id.clone());
        let mut credentials = BTreeMap::new();
        if let Some(id) = crate::store::active_github_connection(&mut **tx, &owner)
            .await
            .map_err(credential_error)?
        {
            let metadata = lock_credential(tx, &owner, &id).await?;
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
        self.admit_binding(tx, context, binding, personal_owner_confirmation)
            .await
    }

    async fn admit_binding(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        context: &GrantContext,
        binding: &EnvironmentAccessBinding,
        personal_owner_confirmation: Option<&OwnerId>,
    ) -> Result<Vec<DerivedGrant>, Error> {
        let profile = profile_for_context(tx, context, binding).await?;
        validate_personal_confirmation(context, &profile, personal_owner_confirmation)?;
        let credentials = load_credentials(tx, &profile).await?;
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
    let row = sqlx::query(
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
    let expires: Option<i64> = row.try_get("expires_at_unix").map_err(database_error)?;
    let metadata = CredentialMetadata {
        id: id.clone(),
        placement: Placement::Platform,
        owner: owner.clone(),
        provider: ProviderId::parse(
            row.try_get::<String, _>("provider")
                .map_err(database_error)?,
        )
        .map_err(|_| Error::CorruptRecord)?,
        authentication_kind: parse_auth_kind(
            &row.try_get::<String, _>("authentication_kind")
                .map_err(database_error)?,
        )
        .map_err(|_| Error::CorruptRecord)?,
        display_name: row.try_get("display_name").map_err(database_error)?,
        account_hint: row.try_get("account_hint").map_err(database_error)?,
        ssh_public_key: parse_ssh_public_key(ssh_public_key, ssh_fingerprint)
            .map_err(|_| Error::CorruptRecord)?,
        status: parse_status(&row.try_get::<String, _>("status").map_err(database_error)?)
            .map_err(|_| Error::CorruptRecord)?,
        expires_at_unix: expires
            .map(|value| u64::try_from(value).map_err(|_| Error::CorruptRecord))
            .transpose()?,
        revocation_generation: positive(
            row.try_get("revocation_generation")
                .map_err(database_error)?,
        )?,
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
    generation(context.environment_generation)?;
    let org = context
        .organization_id
        .as_ref()
        .ok_or(Error::InvalidInput)?;
    if context.placement != GrantPlacement::Platform {
        return Err(Error::InvalidInput);
    }
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
    find_binding(tx, context).await?.ok_or(Error::NotFound)
}

async fn find_binding(
    tx: &mut Transaction<'_, Postgres>,
    context: &GrantContext,
) -> Result<Option<PlatformBindingMetadata>, Error> {
    let Some((id, revision, confirmed_by)): Option<(String, i64, Option<String>)> =
        sqlx::query_as(
            "SELECT profile_id,profile_revision,personal_owner_confirmed_by FROM platform_environment_access_bindings \
             WHERE environment_id=$1",
        )
        .bind(context.environment_id.as_str())
        .fetch_optional(&mut **tx)
        .await
        .map_err(database_error)?
    else {
        return Ok(None);
    };
    Ok(Some(PlatformBindingMetadata {
        binding: EnvironmentAccessBinding {
            environment_id: context.environment_id.clone(),
            profile_id: AccessProfileId::parse(id).map_err(|_| Error::CorruptRecord)?,
            profile_revision: positive(revision)?,
        },
        personal_owner_confirmed_by: confirmed_by
            .map(|id| OwnerId::parse(id).map_err(|_| Error::CorruptRecord))
            .transpose()?,
    }))
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
