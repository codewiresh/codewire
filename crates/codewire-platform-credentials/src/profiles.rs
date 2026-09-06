//! Material-free profile revisions and explicitly pinned environment bindings.
//!
//! Owners and grant contexts must come from an authenticated, authorized caller,
//! not unchecked request fields. This store fences their exact database scope;
//! it does not authenticate a user, decide membership, or authorize credentials.
//! Only same-owner entries are supported. Profile edits publish a new immutable
//! revision; an existing environment keeps its explicitly selected revision.

use std::collections::{BTreeMap, BTreeSet};
use std::time::{SystemTime, UNIX_EPOCH};

use codewire_access::{
    AccessError, AccessProfile, AccessProfileId, AccessProfileName, CapabilitySlot, CredentialId,
    CredentialMetadata, DerivedGrant, EnvironmentAccessBinding, GrantContext, Owner, OwnerId,
    Placement, ProviderCatalog, ProviderId, derive_grants, validate_profile_entries,
};
use sqlx::{PgPool, Postgres, Row, Transaction};
use uuid::Uuid;

use crate::model::{parse_auth_kind, parse_status};

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
        let mut tx = self.pool.begin().await.map_err(database_error)?;
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
        let mut tx = self.pool.begin().await.map_err(database_error)?;
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
        let mut tx = self.pool.begin().await.map_err(database_error)?;
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
        let mut tx = self.pool.begin().await.map_err(database_error)?;
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
        let mut tx = self.pool.begin().await.map_err(database_error)?;
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

    pub async fn delete(
        &self,
        owner: &Owner,
        id: &AccessProfileId,
        expected_revision: u64,
    ) -> Result<(), Error> {
        generation(expected_revision)?;
        let mut tx = self.pool.begin().await.map_err(database_error)?;
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
    pub async fn create_binding(
        &self,
        context: &GrantContext,
        binding: EnvironmentAccessBinding,
    ) -> Result<EnvironmentAccessBinding, Error> {
        validate_binding(context, &binding)?;
        let mut tx = self.pool.begin().await.map_err(database_error)?;
        lock_environment(&mut tx, context, false, true).await?;
        self.admit_binding(&mut tx, context, &binding).await?;
        sqlx::query(
            "INSERT INTO platform_environment_access_bindings \
             (environment_id,profile_id,profile_revision) VALUES ($1,$2,$3)",
        )
        .bind(binding.environment_id.as_str())
        .bind(binding.profile_id.as_str())
        .bind(generation(binding.profile_revision)?)
        .execute(&mut *tx)
        .await
        .map_err(database_error)?;
        tx.commit().await.map_err(database_error)?;
        Ok(binding)
    }

    pub async fn replace_binding(
        &self,
        context: &GrantContext,
        expected: &EnvironmentAccessBinding,
        replacement: EnvironmentAccessBinding,
    ) -> Result<EnvironmentAccessBinding, Error> {
        validate_binding(context, expected)?;
        validate_binding(context, &replacement)?;
        let mut tx = self.pool.begin().await.map_err(database_error)?;
        lock_environment(&mut tx, context, false, true).await?;
        if load_binding(&mut tx, context).await? != *expected {
            return Err(Error::StaleBinding);
        }
        self.admit_binding(&mut tx, context, &replacement).await?;
        sqlx::query(
            "UPDATE platform_environment_access_bindings SET profile_id=$2,profile_revision=$3, \
             updated_at=now() WHERE environment_id=$1",
        )
        .bind(replacement.environment_id.as_str())
        .bind(replacement.profile_id.as_str())
        .bind(generation(replacement.profile_revision)?)
        .execute(&mut *tx)
        .await
        .map_err(database_error)?;
        tx.commit().await.map_err(database_error)?;
        Ok(replacement)
    }

    pub async fn get_binding(
        &self,
        context: &GrantContext,
    ) -> Result<EnvironmentAccessBinding, Error> {
        let mut tx = self.pool.begin().await.map_err(database_error)?;
        lock_environment(&mut tx, context, false, false).await?;
        let binding = load_binding(&mut tx, context).await?;
        profile_for_context(&mut tx, context, &binding).await?;
        tx.commit().await.map_err(database_error)?;
        Ok(binding)
    }

    pub async fn delete_binding(
        &self,
        context: &GrantContext,
        expected: &EnvironmentAccessBinding,
    ) -> Result<(), Error> {
        validate_binding(context, expected)?;
        let mut tx = self.pool.begin().await.map_err(database_error)?;
        lock_environment(&mut tx, context, false, true).await?;
        if load_binding(&mut tx, context).await? != *expected {
            return Err(Error::StaleBinding);
        }
        profile_for_context(&mut tx, context, expected).await?;
        sqlx::query("DELETE FROM platform_environment_access_bindings WHERE environment_id=$1")
            .bind(context.environment_id.as_str())
            .execute(&mut *tx)
            .await
            .map_err(database_error)?;
        tx.commit().await.map_err(database_error)
    }

    /// One metadata admission point, not an irrevocable lease. The broker must
    /// repeat its operation, runtime identity, expiry and revocation fences when
    /// consuming material. A stopped or superseded runtime cannot derive grants.
    pub async fn evaluate_grants(
        &self,
        context: &GrantContext,
    ) -> Result<Vec<DerivedGrant>, Error> {
        let mut tx = self.pool.begin().await.map_err(database_error)?;
        lock_environment(&mut tx, context, true, false).await?;
        let binding = load_binding(&mut tx, context).await?;
        let grants = self.admit_binding(&mut tx, context, &binding).await?;
        tx.commit().await.map_err(database_error)?;
        Ok(grants)
    }

    async fn admit_binding(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        context: &GrantContext,
        binding: &EnvironmentAccessBinding,
    ) -> Result<Vec<DerivedGrant>, Error> {
        let profile = profile_for_context(tx, context, binding).await?;
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
    let (user_id, organization_id) = owner_columns(&profile.owner);
    let mut credentials = BTreeMap::new();
    // A shared lock fences replacement/revocation/deletion through admission.
    // Deterministic order avoids opposite-order locks across multi-slot profiles.
    for id in profile.entries.values().collect::<BTreeSet<_>>() {
        let row = sqlx::query(
            "SELECT provider,authentication_kind,display_name,account_hint,status, \
             expires_at_unix,revocation_generation FROM platform_credentials \
             WHERE id=$1 AND (user_id=$2 OR organization_id=$3) FOR SHARE",
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
            owner: profile.owner.clone(),
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
        credentials.insert(id.clone(), metadata);
    }
    Ok(credentials)
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
    if context.placement != Placement::Platform {
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
) -> Result<EnvironmentAccessBinding, Error> {
    let (id, revision): (String, i64) = sqlx::query_as(
        "SELECT profile_id,profile_revision FROM platform_environment_access_bindings \
         WHERE environment_id=$1",
    )
    .bind(context.environment_id.as_str())
    .fetch_optional(&mut **tx)
    .await
    .map_err(database_error)?
    .ok_or(Error::NotFound)?;
    Ok(EnvironmentAccessBinding {
        environment_id: context.environment_id.clone(),
        profile_id: AccessProfileId::parse(id).map_err(|_| Error::CorruptRecord)?,
        profile_revision: positive(revision)?,
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

fn access_error(error: AccessError) -> Error {
    match error {
        AccessError::CredentialInactive { .. } => Error::InactiveCredential,
        AccessError::CredentialExpired { .. } => Error::ExpiredCredential,
        AccessError::CredentialMissing { .. } => Error::NotFound,
        AccessError::BindingMismatch => Error::StaleBinding,
        _ => Error::UnsupportedEntry,
    }
}
