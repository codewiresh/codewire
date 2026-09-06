//! Personal, material-free access-profile APIs.
//!
//! Authentication supplies the owner. Environment selection additionally locks
//! current creator/membership/organization authority in the same transaction as
//! the profile store's existing generation, revision and credential fences.
//! No KEK provider or protected-material accessor enters this service.

use std::collections::{BTreeMap, BTreeSet};

use codewire_access::{
    AccessProfile, AccessProfileId, AccessProfileName, CapabilitySlot, CredentialId,
    EnvironmentAccessBinding, EnvironmentId, GrantContext, Owner, OwnerId, Placement,
    builtin_provider_catalog,
};
use codewire_platform_credentials::{
    PlatformAccessProfileStore, PlatformBindingMetadata, PlatformProfileError,
};
use codewire_server_core::auth::AuthUser;
use codewire_server_core::{AppError, AppResult};
use sqlx::{PgPool, Postgres, Transaction};

/// Account-scoped profile metadata and explicit environment selections.
#[derive(Clone)]
pub struct AccessProfiles {
    profiles: PlatformAccessProfileStore,
}

impl AccessProfiles {
    pub fn new(pool: PgPool) -> Self {
        Self {
            profiles: PlatformAccessProfileStore::new(pool, builtin_provider_catalog()),
        }
    }

    pub async fn list(
        &self,
        user: &AuthUser,
        page_size: i32,
        page_token: &str,
    ) -> AppResult<(Vec<AccessProfile>, String)> {
        let owner = personal_owner(user)?;
        let (limit, after) = pagination(page_size, page_token)?;
        // One extra row determines whether another page really exists. There
        // is no total-count query or hidden all-pages fetch in the server.
        let mut profiles = self
            .profiles
            .list(&owner, after.as_ref(), limit + 1)
            .await
            .map_err(profile_error)?;
        let next = if profiles.len() > limit as usize {
            profiles.truncate(limit as usize);
            profiles
                .last()
                .expect("positive page size")
                .id
                .as_str()
                .to_owned()
        } else {
            String::new()
        };
        Ok((profiles, next))
    }

    pub async fn get(
        &self,
        user: &AuthUser,
        selector: ProfileSelector<'_>,
        revision: Option<u64>,
    ) -> AppResult<AccessProfile> {
        let owner = personal_owner(user)?;
        if let Some(revision) = revision {
            positive_revision(revision)?;
        }
        let profile = match selector {
            ProfileSelector::Id(id) => self.profiles.get(&owner, &profile_id(id)?).await,
            ProfileSelector::Name(name) => {
                self.profiles.resolve(&owner, &profile_name(name)?).await
            }
        }
        .map_err(profile_error)?;
        match revision {
            None => Ok(profile),
            Some(revision) => self
                .profiles
                .get_revision(&owner, &profile.id, revision)
                .await
                .map_err(profile_error),
        }
    }

    pub async fn create(
        &self,
        user: &AuthUser,
        name: &str,
        entries: BTreeMap<CapabilitySlot, CredentialId>,
    ) -> AppResult<AccessProfile> {
        let owner = personal_owner(user)?;
        self.profiles
            .create(&owner, profile_name(name)?, entries)
            .await
            .map_err(profile_error)
    }

    pub async fn update(
        &self,
        user: &AuthUser,
        id: &str,
        expected_revision: u64,
        entries: BTreeMap<CapabilitySlot, CredentialId>,
    ) -> AppResult<AccessProfile> {
        let owner = personal_owner(user)?;
        positive_revision(expected_revision)?;
        self.profiles
            .update(&owner, &profile_id(id)?, expected_revision, entries)
            .await
            .map_err(profile_error)
    }

    pub async fn delete(&self, user: &AuthUser, id: &str, expected_revision: u64) -> AppResult<()> {
        let owner = personal_owner(user)?;
        positive_revision(expected_revision)?;
        self.profiles
            .delete(&owner, &profile_id(id)?, expected_revision)
            .await
            .map_err(profile_error)
    }

    pub async fn get_binding(
        &self,
        user: &AuthUser,
        environment: &str,
    ) -> AppResult<PlatformBindingMetadata> {
        let owner = personal_owner(user)?;
        let environment = environment_id(environment)?;
        let mut tx = self
            .profiles
            .begin_transaction()
            .await
            .map_err(profile_error)?;
        let context = authorize_environment(&mut tx, &owner, &environment, false).await?;
        let metadata = self
            .profiles
            .get_binding_metadata_in(&mut tx, &context)
            .await
            .map_err(profile_error)?;
        require_personal_profile(&mut tx, &owner, &metadata.binding.profile_id).await?;
        tx.commit().await.map_err(database_error)?;
        Ok(metadata)
    }

    pub async fn set_binding(
        &self,
        user: &AuthUser,
        binding: EnvironmentAccessBinding,
        expected: Option<EnvironmentAccessBinding>,
        confirm_personal_credentials: bool,
    ) -> AppResult<EnvironmentAccessBinding> {
        let owner = personal_owner(user)?;
        binding.validate().map_err(|_| invalid_binding())?;
        if !confirm_personal_credentials {
            return Err(AppError::Precondition(
                "explicit personal credential confirmation is required".into(),
            ));
        }
        if let Some(expected) = &expected {
            expected.validate().map_err(|_| invalid_binding())?;
            if expected.environment_id != binding.environment_id {
                return Err(invalid_binding());
            }
        }
        // Resolve immutable, same-owner metadata before taking a connection for
        // the binding transaction. Never acquire a second pooled connection
        // while holding authority locks; concurrent requests cannot exhaust the
        // pool while waiting for themselves. Store admission revalidates it.
        let profile = self
            .profiles
            .get_revision(&owner, &binding.profile_id, binding.profile_revision)
            .await
            .map_err(profile_error)?;
        let mut tx = self
            .profiles
            .begin_transaction()
            .await
            .map_err(profile_error)?;
        let mut context =
            authorize_environment(&mut tx, &owner, &binding.environment_id, true).await?;
        context.authorized_credentials = profile.entries.values().cloned().collect();
        let result = match expected {
            Some(expected) => {
                self.profiles
                    .replace_binding_in(&mut tx, &context, &expected, binding, Some(owner.id()))
                    .await
            }
            None => {
                self.profiles
                    .create_binding_in(&mut tx, &context, binding, Some(owner.id()))
                    .await
            }
        }
        .map_err(profile_error)?;
        tx.commit().await.map_err(database_error)?;
        Ok(result)
    }

    pub async fn clear_binding(
        &self,
        user: &AuthUser,
        expected: EnvironmentAccessBinding,
    ) -> AppResult<()> {
        let owner = personal_owner(user)?;
        expected.validate().map_err(|_| invalid_binding())?;
        let mut tx = self
            .profiles
            .begin_transaction()
            .await
            .map_err(profile_error)?;
        let context =
            authorize_environment(&mut tx, &owner, &expected.environment_id, true).await?;
        // Keep the same global lock order as store admission: environment,
        // then the profile. Organization-owned profiles are not this API.
        require_personal_profile(&mut tx, &owner, &expected.profile_id).await?;
        self.profiles
            .delete_binding_in(&mut tx, &context, &expected)
            .await
            .map_err(profile_error)?;
        tx.commit().await.map_err(database_error)
    }
}

pub enum ProfileSelector<'a> {
    Id(&'a str),
    Name(&'a str),
}

/// Preserve duplicate detection before constructing the canonical entry map.
pub fn profile_entries<'a>(
    entries: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> AppResult<BTreeMap<CapabilitySlot, CredentialId>> {
    let mut parsed = BTreeMap::new();
    for (slot, id) in entries {
        if parsed.len() >= 128 {
            return Err(invalid_profile());
        }
        let slot = CapabilitySlot::parse(slot).map_err(|_| invalid_profile())?;
        let id = CredentialId::parse(id).map_err(|_| invalid_profile())?;
        if parsed.insert(slot, id).is_some() {
            return Err(invalid_profile());
        }
    }
    Ok(parsed)
}

pub fn parse_binding(
    environment: &str,
    profile: &str,
    revision: u64,
) -> AppResult<EnvironmentAccessBinding> {
    positive_revision(revision)?;
    Ok(EnvironmentAccessBinding {
        environment_id: environment_id(environment)?,
        profile_id: profile_id(profile)?,
        profile_revision: revision,
    })
}

fn personal_owner(user: &AuthUser) -> AppResult<Owner> {
    user.require_account_credential()?;
    Ok(Owner::User(
        OwnerId::parse(&user.user_id).map_err(|_| AppError::Unauthorized)?,
    ))
}

async fn authorize_environment(
    tx: &mut Transaction<'_, Postgres>,
    owner: &Owner,
    environment: &EnvironmentId,
    write: bool,
) -> AppResult<GrantContext> {
    // Discover only coordinates, never infer authorization from a creator ACL
    // shortcut. Re-read the exact row after owner locks in the store's order.
    let organization: String =
        sqlx::query_scalar("SELECT org_id FROM environments WHERE id=$1 AND created_by=$2")
            .bind(environment.as_str())
            .bind(owner.id().as_str())
            .fetch_optional(&mut **tx)
            .await
            .map_err(database_error)?
            .ok_or_else(not_found)?;
    for (kind, id) in [
        ("user", owner.id().as_str()),
        ("organization", organization.as_str()),
    ] {
        let active: bool =
            sqlx::query_scalar("SELECT public.codewire_platform_lock_owner($1::text,$2::text)")
                .bind(kind)
                .bind(id)
                .fetch_one(&mut **tx)
                .await
                .map_err(database_error)?;
        if !active {
            return Err(not_found());
        }
    }
    let sql = if write {
        "SELECT environment_operation_generation FROM environments \
         WHERE id=$1 AND created_by=$2 AND org_id=$3 AND type='sandbox' \
         AND desired_state<>'destroyed' AND state NOT IN ('destroyed','destroying') \
         AND deletion_requested_at IS NULL FOR UPDATE"
    } else {
        "SELECT environment_operation_generation FROM environments \
         WHERE id=$1 AND created_by=$2 AND org_id=$3 AND type='sandbox' \
         AND desired_state<>'destroyed' AND state NOT IN ('destroyed','destroying') \
         AND deletion_requested_at IS NULL FOR SHARE"
    };
    let generation: i64 = sqlx::query_scalar(sql)
        .bind(environment.as_str())
        .bind(owner.id().as_str())
        .bind(&organization)
        .fetch_optional(&mut **tx)
        .await
        .map_err(database_error)?
        .ok_or_else(not_found)?;
    if generation <= 0 {
        return Err(AppError::Precondition(
            "environment operation has not been admitted".into(),
        ));
    }
    let membership: Option<String> =
        sqlx::query_scalar("SELECT id FROM org_members WHERE user_id=$1 AND org_id=$2 FOR SHARE")
            .bind(owner.id().as_str())
            .bind(&organization)
            .fetch_optional(&mut **tx)
            .await
            .map_err(database_error)?;
    if membership.is_none() {
        return Err(not_found());
    }
    Ok(GrantContext {
        environment_id: environment.clone(),
        environment_generation: generation as u64,
        placement: Placement::Platform,
        user_id: owner.id().clone(),
        organization_id: Some(OwnerId::parse(organization).map_err(|_| unavailable())?),
        allow_personal_credentials: true,
        authorized_credentials: BTreeSet::new(),
    })
}

async fn require_personal_profile(
    tx: &mut Transaction<'_, Postgres>,
    owner: &Owner,
    profile: &AccessProfileId,
) -> AppResult<()> {
    let found: Option<String> = sqlx::query_scalar(
        "SELECT id FROM platform_access_profiles WHERE id=$1 AND user_id=$2 AND organization_id IS NULL FOR SHARE",
    ).bind(profile.as_str()).bind(owner.id().as_str())
        .fetch_optional(&mut **tx).await.map_err(database_error)?;
    if found.is_some() {
        Ok(())
    } else {
        Err(not_found())
    }
}

fn pagination(size: i32, token: &str) -> AppResult<(u32, Option<AccessProfileId>)> {
    let size = match size {
        0 => 100,
        1..=100 => size as u32,
        _ => return Err(invalid_profile()),
    };
    let after = if token.is_empty() {
        None
    } else {
        Some(profile_id(token)?)
    };
    Ok((size, after))
}

fn profile_id(value: &str) -> AppResult<AccessProfileId> {
    AccessProfileId::parse(value).map_err(|_| invalid_profile())
}
fn profile_name(value: &str) -> AppResult<AccessProfileName> {
    AccessProfileName::parse(value).map_err(|_| invalid_profile())
}
fn environment_id(value: &str) -> AppResult<EnvironmentId> {
    EnvironmentId::parse(value).map_err(|_| invalid_binding())
}
fn positive_revision(value: u64) -> AppResult<()> {
    if value == 0 || value > i64::MAX as u64 {
        Err(invalid_profile())
    } else {
        Ok(())
    }
}
fn invalid_profile() -> AppError {
    AppError::BadRequest("invalid access profile, entries, revision or pagination".into())
}
fn invalid_binding() -> AppError {
    AppError::BadRequest("invalid environment access-profile binding".into())
}
fn not_found() -> AppError {
    AppError::NotFound("access profile or authorized environment not found".into())
}
fn unavailable() -> AppError {
    AppError::ServiceUnavailable("access profile service unavailable".into())
}
fn database_error(_: sqlx::Error) -> AppError {
    unavailable()
}
fn profile_error(error: PlatformProfileError) -> AppError {
    use PlatformProfileError as E;
    match error {
        E::InvalidInput => invalid_profile(),
        E::NotFound => not_found(),
        E::AlreadyExists | E::StaleRevision | E::StaleBinding => {
            AppError::Conflict(error.to_string().into())
        }
        E::StaleEnvironment
        | E::UnsupportedEntry
        | E::InactiveCredential
        | E::ExpiredCredential
        | E::ProfileInUse => AppError::Precondition(error.to_string().into()),
        E::CorruptRecord | E::DatabaseUnavailable | E::ClockUnavailable => unavailable(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn personal_authority_rejects_api_keys_even_for_admins() {
        let mut user = AuthUser {
            user_id: "synthetic-owner".into(),
            org_id: Some("synthetic-org".into()),
            is_admin: true,
            via_api_key: true,
        };
        assert!(personal_owner(&user).unwrap_err().is_forbidden());
        user.via_api_key = false;
        assert_eq!(
            personal_owner(&user).unwrap().id().as_str(),
            "synthetic-owner"
        );
    }

    #[test]
    fn entries_revisions_and_pagination_are_bounded_and_explicit() {
        assert!(profile_entries([("codex", "first"), ("codex", "second")]).is_err());
        assert!(profile_entries([("codex", "has spaces")]).is_err());
        assert!(profile_entries([]).unwrap().is_empty());
        assert!(positive_revision(0).is_err());
        assert!(positive_revision(u64::MAX).is_err());
        assert!(positive_revision(1).is_ok());
        assert_eq!(pagination(0, "").unwrap(), (100, None));
        for size in [-1, 101, i32::MAX] {
            assert!(pagination(size, "").is_err());
        }
        assert!(pagination(1, "invalid token").is_err());
        assert!(parse_binding("env", "profile", 0).is_err());
    }
}
