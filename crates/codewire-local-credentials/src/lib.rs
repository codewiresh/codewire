#![forbid(unsafe_code)]

//! Private metadata and protected-value lifecycle for the local credential
//! authority.
//!
//! SQLite contains metadata and exact protected-store entry references only.
//! Provider material is accepted as [`ProtectedValue`], written to one exact
//! entry, and never serialized, formatted, or exposed through metadata APIs.
//! The synchronous persistence kernel is served by a separate owner-only local
//! RPC process on bounded blocking workers. The VM supervisor does not link or
//! own that material-bearing authority.

mod client;
mod control;
mod service;
mod transport;

pub use client::{AuthorityInfo, LocalCredentialClient, LocalCredentialControlClient};
pub use service::{serve_local_credential_authority, serve_os_local_credential_authority};
pub use transport::{AuthorityRuntimeConfig, AuthorityRuntimeError};

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::path::Path;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use codewire_access::{
    AccessError, AccessProfile, AccessProfileId, AccessProfileName, AccessProfileReference,
    AccessProfileScope, CapabilitySlot, CredentialAuthKind, CredentialId, CredentialMetadata,
    CredentialStatus, DerivedGrant, EnvironmentAccessBinding, EnvironmentId, GrantContext, Owner,
    OwnerId, Placement, ProviderCatalog, ProviderId, derive_grants, validate_profile_entries,
};
use codewire_protected_store::{
    ProtectedEntryId, ProtectedStore, ProtectedStoreError, ProtectedStorePersistence,
    ProtectedValue,
};
use rusqlite::config::DbConfig;
use rusqlite::{Connection, OpenFlags, OptionalExtension as _, TransactionBehavior, params};
use thiserror::Error;
use uuid::Uuid;

#[cfg(unix)]
use rustix::fs::{FlockOperation, Mode, OFlags, flock, open};
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, PermissionsExt as _};

pub const DATABASE_FILE: &str = "credentials.db";
pub const LOCAL_OWNER_ID: &str = "local-user";
/// The complete environment inherited by the detached Linux authority.
///
/// These variables locate the user session bus used by Secret Service. The
/// launcher clears every other ambient variable before exec.
pub const AUTHORITY_ALLOWED_ENVIRONMENT_VARIABLES: [&str; 2] =
    ["DBUS_SESSION_BUS_ADDRESS", "XDG_RUNTIME_DIR"];

const AUTHORITY_LOCK_FILE: &str = "authority.lock";
const DATABASE_APPLICATION_ID: i64 = 0x4357_4352; // "CWCR"
const DATABASE_SCHEMA_VERSION: i64 = 1;
const DATABASE_BUSY_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewCredential {
    pub provider: ProviderId,
    pub authentication_kind: CredentialAuthKind,
    pub display_name: String,
    pub account_hint: Option<String>,
    pub expires_at_unix: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialRecord {
    pub metadata: CredentialMetadata,
    pub persistence: ProtectedStorePersistence,
    /// A retired or uncommitted protected entry still needs exact deletion.
    /// The active material remains usable while this is true.
    pub protected_store_cleanup_pending: bool,
    pub created_at_unix_ms: u64,
    pub updated_at_unix_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccessProfileRecord {
    pub profile: AccessProfile,
    pub created_at_unix_ms: u64,
    pub updated_at_unix_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccessProfileRevisionRecord {
    pub profile: AccessProfile,
    pub profile_created_at_unix_ms: u64,
    pub revision_created_at_unix_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnvironmentAccessBindingRecord {
    pub binding: EnvironmentAccessBinding,
    pub created_at_unix_ms: u64,
    pub updated_at_unix_ms: u64,
}

/// Material lease for the future authority/broker process. Debug output never
/// renders the protected value.
pub struct CredentialMaterial {
    pub record: CredentialRecord,
    value: ProtectedValue,
}

impl CredentialMaterial {
    pub fn expose_secret(&self) -> &[u8] {
        self.value.expose_secret()
    }
}

impl fmt::Debug for CredentialMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialMaterial")
            .field("record", &self.record)
            .field("value", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MaterialState {
    PendingWrite,
    Ready,
    PendingDelete,
}

impl MaterialState {
    fn as_str(self) -> &'static str {
        match self {
            Self::PendingWrite => "pending_write",
            Self::Ready => "ready",
            Self::PendingDelete => "pending_delete",
        }
    }

    fn parse(value: &str) -> Result<Self, LocalCredentialError> {
        match value {
            "pending_write" => Ok(Self::PendingWrite),
            "ready" => Ok(Self::Ready),
            "pending_delete" => Ok(Self::PendingDelete),
            _ => Err(LocalCredentialError::CorruptMetadata),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum JournalOperation {
    RollbackWrite,
    DeleteRetired,
}

impl JournalOperation {
    fn as_str(self) -> &'static str {
        match self {
            Self::RollbackWrite => "rollback_write",
            Self::DeleteRetired => "delete_retired",
        }
    }

    fn parse(value: &str) -> Result<Self, LocalCredentialError> {
        match value {
            "rollback_write" => Ok(Self::RollbackWrite),
            "delete_retired" => Ok(Self::DeleteRetired),
            _ => Err(LocalCredentialError::CorruptMetadata),
        }
    }
}

struct ProtectedEntryJournal {
    operation: JournalOperation,
    protected_entry_id: ProtectedEntryId,
}

impl fmt::Debug for ProtectedEntryJournal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProtectedEntryJournal")
            .field("operation", &self.operation)
            .field("protected_entry_id", &"[REDACTED]")
            .finish()
    }
}

struct InternalCredentialRecord {
    public: CredentialRecord,
    material_generation: u64,
    protected_entry_id: ProtectedEntryId,
    material_state: MaterialState,
}

impl fmt::Debug for InternalCredentialRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InternalCredentialRecord")
            .field("public", &self.public)
            .field("material_generation", &self.material_generation)
            .field("protected_entry_id", &"[REDACTED]")
            .field("material_state", &self.material_state)
            .finish()
    }
}

/// Single-process local authority state. The mutex serializes SQLite and OS
/// protected-store transitions so callers cannot interleave one credential's
/// journal with another operation.
pub struct LocalCredentialAuthority<S: ProtectedStore> {
    _authority_lock: AuthorityLock,
    connection: Mutex<Connection>,
    protected_store: S,
    catalog: ProviderCatalog,
    owner_id: OwnerId,
}

impl<S: ProtectedStore> fmt::Debug for LocalCredentialAuthority<S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalCredentialAuthority")
            .field("protected_store", &"[REDACTED]")
            .field("owner_id", &self.owner_id)
            .finish_non_exhaustive()
    }
}

impl<S: ProtectedStore> LocalCredentialAuthority<S> {
    pub fn open(
        root: &Path,
        protected_store: S,
        catalog: ProviderCatalog,
    ) -> Result<Self, LocalCredentialError> {
        let owner_id = OwnerId::parse(LOCAL_OWNER_ID)?;
        #[cfg(unix)]
        ensure_private_root(root)?;
        let authority_lock = AuthorityLock::acquire(root)?;
        let connection = open_database(root)?;
        ensure_authority_identity(&connection, &owner_id, protected_store.persistence())?;
        let authority = Self {
            _authority_lock: authority_lock,
            connection: Mutex::new(connection),
            protected_store,
            catalog,
            owner_id,
        };
        authority.reconcile()?;
        Ok(authority)
    }

    pub fn owner_id(&self) -> &OwnerId {
        &self.owner_id
    }

    pub fn protected_store_persistence(&self) -> ProtectedStorePersistence {
        self.protected_store.persistence()
    }

    pub fn add_credential(
        &self,
        input: NewCredential,
        material: ProtectedValue,
    ) -> Result<CredentialRecord, LocalCredentialError> {
        let provider =
            self.catalog
                .get(&input.provider)
                .ok_or_else(|| AccessError::ProviderUnavailable {
                    provider: input.provider.clone(),
                })?;
        if !provider.supports_authentication_kind(input.authentication_kind) {
            return Err(AccessError::UnsupportedAuthenticationKind {
                provider: input.provider,
                kind: input.authentication_kind,
            }
            .into());
        }

        let id = CredentialId::parse(Uuid::new_v4().to_string())?;
        let metadata = CredentialMetadata {
            id: id.clone(),
            placement: Placement::Local,
            owner: Owner::User(self.owner_id.clone()),
            provider: input.provider,
            authentication_kind: input.authentication_kind,
            display_name: input.display_name,
            account_hint: input.account_hint,
            status: CredentialStatus::Active,
            expires_at_unix: input.expires_at_unix,
            revocation_generation: 1,
        };
        metadata.validate()?;
        let entry_id = protected_entry_id(&id, 1)?;
        let persistence = self.protected_store.persistence();
        let now = unix_millis()?;
        let expires_at = optional_u64_to_i64(metadata.expires_at_unix)?;

        let connection = self.connection()?;
        match self.protected_store.get(&entry_id) {
            Ok(None) => {}
            Ok(Some(_)) => return Err(LocalCredentialError::ProtectedEntryCollision),
            Err(error) => return Err(error.into()),
        }
        let inserted = connection.execute(
            "INSERT INTO credentials(
               id, provider, authentication_kind, display_name, account_hint,
               status, expires_at_unix, revocation_generation,
               material_generation, protected_entry_id, store_persistence, material_state,
               created_at_unix_ms, updated_at_unix_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 1, ?9, ?10, ?11, ?12, ?12)",
            params![
                id.as_str(),
                metadata.provider.as_str(),
                auth_kind_to_str(metadata.authentication_kind),
                metadata.display_name,
                metadata.account_hint,
                status_to_str(metadata.status),
                expires_at,
                i64::try_from(metadata.revocation_generation)
                    .map_err(|_| LocalCredentialError::InvalidTime)?,
                entry_id.expose_reference(),
                persistence_to_str(persistence),
                MaterialState::PendingWrite.as_str(),
                i64::try_from(now).map_err(|_| LocalCredentialError::InvalidTime)?,
            ],
        );
        if let Err(error) = inserted {
            return Err(map_insert_error(error));
        }

        if let Err(error) = self.protected_store.put(&entry_id, &material) {
            if self.protected_store.delete(&entry_id).is_ok() {
                delete_pending_write(&connection, &id)?;
            }
            return Err(error.into());
        }

        let changed = connection
            .execute(
                "UPDATE credentials
                 SET material_state = 'ready', updated_at_unix_ms = ?2
                 WHERE id = ?1 AND material_state = 'pending_write'",
                params![
                    id.as_str(),
                    i64::try_from(unix_millis()?).map_err(|_| LocalCredentialError::InvalidTime)?
                ],
            )
            .map_err(database_error)?;
        if changed != 1 {
            return Err(LocalCredentialError::CorruptMetadata);
        }
        load_internal_credential(&connection, &id, Some(MaterialState::Ready))
            .map(|record| record.public)
    }

    pub fn list_credentials(&self) -> Result<Vec<CredentialRecord>, LocalCredentialError> {
        let connection = self.connection()?;
        let mut statement = connection
            .prepare(
                "SELECT id FROM credentials
                 WHERE material_state = 'ready'
                 ORDER BY display_name COLLATE NOCASE, id",
            )
            .map_err(database_error)?;
        let rows = statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(database_error)?;
        let ids = rows
            .map(|row| row.map_err(database_error))
            .collect::<Result<Vec<_>, _>>()?;
        ids.into_iter()
            .map(|id| {
                let id =
                    CredentialId::parse(id).map_err(|_| LocalCredentialError::CorruptMetadata)?;
                load_internal_credential(&connection, &id, Some(MaterialState::Ready))
                    .map(|record| record.public)
            })
            .collect()
    }

    pub fn get_credential(
        &self,
        id: &CredentialId,
    ) -> Result<CredentialRecord, LocalCredentialError> {
        let connection = self.connection()?;
        load_internal_credential(&connection, id, Some(MaterialState::Ready))
            .map(|record| record.public)
    }

    pub fn resolve_credential(
        &self,
        display_name: &str,
    ) -> Result<CredentialRecord, LocalCredentialError> {
        let connection = self.connection()?;
        let id = connection
            .query_row(
                "SELECT id FROM credentials
                 WHERE display_name = ?1 COLLATE NOCASE AND material_state = 'ready'",
                [display_name],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(database_error)?
            .ok_or(LocalCredentialError::CredentialNotFound)?;
        let id = CredentialId::parse(id).map_err(|_| LocalCredentialError::CorruptMetadata)?;
        load_internal_credential(&connection, &id, Some(MaterialState::Ready))
            .map(|record| record.public)
    }

    pub fn rename_credential(
        &self,
        id: &CredentialId,
        display_name: String,
    ) -> Result<CredentialRecord, LocalCredentialError> {
        let connection = self.connection()?;
        let current = load_internal_credential(&connection, id, Some(MaterialState::Ready))?;
        let mut metadata = current.public.metadata;
        metadata.display_name = display_name;
        metadata.validate()?;
        let changed = connection.execute(
            "UPDATE credentials SET display_name = ?2, updated_at_unix_ms = ?3
             WHERE id = ?1 AND material_state = 'ready'",
            params![
                id.as_str(),
                metadata.display_name,
                i64::try_from(unix_millis()?).map_err(|_| LocalCredentialError::InvalidTime)?
            ],
        );
        match changed {
            Ok(1) => load_internal_credential(&connection, id, Some(MaterialState::Ready))
                .map(|record| record.public),
            Ok(_) => Err(LocalCredentialError::CorruptMetadata),
            Err(error) => Err(map_insert_error(error)),
        }
    }

    /// Atomically make a new protected value active behind the same credential
    /// ID. The old value remains active until the new entry and metadata commit
    /// are durable. Failure to delete the retired entry is journaled and
    /// reported through metadata without making the new value unavailable.
    pub fn rotate_credential_material(
        &self,
        id: &CredentialId,
        material: ProtectedValue,
        expires_at_unix: Option<u64>,
    ) -> Result<CredentialRecord, LocalCredentialError> {
        let mut connection = self.connection()?;
        let mut current = load_internal_credential(&connection, id, Some(MaterialState::Ready))?;
        reconcile_ready_journal(&connection, &self.protected_store, &current)?;
        current = load_internal_credential(&connection, id, Some(MaterialState::Ready))?;

        let generation = current
            .public
            .metadata
            .revocation_generation
            .checked_add(1)
            .ok_or(LocalCredentialError::CorruptMetadata)?;
        let material_generation = current
            .material_generation
            .checked_add(1)
            .ok_or(LocalCredentialError::CorruptMetadata)?;
        let next_entry_id = protected_entry_id(id, material_generation)?;
        match self.protected_store.get(&next_entry_id) {
            Ok(None) => {}
            Ok(Some(_)) => return Err(LocalCredentialError::ProtectedEntryCollision),
            Err(error) => return Err(error.into()),
        }
        let now = unix_millis()?;
        insert_protected_entry_journal(
            &connection,
            id,
            JournalOperation::RollbackWrite,
            &next_entry_id,
            now,
        )?;

        if let Err(error) = self.protected_store.put(&next_entry_id, &material) {
            if self.protected_store.delete(&next_entry_id).is_ok() {
                delete_protected_entry_journal(&connection, id)?;
            }
            return Err(error.into());
        }

        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        let changed = transaction
            .execute(
                "UPDATE credentials
                 SET protected_entry_id = ?2, status = 'active', expires_at_unix = ?3,
                     revocation_generation = ?4, material_generation = ?5,
                     updated_at_unix_ms = ?6
                 WHERE id = ?1 AND material_state = 'ready'",
                params![
                    id.as_str(),
                    next_entry_id.expose_reference(),
                    optional_u64_to_i64(expires_at_unix)?,
                    i64::try_from(generation).map_err(|_| LocalCredentialError::CorruptMetadata)?,
                    i64::try_from(material_generation)
                        .map_err(|_| LocalCredentialError::CorruptMetadata)?,
                    i64::try_from(now).map_err(|_| LocalCredentialError::InvalidTime)?
                ],
            )
            .map_err(database_error)?;
        if changed != 1 {
            return Err(LocalCredentialError::CorruptMetadata);
        }
        let journal_changed = transaction
            .execute(
                "UPDATE protected_entry_journal
                 SET operation = 'delete_retired', protected_entry_id = ?2
                 WHERE credential_id = ?1 AND operation = 'rollback_write'",
                params![id.as_str(), current.protected_entry_id.expose_reference()],
            )
            .map_err(database_error)?;
        if journal_changed != 1 {
            return Err(LocalCredentialError::CorruptMetadata);
        }
        transaction.commit().map_err(database_error)?;

        if self
            .protected_store
            .delete(&current.protected_entry_id)
            .is_ok()
        {
            delete_protected_entry_journal(&connection, id)?;
        }
        load_internal_credential(&connection, id, Some(MaterialState::Ready))
            .map(|record| record.public)
    }

    pub fn revoke_credential(
        &self,
        id: &CredentialId,
    ) -> Result<CredentialRecord, LocalCredentialError> {
        let connection = self.connection()?;
        let current = load_internal_credential(&connection, id, Some(MaterialState::Ready))?;
        if current.public.metadata.status == CredentialStatus::Revoked {
            return Ok(current.public);
        }
        let generation = current
            .public
            .metadata
            .revocation_generation
            .checked_add(1)
            .ok_or(LocalCredentialError::CorruptMetadata)?;
        let changed = connection
            .execute(
                "UPDATE credentials
                 SET status = 'revoked', revocation_generation = ?2, updated_at_unix_ms = ?3
                 WHERE id = ?1 AND material_state = 'ready'",
                params![
                    id.as_str(),
                    i64::try_from(generation).map_err(|_| LocalCredentialError::CorruptMetadata)?,
                    i64::try_from(unix_millis()?).map_err(|_| LocalCredentialError::InvalidTime)?
                ],
            )
            .map_err(database_error)?;
        if changed != 1 {
            return Err(LocalCredentialError::CorruptMetadata);
        }
        load_internal_credential(&connection, id, Some(MaterialState::Ready))
            .map(|record| record.public)
    }

    pub fn delete_credential(&self, id: &CredentialId) -> Result<(), LocalCredentialError> {
        let connection = self.connection()?;
        if profile_or_binding_references_credential(&connection, id)? {
            return Err(LocalCredentialError::CredentialInUse);
        }
        let record = load_internal_credential(&connection, id, None)?;
        if record.material_state == MaterialState::PendingWrite {
            return Err(LocalCredentialError::CredentialUnavailable);
        }
        let journal = load_validated_protected_entry_journal(&connection, &record)?;
        if record.material_state == MaterialState::Ready {
            let changed = connection
                .execute(
                    "UPDATE credentials SET material_state = 'pending_delete', updated_at_unix_ms = ?2
                     WHERE id = ?1 AND material_state = 'ready'",
                    params![
                        id.as_str(),
                        i64::try_from(unix_millis()?)
                            .map_err(|_| LocalCredentialError::InvalidTime)?
                    ],
                )
                .map_err(database_error)?;
            if changed != 1 {
                return Err(LocalCredentialError::CorruptMetadata);
            }
        }
        self.protected_store
            .delete(&record.protected_entry_id)
            .map_err(LocalCredentialError::from)?;
        if let Some(journal) = journal {
            self.protected_store
                .delete(&journal.protected_entry_id)
                .map_err(LocalCredentialError::from)?;
        }
        delete_pending_delete(&connection, id)
    }

    pub fn credential_material(
        &self,
        id: &CredentialId,
    ) -> Result<CredentialMaterial, LocalCredentialError> {
        let connection = self.connection()?;
        let record = load_internal_credential(&connection, id, Some(MaterialState::Ready))?;
        if record.public.metadata.status != CredentialStatus::Active {
            return Err(LocalCredentialError::CredentialInactive);
        }
        if let Some(expires_at) = record.public.metadata.expires_at_unix
            && expires_at <= unix_seconds()?
        {
            return Err(LocalCredentialError::CredentialInactive);
        }
        let value = self
            .protected_store
            .get(&record.protected_entry_id)?
            .ok_or(LocalCredentialError::CredentialMaterialMissing)?;
        Ok(CredentialMaterial {
            record: record.public,
            value,
        })
    }

    pub fn create_profile(
        &self,
        name: AccessProfileName,
        entries: BTreeMap<CapabilitySlot, CredentialId>,
    ) -> Result<AccessProfileRecord, LocalCredentialError> {
        let mut connection = self.connection()?;
        let profile = AccessProfile {
            id: AccessProfileId::parse(Uuid::new_v4().to_string())?,
            placement: Placement::Local,
            owner: Owner::User(self.owner_id.clone()),
            name,
            revision: 1,
            entries,
        };
        validate_profile_entries(
            &profile,
            &load_ready_credential_metadata(&connection)?,
            &self.catalog,
        )?;
        let now = unix_millis()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        if let Err(error) = transaction.execute(
            "INSERT INTO profiles(id, owner_id, name, current_revision, created_at_unix_ms, updated_at_unix_ms)
             VALUES (?1, ?2, ?3, 1, ?4, ?4)",
            params![
                profile.id.as_str(),
                self.owner_id.as_str(),
                profile.name.as_str(),
                i64::try_from(now).map_err(|_| LocalCredentialError::InvalidTime)?
            ],
        ) {
            return Err(map_insert_error(error));
        }
        insert_profile_revision(&transaction, &profile, now)?;
        transaction.commit().map_err(database_error)?;
        load_profile(&connection, &profile.id)
    }

    pub fn update_profile(
        &self,
        id: &AccessProfileId,
        expected_revision: u64,
        entries: BTreeMap<CapabilitySlot, CredentialId>,
    ) -> Result<AccessProfileRecord, LocalCredentialError> {
        let mut connection = self.connection()?;
        let current = load_profile(&connection, id)?;
        if current.profile.revision != expected_revision {
            return Err(LocalCredentialError::StaleProfileRevision);
        }
        let revision = expected_revision
            .checked_add(1)
            .ok_or(LocalCredentialError::CorruptMetadata)?;
        let profile = AccessProfile {
            revision,
            entries,
            ..current.profile
        };
        validate_profile_entries(
            &profile,
            &load_ready_credential_metadata(&connection)?,
            &self.catalog,
        )?;
        let now = unix_millis()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        let changed = transaction
            .execute(
                "UPDATE profiles SET current_revision = ?3, updated_at_unix_ms = ?4
                 WHERE id = ?1 AND current_revision = ?2",
                params![
                    id.as_str(),
                    i64::try_from(expected_revision)
                        .map_err(|_| LocalCredentialError::CorruptMetadata)?,
                    i64::try_from(revision).map_err(|_| LocalCredentialError::CorruptMetadata)?,
                    i64::try_from(now).map_err(|_| LocalCredentialError::InvalidTime)?
                ],
            )
            .map_err(database_error)?;
        if changed != 1 {
            return Err(LocalCredentialError::StaleProfileRevision);
        }
        insert_profile_revision(&transaction, &profile, now)?;
        transaction.commit().map_err(database_error)?;
        load_profile(&connection, id)
    }

    pub fn get_profile(
        &self,
        id: &AccessProfileId,
    ) -> Result<AccessProfileRecord, LocalCredentialError> {
        let connection = self.connection()?;
        load_profile(&connection, id)
    }

    pub fn get_profile_revision(
        &self,
        id: &AccessProfileId,
        revision: u64,
    ) -> Result<AccessProfileRevisionRecord, LocalCredentialError> {
        let connection = self.connection()?;
        load_profile_revision(&connection, id, revision)
    }

    pub fn list_profile_revisions(
        &self,
        id: &AccessProfileId,
    ) -> Result<Vec<AccessProfileRevisionRecord>, LocalCredentialError> {
        let connection = self.connection()?;
        if !profile_exists(&connection, id)? {
            return Err(LocalCredentialError::ProfileNotFound);
        }
        let mut statement = connection
            .prepare(
                "SELECT revision FROM profile_revisions
                 WHERE profile_id = ?1 ORDER BY revision",
            )
            .map_err(database_error)?;
        let rows = statement
            .query_map([id.as_str()], |row| row.get::<_, i64>(0))
            .map_err(database_error)?;
        let revisions = rows
            .map(|row| {
                let revision = row.map_err(database_error)?;
                u64::try_from(revision).map_err(|_| LocalCredentialError::CorruptMetadata)
            })
            .collect::<Result<Vec<_>, _>>()?;
        revisions
            .into_iter()
            .map(|revision| load_profile_revision(&connection, id, revision))
            .collect()
    }

    pub fn resolve_profile(
        &self,
        reference: &AccessProfileReference,
    ) -> Result<AccessProfileRecord, LocalCredentialError> {
        if reference.scope() != AccessProfileScope::User {
            return Err(AccessError::LocalOrganizationUnsupported.into());
        }
        let connection = self.connection()?;
        let id = connection
            .query_row(
                "SELECT id FROM profiles WHERE owner_id = ?1 AND name = ?2 COLLATE NOCASE",
                params![self.owner_id.as_str(), reference.name().as_str()],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(database_error)?
            .ok_or(LocalCredentialError::ProfileNotFound)?;
        let id = AccessProfileId::parse(id).map_err(|_| LocalCredentialError::CorruptMetadata)?;
        load_profile(&connection, &id)
    }

    pub fn list_profiles(&self) -> Result<Vec<AccessProfileRecord>, LocalCredentialError> {
        let connection = self.connection()?;
        let mut statement = connection
            .prepare("SELECT id FROM profiles ORDER BY name COLLATE NOCASE, id")
            .map_err(database_error)?;
        let rows = statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(database_error)?;
        let ids = rows
            .map(|row| row.map_err(database_error))
            .collect::<Result<Vec<_>, _>>()?;
        ids.into_iter()
            .map(|id| {
                let id = AccessProfileId::parse(id)
                    .map_err(|_| LocalCredentialError::CorruptMetadata)?;
                load_profile(&connection, &id)
            })
            .collect()
    }

    pub fn delete_profile(&self, id: &AccessProfileId) -> Result<(), LocalCredentialError> {
        let connection = self.connection()?;
        if environment_binding_references_profile(&connection, id)? {
            return Err(LocalCredentialError::ProfileInUse);
        }
        let changed = connection
            .execute("DELETE FROM profiles WHERE id = ?1", [id.as_str()])
            .map_err(database_error)?;
        if changed == 0 {
            return Err(LocalCredentialError::ProfileNotFound);
        }
        Ok(())
    }

    pub fn create_environment_access_binding(
        &self,
        binding: EnvironmentAccessBinding,
    ) -> Result<EnvironmentAccessBindingRecord, LocalCredentialError> {
        binding.validate()?;
        let connection = self.connection()?;
        if environment_binding_exists(&connection, &binding.environment_id)? {
            return Err(LocalCredentialError::EnvironmentBindingAlreadyExists);
        }
        derive_local_environment_grants(&connection, &binding, 1, &self.owner_id, &self.catalog)?;
        let now = unix_millis()?;
        let changed = connection
            .execute(
                "INSERT INTO environment_access_bindings(
                   environment_id, profile_id, profile_revision,
                   created_at_unix_ms, updated_at_unix_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?4)",
                params![
                    binding.environment_id.as_str(),
                    binding.profile_id.as_str(),
                    i64::try_from(binding.profile_revision)
                        .map_err(|_| LocalCredentialError::CorruptMetadata)?,
                    i64::try_from(now).map_err(|_| LocalCredentialError::InvalidTime)?,
                ],
            )
            .map_err(database_error)?;
        if changed != 1 {
            return Err(LocalCredentialError::CorruptMetadata);
        }
        load_environment_access_binding(&connection, &binding.environment_id)
    }

    pub fn replace_environment_access_binding(
        &self,
        environment_id: &EnvironmentId,
        expected_profile_id: &AccessProfileId,
        expected_profile_revision: u64,
        profile_id: AccessProfileId,
        profile_revision: u64,
    ) -> Result<EnvironmentAccessBindingRecord, LocalCredentialError> {
        let replacement = EnvironmentAccessBinding {
            environment_id: environment_id.clone(),
            profile_id,
            profile_revision,
        };
        replacement.validate()?;
        let connection = self.connection()?;
        let current = load_environment_access_binding(&connection, environment_id)?;
        if current.binding.profile_id != *expected_profile_id
            || current.binding.profile_revision != expected_profile_revision
        {
            return Err(LocalCredentialError::StaleEnvironmentBinding);
        }
        derive_local_environment_grants(
            &connection,
            &replacement,
            1,
            &self.owner_id,
            &self.catalog,
        )?;
        let changed = connection
            .execute(
                "UPDATE environment_access_bindings
                 SET profile_id = ?4, profile_revision = ?5, updated_at_unix_ms = ?6
                 WHERE environment_id = ?1 AND profile_id = ?2 AND profile_revision = ?3",
                params![
                    environment_id.as_str(),
                    expected_profile_id.as_str(),
                    i64::try_from(expected_profile_revision)
                        .map_err(|_| LocalCredentialError::CorruptMetadata)?,
                    replacement.profile_id.as_str(),
                    i64::try_from(replacement.profile_revision)
                        .map_err(|_| LocalCredentialError::CorruptMetadata)?,
                    i64::try_from(unix_millis()?).map_err(|_| LocalCredentialError::InvalidTime)?,
                ],
            )
            .map_err(database_error)?;
        if changed != 1 {
            return Err(LocalCredentialError::StaleEnvironmentBinding);
        }
        load_environment_access_binding(&connection, environment_id)
    }

    pub fn get_environment_access_binding(
        &self,
        environment_id: &EnvironmentId,
    ) -> Result<EnvironmentAccessBindingRecord, LocalCredentialError> {
        let connection = self.connection()?;
        load_environment_access_binding(&connection, environment_id)
    }

    pub fn list_environment_access_bindings(
        &self,
    ) -> Result<Vec<EnvironmentAccessBindingRecord>, LocalCredentialError> {
        let connection = self.connection()?;
        let mut statement = connection
            .prepare(
                "SELECT environment_id FROM environment_access_bindings
                 ORDER BY environment_id",
            )
            .map_err(database_error)?;
        let rows = statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(database_error)?;
        rows.map(|row| {
            let id = EnvironmentId::parse(row.map_err(database_error)?)
                .map_err(|_| LocalCredentialError::CorruptMetadata)?;
            load_environment_access_binding(&connection, &id)
        })
        .collect()
    }

    pub fn delete_environment_access_binding(
        &self,
        environment_id: &EnvironmentId,
        expected_profile_id: &AccessProfileId,
        expected_profile_revision: u64,
    ) -> Result<(), LocalCredentialError> {
        let connection = self.connection()?;
        let current = load_environment_access_binding(&connection, environment_id)?;
        if current.binding.profile_id != *expected_profile_id
            || current.binding.profile_revision != expected_profile_revision
        {
            return Err(LocalCredentialError::StaleEnvironmentBinding);
        }
        let changed = connection
            .execute(
                "DELETE FROM environment_access_bindings
                 WHERE environment_id = ?1 AND profile_id = ?2 AND profile_revision = ?3",
                params![
                    environment_id.as_str(),
                    expected_profile_id.as_str(),
                    i64::try_from(expected_profile_revision)
                        .map_err(|_| LocalCredentialError::CorruptMetadata)?,
                ],
            )
            .map_err(database_error)?;
        if changed != 1 {
            return Err(LocalCredentialError::StaleEnvironmentBinding);
        }
        Ok(())
    }

    pub fn evaluate_environment_grants(
        &self,
        environment_id: &EnvironmentId,
        environment_generation: u64,
    ) -> Result<Vec<DerivedGrant>, LocalCredentialError> {
        let connection = self.connection()?;
        let binding = load_environment_access_binding(&connection, environment_id)?.binding;
        derive_local_environment_grants(
            &connection,
            &binding,
            environment_generation,
            &self.owner_id,
            &self.catalog,
        )
    }

    fn reconcile(&self) -> Result<(), LocalCredentialError> {
        let connection = self.connection()?;
        let records = load_all_internal_credentials(&connection)?;
        let expected_persistence = self.protected_store.persistence();
        for record in &records {
            if record.public.persistence != expected_persistence {
                return Err(LocalCredentialError::ProtectedStoreMismatch);
            }
        }
        for record in records {
            match record.material_state {
                MaterialState::PendingWrite => {
                    if load_protected_entry_journal(&connection, &record.public.metadata.id)?
                        .is_some()
                    {
                        return Err(LocalCredentialError::CorruptMetadata);
                    }
                    self.protected_store.delete(&record.protected_entry_id)?;
                    delete_pending_write(&connection, &record.public.metadata.id)?;
                }
                MaterialState::PendingDelete => {
                    let journal = load_validated_protected_entry_journal(&connection, &record)?;
                    self.protected_store.delete(&record.protected_entry_id)?;
                    if let Some(journal) = journal {
                        self.protected_store.delete(&journal.protected_entry_id)?;
                    }
                    delete_pending_delete(&connection, &record.public.metadata.id)?;
                }
                MaterialState::Ready => {
                    reconcile_ready_journal(&connection, &self.protected_store, &record)?;
                    if expected_persistence == ProtectedStorePersistence::ProcessLifetime
                        && self
                            .protected_store
                            .get(&record.protected_entry_id)?
                            .is_none()
                    {
                        connection
                            .execute(
                                "UPDATE credentials SET status = 'expired', updated_at_unix_ms = ?2
                                 WHERE id = ?1 AND material_state = 'ready'",
                                params![
                                    record.public.metadata.id.as_str(),
                                    i64::try_from(unix_millis()?)
                                        .map_err(|_| LocalCredentialError::InvalidTime)?
                                ],
                            )
                            .map_err(database_error)?;
                    }
                }
            }
        }
        validate_environment_access_bindings(&connection)?;
        validate_database(&connection)
    }

    fn connection(&self) -> Result<MutexGuard<'_, Connection>, LocalCredentialError> {
        self.connection
            .lock()
            .map_err(|_| LocalCredentialError::DatabaseUnavailable)
    }
}

struct AuthorityLock {
    #[cfg(unix)]
    _file: fs::File,
}

impl AuthorityLock {
    fn acquire(root: &Path) -> Result<Self, LocalCredentialError> {
        #[cfg(not(unix))]
        {
            let _ = root;
            Err(LocalCredentialError::UnsupportedPlatform)
        }

        #[cfg(unix)]
        {
            let path = root.join(AUTHORITY_LOCK_FILE);
            let descriptor = open(
                &path,
                OFlags::RDWR | OFlags::CREATE | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::RUSR | Mode::WUSR,
            )
            .map_err(|_| LocalCredentialError::InvalidDatabasePath)?;
            let file = fs::File::from(descriptor);
            validate_private_file(
                &file
                    .metadata()
                    .map_err(|_| LocalCredentialError::InvalidDatabasePath)?,
            )?;
            flock(&file, FlockOperation::NonBlockingLockExclusive)
                .map_err(|_| LocalCredentialError::AlreadyRunning)?;
            Ok(Self { _file: file })
        }
    }
}

fn open_database(root: &Path) -> Result<Connection, LocalCredentialError> {
    #[cfg(not(unix))]
    {
        let _ = root;
        return Err(LocalCredentialError::UnsupportedPlatform);
    }

    #[cfg(unix)]
    {
        ensure_private_root(root)?;
        let path = root.join(DATABASE_FILE);
        let before = match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                validate_private_file(&metadata)?;
                Some(metadata.len())
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(_) => return Err(LocalCredentialError::InvalidDatabasePath),
        };
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW;
        let connection = Connection::open_with_flags(&path, flags).map_err(database_error)?;
        if before.is_none() {
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                .map_err(|_| LocalCredentialError::InvalidDatabasePath)?;
        }
        let after =
            fs::symlink_metadata(&path).map_err(|_| LocalCredentialError::InvalidDatabasePath)?;
        validate_private_file(&after)?;
        configure_database(&connection)?;
        if before.is_none() || before == Some(0) {
            initialize_schema(&connection)?;
        } else {
            validate_schema(&connection)?;
        }
        validate_database(&connection)?;
        Ok(connection)
    }
}

#[cfg(unix)]
pub(crate) fn ensure_private_root(root: &Path) -> Result<(), LocalCredentialError> {
    validate_private_parent(root)?;
    match fs::symlink_metadata(root) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut builder = fs::DirBuilder::new();
            builder.mode(0o700);
            builder
                .create(root)
                .map_err(|_| LocalCredentialError::InvalidDatabasePath)?;
        }
        Err(_) => return Err(LocalCredentialError::InvalidDatabasePath),
    }
    let metadata =
        fs::symlink_metadata(root).map_err(|_| LocalCredentialError::InvalidDatabasePath)?;
    let current_uid = rustix::process::geteuid().as_raw();
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != current_uid
        || metadata.mode() & 0o7777 != 0o700
        || fs::canonicalize(root).map_err(|_| LocalCredentialError::InvalidDatabasePath)? != root
    {
        return Err(LocalCredentialError::InvalidDatabasePath);
    }
    Ok(())
}

#[cfg(unix)]
pub(crate) fn validate_private_parent(root: &Path) -> Result<(), LocalCredentialError> {
    let parent = root
        .parent()
        .filter(|parent| *parent != root)
        .ok_or(LocalCredentialError::InvalidDatabasePath)?;
    let parent_metadata =
        fs::symlink_metadata(parent).map_err(|_| LocalCredentialError::InvalidDatabasePath)?;
    if !parent_metadata.file_type().is_dir()
        || parent_metadata.file_type().is_symlink()
        || parent_metadata.mode() & 0o022 != 0
        || fs::canonicalize(parent).map_err(|_| LocalCredentialError::InvalidDatabasePath)?
            != parent
    {
        return Err(LocalCredentialError::InvalidDatabasePath);
    }
    Ok(())
}

#[cfg(unix)]
fn validate_private_file(metadata: &fs::Metadata) -> Result<(), LocalCredentialError> {
    let current_uid = rustix::process::geteuid().as_raw();
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != current_uid
        || metadata.mode() & 0o7777 != 0o600
    {
        return Err(LocalCredentialError::InvalidDatabasePath);
    }
    Ok(())
}

fn configure_database(connection: &Connection) -> Result<(), LocalCredentialError> {
    connection
        .busy_timeout(DATABASE_BUSY_TIMEOUT)
        .map_err(database_error)?;
    connection
        .set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)
        .map_err(database_error)?;
    connection
        .pragma_update(None, "foreign_keys", true)
        .map_err(database_error)?;
    connection
        .pragma_update(None, "trusted_schema", false)
        .map_err(database_error)?;
    connection
        .pragma_update(None, "synchronous", "FULL")
        .map_err(database_error)?;
    connection
        .pragma_update(None, "temp_store", "MEMORY")
        .map_err(database_error)?;
    let journal: String = connection
        .pragma_update_and_check(None, "journal_mode", "DELETE", |row| row.get(0))
        .map_err(database_error)?;
    if !journal.eq_ignore_ascii_case("delete") {
        return Err(LocalCredentialError::InvalidDatabase);
    }
    Ok(())
}

fn initialize_schema(connection: &Connection) -> Result<(), LocalCredentialError> {
    connection
        .execute_batch(
            "BEGIN IMMEDIATE;
             CREATE TABLE authority_metadata(
               key TEXT PRIMARY KEY NOT NULL,
               value TEXT NOT NULL
             ) STRICT;
             CREATE TABLE credentials(
               id TEXT PRIMARY KEY NOT NULL,
               provider TEXT NOT NULL,
               authentication_kind TEXT NOT NULL,
               display_name TEXT NOT NULL COLLATE NOCASE UNIQUE,
               account_hint TEXT NULL,
               status TEXT NOT NULL CHECK(status IN ('active', 'expired', 'refresh_failed', 'revoked')),
               expires_at_unix INTEGER NULL CHECK(expires_at_unix IS NULL OR expires_at_unix >= 0),
               revocation_generation INTEGER NOT NULL CHECK(revocation_generation > 0),
               material_generation INTEGER NOT NULL CHECK(material_generation > 0),
               protected_entry_id TEXT NOT NULL UNIQUE,
               store_persistence TEXT NOT NULL CHECK(store_persistence IN ('operating_system', 'process_lifetime')),
               material_state TEXT NOT NULL CHECK(material_state IN ('pending_write', 'ready', 'pending_delete')),
               created_at_unix_ms INTEGER NOT NULL CHECK(created_at_unix_ms >= 0),
               updated_at_unix_ms INTEGER NOT NULL CHECK(updated_at_unix_ms >= created_at_unix_ms)
             ) STRICT;
             CREATE TABLE protected_entry_journal(
               credential_id TEXT PRIMARY KEY NOT NULL,
               operation TEXT NOT NULL CHECK(operation IN ('rollback_write', 'delete_retired')),
               protected_entry_id TEXT NOT NULL UNIQUE,
               created_at_unix_ms INTEGER NOT NULL CHECK(created_at_unix_ms >= 0),
               FOREIGN KEY(credential_id) REFERENCES credentials(id) ON DELETE CASCADE
             ) STRICT;
             CREATE TABLE profiles(
               id TEXT PRIMARY KEY NOT NULL,
               owner_id TEXT NOT NULL,
               name TEXT NOT NULL COLLATE NOCASE,
               current_revision INTEGER NOT NULL CHECK(current_revision > 0),
               created_at_unix_ms INTEGER NOT NULL CHECK(created_at_unix_ms >= 0),
               updated_at_unix_ms INTEGER NOT NULL CHECK(updated_at_unix_ms >= created_at_unix_ms),
               UNIQUE(owner_id, name)
             ) STRICT;
             CREATE TABLE profile_revisions(
               profile_id TEXT NOT NULL,
               revision INTEGER NOT NULL CHECK(revision > 0),
               created_at_unix_ms INTEGER NOT NULL CHECK(created_at_unix_ms >= 0),
               PRIMARY KEY(profile_id, revision),
               FOREIGN KEY(profile_id) REFERENCES profiles(id) ON DELETE CASCADE
             ) STRICT;
             CREATE TABLE profile_entries(
               profile_id TEXT NOT NULL,
               revision INTEGER NOT NULL,
               capability_slot TEXT NOT NULL,
               credential_id TEXT NOT NULL,
               PRIMARY KEY(profile_id, revision, capability_slot),
               FOREIGN KEY(profile_id, revision)
                 REFERENCES profile_revisions(profile_id, revision) ON DELETE CASCADE
             ) STRICT;
             CREATE TABLE environment_access_bindings(
               environment_id TEXT PRIMARY KEY NOT NULL,
               profile_id TEXT NOT NULL,
               profile_revision INTEGER NOT NULL CHECK(profile_revision > 0),
               created_at_unix_ms INTEGER NOT NULL CHECK(created_at_unix_ms >= 0),
               updated_at_unix_ms INTEGER NOT NULL CHECK(updated_at_unix_ms >= created_at_unix_ms),
               FOREIGN KEY(profile_id, profile_revision)
                 REFERENCES profile_revisions(profile_id, revision) ON DELETE RESTRICT
             ) STRICT;
             CREATE INDEX environment_access_bindings_profile
               ON environment_access_bindings(profile_id, profile_revision);
             COMMIT;",
        )
        .map_err(database_error)?;
    connection
        .pragma_update(None, "application_id", DATABASE_APPLICATION_ID)
        .map_err(database_error)?;
    connection
        .pragma_update(None, "user_version", DATABASE_SCHEMA_VERSION)
        .map_err(database_error)?;
    validate_schema(connection)
}

fn validate_schema(connection: &Connection) -> Result<(), LocalCredentialError> {
    let application_id: i64 = connection
        .pragma_query_value(None, "application_id", |row| row.get(0))
        .map_err(database_error)?;
    let schema_version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(database_error)?;
    if application_id != DATABASE_APPLICATION_ID || schema_version != DATABASE_SCHEMA_VERSION {
        return Err(LocalCredentialError::UnsupportedSchema);
    }
    for table in [
        "authority_metadata",
        "credentials",
        "protected_entry_journal",
        "profiles",
        "profile_revisions",
        "profile_entries",
        "environment_access_bindings",
    ] {
        let present = connection
            .query_row(
                "SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = ?1",
                [table],
                |_| Ok(()),
            )
            .optional()
            .map_err(database_error)?
            .is_some();
        if !present {
            return Err(LocalCredentialError::InvalidDatabase);
        }
    }
    Ok(())
}

fn validate_database(connection: &Connection) -> Result<(), LocalCredentialError> {
    let result: String = connection
        .query_row("PRAGMA quick_check(1)", [], |row| row.get(0))
        .map_err(database_error)?;
    if result != "ok" {
        return Err(LocalCredentialError::InvalidDatabase);
    }
    let foreign_key_violation = connection
        .query_row("SELECT 1 FROM pragma_foreign_key_check LIMIT 1", [], |_| {
            Ok(())
        })
        .optional()
        .map_err(database_error)?
        .is_some();
    if foreign_key_violation {
        return Err(LocalCredentialError::InvalidDatabase);
    }
    Ok(())
}

fn ensure_authority_identity(
    connection: &Connection,
    owner_id: &OwnerId,
    persistence: ProtectedStorePersistence,
) -> Result<(), LocalCredentialError> {
    let transaction = connection.unchecked_transaction().map_err(database_error)?;
    for (key, expected) in [
        ("owner_id", owner_id.as_str()),
        ("store_persistence", persistence_to_str(persistence)),
    ] {
        match transaction
            .query_row(
                "SELECT value FROM authority_metadata WHERE key = ?1",
                [key],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(database_error)?
        {
            Some(observed) if observed == expected => {}
            Some(_) if key == "owner_id" => return Err(LocalCredentialError::OwnerMismatch),
            Some(_) => return Err(LocalCredentialError::ProtectedStoreMismatch),
            None => {
                transaction
                    .execute(
                        "INSERT INTO authority_metadata(key, value) VALUES (?1, ?2)",
                        [key, expected],
                    )
                    .map_err(database_error)?;
            }
        }
    }
    transaction.commit().map_err(database_error)
}

fn protected_entry_id(
    id: &CredentialId,
    generation: u64,
) -> Result<ProtectedEntryId, LocalCredentialError> {
    ProtectedEntryId::parse(format!("local/credentials/{id}/material-v{generation}"))
        .map_err(Into::into)
}

fn insert_protected_entry_journal(
    connection: &Connection,
    credential_id: &CredentialId,
    operation: JournalOperation,
    protected_entry_id: &ProtectedEntryId,
    now: u64,
) -> Result<(), LocalCredentialError> {
    let changed = connection
        .execute(
            "INSERT INTO protected_entry_journal(
               credential_id, operation, protected_entry_id, created_at_unix_ms
             ) VALUES (?1, ?2, ?3, ?4)",
            params![
                credential_id.as_str(),
                operation.as_str(),
                protected_entry_id.expose_reference(),
                i64::try_from(now).map_err(|_| LocalCredentialError::InvalidTime)?
            ],
        )
        .map_err(database_error)?;
    if changed != 1 {
        return Err(LocalCredentialError::CorruptMetadata);
    }
    Ok(())
}

fn load_protected_entry_journal(
    connection: &Connection,
    credential_id: &CredentialId,
) -> Result<Option<ProtectedEntryJournal>, LocalCredentialError> {
    connection
        .query_row(
            "SELECT operation, protected_entry_id
             FROM protected_entry_journal WHERE credential_id = ?1",
            [credential_id.as_str()],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()
        .map_err(database_error)?
        .map(|(operation, protected_entry_id)| {
            Ok(ProtectedEntryJournal {
                operation: JournalOperation::parse(&operation)?,
                protected_entry_id: ProtectedEntryId::parse(protected_entry_id)
                    .map_err(|_| LocalCredentialError::CorruptMetadata)?,
            })
        })
        .transpose()
}

fn delete_protected_entry_journal(
    connection: &Connection,
    credential_id: &CredentialId,
) -> Result<(), LocalCredentialError> {
    let changed = connection
        .execute(
            "DELETE FROM protected_entry_journal WHERE credential_id = ?1",
            [credential_id.as_str()],
        )
        .map_err(database_error)?;
    if changed != 1 {
        return Err(LocalCredentialError::CorruptMetadata);
    }
    Ok(())
}

fn load_validated_protected_entry_journal(
    connection: &Connection,
    credential: &InternalCredentialRecord,
) -> Result<Option<ProtectedEntryJournal>, LocalCredentialError> {
    let Some(journal) = load_protected_entry_journal(connection, &credential.public.metadata.id)?
    else {
        return Ok(None);
    };
    let expected_generation = match journal.operation {
        JournalOperation::RollbackWrite => credential
            .material_generation
            .checked_add(1)
            .ok_or(LocalCredentialError::CorruptMetadata)?,
        JournalOperation::DeleteRetired => credential
            .material_generation
            .checked_sub(1)
            .filter(|generation| *generation > 0)
            .ok_or(LocalCredentialError::CorruptMetadata)?,
    };
    if journal.protected_entry_id
        != protected_entry_id(&credential.public.metadata.id, expected_generation)?
    {
        return Err(LocalCredentialError::CorruptMetadata);
    }
    Ok(Some(journal))
}

fn reconcile_ready_journal<S: ProtectedStore>(
    connection: &Connection,
    protected_store: &S,
    credential: &InternalCredentialRecord,
) -> Result<(), LocalCredentialError> {
    let Some(journal) = load_validated_protected_entry_journal(connection, credential)? else {
        return Ok(());
    };
    match journal.operation {
        JournalOperation::RollbackWrite | JournalOperation::DeleteRetired => {
            protected_store.delete(&journal.protected_entry_id)?;
        }
    }
    delete_protected_entry_journal(connection, &credential.public.metadata.id)
}

fn load_internal_credential(
    connection: &Connection,
    id: &CredentialId,
    required_state: Option<MaterialState>,
) -> Result<InternalCredentialRecord, LocalCredentialError> {
    let raw = connection
        .query_row(
            "SELECT provider, authentication_kind, display_name, account_hint,
                    status, expires_at_unix, revocation_generation,
                    material_generation, protected_entry_id, store_persistence, material_state,
                    created_at_unix_ms, updated_at_unix_ms,
                    EXISTS(
                      SELECT 1 FROM protected_entry_journal j
                      WHERE j.credential_id = credentials.id
                    )
             FROM credentials WHERE id = ?1",
            [id.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Option<i64>>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, i64>(11)?,
                    row.get::<_, i64>(12)?,
                    row.get::<_, bool>(13)?,
                ))
            },
        )
        .optional()
        .map_err(database_error)?
        .ok_or(LocalCredentialError::CredentialNotFound)?;
    let material_state = MaterialState::parse(&raw.10)?;
    if required_state.is_some_and(|state| material_state != state) {
        return Err(LocalCredentialError::CredentialUnavailable);
    }
    let metadata = CredentialMetadata {
        id: id.clone(),
        placement: Placement::Local,
        owner: Owner::User(OwnerId::parse(LOCAL_OWNER_ID)?),
        provider: ProviderId::parse(raw.0).map_err(|_| LocalCredentialError::CorruptMetadata)?,
        authentication_kind: parse_auth_kind(&raw.1)?,
        display_name: raw.2,
        account_hint: raw.3,
        status: parse_status(&raw.4)?,
        expires_at_unix: optional_i64_to_u64(raw.5)?,
        revocation_generation: u64::try_from(raw.6)
            .map_err(|_| LocalCredentialError::CorruptMetadata)?,
    };
    metadata
        .validate()
        .map_err(|_| LocalCredentialError::CorruptMetadata)?;
    let material_generation =
        u64::try_from(raw.7).map_err(|_| LocalCredentialError::CorruptMetadata)?;
    let active_entry_id =
        ProtectedEntryId::parse(raw.8).map_err(|_| LocalCredentialError::CorruptMetadata)?;
    if active_entry_id != protected_entry_id(id, material_generation)? {
        return Err(LocalCredentialError::CorruptMetadata);
    }
    Ok(InternalCredentialRecord {
        public: CredentialRecord {
            metadata,
            persistence: parse_persistence(&raw.9)?,
            protected_store_cleanup_pending: raw.13,
            created_at_unix_ms: u64::try_from(raw.11)
                .map_err(|_| LocalCredentialError::CorruptMetadata)?,
            updated_at_unix_ms: u64::try_from(raw.12)
                .map_err(|_| LocalCredentialError::CorruptMetadata)?,
        },
        material_generation,
        protected_entry_id: active_entry_id,
        material_state,
    })
}

fn load_all_internal_credentials(
    connection: &Connection,
) -> Result<Vec<InternalCredentialRecord>, LocalCredentialError> {
    let mut statement = connection
        .prepare("SELECT id FROM credentials ORDER BY id")
        .map_err(database_error)?;
    let rows = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(database_error)?;
    let ids = rows
        .map(|row| row.map_err(database_error))
        .collect::<Result<Vec<_>, _>>()?;
    ids.into_iter()
        .map(|id| {
            let id = CredentialId::parse(id).map_err(|_| LocalCredentialError::CorruptMetadata)?;
            load_internal_credential(connection, &id, None)
        })
        .collect()
}

fn load_ready_credential_metadata(
    connection: &Connection,
) -> Result<BTreeMap<CredentialId, CredentialMetadata>, LocalCredentialError> {
    load_all_internal_credentials(connection)?
        .into_iter()
        .filter(|record| record.material_state == MaterialState::Ready)
        .map(|record| {
            let metadata = record.public.metadata;
            Ok((metadata.id.clone(), metadata))
        })
        .collect()
}

fn delete_pending_write(
    connection: &Connection,
    id: &CredentialId,
) -> Result<(), LocalCredentialError> {
    let changed = connection
        .execute(
            "DELETE FROM credentials WHERE id = ?1 AND material_state = 'pending_write'",
            [id.as_str()],
        )
        .map_err(database_error)?;
    if changed != 1 {
        return Err(LocalCredentialError::CorruptMetadata);
    }
    Ok(())
}

fn delete_pending_delete(
    connection: &Connection,
    id: &CredentialId,
) -> Result<(), LocalCredentialError> {
    let changed = connection
        .execute(
            "DELETE FROM credentials WHERE id = ?1 AND material_state = 'pending_delete'",
            [id.as_str()],
        )
        .map_err(database_error)?;
    if changed != 1 {
        return Err(LocalCredentialError::CorruptMetadata);
    }
    Ok(())
}

fn profile_or_binding_references_credential(
    connection: &Connection,
    id: &CredentialId,
) -> Result<bool, LocalCredentialError> {
    connection
        .query_row(
            "SELECT EXISTS(
               SELECT 1 FROM profiles p
               JOIN profile_entries e
                 ON e.profile_id = p.id AND e.revision = p.current_revision
               WHERE e.credential_id = ?1
             ) OR EXISTS(
               SELECT 1 FROM environment_access_bindings b
               JOIN profile_entries e
                 ON e.profile_id = b.profile_id AND e.revision = b.profile_revision
               WHERE e.credential_id = ?1
             )",
            [id.as_str()],
            |row| row.get(0),
        )
        .map_err(database_error)
}

fn environment_binding_exists(
    connection: &Connection,
    environment_id: &EnvironmentId,
) -> Result<bool, LocalCredentialError> {
    connection
        .query_row(
            "SELECT EXISTS(
               SELECT 1 FROM environment_access_bindings WHERE environment_id = ?1
             )",
            [environment_id.as_str()],
            |row| row.get(0),
        )
        .map_err(database_error)
}

fn environment_binding_references_profile(
    connection: &Connection,
    profile_id: &AccessProfileId,
) -> Result<bool, LocalCredentialError> {
    connection
        .query_row(
            "SELECT EXISTS(
               SELECT 1 FROM environment_access_bindings WHERE profile_id = ?1
             )",
            [profile_id.as_str()],
            |row| row.get(0),
        )
        .map_err(database_error)
}

fn load_environment_access_binding(
    connection: &Connection,
    environment_id: &EnvironmentId,
) -> Result<EnvironmentAccessBindingRecord, LocalCredentialError> {
    let raw = connection
        .query_row(
            "SELECT profile_id, profile_revision, created_at_unix_ms, updated_at_unix_ms
             FROM environment_access_bindings WHERE environment_id = ?1",
            [environment_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()
        .map_err(database_error)?
        .ok_or(LocalCredentialError::EnvironmentBindingNotFound)?;
    let record = EnvironmentAccessBindingRecord {
        binding: EnvironmentAccessBinding {
            environment_id: environment_id.clone(),
            profile_id: AccessProfileId::parse(raw.0)
                .map_err(|_| LocalCredentialError::CorruptMetadata)?,
            profile_revision: u64::try_from(raw.1)
                .map_err(|_| LocalCredentialError::CorruptMetadata)?,
        },
        created_at_unix_ms: u64::try_from(raw.2)
            .map_err(|_| LocalCredentialError::CorruptMetadata)?,
        updated_at_unix_ms: u64::try_from(raw.3)
            .map_err(|_| LocalCredentialError::CorruptMetadata)?,
    };
    record.binding.validate()?;
    if record.updated_at_unix_ms < record.created_at_unix_ms {
        return Err(LocalCredentialError::CorruptMetadata);
    }
    Ok(record)
}

fn derive_local_environment_grants(
    connection: &Connection,
    binding: &EnvironmentAccessBinding,
    environment_generation: u64,
    owner_id: &OwnerId,
    catalog: &ProviderCatalog,
) -> Result<Vec<DerivedGrant>, LocalCredentialError> {
    let profile =
        load_profile_revision(connection, &binding.profile_id, binding.profile_revision)?.profile;
    let credentials = load_ready_credential_metadata(connection)?;
    let context = GrantContext {
        environment_id: binding.environment_id.clone(),
        environment_generation,
        placement: Placement::Local,
        user_id: owner_id.clone(),
        organization_id: None,
        allow_personal_credentials: false,
        authorized_credentials: profile.entries.values().cloned().collect::<BTreeSet<_>>(),
    };
    derive_grants(
        &context,
        binding,
        &profile,
        &credentials,
        catalog,
        unix_seconds()?,
    )
    .map_err(Into::into)
}

fn validate_environment_access_bindings(
    connection: &Connection,
) -> Result<(), LocalCredentialError> {
    let environment_ids = {
        let mut statement = connection
            .prepare("SELECT environment_id FROM environment_access_bindings")
            .map_err(database_error)?;
        let rows = statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(database_error)?;
        rows.map(|row| row.map_err(database_error))
            .collect::<Result<Vec<_>, _>>()?
    };
    for environment_id in environment_ids {
        let environment_id = EnvironmentId::parse(environment_id)
            .map_err(|_| LocalCredentialError::CorruptMetadata)?;
        let binding = load_environment_access_binding(connection, &environment_id)?.binding;
        load_profile_revision(connection, &binding.profile_id, binding.profile_revision)?;
    }
    Ok(())
}

fn insert_profile_revision(
    transaction: &rusqlite::Transaction<'_>,
    profile: &AccessProfile,
    now: u64,
) -> Result<(), LocalCredentialError> {
    transaction
        .execute(
            "INSERT INTO profile_revisions(profile_id, revision, created_at_unix_ms)
             VALUES (?1, ?2, ?3)",
            params![
                profile.id.as_str(),
                i64::try_from(profile.revision)
                    .map_err(|_| LocalCredentialError::CorruptMetadata)?,
                i64::try_from(now).map_err(|_| LocalCredentialError::InvalidTime)?
            ],
        )
        .map_err(database_error)?;
    for (slot, credential_id) in &profile.entries {
        transaction
            .execute(
                "INSERT INTO profile_entries(profile_id, revision, capability_slot, credential_id)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    profile.id.as_str(),
                    i64::try_from(profile.revision)
                        .map_err(|_| LocalCredentialError::CorruptMetadata)?,
                    slot.as_str(),
                    credential_id.as_str()
                ],
            )
            .map_err(database_error)?;
    }
    Ok(())
}

fn load_profile(
    connection: &Connection,
    id: &AccessProfileId,
) -> Result<AccessProfileRecord, LocalCredentialError> {
    let raw = connection
        .query_row(
            "SELECT owner_id, name, current_revision, created_at_unix_ms, updated_at_unix_ms
             FROM profiles WHERE id = ?1",
            [id.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
        .optional()
        .map_err(database_error)?
        .ok_or(LocalCredentialError::ProfileNotFound)?;
    let owner = OwnerId::parse(raw.0).map_err(|_| LocalCredentialError::CorruptMetadata)?;
    if owner.as_str() != LOCAL_OWNER_ID {
        return Err(LocalCredentialError::OwnerMismatch);
    }
    let revision = u64::try_from(raw.2).map_err(|_| LocalCredentialError::CorruptMetadata)?;
    let entries = load_profile_entries(connection, id, revision)?;
    let profile = AccessProfile {
        id: id.clone(),
        placement: Placement::Local,
        owner: Owner::User(owner),
        name: AccessProfileName::parse(raw.1).map_err(|_| LocalCredentialError::CorruptMetadata)?,
        revision,
        entries,
    };
    profile
        .validate()
        .map_err(|_| LocalCredentialError::CorruptMetadata)?;
    Ok(AccessProfileRecord {
        profile,
        created_at_unix_ms: u64::try_from(raw.3)
            .map_err(|_| LocalCredentialError::CorruptMetadata)?,
        updated_at_unix_ms: u64::try_from(raw.4)
            .map_err(|_| LocalCredentialError::CorruptMetadata)?,
    })
}

fn profile_exists(
    connection: &Connection,
    id: &AccessProfileId,
) -> Result<bool, LocalCredentialError> {
    connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM profiles WHERE id = ?1)",
            [id.as_str()],
            |row| row.get(0),
        )
        .map_err(database_error)
}

fn load_profile_revision(
    connection: &Connection,
    id: &AccessProfileId,
    revision: u64,
) -> Result<AccessProfileRevisionRecord, LocalCredentialError> {
    if revision == 0 {
        return Err(LocalCredentialError::ProfileRevisionNotFound);
    }
    let raw = connection
        .query_row(
            "SELECT p.owner_id, p.name, p.created_at_unix_ms, r.created_at_unix_ms
             FROM profiles p
             JOIN profile_revisions r ON r.profile_id = p.id
             WHERE p.id = ?1 AND r.revision = ?2",
            params![
                id.as_str(),
                i64::try_from(revision).map_err(|_| LocalCredentialError::CorruptMetadata)?
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()
        .map_err(database_error)?;
    let Some(raw) = raw else {
        return if profile_exists(connection, id)? {
            Err(LocalCredentialError::ProfileRevisionNotFound)
        } else {
            Err(LocalCredentialError::ProfileNotFound)
        };
    };
    let owner = OwnerId::parse(raw.0).map_err(|_| LocalCredentialError::CorruptMetadata)?;
    if owner.as_str() != LOCAL_OWNER_ID {
        return Err(LocalCredentialError::OwnerMismatch);
    }
    let profile = AccessProfile {
        id: id.clone(),
        placement: Placement::Local,
        owner: Owner::User(owner),
        name: AccessProfileName::parse(raw.1).map_err(|_| LocalCredentialError::CorruptMetadata)?,
        revision,
        entries: load_profile_entries(connection, id, revision)?,
    };
    profile
        .validate()
        .map_err(|_| LocalCredentialError::CorruptMetadata)?;
    Ok(AccessProfileRevisionRecord {
        profile,
        profile_created_at_unix_ms: u64::try_from(raw.2)
            .map_err(|_| LocalCredentialError::CorruptMetadata)?,
        revision_created_at_unix_ms: u64::try_from(raw.3)
            .map_err(|_| LocalCredentialError::CorruptMetadata)?,
    })
}

fn load_profile_entries(
    connection: &Connection,
    id: &AccessProfileId,
    revision: u64,
) -> Result<BTreeMap<CapabilitySlot, CredentialId>, LocalCredentialError> {
    let mut statement = connection
        .prepare(
            "SELECT capability_slot, credential_id FROM profile_entries
             WHERE profile_id = ?1 AND revision = ?2 ORDER BY capability_slot",
        )
        .map_err(database_error)?;
    let rows = statement
        .query_map(
            params![
                id.as_str(),
                i64::try_from(revision).map_err(|_| LocalCredentialError::CorruptMetadata)?
            ],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .map_err(database_error)?;
    let mut entries = BTreeMap::new();
    for row in rows {
        let (slot, credential_id) = row.map_err(database_error)?;
        let slot =
            CapabilitySlot::parse(slot).map_err(|_| LocalCredentialError::CorruptMetadata)?;
        let credential_id = CredentialId::parse(credential_id)
            .map_err(|_| LocalCredentialError::CorruptMetadata)?;
        if entries.insert(slot, credential_id).is_some() {
            return Err(LocalCredentialError::CorruptMetadata);
        }
    }
    Ok(entries)
}

fn auth_kind_to_str(kind: CredentialAuthKind) -> &'static str {
    match kind {
        CredentialAuthKind::OAuth => "oauth",
        CredentialAuthKind::ApiKey => "api_key",
        CredentialAuthKind::AccessToken => "access_token",
        CredentialAuthKind::GitHubApp => "github_app",
        CredentialAuthKind::SshPrivateKey => "ssh_private_key",
        CredentialAuthKind::SshAgent => "ssh_agent",
    }
}

fn parse_auth_kind(value: &str) -> Result<CredentialAuthKind, LocalCredentialError> {
    match value {
        "oauth" => Ok(CredentialAuthKind::OAuth),
        "api_key" => Ok(CredentialAuthKind::ApiKey),
        "access_token" => Ok(CredentialAuthKind::AccessToken),
        "github_app" => Ok(CredentialAuthKind::GitHubApp),
        "ssh_private_key" => Ok(CredentialAuthKind::SshPrivateKey),
        "ssh_agent" => Ok(CredentialAuthKind::SshAgent),
        _ => Err(LocalCredentialError::CorruptMetadata),
    }
}

fn status_to_str(status: CredentialStatus) -> &'static str {
    match status {
        CredentialStatus::Active => "active",
        CredentialStatus::Expired => "expired",
        CredentialStatus::RefreshFailed => "refresh_failed",
        CredentialStatus::Revoked => "revoked",
    }
}

fn parse_status(value: &str) -> Result<CredentialStatus, LocalCredentialError> {
    match value {
        "active" => Ok(CredentialStatus::Active),
        "expired" => Ok(CredentialStatus::Expired),
        "refresh_failed" => Ok(CredentialStatus::RefreshFailed),
        "revoked" => Ok(CredentialStatus::Revoked),
        _ => Err(LocalCredentialError::CorruptMetadata),
    }
}

fn persistence_to_str(persistence: ProtectedStorePersistence) -> &'static str {
    match persistence {
        ProtectedStorePersistence::OperatingSystem => "operating_system",
        ProtectedStorePersistence::ProcessLifetime => "process_lifetime",
    }
}

fn parse_persistence(value: &str) -> Result<ProtectedStorePersistence, LocalCredentialError> {
    match value {
        "operating_system" => Ok(ProtectedStorePersistence::OperatingSystem),
        "process_lifetime" => Ok(ProtectedStorePersistence::ProcessLifetime),
        _ => Err(LocalCredentialError::CorruptMetadata),
    }
}

fn optional_u64_to_i64(value: Option<u64>) -> Result<Option<i64>, LocalCredentialError> {
    value
        .map(|value| i64::try_from(value).map_err(|_| LocalCredentialError::InvalidTime))
        .transpose()
}

fn optional_i64_to_u64(value: Option<i64>) -> Result<Option<u64>, LocalCredentialError> {
    value
        .map(|value| u64::try_from(value).map_err(|_| LocalCredentialError::CorruptMetadata))
        .transpose()
}

fn unix_millis() -> Result<u64, LocalCredentialError> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| LocalCredentialError::InvalidTime)?
        .as_millis();
    u64::try_from(millis).map_err(|_| LocalCredentialError::InvalidTime)
}

fn unix_seconds() -> Result<u64, LocalCredentialError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| LocalCredentialError::InvalidTime)
}

fn database_error(_: rusqlite::Error) -> LocalCredentialError {
    LocalCredentialError::DatabaseUnavailable
}

fn map_insert_error(error: rusqlite::Error) -> LocalCredentialError {
    if error.sqlite_error_code() == Some(rusqlite::ErrorCode::ConstraintViolation) {
        LocalCredentialError::AlreadyExists
    } else {
        database_error(error)
    }
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum LocalCredentialError {
    #[error("local credential metadata path is not an owner-only directory or private file")]
    InvalidDatabasePath,
    #[error("local credential metadata database is unavailable")]
    DatabaseUnavailable,
    #[error("local credential authority is already running")]
    AlreadyRunning,
    #[error("local credential metadata database is invalid")]
    InvalidDatabase,
    #[error("local credential metadata schema is unsupported")]
    UnsupportedSchema,
    #[error("local credential metadata is corrupt")]
    CorruptMetadata,
    #[error("local credential authority owner does not match persisted metadata")]
    OwnerMismatch,
    #[error("local credential protected-store backend does not match persisted metadata")]
    ProtectedStoreMismatch,
    #[error("local credential operation is unsupported on this platform")]
    UnsupportedPlatform,
    #[error("local credential time value is invalid")]
    InvalidTime,
    #[error("a local credential or access profile with that name already exists")]
    AlreadyExists,
    #[error("local credential was not found")]
    CredentialNotFound,
    #[error("local credential is not available")]
    CredentialUnavailable,
    #[error("local credential is inactive")]
    CredentialInactive,
    #[error("local credential material is missing from protected storage")]
    CredentialMaterialMissing,
    #[error("local credential protected entry unexpectedly already exists")]
    ProtectedEntryCollision,
    #[error("local credential is selected by an access profile or environment")]
    CredentialInUse,
    #[error("local access profile was not found")]
    ProfileNotFound,
    #[error("local access profile revision was not found")]
    ProfileRevisionNotFound,
    #[error("local access profile revision changed")]
    StaleProfileRevision,
    #[error("local access profile is selected by an environment")]
    ProfileInUse,
    #[error("local environment access binding already exists")]
    EnvironmentBindingAlreadyExists,
    #[error("local environment access binding was not found")]
    EnvironmentBindingNotFound,
    #[error("local environment access binding changed")]
    StaleEnvironmentBinding,
    #[error(transparent)]
    Access(#[from] AccessError),
    #[error(transparent)]
    ProtectedStore(#[from] ProtectedStoreError),
}

#[cfg(test)]
mod rpc_tests;
#[cfg(test)]
mod tests;
