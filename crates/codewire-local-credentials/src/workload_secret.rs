//! Local workload-secret metadata and protected-value lifecycle.
//!
//! Values enter only as [`ProtectedValue`] and remain in the protected store.
//! SQLite contains stable IDs, keys, scope metadata, and exact cleanup journal
//! entries; public records and resolution previews never contain values or
//! protected-store references.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{
    DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _,
};
use std::path::{Path, PathBuf};

use codewire_protected_store::{
    ProtectedEntryId, ProtectedStore, ProtectedStorePersistence, ProtectedValue,
};
pub use codewire_workload_secrets::{ResolvedWorkloadSecretMetadata, WorkloadSecretSource};
use codewire_workload_secrets::{
    WorkloadSecretBinding, encode_workload_secrets, resolve_workload_secret_metadata,
    validate_workload_secret_value, workload_secret_delivery_relative_path,
};
use rusqlite::{Connection, OptionalExtension as _, params};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    JournalOperation, LOCAL_OWNER_ID, LocalCredentialAuthority, LocalCredentialError,
    MaterialState, database_error, map_insert_error, unix_millis,
};

const MAX_SECRET_KEY_BYTES: usize = 256;
const MAX_SECRET_PROJECT_NAME_BYTES: usize = 64;
const TMPFS_MAGIC: rustix::fs::FsWord = 0x0102_1994;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkloadSecretMetadata {
    pub key: String,
    pub created_at_unix_ms: u64,
    pub updated_at_unix_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalSecretProject {
    pub id: Uuid,
    pub name: String,
    pub secret_count: u64,
    pub created_at_unix_ms: u64,
    pub updated_at_unix_ms: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WorkloadSecretSelection {
    pub organization: bool,
    pub project: Option<String>,
    pub user: bool,
    pub explicit_environment_keys: BTreeSet<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkloadSecretDelivery {
    pub binding: Option<WorkloadSecretBinding>,
    pub metadata: Vec<ResolvedWorkloadSecretMetadata>,
}

pub(crate) struct ResolvedWorkloadSecrets {
    pub metadata: Vec<ResolvedWorkloadSecretMetadata>,
    pub values: BTreeMap<String, ProtectedValue>,
}

impl std::fmt::Debug for ResolvedWorkloadSecrets {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ResolvedWorkloadSecrets")
            .field("metadata", &self.metadata)
            .field("value_count", &self.values.len())
            .field("values", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SecretScope<'a> {
    User,
    Project(&'a Uuid),
}

impl SecretScope<'_> {
    fn kind(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Project(_) => "project",
        }
    }

    fn id(self) -> String {
        match self {
            Self::User => LOCAL_OWNER_ID.to_owned(),
            Self::Project(id) => id.to_string(),
        }
    }

    fn project_id(self) -> Option<String> {
        match self {
            Self::User => None,
            Self::Project(id) => Some(id.to_string()),
        }
    }
}

struct InternalWorkloadSecret {
    id: Uuid,
    metadata: WorkloadSecretMetadata,
    material_generation: u64,
    protected_entry_id: ProtectedEntryId,
    material_state: MaterialState,
}

struct WorkloadSecretJournal {
    operation: JournalOperation,
    protected_entry_id: ProtectedEntryId,
}

struct PendingDeliveryFile {
    path: PathBuf,
    device: u64,
    inode: u64,
    armed: bool,
}

impl PendingDeliveryFile {
    fn new(path: PathBuf, metadata: &fs::Metadata) -> Self {
        Self {
            path,
            device: metadata.dev(),
            inode: metadata.ino(),
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for PendingDeliveryFile {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let exact = fs::symlink_metadata(&self.path).is_ok_and(|metadata| {
            metadata.is_file()
                && !metadata.file_type().is_symlink()
                && metadata.uid() == rustix::process::geteuid().as_raw()
                && metadata.dev() == self.device
                && metadata.ino() == self.inode
                && metadata.nlink() == 1
                && metadata.permissions().mode() & 0o7777 == 0o400
        });
        if exact {
            let _ = fs::remove_file(&self.path);
        }
    }
}

impl<S: ProtectedStore> LocalCredentialAuthority<S> {
    pub fn create_secret_project(
        &self,
        name: &str,
    ) -> Result<LocalSecretProject, LocalCredentialError> {
        validate_project_name(name)?;
        let id = Uuid::new_v4();
        let now = unix_millis()?;
        let connection = self.connection()?;
        connection
            .execute(
                "INSERT INTO secret_projects(id, owner_id, name, created_at_unix_ms, updated_at_unix_ms)
                 VALUES (?1, ?2, ?3, ?4, ?4)",
                params![id.to_string(), LOCAL_OWNER_ID, name, to_i64(now)?],
            )
            .map_err(map_insert_error)?;
        load_project(&connection, &id)
    }

    pub fn list_secret_projects(&self) -> Result<Vec<LocalSecretProject>, LocalCredentialError> {
        let connection = self.connection()?;
        let mut statement = connection
            .prepare(
                "SELECT id FROM secret_projects WHERE owner_id = ?1
                 ORDER BY name COLLATE NOCASE, id",
            )
            .map_err(database_error)?;
        let ids = statement
            .query_map([LOCAL_OWNER_ID], |row| row.get::<_, String>(0))
            .map_err(database_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(database_error)?;
        ids.into_iter()
            .map(|id| {
                let id = parse_uuid(&id)?;
                load_project(&connection, &id)
            })
            .collect()
    }

    pub fn delete_secret_project(&self, id: Uuid) -> Result<(), LocalCredentialError> {
        let connection = self.connection()?;
        require_project(&connection, &id)?;
        let secret_ids = list_secret_ids(&connection, SecretScope::Project(&id))?;
        for secret_id in secret_ids {
            delete_secret_locked(self, &connection, secret_id)?;
        }
        let changed = connection
            .execute(
                "DELETE FROM secret_projects WHERE id = ?1 AND owner_id = ?2",
                params![id.to_string(), LOCAL_OWNER_ID],
            )
            .map_err(database_error)?;
        if changed != 1 {
            return Err(LocalCredentialError::SecretProjectNotFound);
        }
        Ok(())
    }

    pub fn list_user_workload_secrets(
        &self,
    ) -> Result<Vec<WorkloadSecretMetadata>, LocalCredentialError> {
        let connection = self.connection()?;
        list_secret_metadata(&connection, SecretScope::User)
    }

    pub fn set_user_workload_secret(
        &self,
        key: &str,
        value: ProtectedValue,
    ) -> Result<WorkloadSecretMetadata, LocalCredentialError> {
        let connection = self.connection()?;
        set_secret_locked(self, &connection, SecretScope::User, key, value)
    }

    pub fn delete_user_workload_secret(&self, key: &str) -> Result<(), LocalCredentialError> {
        let connection = self.connection()?;
        let secret = load_secret_by_key(&connection, SecretScope::User, key)?
            .ok_or(LocalCredentialError::WorkloadSecretNotFound)?;
        delete_secret_locked(self, &connection, secret.id)
    }

    pub fn rename_user_workload_secret(
        &self,
        key: &str,
        new_key: &str,
    ) -> Result<WorkloadSecretMetadata, LocalCredentialError> {
        let connection = self.connection()?;
        rename_secret_locked(&connection, SecretScope::User, key, new_key)
    }

    pub fn list_project_workload_secrets(
        &self,
        project_id: Uuid,
    ) -> Result<Vec<WorkloadSecretMetadata>, LocalCredentialError> {
        let connection = self.connection()?;
        require_project(&connection, &project_id)?;
        list_secret_metadata(&connection, SecretScope::Project(&project_id))
    }

    pub fn set_project_workload_secret(
        &self,
        project_id: Uuid,
        key: &str,
        value: ProtectedValue,
    ) -> Result<WorkloadSecretMetadata, LocalCredentialError> {
        let connection = self.connection()?;
        require_project(&connection, &project_id)?;
        set_secret_locked(
            self,
            &connection,
            SecretScope::Project(&project_id),
            key,
            value,
        )
    }

    pub fn delete_project_workload_secret(
        &self,
        project_id: Uuid,
        key: &str,
    ) -> Result<(), LocalCredentialError> {
        let connection = self.connection()?;
        require_project(&connection, &project_id)?;
        let secret = load_secret_by_key(&connection, SecretScope::Project(&project_id), key)?
            .ok_or(LocalCredentialError::WorkloadSecretNotFound)?;
        delete_secret_locked(self, &connection, secret.id)
    }

    pub fn rename_project_workload_secret(
        &self,
        project_id: Uuid,
        key: &str,
        new_key: &str,
    ) -> Result<WorkloadSecretMetadata, LocalCredentialError> {
        let connection = self.connection()?;
        require_project(&connection, &project_id)?;
        rename_secret_locked(&connection, SecretScope::Project(&project_id), key, new_key)
    }

    pub fn resolve_workload_secret_metadata(
        &self,
        selection: &WorkloadSecretSelection,
    ) -> Result<Vec<ResolvedWorkloadSecretMetadata>, LocalCredentialError> {
        Ok(self.resolve_workload_secrets(selection, false)?.metadata)
    }

    pub fn prepare_environment_workload_secrets(
        &self,
        selection: &WorkloadSecretSelection,
        environment_id: Uuid,
        environment_generation: u64,
        runtime_root: &Path,
    ) -> Result<WorkloadSecretDelivery, LocalCredentialError> {
        if environment_id.is_nil() || environment_generation == 0 {
            return Err(LocalCredentialError::InvalidWorkloadSecret);
        }
        validate_private_tmpfs_runtime(runtime_root)?;
        let resolved = self.resolve_workload_secrets(selection, true)?;
        if resolved.values.is_empty() {
            return Ok(WorkloadSecretDelivery {
                binding: None,
                metadata: resolved.metadata,
            });
        }
        let encoded = encode_workload_secrets(
            resolved
                .values
                .iter()
                .map(|(key, value)| (key.as_str(), value.expose_secret())),
        )
        .map_err(|_| LocalCredentialError::InvalidWorkloadSecret)?;
        let relative =
            workload_secret_delivery_relative_path(environment_id, environment_generation)
                .map_err(|_| LocalCredentialError::InvalidWorkloadSecret)?;
        let path = prepare_delivery_parent(runtime_root, &relative)?;
        let mut options = OpenOptions::new();
        options
            .write(true)
            .create_new(true)
            .mode(0o400)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let mut file = match options.open(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                validate_existing_delivery(&path, encoded.bytes())?;
                return Ok(WorkloadSecretDelivery {
                    binding: Some(encoded.binding()),
                    metadata: resolved.metadata,
                });
            }
            Err(_) => return Err(LocalCredentialError::WorkloadSecretDeliveryUnavailable),
        };
        let initial = file
            .metadata()
            .map_err(|_| LocalCredentialError::WorkloadSecretDeliveryUnavailable)?;
        let mut pending = PendingDeliveryFile::new(path, &initial);
        if !initial.is_file()
            || initial.uid() != rustix::process::geteuid().as_raw()
            || initial.permissions().mode() & 0o7777 != 0o400
            || initial.nlink() != 1
        {
            return Err(LocalCredentialError::WorkloadSecretDeliveryUnavailable);
        }
        file.write_all(encoded.bytes())
            .and_then(|()| file.sync_all())
            .map_err(|_| LocalCredentialError::WorkloadSecretDeliveryUnavailable)?;
        let metadata = file
            .metadata()
            .map_err(|_| LocalCredentialError::WorkloadSecretDeliveryUnavailable)?;
        if !metadata.is_file()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.permissions().mode() & 0o7777 != 0o400
            || metadata.nlink() != 1
            || metadata.len() != encoded.binding().total_bytes()
        {
            return Err(LocalCredentialError::WorkloadSecretDeliveryUnavailable);
        }
        pending.disarm();
        Ok(WorkloadSecretDelivery {
            binding: Some(encoded.binding()),
            metadata: resolved.metadata,
        })
    }

    pub(crate) fn resolve_workload_secrets(
        &self,
        selection: &WorkloadSecretSelection,
        include_values: bool,
    ) -> Result<ResolvedWorkloadSecrets, LocalCredentialError> {
        validate_selection(selection)?;
        if selection.organization {
            return Err(LocalCredentialError::OrganizationSecretsUnsupported);
        }
        let connection = self.connection()?;
        let mut metadata_sources = Vec::<(WorkloadSecretSource, String)>::new();
        let mut winners: BTreeMap<String, InternalWorkloadSecret> = BTreeMap::new();

        if let Some(project_name) = selection.project.as_deref() {
            let project = load_project_by_name(&connection, project_name)?
                .ok_or(LocalCredentialError::SecretProjectNotFound)?;
            for secret in list_internal_secrets(&connection, SecretScope::Project(&project.id))? {
                metadata_sources.push((WorkloadSecretSource::Project, secret.metadata.key.clone()));
                winners.insert(secret.metadata.key.clone(), secret);
            }
        }
        if selection.user {
            for secret in list_internal_secrets(&connection, SecretScope::User)? {
                metadata_sources.push((WorkloadSecretSource::User, secret.metadata.key.clone()));
                winners.insert(secret.metadata.key.clone(), secret);
            }
        }
        for key in &selection.explicit_environment_keys {
            metadata_sources.push((WorkloadSecretSource::ExplicitEnvironment, key.clone()));
            winners.remove(key);
        }

        let metadata = resolve_workload_secret_metadata(
            metadata_sources
                .iter()
                .map(|(source, key)| (*source, key.as_str())),
        )
        .map_err(|_| LocalCredentialError::InvalidWorkloadSecret)?;
        let mut values = BTreeMap::new();
        if include_values {
            for (key, secret) in winners {
                if secret.material_state != MaterialState::Ready {
                    return Err(LocalCredentialError::CorruptMetadata);
                }
                let value = self
                    .protected_store
                    .get(&secret.protected_entry_id)?
                    .ok_or(LocalCredentialError::WorkloadSecretMaterialMissing)?;
                validate_secret_value(value.expose_secret())?;
                values.insert(key, value);
            }
        }
        Ok(ResolvedWorkloadSecrets { metadata, values })
    }

    pub(crate) fn reconcile_workload_secrets(&self) -> Result<(), LocalCredentialError> {
        let connection = self.connection()?;
        let mut statement = connection
            .prepare("SELECT id FROM workload_secrets ORDER BY id")
            .map_err(database_error)?;
        let ids = statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(database_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(database_error)?;
        drop(statement);
        for id in ids {
            reconcile_secret(self, &connection, parse_uuid(&id)?)?;
        }
        Ok(())
    }
}

fn set_secret_locked<S: ProtectedStore>(
    authority: &LocalCredentialAuthority<S>,
    connection: &Connection,
    scope: SecretScope<'_>,
    key: &str,
    value: ProtectedValue,
) -> Result<WorkloadSecretMetadata, LocalCredentialError> {
    validate_secret_key(key)?;
    validate_secret_value(value.expose_secret())?;
    let now = unix_millis()?;
    match load_secret_by_key(connection, scope, key)? {
        None => {
            let id = Uuid::new_v4();
            let entry = secret_entry_id(id, 1)?;
            ensure_entry_absent(authority, &entry)?;
            let transaction = connection.unchecked_transaction().map_err(database_error)?;
            transaction
                .execute(
                    "INSERT INTO workload_secrets(
                       id, scope_kind, scope_id, project_id, key, material_generation,
                       protected_entry_id, material_state, created_at_unix_ms, updated_at_unix_ms
                     ) VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6, 'pending_write', ?7, ?7)",
                    params![
                        id.to_string(),
                        scope.kind(),
                        scope.id(),
                        scope.project_id(),
                        key,
                        entry.expose_reference(),
                        to_i64(now)?,
                    ],
                )
                .map_err(map_insert_error)?;
            insert_journal(
                &transaction,
                id,
                JournalOperation::RollbackWrite,
                &entry,
                now,
            )?;
            transaction.commit().map_err(database_error)?;
            authority.protected_store.put(&entry, &value)?;
            let transaction = connection.unchecked_transaction().map_err(database_error)?;
            let changed = transaction
                .execute(
                    "UPDATE workload_secrets SET material_state = 'ready', updated_at_unix_ms = ?2
                     WHERE id = ?1 AND material_state = 'pending_write'",
                    params![id.to_string(), to_i64(unix_millis()?)?],
                )
                .map_err(database_error)?;
            delete_journal(&transaction, id, JournalOperation::RollbackWrite, &entry)?;
            if changed != 1 {
                return Err(LocalCredentialError::CorruptMetadata);
            }
            transaction.commit().map_err(database_error)?;
            Ok(load_secret_by_id(connection, id)?.metadata)
        }
        Some(current) => {
            if current.material_state != MaterialState::Ready {
                return Err(LocalCredentialError::CorruptMetadata);
            }
            let next_generation = current
                .material_generation
                .checked_add(1)
                .ok_or(LocalCredentialError::CorruptMetadata)?;
            let next_entry = secret_entry_id(current.id, next_generation)?;
            ensure_entry_absent(authority, &next_entry)?;
            insert_journal(
                connection,
                current.id,
                JournalOperation::RollbackWrite,
                &next_entry,
                now,
            )?;
            authority.protected_store.put(&next_entry, &value)?;
            let transaction = connection.unchecked_transaction().map_err(database_error)?;
            let changed = transaction
                .execute(
                    "UPDATE workload_secrets
                     SET material_generation = ?2, protected_entry_id = ?3, updated_at_unix_ms = ?4
                     WHERE id = ?1 AND material_generation = ?5 AND protected_entry_id = ?6
                       AND material_state = 'ready'",
                    params![
                        current.id.to_string(),
                        to_i64(next_generation)?,
                        next_entry.expose_reference(),
                        to_i64(unix_millis()?)?,
                        to_i64(current.material_generation)?,
                        current.protected_entry_id.expose_reference(),
                    ],
                )
                .map_err(database_error)?;
            let journal_changed = transaction
                .execute(
                    "UPDATE workload_secret_journal
                     SET operation = 'delete_retired', protected_entry_id = ?2
                     WHERE secret_id = ?1 AND operation = 'rollback_write' AND protected_entry_id = ?3",
                    params![
                        current.id.to_string(),
                        current.protected_entry_id.expose_reference(),
                        next_entry.expose_reference(),
                    ],
                )
                .map_err(database_error)?;
            if changed != 1 || journal_changed != 1 {
                return Err(LocalCredentialError::CorruptMetadata);
            }
            transaction.commit().map_err(database_error)?;
            authority
                .protected_store
                .delete(&current.protected_entry_id)?;
            delete_journal(
                connection,
                current.id,
                JournalOperation::DeleteRetired,
                &current.protected_entry_id,
            )?;
            Ok(load_secret_by_id(connection, current.id)?.metadata)
        }
    }
}

fn delete_secret_locked<S: ProtectedStore>(
    authority: &LocalCredentialAuthority<S>,
    connection: &Connection,
    id: Uuid,
) -> Result<(), LocalCredentialError> {
    let current = load_secret_by_id(connection, id)?;
    if current.material_state != MaterialState::Ready {
        return Err(LocalCredentialError::CorruptMetadata);
    }
    let transaction = connection.unchecked_transaction().map_err(database_error)?;
    let changed = transaction
        .execute(
            "UPDATE workload_secrets SET material_state = 'pending_delete', updated_at_unix_ms = ?2
             WHERE id = ?1 AND material_state = 'ready'",
            params![id.to_string(), to_i64(unix_millis()?)?],
        )
        .map_err(database_error)?;
    insert_journal(
        &transaction,
        id,
        JournalOperation::DeleteRetired,
        &current.protected_entry_id,
        unix_millis()?,
    )?;
    if changed != 1 {
        return Err(LocalCredentialError::CorruptMetadata);
    }
    transaction.commit().map_err(database_error)?;
    authority
        .protected_store
        .delete(&current.protected_entry_id)?;
    let changed = connection
        .execute(
            "DELETE FROM workload_secrets WHERE id = ?1",
            [id.to_string()],
        )
        .map_err(database_error)?;
    if changed != 1 {
        return Err(LocalCredentialError::CorruptMetadata);
    }
    Ok(())
}

fn rename_secret_locked(
    connection: &Connection,
    scope: SecretScope<'_>,
    key: &str,
    new_key: &str,
) -> Result<WorkloadSecretMetadata, LocalCredentialError> {
    validate_secret_key(key)?;
    validate_secret_key(new_key)?;
    let current = load_secret_by_key(connection, scope, key)?
        .ok_or(LocalCredentialError::WorkloadSecretNotFound)?;
    if current.material_state != MaterialState::Ready {
        return Err(LocalCredentialError::CorruptMetadata);
    }
    let changed = connection
        .execute(
            "UPDATE workload_secrets SET key = ?2, updated_at_unix_ms = ?3
             WHERE id = ?1 AND material_state = 'ready'",
            params![current.id.to_string(), new_key, to_i64(unix_millis()?)?],
        )
        .map_err(map_insert_error)?;
    if changed != 1 {
        return Err(LocalCredentialError::WorkloadSecretNotFound);
    }
    Ok(load_secret_by_id(connection, current.id)?.metadata)
}

fn reconcile_secret<S: ProtectedStore>(
    authority: &LocalCredentialAuthority<S>,
    connection: &Connection,
    id: Uuid,
) -> Result<(), LocalCredentialError> {
    let current = load_secret_by_id(connection, id)?;
    let journal = load_journal(connection, id)?;
    match (current.material_state, journal) {
        (MaterialState::Ready, None) => {
            if authority
                .protected_store
                .get(&current.protected_entry_id)?
                .is_none()
            {
                if authority.protected_store.persistence()
                    == ProtectedStorePersistence::ProcessLifetime
                {
                    connection
                        .execute(
                            "DELETE FROM workload_secrets WHERE id = ?1",
                            [id.to_string()],
                        )
                        .map_err(database_error)?;
                } else {
                    return Err(LocalCredentialError::WorkloadSecretMaterialMissing);
                }
            }
        }
        (MaterialState::PendingWrite, Some(journal))
            if journal.operation == JournalOperation::RollbackWrite
                && journal.protected_entry_id == current.protected_entry_id =>
        {
            authority
                .protected_store
                .delete(&journal.protected_entry_id)?;
            connection
                .execute(
                    "DELETE FROM workload_secrets WHERE id = ?1",
                    [id.to_string()],
                )
                .map_err(database_error)?;
        }
        (MaterialState::Ready, Some(journal))
            if journal.operation == JournalOperation::RollbackWrite
                && journal.protected_entry_id != current.protected_entry_id =>
        {
            authority
                .protected_store
                .delete(&journal.protected_entry_id)?;
            delete_journal(
                connection,
                id,
                JournalOperation::RollbackWrite,
                &journal.protected_entry_id,
            )?;
        }
        (MaterialState::Ready, Some(journal))
            if journal.operation == JournalOperation::DeleteRetired
                && journal.protected_entry_id != current.protected_entry_id =>
        {
            authority
                .protected_store
                .delete(&journal.protected_entry_id)?;
            delete_journal(
                connection,
                id,
                JournalOperation::DeleteRetired,
                &journal.protected_entry_id,
            )?;
        }
        (MaterialState::PendingDelete, Some(journal))
            if journal.operation == JournalOperation::DeleteRetired
                && journal.protected_entry_id == current.protected_entry_id =>
        {
            authority
                .protected_store
                .delete(&journal.protected_entry_id)?;
            connection
                .execute(
                    "DELETE FROM workload_secrets WHERE id = ?1",
                    [id.to_string()],
                )
                .map_err(database_error)?;
        }
        _ => return Err(LocalCredentialError::CorruptMetadata),
    }
    Ok(())
}

fn load_project(
    connection: &Connection,
    id: &Uuid,
) -> Result<LocalSecretProject, LocalCredentialError> {
    connection
        .query_row(
            "SELECT p.name, p.created_at_unix_ms, p.updated_at_unix_ms,
                    (SELECT COUNT(*) FROM workload_secrets s
                     WHERE s.scope_kind = 'project' AND s.scope_id = p.id AND s.material_state = 'ready')
             FROM secret_projects p WHERE p.id = ?1 AND p.owner_id = ?2",
            params![id.to_string(), LOCAL_OWNER_ID],
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
        .ok_or(LocalCredentialError::SecretProjectNotFound)
        .and_then(|(name, created, updated, count)| {
            Ok(LocalSecretProject {
                id: *id,
                name,
                secret_count: from_i64(count)?,
                created_at_unix_ms: from_i64(created)?,
                updated_at_unix_ms: from_i64(updated)?,
            })
        })
}

fn load_project_by_name(
    connection: &Connection,
    name: &str,
) -> Result<Option<LocalSecretProject>, LocalCredentialError> {
    validate_project_name(name)?;
    let id = connection
        .query_row(
            "SELECT id FROM secret_projects WHERE owner_id = ?1 AND name = ?2 COLLATE NOCASE",
            params![LOCAL_OWNER_ID, name],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(database_error)?;
    id.map(|id| load_project(connection, &parse_uuid(&id)?))
        .transpose()
}

fn require_project(connection: &Connection, id: &Uuid) -> Result<(), LocalCredentialError> {
    load_project(connection, id).map(|_| ())
}

fn list_secret_metadata(
    connection: &Connection,
    scope: SecretScope<'_>,
) -> Result<Vec<WorkloadSecretMetadata>, LocalCredentialError> {
    Ok(list_internal_secrets(connection, scope)?
        .into_iter()
        .map(|secret| secret.metadata)
        .collect())
}

fn list_internal_secrets(
    connection: &Connection,
    scope: SecretScope<'_>,
) -> Result<Vec<InternalWorkloadSecret>, LocalCredentialError> {
    let mut statement = connection
        .prepare(
            "SELECT id FROM workload_secrets
             WHERE scope_kind = ?1 AND scope_id = ?2 AND material_state = 'ready'
             ORDER BY key, id",
        )
        .map_err(database_error)?;
    let ids = statement
        .query_map(params![scope.kind(), scope.id()], |row| {
            row.get::<_, String>(0)
        })
        .map_err(database_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(database_error)?;
    ids.into_iter()
        .map(|id| load_secret_by_id(connection, parse_uuid(&id)?))
        .collect()
}

fn list_secret_ids(
    connection: &Connection,
    scope: SecretScope<'_>,
) -> Result<Vec<Uuid>, LocalCredentialError> {
    let mut statement = connection
        .prepare(
            "SELECT id FROM workload_secrets WHERE scope_kind = ?1 AND scope_id = ?2 ORDER BY id",
        )
        .map_err(database_error)?;
    statement
        .query_map(params![scope.kind(), scope.id()], |row| {
            row.get::<_, String>(0)
        })
        .map_err(database_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(database_error)?
        .into_iter()
        .map(|id| parse_uuid(&id))
        .collect()
}

fn load_secret_by_key(
    connection: &Connection,
    scope: SecretScope<'_>,
    key: &str,
) -> Result<Option<InternalWorkloadSecret>, LocalCredentialError> {
    validate_secret_key(key)?;
    let id = connection
        .query_row(
            "SELECT id FROM workload_secrets WHERE scope_kind = ?1 AND scope_id = ?2 AND key = ?3",
            params![scope.kind(), scope.id(), key],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(database_error)?;
    id.map(|id| load_secret_by_id(connection, parse_uuid(&id)?))
        .transpose()
}

fn load_secret_by_id(
    connection: &Connection,
    id: Uuid,
) -> Result<InternalWorkloadSecret, LocalCredentialError> {
    let row = connection
        .query_row(
            "SELECT key, material_generation, protected_entry_id, material_state,
                    created_at_unix_ms, updated_at_unix_ms
             FROM workload_secrets WHERE id = ?1",
            [id.to_string()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            },
        )
        .optional()
        .map_err(database_error)?
        .ok_or(LocalCredentialError::WorkloadSecretNotFound)?;
    validate_secret_key(&row.0)?;
    let generation = from_i64(row.1)?;
    let entry = ProtectedEntryId::parse(row.2)?;
    if entry != secret_entry_id(id, generation)? {
        return Err(LocalCredentialError::CorruptMetadata);
    }
    Ok(InternalWorkloadSecret {
        id,
        metadata: WorkloadSecretMetadata {
            key: row.0,
            created_at_unix_ms: from_i64(row.4)?,
            updated_at_unix_ms: from_i64(row.5)?,
        },
        material_generation: generation,
        protected_entry_id: entry,
        material_state: MaterialState::parse(&row.3)?,
    })
}

fn insert_journal(
    connection: &Connection,
    id: Uuid,
    operation: JournalOperation,
    entry: &ProtectedEntryId,
    now: u64,
) -> Result<(), LocalCredentialError> {
    let changed = connection
        .execute(
            "INSERT INTO workload_secret_journal(secret_id, operation, protected_entry_id, created_at_unix_ms)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                id.to_string(),
                operation.as_str(),
                entry.expose_reference(),
                to_i64(now)?,
            ],
        )
        .map_err(database_error)?;
    if changed != 1 {
        return Err(LocalCredentialError::CorruptMetadata);
    }
    Ok(())
}

fn load_journal(
    connection: &Connection,
    id: Uuid,
) -> Result<Option<WorkloadSecretJournal>, LocalCredentialError> {
    connection
        .query_row(
            "SELECT operation, protected_entry_id FROM workload_secret_journal WHERE secret_id = ?1",
            [id.to_string()],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()
        .map_err(database_error)?
        .map(|(operation, entry)| {
            Ok(WorkloadSecretJournal {
                operation: JournalOperation::parse(&operation)?,
                protected_entry_id: ProtectedEntryId::parse(entry)?,
            })
        })
        .transpose()
}

fn delete_journal(
    connection: &Connection,
    id: Uuid,
    operation: JournalOperation,
    entry: &ProtectedEntryId,
) -> Result<(), LocalCredentialError> {
    let changed = connection
        .execute(
            "DELETE FROM workload_secret_journal
             WHERE secret_id = ?1 AND operation = ?2 AND protected_entry_id = ?3",
            params![id.to_string(), operation.as_str(), entry.expose_reference()],
        )
        .map_err(database_error)?;
    if changed != 1 {
        return Err(LocalCredentialError::CorruptMetadata);
    }
    Ok(())
}

fn ensure_entry_absent<S: ProtectedStore>(
    authority: &LocalCredentialAuthority<S>,
    entry: &ProtectedEntryId,
) -> Result<(), LocalCredentialError> {
    if authority.protected_store.get(entry)?.is_some() {
        return Err(LocalCredentialError::ProtectedEntryCollision);
    }
    Ok(())
}

fn secret_entry_id(id: Uuid, generation: u64) -> Result<ProtectedEntryId, LocalCredentialError> {
    Ok(ProtectedEntryId::parse(format!(
        "local/workload-secrets/{id}/material-v{generation}"
    ))?)
}

fn validate_selection(selection: &WorkloadSecretSelection) -> Result<(), LocalCredentialError> {
    if let Some(project) = &selection.project {
        validate_project_name(project)?;
    }
    for key in &selection.explicit_environment_keys {
        validate_secret_key(key)?;
    }
    Ok(())
}

fn validate_project_name(name: &str) -> Result<(), LocalCredentialError> {
    let mut bytes = name.bytes();
    if name.is_empty()
        || name.len() > MAX_SECRET_PROJECT_NAME_BYTES
        || !bytes
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        || !bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(LocalCredentialError::InvalidWorkloadSecret);
    }
    Ok(())
}

fn validate_secret_key(key: &str) -> Result<(), LocalCredentialError> {
    let mut bytes = key.bytes();
    if key.is_empty()
        || key.len() > MAX_SECRET_KEY_BYTES
        || !bytes
            .next()
            .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        || !bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(LocalCredentialError::InvalidWorkloadSecret);
    }
    Ok(())
}

fn validate_secret_value(value: &[u8]) -> Result<(), LocalCredentialError> {
    validate_workload_secret_value(value).map_err(|_| LocalCredentialError::InvalidWorkloadSecret)
}

fn parse_uuid(value: &str) -> Result<Uuid, LocalCredentialError> {
    let id = Uuid::parse_str(value).map_err(|_| LocalCredentialError::CorruptMetadata)?;
    if id.is_nil() || id.to_string() != value {
        return Err(LocalCredentialError::CorruptMetadata);
    }
    Ok(id)
}

fn to_i64(value: u64) -> Result<i64, LocalCredentialError> {
    i64::try_from(value).map_err(|_| LocalCredentialError::InvalidTime)
}

fn from_i64(value: i64) -> Result<u64, LocalCredentialError> {
    u64::try_from(value).map_err(|_| LocalCredentialError::CorruptMetadata)
}

fn validate_private_tmpfs_runtime(path: &Path) -> Result<(), LocalCredentialError> {
    if !path.is_absolute()
        || path.components().any(|component| {
            !matches!(
                component,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        })
    {
        return Err(LocalCredentialError::WorkloadSecretDeliveryUnavailable);
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| LocalCredentialError::WorkloadSecretDeliveryUnavailable)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o077 != 0
        || fs::canonicalize(path)
            .map_err(|_| LocalCredentialError::WorkloadSecretDeliveryUnavailable)?
            != path
    {
        return Err(LocalCredentialError::WorkloadSecretDeliveryUnavailable);
    }
    let directory =
        File::open(path).map_err(|_| LocalCredentialError::WorkloadSecretDeliveryUnavailable)?;
    if rustix::fs::fstatfs(&directory)
        .map_err(|_| LocalCredentialError::WorkloadSecretDeliveryUnavailable)?
        .f_type
        != TMPFS_MAGIC
    {
        return Err(LocalCredentialError::WorkloadSecretDeliveryUnavailable);
    }
    Ok(())
}

fn prepare_delivery_parent(
    runtime_root: &Path,
    relative: &Path,
) -> Result<PathBuf, LocalCredentialError> {
    let parent = relative
        .parent()
        .ok_or(LocalCredentialError::WorkloadSecretDeliveryUnavailable)?;
    let mut current = runtime_root.to_owned();
    for component in parent.components() {
        let std::path::Component::Normal(component) = component else {
            return Err(LocalCredentialError::WorkloadSecretDeliveryUnavailable);
        };
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                DirBuilder::new()
                    .mode(0o700)
                    .create(&current)
                    .map_err(|_| LocalCredentialError::WorkloadSecretDeliveryUnavailable)?;
            }
            Err(_) => return Err(LocalCredentialError::WorkloadSecretDeliveryUnavailable),
        }
        let metadata = fs::symlink_metadata(&current)
            .map_err(|_| LocalCredentialError::WorkloadSecretDeliveryUnavailable)?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.permissions().mode() & 0o7777 != 0o700
        {
            return Err(LocalCredentialError::WorkloadSecretDeliveryUnavailable);
        }
    }
    Ok(runtime_root.join(relative))
}

fn validate_existing_delivery(path: &Path, expected: &[u8]) -> Result<(), LocalCredentialError> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let mut file = options
        .open(path)
        .map_err(|_| LocalCredentialError::WorkloadSecretDeliveryUnavailable)?;
    let metadata = file
        .metadata()
        .map_err(|_| LocalCredentialError::WorkloadSecretDeliveryUnavailable)?;
    if !metadata.is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o7777 != 0o400
        || metadata.nlink() != 1
        || metadata.len() != expected.len() as u64
        || rustix::fs::fstatfs(&file)
            .map_err(|_| LocalCredentialError::WorkloadSecretDeliveryUnavailable)?
            .f_type
            != TMPFS_MAGIC
    {
        return Err(LocalCredentialError::WorkloadSecretDeliveryUnavailable);
    }
    let mut actual = Zeroizing::new(vec![0_u8; expected.len()]);
    file.read_exact(&mut actual)
        .map_err(|_| LocalCredentialError::WorkloadSecretDeliveryUnavailable)?;
    if actual.as_slice() != expected {
        return Err(LocalCredentialError::WorkloadSecretDeliveryUnavailable);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;

    use codewire_access::builtin_provider_catalog;
    use codewire_protected_store::EphemeralProtectedStore;
    use tempfile::TempDir;

    use super::*;

    fn authority_root(temp: &TempDir) -> std::path::PathBuf {
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        temp.path().join("authority")
    }

    fn value(value: &str) -> ProtectedValue {
        ProtectedValue::from_slice(value.as_bytes()).unwrap()
    }

    #[test]
    fn local_workload_secret_crud_returns_metadata_only() {
        let temp = TempDir::new().unwrap();
        let authority = LocalCredentialAuthority::open(
            &authority_root(&temp),
            EphemeralProtectedStore::default(),
            builtin_provider_catalog(),
        )
        .unwrap();

        let created = authority
            .set_user_workload_secret("DATABASE_URL", value("synthetic-user-one"))
            .unwrap();
        assert_eq!(created.key, "DATABASE_URL");
        assert_eq!(
            authority.list_user_workload_secrets().unwrap(),
            vec![created.clone()]
        );

        let rotated = authority
            .set_user_workload_secret("DATABASE_URL", value("synthetic-user-two"))
            .unwrap();
        assert_eq!(rotated.created_at_unix_ms, created.created_at_unix_ms);
        assert!(rotated.updated_at_unix_ms >= created.updated_at_unix_ms);
        let renamed = authority
            .rename_user_workload_secret("DATABASE_URL", "DATABASE_DSN")
            .unwrap();
        assert_eq!(renamed.key, "DATABASE_DSN");
        authority
            .delete_user_workload_secret("DATABASE_DSN")
            .unwrap();
        assert!(authority.list_user_workload_secrets().unwrap().is_empty());
    }

    #[test]
    fn project_user_and_explicit_environment_overlay_is_deterministic() {
        let temp = TempDir::new().unwrap();
        let authority = LocalCredentialAuthority::open(
            &authority_root(&temp),
            EphemeralProtectedStore::default(),
            builtin_provider_catalog(),
        )
        .unwrap();
        let project = authority.create_secret_project("development").unwrap();
        authority
            .set_project_workload_secret(project.id, "PROJECT_ONLY", value("project"))
            .unwrap();
        authority
            .set_project_workload_secret(project.id, "SHARED", value("project-shared"))
            .unwrap();
        authority
            .set_user_workload_secret("SHARED", value("user-shared"))
            .unwrap();
        authority
            .set_user_workload_secret("EXPLICIT", value("user-explicit"))
            .unwrap();

        let selection = WorkloadSecretSelection {
            organization: false,
            project: Some("development".into()),
            user: true,
            explicit_environment_keys: BTreeSet::from(["EXPLICIT".into()]),
        };
        let resolved = authority
            .resolve_workload_secrets(&selection, true)
            .unwrap();
        assert_eq!(
            resolved.metadata,
            vec![
                ResolvedWorkloadSecretMetadata {
                    key: "EXPLICIT".into(),
                    source: WorkloadSecretSource::ExplicitEnvironment,
                    overridden_sources: vec![WorkloadSecretSource::User],
                },
                ResolvedWorkloadSecretMetadata {
                    key: "PROJECT_ONLY".into(),
                    source: WorkloadSecretSource::Project,
                    overridden_sources: vec![],
                },
                ResolvedWorkloadSecretMetadata {
                    key: "SHARED".into(),
                    source: WorkloadSecretSource::User,
                    overridden_sources: vec![WorkloadSecretSource::Project],
                },
            ]
        );
        assert_eq!(
            resolved.values.get("SHARED").unwrap().expose_secret(),
            b"user-shared"
        );
        assert!(!resolved.values.contains_key("EXPLICIT"));
        assert_eq!(format!("{resolved:?}").matches("synthetic").count(), 0);
    }

    #[test]
    fn organization_selection_is_typed_unsupported_and_missing_selection_loads_nothing() {
        let temp = TempDir::new().unwrap();
        let authority = LocalCredentialAuthority::open(
            &authority_root(&temp),
            EphemeralProtectedStore::default(),
            builtin_provider_catalog(),
        )
        .unwrap();
        authority
            .set_user_workload_secret("TOKEN", value("synthetic"))
            .unwrap();
        assert!(
            authority
                .resolve_workload_secret_metadata(&WorkloadSecretSelection::default())
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            authority.resolve_workload_secret_metadata(&WorkloadSecretSelection {
                organization: true,
                ..WorkloadSecretSelection::default()
            }),
            Err(LocalCredentialError::OrganizationSecretsUnsupported)
        );
    }

    #[test]
    fn process_lifetime_secret_metadata_is_removed_after_store_loss() {
        let temp = TempDir::new().unwrap();
        let root = authority_root(&temp);
        let authority = LocalCredentialAuthority::open(
            &root,
            EphemeralProtectedStore::default(),
            builtin_provider_catalog(),
        )
        .unwrap();
        authority
            .set_user_workload_secret("EPHEMERAL", value("synthetic"))
            .unwrap();
        drop(authority);

        let reopened = LocalCredentialAuthority::open(
            &root,
            EphemeralProtectedStore::default(),
            builtin_provider_catalog(),
        )
        .unwrap();
        assert!(reopened.list_user_workload_secrets().unwrap().is_empty());
    }
}
