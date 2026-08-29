//! Durable, owner-only state for the native local supervisor.
//!
//! SQLite is the authority after a preview `state.json` has been imported.
//! The supervisor singleton is the only writer, but WAL and explicit replay
//! records keep every lifecycle transition recoverable across process death.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::io::{self, Read as _};
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rusqlite::config::DbConfig;
use rusqlite::{
    Connection, OpenFlags, OptionalExtension as _, Transaction, TransactionBehavior, params,
};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::linux::path::{PathError, PrivateRoot};
use crate::supervisor::{EnvironmentRecord, RunnerRecord, StoredEnvironmentState, SupervisorState};

pub(crate) const DATABASE_FILE: &str = "supervisor.db";
const DATABASE_WAL_FILE: &str = "supervisor.db-wal";
const DATABASE_SHM_FILE: &str = "supervisor.db-shm";
const LEGACY_STATE_FILE: &str = "state.json";
const LEGACY_ARCHIVE_FILE: &str = "state.v1.imported.json";
const DATABASE_APPLICATION_ID: i64 = 0x4357_564d; // "CWVM"
const DATABASE_SCHEMA_VERSION: i64 = 1;
const MAXIMUM_STATE_BYTES: u64 = 1024 * 1024;
const MAXIMUM_OPERATION_BYTES: usize = 64 * 1024;
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OperationKind {
    Create,
    Start,
    Stop,
    Restart,
    Delete,
    GrowDisk,
    Reconcile,
}

impl OperationKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Start => "start",
            Self::Stop => "stop",
            Self::Restart => "restart",
            Self::Delete => "delete",
            Self::GrowDisk => "grow_disk",
            Self::Reconcile => "reconcile",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "create" => Some(Self::Create),
            "start" => Some(Self::Start),
            "stop" => Some(Self::Stop),
            "restart" => Some(Self::Restart),
            "delete" => Some(Self::Delete),
            "grow_disk" => Some(Self::GrowDisk),
            "reconcile" => Some(Self::Reconcile),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OperationPhase {
    Intent,
    EffectApplied,
    Completed,
    Failed,
    Interrupted,
}

impl OperationPhase {
    fn as_str(self) -> &'static str {
        match self {
            Self::Intent => "intent",
            Self::EffectApplied => "effect_applied",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Interrupted => "interrupted",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "intent" => Some(Self::Intent),
            "effect_applied" => Some(Self::EffectApplied),
            "completed" => Some(Self::Completed),
            "failed" => Some(Self::Failed),
            "interrupted" => Some(Self::Interrupted),
            _ => None,
        }
    }

    fn terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Interrupted)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct OperationRecord {
    pub(crate) operation_id: Uuid,
    pub(crate) request_id: Uuid,
    pub(crate) environment_id: Option<Uuid>,
    pub(crate) kind: OperationKind,
    pub(crate) phase: OperationPhase,
    pub(crate) checkpoint: u32,
    pub(crate) payload: serde_json::Value,
    pub(crate) result: Option<serde_json::Value>,
    pub(crate) error_code: Option<String>,
}

pub(crate) struct SupervisorStore {
    connection: Connection,
    root: PathBuf,
}

impl std::fmt::Debug for SupervisorStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SupervisorStore")
            .field("root", &self.root)
            .finish_non_exhaustive()
    }
}

impl SupervisorStore {
    pub(crate) fn open(
        root: &PrivateRoot,
    ) -> Result<(Self, SupervisorState), SupervisorStoreError> {
        let boot_id = current_boot_id()?;
        Self::open_for_boot(root, &boot_id)
    }

    pub(crate) fn inspect(
        root: &PrivateRoot,
    ) -> Result<(Option<Self>, SupervisorState), SupervisorStoreError> {
        let relative = Path::new(DATABASE_FILE);
        let opened = match root.open_regular(relative, false, None, false, Some(0o600)) {
            Ok(opened) => opened,
            Err(error) if path_error_is_not_found(&error) => {
                let legacy = read_legacy_state(root)?
                    .map(|(state, _)| state)
                    .unwrap_or_default();
                return Ok((None, legacy));
            }
            Err(error) => return Err(error.into()),
        };
        let identity = opened.identity().clone();
        drop(opened);
        let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        let connection = Connection::open_with_flags(root.path().join(relative), flags)?;
        connection.busy_timeout(BUSY_TIMEOUT)?;
        connection.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)?;
        connection.pragma_update(None, "foreign_keys", true)?;
        connection.pragma_update(None, "trusted_schema", false)?;
        validate_schema(&connection)?;
        validate_database(&connection)?;
        let reopened = root.open_regular(relative, false, None, false, Some(0o600))?;
        if reopened.identity() != &identity {
            return Err(SupervisorStoreError::DatabaseIdentityChanged);
        }
        validate_database_files(root, false)?;
        let store = Self {
            connection,
            root: root.path().to_owned(),
        };
        let state = store.load_state()?;
        Ok((Some(store), state))
    }

    fn open_for_boot(
        root: &PrivateRoot,
        boot_id: &str,
    ) -> Result<(Self, SupervisorState), SupervisorStoreError> {
        validate_boot_id(boot_id)?;
        let (connection, initialize) = open_database(root)?;
        configure_connection(&connection)?;
        if initialize {
            initialize_schema(&connection)?;
        } else {
            validate_schema(&connection)?;
        }
        validate_database(&connection)?;

        let store = Self {
            connection,
            root: root.path().to_owned(),
        };
        store.ensure_metadata(boot_id)?;
        let mut state = store.load_state()?;
        let mut changed_for_boot = false;

        if let Some((mut legacy, bytes)) = read_legacy_state(root)? {
            let digest = sha256_hex(&bytes);
            match store.legacy_import_digest()? {
                Some(imported) if imported == digest => {}
                Some(_) => return Err(SupervisorStoreError::LegacyStateChanged),
                None if state.environments.is_empty() => {
                    changed_for_boot = normalize_imported_state(&mut legacy, boot_id);
                    store.import_legacy_state(&legacy, &digest)?;
                }
                None => return Err(SupervisorStoreError::UntrackedLegacyState),
            }
            finish_legacy_archive(root, &bytes, &digest)?;
            // Re-read the committed representation rather than trusting the
            // import input after its authoritative handoff.
            state = store.load_state()?;
        } else if legacy_archive_exists(root)? && store.legacy_import_digest()?.is_none() {
            return Err(SupervisorStoreError::UntrackedLegacyArchive);
        }

        if store.reconcile_host_boot(boot_id)? {
            changed_for_boot = true;
            state = store.load_state()?;
        }
        if changed_for_boot {
            state
                .validate()
                .map_err(|_| SupervisorStoreError::InvalidState)?;
        }
        validate_database_files(root, true)?;
        Ok((store, state))
    }

    pub(crate) fn replace_state(
        &self,
        state: &SupervisorState,
    ) -> Result<(), SupervisorStoreError> {
        state
            .validate()
            .map_err(|_| SupervisorStoreError::InvalidState)?;
        let transaction = self.connection.unchecked_transaction()?;
        write_state(&transaction, state)?;
        transaction.commit()?;
        validate_database_files(&PrivateRoot::open(&self.root)?, true)?;
        Ok(())
    }

    pub(crate) fn begin_operation(
        &self,
        request_id: Uuid,
        environment_id: Option<Uuid>,
        kind: OperationKind,
        payload: &serde_json::Value,
    ) -> Result<OperationRecord, SupervisorStoreError> {
        validate_non_nil(request_id)?;
        if let Some(environment_id) = environment_id {
            validate_non_nil(environment_id)?;
        }
        let payload_bytes = encode_operation_json(payload)?;
        let operation_id = Uuid::new_v4();
        let now = unix_millis()?;
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        transaction.execute(
            "INSERT OR IGNORE INTO operations(
               operation_id, request_id, environment_id, kind, phase, checkpoint,
               payload_json, result_json, error_code, created_unix_ms, updated_unix_ms
             ) VALUES (?1, ?2, ?3, ?4, 'intent', 0, ?5, NULL, NULL, ?6, ?6)",
            params![
                operation_id.to_string(),
                request_id.to_string(),
                environment_id.map(|id| id.to_string()),
                kind.as_str(),
                payload_bytes,
                now,
            ],
        )?;
        let record = operation_for_request(&transaction, request_id)?
            .ok_or(SupervisorStoreError::InvalidOperation)?;
        if record.environment_id != environment_id
            || record.kind != kind
            || record.payload != *payload
        {
            return Err(SupervisorStoreError::RequestCollision);
        }
        transaction.commit()?;
        Ok(record)
    }

    pub(crate) fn advance_operation(
        &self,
        operation_id: Uuid,
        expected_checkpoint: u32,
        phase: OperationPhase,
        result: Option<&serde_json::Value>,
        error_code: Option<&str>,
    ) -> Result<OperationRecord, SupervisorStoreError> {
        validate_non_nil(operation_id)?;
        validate_operation_outcome(phase, result, error_code)?;
        let result_bytes = result.map(encode_operation_json).transpose()?;
        let next_checkpoint = expected_checkpoint
            .checked_add(1)
            .ok_or(SupervisorStoreError::InvalidOperation)?;
        let now = unix_millis()?;
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let current = operation_for_id(&transaction, operation_id)?
            .ok_or(SupervisorStoreError::OperationNotFound)?;
        if current.checkpoint > expected_checkpoint {
            if current.checkpoint == next_checkpoint
                && current.phase == phase
                && current.result.as_ref() == result
                && current.error_code.as_deref() == error_code
            {
                transaction.commit()?;
                return Ok(current);
            }
            return Err(SupervisorStoreError::JournalConflict);
        }
        if current.checkpoint != expected_checkpoint
            || !valid_phase_transition(current.phase, phase)
        {
            return Err(SupervisorStoreError::JournalConflict);
        }
        let updated = transaction.execute(
            "UPDATE operations \
             SET phase = ?1, checkpoint = ?2, result_json = ?3, error_code = ?4, updated_unix_ms = ?5 \
             WHERE operation_id = ?6 AND checkpoint = ?7",
            params![
                phase.as_str(),
                i64::from(next_checkpoint),
                result_bytes,
                error_code,
                now,
                operation_id.to_string(),
                i64::from(expected_checkpoint),
            ],
        )?;
        if updated != 1 {
            return Err(SupervisorStoreError::JournalConflict);
        }
        let record = operation_for_id(&transaction, operation_id)?
            .ok_or(SupervisorStoreError::OperationNotFound)?;
        transaction.commit()?;
        Ok(record)
    }

    pub(crate) fn pending_operations(&self) -> Result<Vec<OperationRecord>, SupervisorStoreError> {
        let mut statement = self.connection.prepare(
            "SELECT operation_id, request_id, environment_id, kind, phase, checkpoint,
                    payload_json, result_json, error_code
             FROM operations
             WHERE phase NOT IN ('completed', 'failed', 'interrupted')
             ORDER BY created_unix_ms, operation_id",
        )?;
        let rows = statement.query_map([], decode_operation_row)?;
        rows.map(|row| row.map_err(Into::into)).collect()
    }

    pub(crate) fn operation_by_request(
        &self,
        request_id: Uuid,
    ) -> Result<Option<OperationRecord>, SupervisorStoreError> {
        validate_non_nil(request_id)?;
        operation_for_request(&self.connection, request_id)
    }

    pub(crate) fn deletion_trash_names(
        &self,
    ) -> Result<std::collections::BTreeSet<String>, SupervisorStoreError> {
        let mut statement = self.connection.prepare(
            "SELECT operation_id, environment_id FROM operations \
             WHERE kind = 'delete' AND environment_id IS NOT NULL",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        let mut names = std::collections::BTreeSet::new();
        for row in rows {
            let (operation_id, environment_id) = row?;
            let operation_id = parse_uuid(&operation_id)?;
            let environment_id = parse_uuid(&environment_id)?;
            names.insert(format!("delete-{operation_id}-{environment_id}"));
        }
        Ok(names)
    }

    fn load_state(&self) -> Result<SupervisorState, SupervisorStoreError> {
        let current_id: Option<String> = self.connection.query_row(
            "SELECT current_environment_id FROM supervisor_settings WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        let mut statement = self.connection.prepare(
            "SELECT id, name, observed_state, vcpus, memory_mib, disk_bytes, generation, \
                    workspace_commit, source_path, runner_json, active_artifact_generation, \
                    staging_artifact_generation \
             FROM environments ORDER BY name",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, String>(7)?,
                row.get::<_, Vec<u8>>(8)?,
                row.get::<_, Option<Vec<u8>>>(9)?,
                row.get::<_, Option<String>>(10)?,
                row.get::<_, Option<String>>(11)?,
            ))
        })?;
        let mut environments = BTreeMap::new();
        let mut current = None;
        for row in rows {
            let (
                id,
                name,
                observed_state,
                vcpus,
                memory_mib,
                disk_bytes,
                generation,
                workspace_commit,
                source_path,
                runner_json,
                active_artifact_generation,
                staging_artifact_generation,
            ) = row?;
            let id_text = id;
            let id = parse_uuid(&id_text)?;
            let runner = runner_json
                .map(|bytes| serde_json::from_slice::<RunnerRecord>(&bytes))
                .transpose()
                .map_err(|_| SupervisorStoreError::InvalidState)?;
            let record = EnvironmentRecord {
                id,
                name: name.clone(),
                state: StoredEnvironmentState::parse(&observed_state)
                    .ok_or(SupervisorStoreError::InvalidState)?,
                vcpus: u8::try_from(vcpus).map_err(|_| SupervisorStoreError::InvalidState)?,
                memory_mib: u32::try_from(memory_mib)
                    .map_err(|_| SupervisorStoreError::InvalidState)?,
                disk_bytes: u64::try_from(disk_bytes)
                    .map_err(|_| SupervisorStoreError::InvalidState)?,
                generation: u64::try_from(generation)
                    .map_err(|_| SupervisorStoreError::InvalidState)?,
                workspace_commit,
                source_path: PathBuf::from(OsString::from_vec(source_path)),
                runner,
                active_artifact_generation,
                staging_artifact_generation,
            };
            if current_id.as_deref() == Some(id_text.as_str()) {
                current = Some(name.clone());
            }
            if environments.insert(name, record).is_some() {
                return Err(SupervisorStoreError::InvalidState);
            }
        }
        if current_id.is_some() && current.is_none() {
            return Err(SupervisorStoreError::InvalidState);
        }
        let state = SupervisorState {
            schema_version: super::supervisor::SUPERVISOR_STATE_SCHEMA,
            current,
            environments,
        };
        state
            .validate()
            .map_err(|_| SupervisorStoreError::InvalidState)?;
        Ok(state)
    }

    fn ensure_metadata(&self, boot_id: &str) -> Result<(), SupervisorStoreError> {
        let transaction = self.connection.unchecked_transaction()?;
        let namespace = metadata_value(&transaction, "namespace_id")?;
        match namespace {
            Some(value) => {
                parse_uuid(&value)?;
            }
            None => {
                transaction.execute(
                    "INSERT INTO supervisor_metadata(key, value) VALUES ('namespace_id', ?1)",
                    [Uuid::new_v4().to_string()],
                )?;
            }
        }
        if metadata_value(&transaction, "host_boot_id")?.is_none() {
            transaction.execute(
                "INSERT INTO supervisor_metadata(key, value) VALUES ('host_boot_id', ?1)",
                [boot_id],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    fn reconcile_host_boot(&self, boot_id: &str) -> Result<bool, SupervisorStoreError> {
        let transaction = self.connection.unchecked_transaction()?;
        let previous = metadata_value(&transaction, "host_boot_id")?
            .ok_or(SupervisorStoreError::InvalidState)?;
        if previous == boot_id {
            transaction.commit()?;
            return Ok(false);
        }
        transaction.execute(
            "UPDATE environments \
             SET desired_state = 'stopped', observed_state = 'stopped', runner_json = NULL",
            [],
        )?;
        transaction.execute(
            "UPDATE operations \
             SET phase = 'interrupted', error_code = 'host_reboot' \
             WHERE phase NOT IN ('completed', 'failed', 'interrupted')",
            [],
        )?;
        transaction.execute(
            "UPDATE supervisor_metadata SET value = ?1 WHERE key = 'host_boot_id'",
            [boot_id],
        )?;
        transaction.commit()?;
        Ok(true)
    }

    fn legacy_import_digest(&self) -> Result<Option<String>, SupervisorStoreError> {
        metadata_value(&self.connection, "legacy_state_sha256")
    }

    fn import_legacy_state(
        &self,
        state: &SupervisorState,
        digest: &str,
    ) -> Result<(), SupervisorStoreError> {
        let transaction = self.connection.unchecked_transaction()?;
        write_state(&transaction, state)?;
        transaction.execute(
            "INSERT INTO supervisor_metadata(key, value) VALUES ('legacy_state_sha256', ?1)",
            [digest],
        )?;
        transaction.commit()?;
        Ok(())
    }

    #[cfg(test)]
    fn metadata(&self, key: &str) -> Option<String> {
        metadata_value(&self.connection, key).unwrap()
    }
}

fn open_database(root: &PrivateRoot) -> Result<(Connection, bool), SupervisorStoreError> {
    let relative = Path::new(DATABASE_FILE);
    let (identity, initialize) = match root.open_regular(relative, true, None, false, Some(0o600)) {
        Ok(opened) => (opened.identity().clone(), opened.identity().size == 0),
        Err(error) if path_error_is_not_found(&error) => {
            let opened = root.create_regular(relative, 0o600, true)?;
            (opened.identity().clone(), true)
        }
        Err(error) => return Err(error.into()),
    };
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let connection = Connection::open_with_flags(root.path().join(relative), flags)?;
    let reopened = root.open_regular(relative, true, None, false, Some(0o600))?;
    if reopened.identity() != &identity {
        return Err(SupervisorStoreError::DatabaseIdentityChanged);
    }
    Ok((connection, initialize))
}

fn configure_connection(connection: &Connection) -> Result<(), SupervisorStoreError> {
    connection.busy_timeout(BUSY_TIMEOUT)?;
    connection.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)?;
    connection.pragma_update(None, "foreign_keys", true)?;
    connection.pragma_update(None, "trusted_schema", false)?;
    connection.pragma_update(None, "synchronous", "FULL")?;
    let journal: String =
        connection.pragma_update_and_check(None, "journal_mode", "WAL", |row| row.get(0))?;
    if !journal.eq_ignore_ascii_case("wal") {
        return Err(SupervisorStoreError::InvalidDatabase);
    }
    connection.pragma_update(None, "wal_autocheckpoint", 100_i64)?;
    Ok(())
}

fn initialize_schema(connection: &Connection) -> Result<(), SupervisorStoreError> {
    connection.execute_batch(
        "BEGIN IMMEDIATE;
         CREATE TABLE supervisor_metadata (
           key TEXT PRIMARY KEY NOT NULL,
           value TEXT NOT NULL
         ) STRICT;
         CREATE TABLE environments (
           id TEXT PRIMARY KEY NOT NULL,
           name TEXT UNIQUE NOT NULL,
           desired_state TEXT NOT NULL CHECK (desired_state IN ('stopped', 'running', 'deleted')),
           observed_state TEXT NOT NULL CHECK (observed_state IN ('stopped', 'starting', 'running', 'error', 'orphaned', 'deleting')),
           vcpus INTEGER NOT NULL CHECK (vcpus BETWEEN 1 AND 32),
           memory_mib INTEGER NOT NULL CHECK (memory_mib BETWEEN 128 AND 65536),
           disk_bytes INTEGER NOT NULL CHECK (disk_bytes > 0),
           generation INTEGER NOT NULL CHECK (generation >= 0),
           workspace_commit TEXT NOT NULL,
           source_path BLOB NOT NULL,
           runner_json BLOB NULL,
           active_artifact_generation TEXT NULL,
           staging_artifact_generation TEXT NULL
         ) STRICT;
         CREATE TABLE supervisor_settings (
           singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
           current_environment_id TEXT NULL,
           FOREIGN KEY (current_environment_id) REFERENCES environments(id) ON DELETE SET NULL
         ) STRICT;
         INSERT INTO supervisor_settings(singleton, current_environment_id) VALUES (1, NULL);
         CREATE TABLE owned_objects (
           environment_id TEXT NOT NULL,
           kind TEXT NOT NULL,
           relative_path BLOB NOT NULL,
           identity_json BLOB NULL,
           lifecycle TEXT NOT NULL CHECK (lifecycle IN ('active', 'staging', 'trash')),
           PRIMARY KEY (environment_id, kind, relative_path),
           FOREIGN KEY (environment_id) REFERENCES environments(id) ON DELETE CASCADE
         ) STRICT;
         CREATE TABLE operations (
           operation_id TEXT PRIMARY KEY NOT NULL,
           request_id TEXT UNIQUE NOT NULL,
           environment_id TEXT NULL,
           kind TEXT NOT NULL,
           phase TEXT NOT NULL CHECK (phase IN ('intent', 'effect_applied', 'completed', 'failed', 'interrupted')),
           checkpoint INTEGER NOT NULL CHECK (checkpoint >= 0),
           payload_json BLOB NOT NULL,
           result_json BLOB NULL,
           error_code TEXT NULL,
           created_unix_ms INTEGER NOT NULL,
           updated_unix_ms INTEGER NOT NULL
         ) STRICT;
         PRAGMA application_id = 1129797197;
         PRAGMA user_version = 1;
         COMMIT;",
    )?;
    validate_schema(connection)
}

fn validate_schema(connection: &Connection) -> Result<(), SupervisorStoreError> {
    let application_id: i64 =
        connection.pragma_query_value(None, "application_id", |row| row.get(0))?;
    let schema_version: i64 =
        connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if application_id != DATABASE_APPLICATION_ID || schema_version != DATABASE_SCHEMA_VERSION {
        return Err(SupervisorStoreError::UnsupportedSchema {
            application_id,
            schema_version,
        });
    }
    for table in [
        "supervisor_metadata",
        "supervisor_settings",
        "environments",
        "owned_objects",
        "operations",
    ] {
        let present = connection
            .query_row(
                "SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = ?1",
                [table],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if !present {
            return Err(SupervisorStoreError::InvalidDatabase);
        }
    }
    Ok(())
}

fn validate_database(connection: &Connection) -> Result<(), SupervisorStoreError> {
    let result: String = connection.query_row("PRAGMA quick_check(1)", [], |row| row.get(0))?;
    if result != "ok" {
        return Err(SupervisorStoreError::InvalidDatabase);
    }
    Ok(())
}

fn write_state(
    transaction: &Transaction<'_>,
    state: &SupervisorState,
) -> Result<(), SupervisorStoreError> {
    transaction.execute(
        "UPDATE supervisor_settings SET current_environment_id = NULL WHERE singleton = 1",
        [],
    )?;
    transaction.execute_batch(
        "CREATE TEMP TABLE IF NOT EXISTS desired_environments(id TEXT PRIMARY KEY) STRICT;
         DELETE FROM desired_environments;",
    )?;
    for environment in state.environments.values() {
        let runner_json = environment
            .runner
            .as_ref()
            .map(serde_json::to_vec)
            .transpose()
            .map_err(|_| SupervisorStoreError::InvalidState)?;
        let disk_bytes = i64::try_from(environment.disk_bytes)
            .map_err(|_| SupervisorStoreError::InvalidState)?;
        let generation = i64::try_from(environment.generation)
            .map_err(|_| SupervisorStoreError::InvalidState)?;
        transaction.execute(
            "INSERT INTO desired_environments(id) VALUES (?1)",
            [environment.id.to_string()],
        )?;
        transaction.execute(
            "INSERT INTO environments(
               id, name, desired_state, observed_state, vcpus, memory_mib,
               disk_bytes, generation, workspace_commit, source_path, runner_json,
               active_artifact_generation, staging_artifact_generation
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
             ON CONFLICT(id) DO UPDATE SET
               name = excluded.name,
               desired_state = excluded.desired_state,
               observed_state = excluded.observed_state,
               vcpus = excluded.vcpus,
               memory_mib = excluded.memory_mib,
               disk_bytes = excluded.disk_bytes,
               generation = excluded.generation,
               workspace_commit = excluded.workspace_commit,
               source_path = excluded.source_path,
               runner_json = excluded.runner_json,
               active_artifact_generation = excluded.active_artifact_generation,
               staging_artifact_generation = excluded.staging_artifact_generation",
            params![
                environment.id.to_string(),
                &environment.name,
                desired_state(environment.state),
                environment.state.as_str(),
                i64::from(environment.vcpus),
                i64::from(environment.memory_mib),
                disk_bytes,
                generation,
                &environment.workspace_commit,
                environment.source_path.as_os_str().as_bytes(),
                runner_json,
                &environment.active_artifact_generation,
                &environment.staging_artifact_generation,
            ],
        )?;
        transaction.execute(
            "DELETE FROM owned_objects WHERE environment_id = ?1",
            [environment.id.to_string()],
        )?;
        let vm = format!("engine/vms/{}", environment.id);
        for (kind, relative_path, identity_json) in [
            ("vm_tree", vm.clone(), None::<Vec<u8>>),
            ("state_disk", format!("{vm}/disks/state.raw"), None),
            ("vmm_api_socket", format!("{vm}/api/api.sock"), None),
            ("vmm_api_lock", format!("{vm}/api/api.sock.lock"), None),
            ("hybrid_vsock", format!("{vm}/vsock/vsock.sock"), None),
        ] {
            transaction.execute(
                "INSERT INTO owned_objects(
                   environment_id, kind, relative_path, identity_json, lifecycle
                 ) VALUES (?1, ?2, ?3, ?4, 'active')",
                params![
                    environment.id.to_string(),
                    kind,
                    relative_path.as_bytes(),
                    identity_json,
                ],
            )?;
        }
        if let Some(runner) = &environment.runner {
            let identity = serde_json::to_vec(&runner.socket)
                .map_err(|_| SupervisorStoreError::InvalidState)?;
            let relative_path = format!("runners/{}.sock", environment.id);
            transaction.execute(
                "INSERT INTO owned_objects(
                   environment_id, kind, relative_path, identity_json, lifecycle
                 ) VALUES (?1, 'runner_socket', ?2, ?3, 'active')",
                params![
                    environment.id.to_string(),
                    relative_path.as_bytes(),
                    identity,
                ],
            )?;
        }
    }
    transaction.execute(
        "DELETE FROM environments \
         WHERE NOT EXISTS (SELECT 1 FROM desired_environments wanted WHERE wanted.id = environments.id)",
        [],
    )?;
    if let Some(current) = &state.current {
        let id = state
            .environments
            .get(current)
            .ok_or(SupervisorStoreError::InvalidState)?
            .id;
        transaction.execute(
            "UPDATE supervisor_settings SET current_environment_id = ?1 WHERE singleton = 1",
            [id.to_string()],
        )?;
    }
    Ok(())
}

fn desired_state(state: StoredEnvironmentState) -> &'static str {
    match state {
        StoredEnvironmentState::Starting | StoredEnvironmentState::Running => "running",
        StoredEnvironmentState::Stopped
        | StoredEnvironmentState::Error
        | StoredEnvironmentState::Orphaned => "stopped",
    }
}

fn metadata_value(
    connection: &Connection,
    key: &str,
) -> Result<Option<String>, SupervisorStoreError> {
    connection
        .query_row(
            "SELECT value FROM supervisor_metadata WHERE key = ?1",
            [key],
            |row| row.get(0),
        )
        .optional()
        .map_err(Into::into)
}

fn operation_for_request(
    connection: &Connection,
    request_id: Uuid,
) -> Result<Option<OperationRecord>, SupervisorStoreError> {
    connection
        .query_row(
            "SELECT operation_id, request_id, environment_id, kind, phase, checkpoint,
                    payload_json, result_json, error_code
             FROM operations WHERE request_id = ?1",
            [request_id.to_string()],
            decode_operation_row,
        )
        .optional()
        .map_err(Into::into)
}

fn operation_for_id(
    connection: &Connection,
    operation_id: Uuid,
) -> Result<Option<OperationRecord>, SupervisorStoreError> {
    connection
        .query_row(
            "SELECT operation_id, request_id, environment_id, kind, phase, checkpoint,
                    payload_json, result_json, error_code
             FROM operations WHERE operation_id = ?1",
            [operation_id.to_string()],
            decode_operation_row,
        )
        .optional()
        .map_err(Into::into)
}

fn decode_operation_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<OperationRecord> {
    let operation_id = row.get::<_, String>(0)?;
    let request_id = row.get::<_, String>(1)?;
    let environment_id = row.get::<_, Option<String>>(2)?;
    let kind = row.get::<_, String>(3)?;
    let phase = row.get::<_, String>(4)?;
    let checkpoint = row.get::<_, i64>(5)?;
    let payload = row.get::<_, Vec<u8>>(6)?;
    let result = row.get::<_, Option<Vec<u8>>>(7)?;
    let error_code = row.get::<_, Option<String>>(8)?;
    decode_operation(
        &operation_id,
        &request_id,
        environment_id.as_deref(),
        &kind,
        &phase,
        checkpoint,
        &payload,
        result.as_deref(),
        error_code,
    )
    .map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(error))
    })
}

#[allow(clippy::too_many_arguments)]
fn decode_operation(
    operation_id: &str,
    request_id: &str,
    environment_id: Option<&str>,
    kind: &str,
    phase: &str,
    checkpoint: i64,
    payload: &[u8],
    result: Option<&[u8]>,
    error_code: Option<String>,
) -> Result<OperationRecord, SupervisorStoreError> {
    let checkpoint =
        u32::try_from(checkpoint).map_err(|_| SupervisorStoreError::InvalidOperation)?;
    let payload = decode_operation_json(payload)?;
    let result = result.map(decode_operation_json).transpose()?;
    let phase = OperationPhase::parse(phase).ok_or(SupervisorStoreError::InvalidOperation)?;
    validate_operation_outcome(phase, result.as_ref(), error_code.as_deref())?;
    Ok(OperationRecord {
        operation_id: parse_uuid(operation_id)?,
        request_id: parse_uuid(request_id)?,
        environment_id: environment_id.map(parse_uuid).transpose()?,
        kind: OperationKind::parse(kind).ok_or(SupervisorStoreError::InvalidOperation)?,
        phase,
        checkpoint,
        payload,
        result,
        error_code,
    })
}

fn encode_operation_json(value: &serde_json::Value) -> Result<Vec<u8>, SupervisorStoreError> {
    if !value.is_object() || contains_forbidden_key(value) {
        return Err(SupervisorStoreError::InvalidOperation);
    }
    let encoded = serde_json::to_vec(value).map_err(|_| SupervisorStoreError::InvalidOperation)?;
    if encoded.len() > MAXIMUM_OPERATION_BYTES {
        return Err(SupervisorStoreError::InvalidOperation);
    }
    Ok(encoded)
}

fn decode_operation_json(bytes: &[u8]) -> Result<serde_json::Value, SupervisorStoreError> {
    if bytes.len() > MAXIMUM_OPERATION_BYTES {
        return Err(SupervisorStoreError::InvalidOperation);
    }
    let value =
        serde_json::from_slice(bytes).map_err(|_| SupervisorStoreError::InvalidOperation)?;
    encode_operation_json(&value)?;
    Ok(value)
}

fn contains_forbidden_key(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Object(fields) => fields.iter().any(|(name, value)| {
            let name = name.to_ascii_lowercase();
            name.contains("capability")
                || name.contains("credential")
                || name.contains("token")
                || contains_forbidden_key(value)
        }),
        serde_json::Value::Array(values) => values.iter().any(contains_forbidden_key),
        _ => false,
    }
}

fn validate_operation_outcome(
    phase: OperationPhase,
    result: Option<&serde_json::Value>,
    error_code: Option<&str>,
) -> Result<(), SupervisorStoreError> {
    if let Some(result) = result {
        encode_operation_json(result)?;
    }
    if error_code.is_some_and(|code| {
        code.is_empty()
            || code.len() > 64
            || !code
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
    }) {
        return Err(SupervisorStoreError::InvalidOperation);
    }
    let valid = match phase {
        OperationPhase::Intent | OperationPhase::EffectApplied => {
            result.is_none() && error_code.is_none()
        }
        OperationPhase::Completed => result.is_some() && error_code.is_none(),
        OperationPhase::Failed | OperationPhase::Interrupted => {
            result.is_none() && error_code.is_some()
        }
    };
    valid
        .then_some(())
        .ok_or(SupervisorStoreError::InvalidOperation)
}

fn valid_phase_transition(from: OperationPhase, to: OperationPhase) -> bool {
    if from.terminal() {
        return false;
    }
    matches!(
        (from, to),
        (
            OperationPhase::Intent,
            OperationPhase::EffectApplied
                | OperationPhase::Completed
                | OperationPhase::Failed
                | OperationPhase::Interrupted
        ) | (
            OperationPhase::EffectApplied,
            OperationPhase::EffectApplied
                | OperationPhase::Completed
                | OperationPhase::Failed
                | OperationPhase::Interrupted
        )
    )
}

fn validate_non_nil(id: Uuid) -> Result<(), SupervisorStoreError> {
    (!id.is_nil())
        .then_some(())
        .ok_or(SupervisorStoreError::InvalidOperation)
}

fn unix_millis() -> Result<i64, SupervisorStoreError> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| SupervisorStoreError::InvalidOperation)?
        .as_millis();
    i64::try_from(millis).map_err(|_| SupervisorStoreError::InvalidOperation)
}

fn read_legacy_state(
    root: &PrivateRoot,
) -> Result<Option<(SupervisorState, Vec<u8>)>, SupervisorStoreError> {
    let opened = match root.open_regular(
        Path::new(LEGACY_STATE_FILE),
        false,
        None,
        false,
        Some(0o600),
    ) {
        Ok(opened) => opened,
        Err(error) if path_error_is_not_found(&error) => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let mut bytes = Vec::new();
    opened
        .file()
        .take(MAXIMUM_STATE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| SupervisorStoreError::Io {
            path: root.path().join(LEGACY_STATE_FILE),
            source,
        })?;
    if bytes.len() as u64 > MAXIMUM_STATE_BYTES {
        return Err(SupervisorStoreError::InvalidState);
    }
    let state: SupervisorState =
        serde_json::from_slice(&bytes).map_err(|_| SupervisorStoreError::InvalidState)?;
    state
        .validate()
        .map_err(|_| SupervisorStoreError::InvalidState)?;
    Ok(Some((state, bytes)))
}

fn finish_legacy_archive(
    root: &PrivateRoot,
    bytes: &[u8],
    expected_digest: &str,
) -> Result<(), SupervisorStoreError> {
    match root.open_regular(
        Path::new(LEGACY_ARCHIVE_FILE),
        false,
        Some(bytes.len() as u64),
        false,
        Some(0o400),
    ) {
        Ok(opened) => {
            let mut archived = Vec::with_capacity(bytes.len());
            opened.file().read_to_end(&mut archived).map_err(|source| {
                SupervisorStoreError::Io {
                    path: root.path().join(LEGACY_ARCHIVE_FILE),
                    source,
                }
            })?;
            if sha256_hex(&archived) != expected_digest {
                return Err(SupervisorStoreError::LegacyStateChanged);
            }
        }
        Err(error) if path_error_is_not_found(&error) => {
            root.atomic_replace(Path::new(LEGACY_ARCHIVE_FILE), bytes, 0o400)?;
        }
        Err(error) => return Err(error.into()),
    }
    if !root.remove_private_regular(Path::new(LEGACY_STATE_FILE), 0o600)? {
        return Err(SupervisorStoreError::LegacyStateChanged);
    }
    Ok(())
}

fn normalize_imported_state(state: &mut SupervisorState, boot_id: &str) -> bool {
    let mut changed = false;
    for environment in state.environments.values_mut() {
        let runner_matches_boot = environment
            .runner
            .as_ref()
            .is_some_and(|runner| runner.process.boot_id == boot_id);
        if environment.runner.is_some() && !runner_matches_boot
            || environment.runner.is_none()
                && matches!(
                    environment.state,
                    StoredEnvironmentState::Starting | StoredEnvironmentState::Running
                )
        {
            environment.runner = None;
            environment.state = StoredEnvironmentState::Stopped;
            changed = true;
        }
    }
    changed
}

fn legacy_archive_exists(root: &PrivateRoot) -> Result<bool, SupervisorStoreError> {
    match root.open_regular(
        Path::new(LEGACY_ARCHIVE_FILE),
        false,
        None,
        false,
        Some(0o400),
    ) {
        Ok(_) => Ok(true),
        Err(error) if path_error_is_not_found(&error) => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn validate_database_files(root: &PrivateRoot, writable: bool) -> Result<(), SupervisorStoreError> {
    root.open_regular(Path::new(DATABASE_FILE), writable, None, false, Some(0o600))?;
    for sidecar in [DATABASE_WAL_FILE, DATABASE_SHM_FILE] {
        match root.open_regular(Path::new(sidecar), writable, None, false, Some(0o600)) {
            Ok(_) => {}
            Err(error) if path_error_is_not_found(&error) => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn current_boot_id() -> Result<String, SupervisorStoreError> {
    let boot_id = fs::read_to_string("/proc/sys/kernel/random/boot_id").map_err(|source| {
        SupervisorStoreError::Io {
            path: PathBuf::from("/proc/sys/kernel/random/boot_id"),
            source,
        }
    })?;
    let boot_id = boot_id.trim().to_owned();
    validate_boot_id(&boot_id)?;
    Ok(boot_id)
}

fn validate_boot_id(boot_id: &str) -> Result<(), SupervisorStoreError> {
    if boot_id.is_empty()
        || boot_id.len() > 128
        || !boot_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(SupervisorStoreError::InvalidBootId);
    }
    Ok(())
}

fn parse_uuid(value: &str) -> Result<Uuid, SupervisorStoreError> {
    let id = Uuid::parse_str(value).map_err(|_| SupervisorStoreError::InvalidState)?;
    if id.is_nil() {
        return Err(SupervisorStoreError::InvalidState);
    }
    Ok(id)
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn path_error_is_not_found(error: &PathError) -> bool {
    match error {
        PathError::Openat2 { source, .. } => *source == rustix::io::Errno::NOENT,
        PathError::Io { source, .. } => source.kind() == io::ErrorKind::NotFound,
        _ => false,
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SupervisorStoreError {
    #[error("native supervisor database identity changed while opening")]
    DatabaseIdentityChanged,
    #[error("native supervisor database is invalid")]
    InvalidDatabase,
    #[error(
        "native supervisor database schema is unsupported ({application_id}, {schema_version})"
    )]
    UnsupportedSchema {
        application_id: i64,
        schema_version: i64,
    },
    #[error("native supervisor state is invalid")]
    InvalidState,
    #[error("native supervisor boot identity is invalid")]
    InvalidBootId,
    #[error("preview state changed after its durable import")]
    LegacyStateChanged,
    #[error("preview state cannot be merged into a nonempty supervisor database")]
    UntrackedLegacyState,
    #[error("an imported preview-state archive exists without its database receipt")]
    UntrackedLegacyArchive,
    #[error("native supervisor operation is invalid")]
    InvalidOperation,
    #[error("native supervisor operation request ID was reused with different input")]
    RequestCollision,
    #[error("native supervisor operation journal checkpoint conflicts with durable state")]
    JournalConflict,
    #[error("native supervisor operation was not found")]
    OperationNotFound,
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error(transparent)]
    Path(#[from] PathError),
    #[error("filesystem operation failed for {path}: {source}")]
    Io { path: PathBuf, source: io::Error },
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    use crate::linux::path::{FileIdentity, SocketIdentity, current_uid};
    use crate::linux::process::ProcessIdentity;

    use super::*;

    fn root() -> (tempfile::TempDir, PrivateRoot) {
        let parent = tempfile::tempdir().unwrap();
        let root_path = parent.path().join("root");
        fs::create_dir(&root_path).unwrap();
        fs::set_permissions(&root_path, fs::Permissions::from_mode(0o700)).unwrap();
        let root = PrivateRoot::open(&root_path).unwrap();
        (parent, root)
    }

    fn environment(
        state: StoredEnvironmentState,
        runner_boot_id: Option<&str>,
    ) -> EnvironmentRecord {
        let runner = runner_boot_id.map(|boot_id| RunnerRecord {
            process: ProcessIdentity {
                pid: 123,
                boot_id: boot_id.to_owned(),
                start_time_ticks: 456,
                executable: PathBuf::from("/usr/bin/cw"),
                executable_file: FileIdentity {
                    device: 1,
                    inode: 2,
                    size: 3,
                    uid: current_uid(),
                    mode: 0o100500,
                    links: 1,
                },
                executable_sha256: "a".repeat(64),
            },
            socket: SocketIdentity {
                device: 4,
                inode: 5,
                uid: current_uid(),
                mode: 0o140600,
            },
        });
        EnvironmentRecord {
            id: Uuid::new_v4(),
            name: "dev".to_owned(),
            state,
            vcpus: 2,
            memory_mib: 16 * 1024,
            disk_bytes: crate::linux::state::MINIMUM_STATE_DISK_BYTES,
            generation: 7,
            workspace_commit: "b".repeat(40),
            source_path: PathBuf::from("/workspace/source"),
            runner,
            active_artifact_generation: Some("c".repeat(64)),
            staging_artifact_generation: None,
        }
    }

    fn state(environment: EnvironmentRecord) -> SupervisorState {
        SupervisorState {
            schema_version: super::super::supervisor::SUPERVISOR_STATE_SCHEMA,
            current: Some(environment.name.clone()),
            environments: BTreeMap::from([(environment.name.clone(), environment)]),
        }
    }

    #[test]
    fn new_database_is_owner_only_wal_and_stable() {
        let (_parent, root) = root();
        let (store, state) = SupervisorStore::open_for_boot(&root, "boot-a").unwrap();
        assert_eq!(state, SupervisorState::default());
        assert_eq!(store.metadata("host_boot_id").as_deref(), Some("boot-a"));
        let namespace = store.metadata("namespace_id").unwrap();
        assert!(!Uuid::parse_str(&namespace).unwrap().is_nil());
        let metadata = fs::symlink_metadata(root.path().join(DATABASE_FILE)).unwrap();
        assert!(metadata.is_file());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        let journal: String = store
            .connection
            .pragma_query_value(None, "journal_mode", |row| row.get(0))
            .unwrap();
        assert_eq!(journal, "wal");

        drop(store);
        let (reopened, state) = SupervisorStore::open_for_boot(&root, "boot-a").unwrap();
        assert_eq!(state, SupervisorState::default());
        assert_eq!(reopened.metadata("namespace_id").unwrap(), namespace);
    }

    #[test]
    fn preview_json_import_is_exact_and_idempotent() {
        let (_parent, root) = root();
        let expected = state(environment(StoredEnvironmentState::Stopped, None));
        expected.write(&root).unwrap();
        let original = fs::read(root.path().join(LEGACY_STATE_FILE)).unwrap();

        let (store, imported) = SupervisorStore::open_for_boot(&root, "boot-a").unwrap();
        assert_eq!(imported, expected);
        assert!(!root.path().join(LEGACY_STATE_FILE).exists());
        assert_eq!(
            fs::read(root.path().join(LEGACY_ARCHIVE_FILE)).unwrap(),
            original
        );
        assert_eq!(
            fs::symlink_metadata(root.path().join(LEGACY_ARCHIVE_FILE))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o400
        );
        let digest = sha256_hex(&original);
        assert_eq!(
            store.metadata("legacy_state_sha256").as_deref(),
            Some(digest.as_str())
        );

        drop(store);
        let (_reopened, loaded) = SupervisorStore::open_for_boot(&root, "boot-a").unwrap();
        assert_eq!(loaded, expected);
    }

    #[test]
    fn import_from_another_boot_clears_stale_runner_ownership() {
        let (_parent, root) = root();
        let expected = state(environment(
            StoredEnvironmentState::Running,
            Some("boot-before-restart"),
        ));
        expected.write(&root).unwrap();

        let (_store, imported) =
            SupervisorStore::open_for_boot(&root, "boot-after-restart").unwrap();
        let imported = imported.environments.get("dev").unwrap();
        assert_eq!(imported.state, StoredEnvironmentState::Stopped);
        assert!(imported.runner.is_none());
    }

    #[test]
    fn database_reopen_on_another_boot_stops_every_environment() {
        let (_parent, root) = root();
        let (store, _) = SupervisorStore::open_for_boot(&root, "boot-a").unwrap();
        let expected = state(environment(StoredEnvironmentState::Running, Some("boot-a")));
        store.replace_state(&expected).unwrap();
        drop(store);

        let (reopened, loaded) = SupervisorStore::open_for_boot(&root, "boot-b").unwrap();
        let environment = loaded.environments.get("dev").unwrap();
        assert_eq!(environment.state, StoredEnvironmentState::Stopped);
        assert!(environment.runner.is_none());
        assert_eq!(reopened.metadata("host_boot_id").as_deref(), Some("boot-b"));
    }

    #[test]
    fn database_symlink_is_rejected() {
        let (parent, root) = root();
        let outside = parent.path().join("outside.db");
        fs::write(&outside, []).unwrap();
        symlink(&outside, root.path().join(DATABASE_FILE)).unwrap();
        assert!(matches!(
            SupervisorStore::open_for_boot(&root, "boot-a"),
            Err(SupervisorStoreError::Path(_))
        ));
    }

    #[test]
    fn read_only_inspection_does_not_create_or_archive_state() {
        let (_parent, root) = root();
        let legacy = state(environment(StoredEnvironmentState::Stopped, None));
        legacy.write(&root).unwrap();
        let legacy_bytes = fs::read(root.path().join(LEGACY_STATE_FILE)).unwrap();

        let (store, inspected) = SupervisorStore::inspect(&root).unwrap();
        assert!(store.is_none());
        assert_eq!(inspected, legacy);
        assert_eq!(
            fs::read(root.path().join(LEGACY_STATE_FILE)).unwrap(),
            legacy_bytes
        );
        assert!(!root.path().join(DATABASE_FILE).exists());
        assert!(!root.path().join(LEGACY_ARCHIVE_FILE).exists());
    }

    #[test]
    fn sqlite_inspection_opens_the_authority_read_only() {
        let (_parent, root) = root();
        let (store, _) = SupervisorStore::open_for_boot(&root, "boot-a").unwrap();
        let expected = state(environment(StoredEnvironmentState::Stopped, None));
        store.replace_state(&expected).unwrap();
        drop(store);
        let database = root.path().join(DATABASE_FILE);
        let before = fs::read(&database).unwrap();

        let (store, inspected) = SupervisorStore::inspect(&root).unwrap();
        assert!(store.is_some());
        assert_eq!(inspected, expected);
        drop(store);
        assert_eq!(fs::read(database).unwrap(), before);
    }

    #[test]
    fn state_commit_records_artifact_generation_and_owned_runtime_objects() {
        let (_parent, root) = root();
        let (store, _) = SupervisorStore::open_for_boot(&root, "boot-a").unwrap();
        let expected = state(environment(StoredEnvironmentState::Stopped, None));
        let environment = expected.environments.get("dev").unwrap();
        store.replace_state(&expected).unwrap();

        let generation: Option<String> = store
            .connection
            .query_row(
                "SELECT active_artifact_generation FROM environments WHERE id = ?1",
                [environment.id.to_string()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(generation, environment.active_artifact_generation);
        let objects: Vec<(String, Vec<u8>)> = {
            let mut statement = store
                .connection
                .prepare(
                    "SELECT kind, relative_path FROM owned_objects \
                     WHERE environment_id = ?1 ORDER BY kind",
                )
                .unwrap();
            statement
                .query_map([environment.id.to_string()], |row| {
                    Ok((row.get(0)?, row.get(1)?))
                })
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap()
        };
        assert_eq!(objects.len(), 5);
        assert!(objects.iter().any(|(kind, path)| {
            kind == "state_disk"
                && path == format!("engine/vms/{}/disks/state.raw", environment.id).as_bytes()
        }));
    }

    #[test]
    fn operation_requests_are_idempotent_and_collision_safe() {
        let (_parent, root) = root();
        let (store, _) = SupervisorStore::open_for_boot(&root, "boot-a").unwrap();
        let request_id = Uuid::new_v4();
        let environment_id = Uuid::new_v4();
        let payload = serde_json::json!({"name": "dev", "generation": 1});
        let first = store
            .begin_operation(
                request_id,
                Some(environment_id),
                OperationKind::Start,
                &payload,
            )
            .unwrap();
        let repeated = store
            .begin_operation(
                request_id,
                Some(environment_id),
                OperationKind::Start,
                &payload,
            )
            .unwrap();
        assert_eq!(repeated, first);
        assert!(matches!(
            store.begin_operation(
                request_id,
                Some(environment_id),
                OperationKind::Stop,
                &payload,
            ),
            Err(SupervisorStoreError::RequestCollision)
        ));
        assert_eq!(store.pending_operations().unwrap(), vec![first]);
    }

    #[test]
    fn operation_checkpoints_are_monotonic_and_replay_idempotent() {
        let (_parent, root) = root();
        let (store, _) = SupervisorStore::open_for_boot(&root, "boot-a").unwrap();
        let operation = store
            .begin_operation(
                Uuid::new_v4(),
                Some(Uuid::new_v4()),
                OperationKind::Create,
                &serde_json::json!({"name": "dev"}),
            )
            .unwrap();
        let applied = store
            .advance_operation(
                operation.operation_id,
                0,
                OperationPhase::EffectApplied,
                None,
                None,
            )
            .unwrap();
        assert_eq!(applied.checkpoint, 1);
        assert_eq!(
            store
                .advance_operation(
                    operation.operation_id,
                    0,
                    OperationPhase::EffectApplied,
                    None,
                    None,
                )
                .unwrap(),
            applied
        );
        let second_effect = store
            .advance_operation(
                operation.operation_id,
                1,
                OperationPhase::EffectApplied,
                None,
                None,
            )
            .unwrap();
        assert_eq!(second_effect.checkpoint, 2);
        assert_eq!(
            store
                .advance_operation(
                    operation.operation_id,
                    1,
                    OperationPhase::EffectApplied,
                    None,
                    None,
                )
                .unwrap(),
            second_effect
        );
        let completed = store
            .advance_operation(
                operation.operation_id,
                2,
                OperationPhase::Completed,
                Some(&serde_json::json!({"name": "dev"})),
                None,
            )
            .unwrap();
        assert_eq!(completed.checkpoint, 3);
        assert!(store.pending_operations().unwrap().is_empty());
        assert!(matches!(
            store.advance_operation(
                operation.operation_id,
                3,
                OperationPhase::Failed,
                None,
                Some("late_failure"),
            ),
            Err(SupervisorStoreError::JournalConflict)
        ));
    }

    #[test]
    fn operation_payloads_reject_secret_shaped_fields() {
        let (_parent, root) = root();
        let (store, _) = SupervisorStore::open_for_boot(&root, "boot-a").unwrap();
        assert!(matches!(
            store.begin_operation(
                Uuid::new_v4(),
                None,
                OperationKind::Reconcile,
                &serde_json::json!({"nested": {"access_token": "must-not-persist"}}),
            ),
            Err(SupervisorStoreError::InvalidOperation)
        ));
    }
}
