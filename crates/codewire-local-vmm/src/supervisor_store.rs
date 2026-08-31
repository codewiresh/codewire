//! Durable, owner-only state for the native local supervisor.
//!
//! SQLite is the sole authority. The supervisor singleton is the only writer,
//! but WAL and explicit replay
//! records keep every lifecycle transition recoverable across process death.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rusqlite::config::DbConfig;
use rusqlite::{
    Connection, OpenFlags, OptionalExtension as _, Transaction, TransactionBehavior, params,
};
use tokio::sync::broadcast;
use uuid::Uuid;

use crate::linux::path::{PathError, PrivateRoot};
use crate::supervisor::{EnvironmentRecord, RunnerRecord, StoredEnvironmentState, SupervisorState};
use crate::workspace_generation::WorkspaceGenerationRecord;

pub(crate) const DATABASE_FILE: &str = "supervisor.db";
const DATABASE_WAL_FILE: &str = "supervisor.db-wal";
const DATABASE_SHM_FILE: &str = "supervisor.db-shm";
const HOST_REBOOT_WORKSPACE_TRANSITIONS_KEY: &str = "host_reboot_workspace_transitions";
const DATABASE_APPLICATION_ID: i64 = 0x4357_564d; // "CWVM"
const DATABASE_SCHEMA_VERSION: i64 = 4;
// A create journal entry contains the exact canonical project JSON so replay
// never has to reread a mutable codewire.yaml. The source document itself is
// bounded to 256 KiB; this higher bound covers JSON string escaping.
const MAXIMUM_OPERATION_BYTES: usize = 2 * 1024 * 1024;
const MAXIMUM_DIAGNOSTIC_OPERATIONS: usize = 128;
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);
const OPERATION_EVENT_CAPACITY: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OperationKind {
    Create,
    Start,
    Stop,
    Restart,
    UpdateWorkspace,
    RollbackWorkspace,
    Delete,
    GrowDisk,
    Reconcile,
}

impl OperationKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Start => "start",
            Self::Stop => "stop",
            Self::Restart => "restart",
            Self::UpdateWorkspace => "update_workspace",
            Self::RollbackWorkspace => "rollback_workspace",
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
            "update_workspace" => Some(Self::UpdateWorkspace),
            "rollback_workspace" => Some(Self::RollbackWorkspace),
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
    pub(crate) fn as_str(self) -> &'static str {
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

    pub(crate) fn terminal(self) -> bool {
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
    pub(crate) created_unix_ms: i64,
    pub(crate) updated_unix_ms: i64,
}

pub(crate) struct SupervisorStore {
    connection: Connection,
    root: PathBuf,
    operation_events: broadcast::Sender<OperationRecord>,
}

pub(crate) struct SupervisorOperationReader {
    connection: Connection,
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
                return Ok((None, SupervisorState::default()));
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
        require_persistent_wal(&connection)?;
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
            operation_events: broadcast::channel(OPERATION_EVENT_CAPACITY).0,
        };
        let state = store.load_state()?;
        Ok((Some(store), state))
    }

    pub(crate) fn open_for_boot(
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
            operation_events: broadcast::channel(OPERATION_EVENT_CAPACITY).0,
        };
        store.ensure_metadata(boot_id)?;
        let mut state = store.load_state()?;
        if store.reconcile_host_boot(boot_id)? {
            state = store.load_state()?;
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
        let _ = self.operation_events.send(record.clone());
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
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let (record, _) = advance_operation_in_transaction(
            &transaction,
            operation_id,
            expected_checkpoint,
            phase,
            result,
            error_code,
        )?;
        transaction.commit()?;
        let _ = self.operation_events.send(record.clone());
        Ok(record)
    }

    pub(crate) fn replace_state_and_advance_operation(
        &self,
        state: &SupervisorState,
        operation_id: Uuid,
        expected_checkpoint: u32,
        phase: OperationPhase,
        result: Option<&serde_json::Value>,
        error_code: Option<&str>,
    ) -> Result<OperationRecord, SupervisorStoreError> {
        state
            .validate()
            .map_err(|_| SupervisorStoreError::InvalidState)?;
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let (record, advanced) = advance_operation_in_transaction(
            &transaction,
            operation_id,
            expected_checkpoint,
            phase,
            result,
            error_code,
        )?;
        if advanced {
            write_state(&transaction, state)?;
        }
        transaction.commit()?;
        validate_database_files(&PrivateRoot::open(&self.root)?, true)?;
        let _ = self.operation_events.send(record.clone());
        Ok(record)
    }

    pub(crate) fn pending_operations(&self) -> Result<Vec<OperationRecord>, SupervisorStoreError> {
        let mut statement = self.connection.prepare(
            "SELECT operation_id, request_id, environment_id, kind, phase, checkpoint,
                    payload_json, result_json, error_code, created_unix_ms, updated_unix_ms
             FROM operations
             WHERE phase NOT IN ('completed', 'failed', 'interrupted')
             ORDER BY created_unix_ms, operation_id",
        )?;
        let rows = statement.query_map([], decode_operation_row)?;
        rows.map(|row| row.map_err(Into::into)).collect()
    }

    pub(crate) fn host_reboot_interrupted_workspace_transitions(
        &self,
    ) -> Result<Vec<OperationRecord>, SupervisorStoreError> {
        let Some(encoded) =
            metadata_value(&self.connection, HOST_REBOOT_WORKSPACE_TRANSITIONS_KEY)?
        else {
            return Ok(Vec::new());
        };
        if encoded.len() > MAXIMUM_OPERATION_BYTES {
            return Err(SupervisorStoreError::InvalidOperation);
        }
        let ids: Vec<String> =
            serde_json::from_str(&encoded).map_err(|_| SupervisorStoreError::InvalidOperation)?;
        let mut unique = std::collections::BTreeSet::new();
        let mut operations = Vec::with_capacity(ids.len());
        for id in ids {
            let id = parse_uuid(&id)?;
            if !unique.insert(id) {
                return Err(SupervisorStoreError::InvalidOperation);
            }
            let operation = operation_for_id(&self.connection, id)?
                .ok_or(SupervisorStoreError::OperationNotFound)?;
            if operation.phase != OperationPhase::Interrupted
                || operation.error_code.as_deref() != Some("host_reboot")
                || !matches!(
                    operation.kind,
                    OperationKind::UpdateWorkspace | OperationKind::RollbackWorkspace
                )
            {
                return Err(SupervisorStoreError::InvalidOperation);
            }
            operations.push(operation);
        }
        Ok(operations)
    }

    pub(crate) fn clear_host_reboot_workspace_transitions(
        &self,
    ) -> Result<(), SupervisorStoreError> {
        self.connection.execute(
            "DELETE FROM supervisor_metadata WHERE key = ?1",
            [HOST_REBOOT_WORKSPACE_TRANSITIONS_KEY],
        )?;
        Ok(())
    }

    pub(crate) fn operation_by_request(
        &self,
        request_id: Uuid,
    ) -> Result<Option<OperationRecord>, SupervisorStoreError> {
        validate_non_nil(request_id)?;
        operation_for_request(&self.connection, request_id)
    }

    pub(crate) fn operation_events(&self) -> broadcast::Sender<OperationRecord> {
        self.operation_events.clone()
    }

    pub(crate) fn namespace_id(&self) -> Result<Uuid, SupervisorStoreError> {
        metadata_value(&self.connection, "namespace_id")?
            .ok_or(SupervisorStoreError::InvalidState)
            .and_then(|value| parse_uuid(&value))
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
                    workspace_commit, source_path, project_spec_json, project_spec_sha256, \
                    runner_json, active_artifact_generation, staging_artifact_generation, \
                    active_workspace_generation_json, staging_workspace_generation_json, \
                    rollback_workspace_generation_json \
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
                row.get::<_, Vec<u8>>(9)?,
                row.get::<_, String>(10)?,
                row.get::<_, Option<Vec<u8>>>(11)?,
                row.get::<_, String>(12)?,
                row.get::<_, Option<String>>(13)?,
                row.get::<_, Option<Vec<u8>>>(14)?,
                row.get::<_, Option<Vec<u8>>>(15)?,
                row.get::<_, Option<Vec<u8>>>(16)?,
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
                project_spec_json,
                project_spec_sha256,
                runner_json,
                active_artifact_generation,
                staging_artifact_generation,
                active_workspace_generation_json,
                staging_workspace_generation_json,
                rollback_workspace_generation_json,
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
                project_spec_json: Some(project_spec_json),
                project_spec_sha256: Some(project_spec_sha256),
                runner,
                active_artifact_generation: Some(active_artifact_generation),
                staging_artifact_generation,
                active_workspace_generation: decode_workspace_generation(
                    active_workspace_generation_json.as_deref(),
                )?,
                staging_workspace_generation: decode_workspace_generation(
                    staging_workspace_generation_json.as_deref(),
                )?,
                rollback_workspace_generation: decode_workspace_generation(
                    rollback_workspace_generation_json.as_deref(),
                )?,
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
        let interrupted_workspace_transitions = {
            let mut ids = match metadata_value(&transaction, HOST_REBOOT_WORKSPACE_TRANSITIONS_KEY)?
            {
                Some(encoded) => {
                    if encoded.len() > MAXIMUM_OPERATION_BYTES {
                        return Err(SupervisorStoreError::InvalidOperation);
                    }
                    serde_json::from_str::<Vec<String>>(&encoded)
                        .map_err(|_| SupervisorStoreError::InvalidOperation)?
                }
                None => Vec::new(),
            };
            let mut statement = transaction.prepare(
                "SELECT operation_id FROM operations
                 WHERE phase NOT IN ('completed', 'failed', 'interrupted')
                   AND kind IN ('update_workspace', 'rollback_workspace')
                 ORDER BY created_unix_ms, operation_id",
            )?;
            let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
            ids.extend(rows.collect::<Result<Vec<_>, _>>()?);
            let mut unique = std::collections::BTreeSet::new();
            for id in &ids {
                if !unique.insert(parse_uuid(id)?) {
                    return Err(SupervisorStoreError::InvalidOperation);
                }
            }
            serde_json::to_string(&ids).map_err(|_| SupervisorStoreError::InvalidOperation)?
        };
        if interrupted_workspace_transitions.len() > MAXIMUM_OPERATION_BYTES {
            return Err(SupervisorStoreError::InvalidOperation);
        }
        transaction.execute(
            "INSERT INTO supervisor_metadata(key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![
                HOST_REBOOT_WORKSPACE_TRANSITIONS_KEY,
                interrupted_workspace_transitions
            ],
        )?;
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

    #[cfg(test)]
    fn metadata(&self, key: &str) -> Option<String> {
        metadata_value(&self.connection, key).unwrap()
    }
}

impl SupervisorOperationReader {
    pub(crate) fn open(root: &PrivateRoot) -> Result<Self, SupervisorStoreError> {
        let relative = Path::new(DATABASE_FILE);
        let opened = root.open_regular(relative, false, None, false, Some(0o600))?;
        let identity = opened.identity().clone();
        drop(opened);
        let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        let connection = Connection::open_with_flags(root.path().join(relative), flags)?;
        connection.busy_timeout(BUSY_TIMEOUT)?;
        connection.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)?;
        connection.pragma_update(None, "foreign_keys", true)?;
        connection.pragma_update(None, "trusted_schema", false)?;
        require_persistent_wal(&connection)?;
        validate_schema(&connection)?;
        validate_database(&connection)?;
        let reopened = root.open_regular(relative, false, None, false, Some(0o600))?;
        if reopened.identity() != &identity {
            return Err(SupervisorStoreError::DatabaseIdentityChanged);
        }
        validate_database_files(root, false)?;
        Ok(Self { connection })
    }

    pub(crate) fn operation_by_id(
        &self,
        operation_id: Uuid,
    ) -> Result<Option<OperationRecord>, SupervisorStoreError> {
        validate_non_nil(operation_id)?;
        operation_for_id(&self.connection, operation_id)
    }

    pub(crate) fn recent_environment_operations(
        &self,
        environment_id: Uuid,
    ) -> Result<Vec<OperationRecord>, SupervisorStoreError> {
        validate_non_nil(environment_id)?;
        let limit = i64::try_from(MAXIMUM_DIAGNOSTIC_OPERATIONS)
            .map_err(|_| SupervisorStoreError::InvalidOperation)?;
        let mut statement = self.connection.prepare(
            "SELECT operation_id, request_id, environment_id, kind, phase, checkpoint,
                    payload_json, result_json, error_code, created_unix_ms, updated_unix_ms
             FROM operations
             WHERE environment_id = ?1
             ORDER BY updated_unix_ms DESC, operation_id DESC
             LIMIT ?2",
        )?;
        let rows = statement.query_map(
            params![environment_id.to_string(), limit],
            decode_operation_row,
        )?;
        let mut operations = rows
            .map(|row| row.map_err(Into::into))
            .collect::<Result<Vec<_>, SupervisorStoreError>>()?;
        operations.reverse();
        Ok(operations)
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
    require_persistent_wal(connection)?;
    connection.pragma_update(None, "wal_autocheckpoint", 100_i64)?;
    Ok(())
}

fn require_persistent_wal(connection: &Connection) -> Result<(), SupervisorStoreError> {
    fn control(connection: &Connection, value: &mut i32) -> i32 {
        // SAFETY: the connection remains borrowed for the call, `main` is a
        // static NUL-terminated schema name, and this opcode reads or writes
        // exactly the pointed-to integer.
        unsafe {
            rusqlite::ffi::sqlite3_file_control(
                connection.handle(),
                c"main".as_ptr(),
                rusqlite::ffi::SQLITE_FCNTL_PERSIST_WAL,
                std::ptr::from_mut(value).cast(),
            )
        }
    }

    let mut enabled = 1;
    if control(connection, &mut enabled) != rusqlite::ffi::SQLITE_OK {
        return Err(SupervisorStoreError::InvalidDatabase);
    }
    let mut observed = -1;
    if control(connection, &mut observed) != rusqlite::ffi::SQLITE_OK || observed != 1 {
        return Err(SupervisorStoreError::InvalidDatabase);
    }
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
           project_spec_json BLOB NOT NULL,
           project_spec_sha256 TEXT NOT NULL,
           runner_json BLOB NULL,
           active_artifact_generation TEXT NOT NULL,
           staging_artifact_generation TEXT NULL,
           active_workspace_generation_json BLOB NULL,
           staging_workspace_generation_json BLOB NULL,
           rollback_workspace_generation_json BLOB NULL
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
         PRAGMA user_version = 4;
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
    for column in [
        "project_spec_json",
        "project_spec_sha256",
        "active_workspace_generation_json",
        "staging_workspace_generation_json",
        "rollback_workspace_generation_json",
    ] {
        let present = connection
            .query_row(
                "SELECT 1 FROM pragma_table_info('environments') WHERE name = ?1",
                [column],
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
        let active_workspace_generation_json =
            encode_workspace_generation(environment.active_workspace_generation.as_ref())?;
        let staging_workspace_generation_json =
            encode_workspace_generation(environment.staging_workspace_generation.as_ref())?;
        let rollback_workspace_generation_json =
            encode_workspace_generation(environment.rollback_workspace_generation.as_ref())?;
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
               active_artifact_generation, staging_artifact_generation,
               project_spec_json, project_spec_sha256,
               active_workspace_generation_json, staging_workspace_generation_json,
               rollback_workspace_generation_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)
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
               staging_artifact_generation = excluded.staging_artifact_generation,
               project_spec_json = excluded.project_spec_json,
               project_spec_sha256 = excluded.project_spec_sha256,
               active_workspace_generation_json = excluded.active_workspace_generation_json,
               staging_workspace_generation_json = excluded.staging_workspace_generation_json,
               rollback_workspace_generation_json = excluded.rollback_workspace_generation_json",
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
                &environment.project_spec_json,
                &environment.project_spec_sha256,
                active_workspace_generation_json,
                staging_workspace_generation_json,
                rollback_workspace_generation_json,
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
        if matches!(
            environment.state,
            StoredEnvironmentState::Starting | StoredEnvironmentState::Error
        ) && environment.generation == 0
        {
            let relative_path = format!("engine/provision-{}", environment.id);
            transaction.execute(
                "INSERT INTO owned_objects(
                   environment_id, kind, relative_path, identity_json, lifecycle
                 ) VALUES (?1, 'workspace_staging', ?2, NULL, 'staging')",
                params![environment.id.to_string(), relative_path.as_bytes()],
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

fn encode_workspace_generation(
    generation: Option<&WorkspaceGenerationRecord>,
) -> Result<Option<Vec<u8>>, SupervisorStoreError> {
    generation
        .map(WorkspaceGenerationRecord::encode_canonical)
        .transpose()
        .map_err(|_| SupervisorStoreError::InvalidState)
}

fn decode_workspace_generation(
    bytes: Option<&[u8]>,
) -> Result<Option<WorkspaceGenerationRecord>, SupervisorStoreError> {
    bytes
        .map(WorkspaceGenerationRecord::decode_canonical)
        .transpose()
        .map_err(|_| SupervisorStoreError::InvalidState)
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
                    payload_json, result_json, error_code, created_unix_ms, updated_unix_ms
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
                    payload_json, result_json, error_code, created_unix_ms, updated_unix_ms
             FROM operations WHERE operation_id = ?1",
            [operation_id.to_string()],
            decode_operation_row,
        )
        .optional()
        .map_err(Into::into)
}

fn advance_operation_in_transaction(
    transaction: &Transaction<'_>,
    operation_id: Uuid,
    expected_checkpoint: u32,
    phase: OperationPhase,
    result: Option<&serde_json::Value>,
    error_code: Option<&str>,
) -> Result<(OperationRecord, bool), SupervisorStoreError> {
    validate_non_nil(operation_id)?;
    validate_operation_outcome(phase, result, error_code)?;
    let result_bytes = result.map(encode_operation_json).transpose()?;
    let next_checkpoint = expected_checkpoint
        .checked_add(1)
        .ok_or(SupervisorStoreError::InvalidOperation)?;
    let current = operation_for_id(transaction, operation_id)?
        .ok_or(SupervisorStoreError::OperationNotFound)?;
    if current.checkpoint > expected_checkpoint {
        if current.checkpoint == next_checkpoint
            && current.phase == phase
            && current.result.as_ref() == result
            && current.error_code.as_deref() == error_code
        {
            return Ok((current, false));
        }
        return Err(SupervisorStoreError::JournalConflict);
    }
    if current.checkpoint != expected_checkpoint || !valid_phase_transition(current.phase, phase) {
        return Err(SupervisorStoreError::JournalConflict);
    }
    // Wall clocks can step backwards. Public operation timestamps must remain
    // monotonic even when the host clock is corrected during a long boot.
    let updated_unix_ms = unix_millis()?.max(current.updated_unix_ms);
    let updated = transaction.execute(
        "UPDATE operations \
         SET phase = ?1, checkpoint = ?2, result_json = ?3, error_code = ?4, updated_unix_ms = ?5 \
         WHERE operation_id = ?6 AND checkpoint = ?7",
        params![
            phase.as_str(),
            i64::from(next_checkpoint),
            result_bytes,
            error_code,
            updated_unix_ms,
            operation_id.to_string(),
            i64::from(expected_checkpoint),
        ],
    )?;
    if updated != 1 {
        return Err(SupervisorStoreError::JournalConflict);
    }
    operation_for_id(transaction, operation_id)?
        .map(|record| (record, true))
        .ok_or(SupervisorStoreError::OperationNotFound)
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
    let created_unix_ms = row.get::<_, i64>(9)?;
    let updated_unix_ms = row.get::<_, i64>(10)?;
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
        created_unix_ms,
        updated_unix_ms,
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
    created_unix_ms: i64,
    updated_unix_ms: i64,
) -> Result<OperationRecord, SupervisorStoreError> {
    if created_unix_ms < 0 || updated_unix_ms < created_unix_ms {
        return Err(SupervisorStoreError::InvalidOperation);
    }
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
        created_unix_ms,
        updated_unix_ms,
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

    use codewire_vmm_guest_probe::{SetupArchitecture, Sha256Value, oci_root_generation};
    use sha2::{Digest as _, Sha256};

    use crate::linux::path::{FileIdentity, SocketIdentity, current_uid};
    use crate::linux::process::ProcessIdentity;
    use crate::oci::{
        OciArchitecture, ResolvedDescriptor, ResolvedImage, ResolvedLayer, Sha256Digest,
    };

    use super::*;

    type EncodedGenerationSlots = (Option<Vec<u8>>, Option<Vec<u8>>, Option<Vec<u8>>);

    fn root() -> (tempfile::TempDir, PrivateRoot) {
        let parent = tempfile::tempdir().unwrap();
        let root_path = parent.path().join("root");
        fs::create_dir(&root_path).unwrap();
        fs::set_permissions(&root_path, fs::Permissions::from_mode(0o700)).unwrap();
        let root = PrivateRoot::open(&root_path).unwrap();
        (parent, root)
    }

    fn project_intent() -> (Vec<u8>, String) {
        let spec = codewire_project::ProjectSpec {
            image: "registry.example/codewire/workspace:latest".to_owned(),
            resources: codewire_project::ResourceSpec {
                cpu_millicores: Some(2_000),
                memory_mib: Some(16 * 1024),
                disk_gib: Some(1),
            },
            ..Default::default()
        };
        let bytes = spec.canonical_json().unwrap();
        let digest = format!("{:x}", Sha256::digest(&bytes));
        (bytes, digest)
    }

    fn oci_digest(seed: &[u8]) -> Sha256Digest {
        Sha256Digest::parse(&format!("sha256:{:x}", Sha256::digest(seed))).unwrap()
    }

    fn workspace_generation(
        project_spec_json: &[u8],
        project_sha256: &str,
        seed: &[u8],
    ) -> WorkspaceGenerationRecord {
        let architecture = OciArchitecture::native().unwrap();
        let manifest_digest = oci_digest(&[seed, b"-manifest"].concat());
        let manifest = ResolvedDescriptor {
            media_type: "application/vnd.oci.image.manifest.v1+json".to_owned(),
            digest: manifest_digest.clone(),
            size: 512,
        };
        let image = ResolvedImage {
            source_reference: "registry.example/codewire/workspace:latest".to_owned(),
            architecture,
            source: manifest.clone(),
            manifest,
            config: ResolvedDescriptor {
                media_type: "application/vnd.oci.image.config.v1+json".to_owned(),
                digest: oci_digest(&[seed, b"-config"].concat()),
                size: 256,
            },
            layers: vec![ResolvedLayer {
                descriptor: ResolvedDescriptor {
                    media_type: "application/vnd.oci.image.layer.v1.tar+gzip".to_owned(),
                    digest: oci_digest(&[seed, b"-layer"].concat()),
                    size: 1024,
                },
                diff_id: oci_digest(&[seed, b"-diff"].concat()),
            }],
        };
        let setup_architecture = match architecture {
            OciArchitecture::Amd64 => SetupArchitecture::Amd64,
            OciArchitecture::Arm64 => SetupArchitecture::Arm64,
        };
        let root_generation = oci_root_generation(
            Sha256Value::parse_hex(project_sha256).unwrap(),
            Sha256Value::parse_digest(image.manifest.digest.as_str()).unwrap(),
            setup_architecture,
        )
        .to_string();
        WorkspaceGenerationRecord {
            schema_version: 3,
            root_generation,
            project_sha256: project_sha256.to_owned(),
            project_spec_json: String::from_utf8(project_spec_json.to_vec()).unwrap(),
            artifact_generation: "c".repeat(64),
            image,
            root_disk_bytes: crate::linux::state::MINIMUM_ROOT_DISK_BYTES,
        }
    }

    fn environment(
        state: StoredEnvironmentState,
        runner_boot_id: Option<&str>,
    ) -> EnvironmentRecord {
        let (project_spec_json, project_spec_sha256) = project_intent();
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
            artifact_generation: "c".repeat(64),
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
            project_spec_json: Some(project_spec_json),
            project_spec_sha256: Some(project_spec_sha256),
            runner,
            active_artifact_generation: Some("c".repeat(64)),
            staging_artifact_generation: None,
            active_workspace_generation: None,
            staging_workspace_generation: None,
            rollback_workspace_generation: None,
        }
    }

    #[test]
    fn runner_record_requires_an_exact_artifact_generation() {
        let runner = environment(StoredEnvironmentState::Stopped, Some("boot"))
            .runner
            .unwrap();
        let mut value = serde_json::to_value(runner).unwrap();
        value.as_object_mut().unwrap().remove("artifact_generation");

        assert!(serde_json::from_value::<RunnerRecord>(value).is_err());
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
    fn wal_sidecars_remain_named_across_independent_readers_and_reopen() {
        let (_parent, root) = root();
        let database = root.path().join(DATABASE_FILE);
        let operation_id;
        {
            let (store, _) = SupervisorStore::open_for_boot(&root, "boot-a").unwrap();
            let reader = SupervisorOperationReader::open(&root).unwrap();
            let operation = store
                .begin_operation(
                    Uuid::new_v4(),
                    Some(Uuid::new_v4()),
                    OperationKind::Start,
                    &serde_json::json!({"name": "dev", "generation": 1}),
                )
                .unwrap();
            operation_id = operation.operation_id;

            let external = Connection::open_with_flags(
                &database,
                OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
            )
            .unwrap();
            assert_eq!(
                operation_for_id(&external, operation_id).unwrap(),
                Some(operation.clone())
            );
            drop(external);
            for sidecar in [DATABASE_WAL_FILE, DATABASE_SHM_FILE] {
                let metadata = fs::symlink_metadata(root.path().join(sidecar)).unwrap();
                assert!(metadata.is_file());
                assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
            }

            let completed = store
                .advance_operation(
                    operation_id,
                    operation.checkpoint,
                    OperationPhase::Completed,
                    Some(&serde_json::json!({"name": "dev"})),
                    None,
                )
                .unwrap();
            assert_eq!(
                reader.operation_by_id(operation_id).unwrap(),
                Some(completed)
            );
        }

        for sidecar in [DATABASE_WAL_FILE, DATABASE_SHM_FILE] {
            let metadata = fs::symlink_metadata(root.path().join(sidecar)).unwrap();
            assert!(metadata.is_file());
            assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        }
        let (reopened, _) = SupervisorStore::open_for_boot(&root, "boot-a").unwrap();
        assert!(
            operation_for_id(&reopened.connection, operation_id)
                .unwrap()
                .unwrap()
                .phase
                .terminal()
        );
    }

    #[test]
    fn diagnostic_operation_reader_is_environment_scoped_and_chronological() {
        let (_parent, root) = root();
        let (store, _) = SupervisorStore::open_for_boot(&root, "boot-a").unwrap();
        let environment_id = Uuid::new_v4();
        let other_environment_id = Uuid::new_v4();
        let first = store
            .begin_operation(
                Uuid::new_v4(),
                Some(environment_id),
                OperationKind::Start,
                &serde_json::json!({"name": "dev", "generation": 1}),
            )
            .unwrap();
        let second = store
            .begin_operation(
                Uuid::new_v4(),
                Some(environment_id),
                OperationKind::Stop,
                &serde_json::json!({"name": "dev"}),
            )
            .unwrap();
        store
            .begin_operation(
                Uuid::new_v4(),
                Some(other_environment_id),
                OperationKind::Stop,
                &serde_json::json!({"name": "other"}),
            )
            .unwrap();
        let timestamp = first.created_unix_ms.max(second.created_unix_ms);
        store
            .connection
            .execute(
                "UPDATE operations SET updated_unix_ms = ?1 WHERE operation_id = ?2",
                params![timestamp + 10, first.operation_id.to_string()],
            )
            .unwrap();
        store
            .connection
            .execute(
                "UPDATE operations SET updated_unix_ms = ?1 WHERE operation_id = ?2",
                params![timestamp + 20, second.operation_id.to_string()],
            )
            .unwrap();

        let reader = SupervisorOperationReader::open(&root).unwrap();
        let operations = reader
            .recent_environment_operations(environment_id)
            .unwrap();
        assert_eq!(operations.len(), 2);
        assert_eq!(operations[0].operation_id, first.operation_id);
        assert_eq!(operations[1].operation_id, second.operation_id);
        assert!(
            operations
                .iter()
                .all(|operation| operation.environment_id == Some(environment_id))
        );
    }

    #[test]
    fn database_reopen_on_another_boot_stops_every_environment() {
        let (_parent, root) = root();
        let (store, _) = SupervisorStore::open_for_boot(&root, "boot-a").unwrap();
        let expected = state(environment(StoredEnvironmentState::Running, Some("boot-a")));
        let environment_id = expected.environments["dev"].id;
        store.replace_state(&expected).unwrap();
        let request_id = Uuid::new_v4();
        store
            .begin_operation(
                request_id,
                Some(environment_id),
                OperationKind::Start,
                &serde_json::json!({"name": "dev", "generation": 8}),
            )
            .unwrap();
        drop(store);

        let (reopened, loaded) = SupervisorStore::open_for_boot(&root, "boot-b").unwrap();
        let environment = loaded.environments.get("dev").unwrap();
        assert_eq!(environment.state, StoredEnvironmentState::Stopped);
        assert!(environment.runner.is_none());
        assert_eq!(reopened.metadata("host_boot_id").as_deref(), Some("boot-b"));
        let interrupted = reopened.operation_by_request(request_id).unwrap().unwrap();
        assert_eq!(interrupted.phase, OperationPhase::Interrupted);
        assert_eq!(interrupted.checkpoint, 0);
        assert_eq!(interrupted.error_code.as_deref(), Some("host_reboot"));
        assert!(reopened.pending_operations().unwrap().is_empty());
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
    fn read_only_inspection_without_database_is_empty_and_nonmutating() {
        let (_parent, root) = root();

        let (store, inspected) = SupervisorStore::inspect(&root).unwrap();
        assert!(store.is_none());
        assert_eq!(inspected, SupervisorState::default());
        assert!(!root.path().join(DATABASE_FILE).exists());
    }

    #[test]
    fn older_database_schema_is_rejected_without_mutation() {
        let (_parent, root) = root();
        let (store, _) = SupervisorStore::open_for_boot(&root, "boot-a").unwrap();
        store
            .connection
            .pragma_update(None, "user_version", 3_i64)
            .unwrap();
        drop(store);
        let database = root.path().join(DATABASE_FILE);
        let before = fs::read(&database).unwrap();

        assert!(matches!(
            SupervisorStore::open_for_boot(&root, "boot-a"),
            Err(SupervisorStoreError::UnsupportedSchema {
                application_id: DATABASE_APPLICATION_ID,
                schema_version: 3,
            })
        ));
        assert_eq!(fs::read(database).unwrap(), before);
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
    fn workspace_generation_slots_persist_as_exact_canonical_records() {
        let (_parent, root) = root();
        let (store, _) = SupervisorStore::open_for_boot(&root, "boot-a").unwrap();
        let (project_json, project_sha256) = project_intent();
        let mut environment = environment(StoredEnvironmentState::Stopped, None);
        environment.disk_bytes = 1024 * 1024 * 1024;
        environment.project_spec_json = Some(project_json.clone());
        environment.project_spec_sha256 = Some(project_sha256.clone());
        environment.active_workspace_generation = Some(workspace_generation(
            &project_json,
            &project_sha256,
            b"active",
        ));
        environment.staging_workspace_generation = Some(workspace_generation(
            &project_json,
            &project_sha256,
            b"staging",
        ));
        environment.rollback_workspace_generation = Some(workspace_generation(
            &project_json,
            &project_sha256,
            b"rollback",
        ));
        let expected = state(environment);
        let environment = &expected.environments["dev"];

        store.replace_state(&expected).unwrap();
        let encoded: EncodedGenerationSlots = store
            .connection
            .query_row(
                "SELECT active_workspace_generation_json,
                        staging_workspace_generation_json,
                        rollback_workspace_generation_json
                 FROM environments WHERE id = ?1",
                [environment.id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(
            encoded.0.as_deref(),
            Some(
                environment
                    .active_workspace_generation
                    .as_ref()
                    .unwrap()
                    .encode_canonical()
                    .unwrap()
                    .as_slice()
            )
        );
        assert_eq!(
            encoded.1.as_deref(),
            Some(
                environment
                    .staging_workspace_generation
                    .as_ref()
                    .unwrap()
                    .encode_canonical()
                    .unwrap()
                    .as_slice()
            )
        );
        assert_eq!(
            encoded.2.as_deref(),
            Some(
                environment
                    .rollback_workspace_generation
                    .as_ref()
                    .unwrap()
                    .encode_canonical()
                    .unwrap()
                    .as_slice()
            )
        );
        drop(store);

        let (_reopened, persisted) = SupervisorStore::open_for_boot(&root, "boot-a").unwrap();
        assert_eq!(persisted, expected);
    }

    #[test]
    fn workspace_generation_slot_invariants_fail_closed() {
        let (project_json, project_sha256) = project_intent();
        let mut environment = environment(StoredEnvironmentState::Stopped, None);
        environment.disk_bytes = 1024 * 1024 * 1024;
        environment.project_spec_json = Some(project_json.clone());
        environment.project_spec_sha256 = Some(project_sha256.clone());
        let generation = workspace_generation(&project_json, &project_sha256, b"same");

        environment.active_workspace_generation = Some(generation.clone());
        environment.staging_workspace_generation = Some(generation.clone());
        assert!(state(environment.clone()).validate().is_ok());

        environment.staging_workspace_generation = None;
        environment.rollback_workspace_generation = Some(generation.clone());
        assert!(state(environment.clone()).validate().is_err());

        environment.rollback_workspace_generation = None;
        let mut invalid_generation = generation;
        invalid_generation.project_sha256 = "f".repeat(64);
        environment.active_workspace_generation = Some(invalid_generation);
        environment.rollback_workspace_generation = None;
        assert!(state(environment).validate().is_err());
    }

    #[test]
    fn create_manifest_owns_its_replayable_workspace_staging_path() {
        let (_parent, root) = root();
        let (store, _) = SupervisorStore::open_for_boot(&root, "boot-a").unwrap();
        let mut environment = environment(StoredEnvironmentState::Starting, None);
        environment.generation = 0;
        let environment_id = environment.id;
        store.replace_state(&state(environment)).unwrap();

        let staging: (Vec<u8>, String) = store
            .connection
            .query_row(
                "SELECT relative_path, lifecycle FROM owned_objects \
                 WHERE environment_id = ?1 AND kind = 'workspace_staging'",
                [environment_id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(
            staging,
            (
                format!("engine/provision-{environment_id}").into_bytes(),
                "staging".to_owned(),
            )
        );
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

    #[tokio::test]
    async fn operation_reader_and_events_follow_the_durable_journal() {
        let (_parent, root) = root();
        let (store, _) = SupervisorStore::open_for_boot(&root, "boot-a").unwrap();
        let reader = SupervisorOperationReader::open(&root).unwrap();
        let mut events = store.operation_events().subscribe();
        let operation = store
            .begin_operation(
                Uuid::new_v4(),
                Some(Uuid::new_v4()),
                OperationKind::Start,
                &serde_json::json!({"name": "dev", "generation": 1}),
            )
            .unwrap();
        assert_eq!(events.recv().await.unwrap(), operation);
        assert_eq!(
            reader.operation_by_id(operation.operation_id).unwrap(),
            Some(operation.clone())
        );

        let completed = store
            .advance_operation(
                operation.operation_id,
                operation.checkpoint,
                OperationPhase::Completed,
                Some(&serde_json::json!({"name": "dev"})),
                None,
            )
            .unwrap();
        assert!(completed.phase.terminal());
        assert!(completed.updated_unix_ms >= completed.created_unix_ms);
        assert_eq!(events.recv().await.unwrap(), completed);
        assert_eq!(
            reader.operation_by_id(operation.operation_id).unwrap(),
            Some(completed)
        );
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
    fn state_and_checkpoint_commit_atomically_without_replay_overwrite() {
        let (_parent, root) = root();
        let (store, _) = SupervisorStore::open_for_boot(&root, "boot-a").unwrap();
        let environment = environment(StoredEnvironmentState::Starting, None);
        let operation = store
            .begin_operation(
                Uuid::new_v4(),
                Some(environment.id),
                OperationKind::Create,
                &serde_json::json!({"name": "dev"}),
            )
            .unwrap();
        let expected = state(environment);

        let applied = store
            .replace_state_and_advance_operation(
                &expected,
                operation.operation_id,
                operation.checkpoint,
                OperationPhase::EffectApplied,
                None,
                None,
            )
            .unwrap();
        assert_eq!(applied.checkpoint, 1);
        assert_eq!(store.load_state().unwrap(), expected);

        let mut stale_replay = expected.clone();
        stale_replay.environments.get_mut("dev").unwrap().memory_mib = 8 * 1024;
        assert_eq!(
            store
                .replace_state_and_advance_operation(
                    &stale_replay,
                    operation.operation_id,
                    operation.checkpoint,
                    OperationPhase::EffectApplied,
                    None,
                    None,
                )
                .unwrap(),
            applied
        );
        assert_eq!(store.load_state().unwrap(), expected);

        let mut conflicting = expected.clone();
        conflicting.environments.get_mut("dev").unwrap().vcpus = 4;
        assert!(matches!(
            store.replace_state_and_advance_operation(
                &conflicting,
                operation.operation_id,
                7,
                OperationPhase::EffectApplied,
                None,
                None,
            ),
            Err(SupervisorStoreError::JournalConflict)
        ));
        assert_eq!(store.load_state().unwrap(), expected);
    }

    #[test]
    fn staging_generation_and_lifecycle_checkpoint_commit_atomically() {
        let (_parent, root) = root();
        let (store, _) = SupervisorStore::open_for_boot(&root, "boot-a").unwrap();
        let (project_json, project_sha256) = project_intent();
        let mut environment = environment(StoredEnvironmentState::Starting, None);
        environment.disk_bytes = 1024 * 1024 * 1024;
        environment.project_spec_json = Some(project_json.clone());
        environment.project_spec_sha256 = Some(project_sha256.clone());
        let environment_id = environment.id;
        let initial = state(environment);
        store.replace_state(&initial).unwrap();
        let operation = store
            .begin_operation(
                Uuid::new_v4(),
                Some(environment_id),
                OperationKind::Start,
                &serde_json::json!({"name": "dev", "generation": 8}),
            )
            .unwrap();
        let mut staged = initial;
        let staging_generation = workspace_generation(&project_json, &project_sha256, b"staging");
        staged
            .environments
            .get_mut("dev")
            .unwrap()
            .staging_workspace_generation = Some(staging_generation);

        let applied = store
            .replace_state_and_advance_operation(
                &staged,
                operation.operation_id,
                operation.checkpoint,
                OperationPhase::EffectApplied,
                None,
                None,
            )
            .unwrap();
        assert_eq!(applied.checkpoint, 1);
        drop(store);

        let (reopened, persisted) = SupervisorStore::open_for_boot(&root, "boot-a").unwrap();
        assert_eq!(persisted, staged);
        assert_eq!(
            reopened.operation_by_request(operation.request_id).unwrap(),
            Some(applied)
        );
    }

    #[test]
    fn disk_full_rolls_back_state_and_checkpoint_for_retry() {
        let (_parent, root) = root();
        let (store, _) = SupervisorStore::open_for_boot(&root, "boot-a").unwrap();
        let environment = environment(StoredEnvironmentState::Starting, None);
        let operation = store
            .begin_operation(
                Uuid::new_v4(),
                Some(environment.id),
                OperationKind::Create,
                &serde_json::json!({"name": "dev"}),
            )
            .unwrap();
        let initial = state(environment);
        store.replace_state(&initial).unwrap();
        let mut expanded = initial.clone();
        expanded.environments.get_mut("dev").unwrap().source_path =
            PathBuf::from(format!("/{}", "x".repeat(512 * 1024)));

        let page_count: i64 = store
            .connection
            .pragma_query_value(None, "page_count", |row| row.get(0))
            .unwrap();
        store
            .connection
            .pragma_update(None, "max_page_count", page_count)
            .unwrap();
        assert!(matches!(
            store.replace_state_and_advance_operation(
                &expanded,
                operation.operation_id,
                operation.checkpoint,
                OperationPhase::EffectApplied,
                None,
                None,
            ),
            Err(SupervisorStoreError::Sqlite(rusqlite::Error::SqliteFailure(
                error,
                _,
            ))) if error.code == rusqlite::ErrorCode::DiskFull
        ));
        assert_eq!(store.load_state().unwrap(), initial);
        assert_eq!(
            store.operation_by_request(operation.request_id).unwrap(),
            Some(operation.clone())
        );

        store
            .connection
            .pragma_update(None, "max_page_count", page_count + 1024)
            .unwrap();
        let applied = store
            .replace_state_and_advance_operation(
                &expanded,
                operation.operation_id,
                operation.checkpoint,
                OperationPhase::EffectApplied,
                None,
                None,
            )
            .unwrap();
        assert_eq!(applied.checkpoint, 1);
        assert_eq!(store.load_state().unwrap(), expanded);
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
