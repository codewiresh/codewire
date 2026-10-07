//! Durable, owner-only state for the native local supervisor.
//!
//! SQLite is the sole authority. The supervisor singleton is the only writer,
//! but WAL and explicit replay
//! records keep every lifecycle transition recoverable across process death.

use std::collections::BTreeMap;
#[cfg(any(target_os = "linux", test))]
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use codewire_access::EnvironmentId;
#[cfg(test)]
use codewire_access::{AccessProfileId, EnvironmentAccessBinding};
use rusqlite::config::DbConfig;
use rusqlite::{
    Connection, OpenFlags, OptionalExtension as _, Transaction, TransactionBehavior, params,
};
use tokio::sync::broadcast;
use uuid::Uuid;

use crate::host::path::{PathError, PrivateRoot};
#[cfg(test)]
use crate::host_port::HostPortBinding;
use crate::host_port::validate_canonical_host_port_bindings;
#[cfg(test)]
use crate::mesh_ingress::MeshAttachment;
#[cfg(test)]
use crate::supervisor::RunnerRecord;
use crate::supervisor::{EnvironmentRecord, StoredEnvironmentState, SupervisorState};
use crate::supervisor_metadata::CwRuntimeBinding;
use crate::supervisor_store_codec::{parse_uuid, require_persistent_wal};
use crate::workspace_generation::WorkspaceGenerationRecord;
#[cfg(test)]
use crate::workspace_plan::WorkspacePlan;

pub(crate) const DATABASE_FILE: &str = "supervisor.db";
const DATABASE_WAL_FILE: &str = "supervisor.db-wal";
const DATABASE_SHM_FILE: &str = "supervisor.db-shm";
const HOST_REBOOT_WORKSPACE_TRANSITIONS_KEY: &str = "host_reboot_workspace_transitions";
const DATABASE_APPLICATION_ID: i64 = 0x4357_564d; // "CWVM"
const LEGACY_DATABASE_SCHEMA_VERSION: i64 = 11;
const DATABASE_SCHEMA_VERSION: i64 = 12;
const LINUX_PLATFORM: &str = "linux-v1";
const RUNTIME_BINDING_COLUMN_SQL: &str = "cw_runtime_binding_json BLOB NULL";
const MAXIMUM_RUNTIME_BINDING_BYTES: usize = 512;
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
    UpdateEnvironmentSources,
    Delete,
    GrowDisk,
    Reconcile,
    UpdateCwRuntime,
    RollbackCwRuntime,
}

impl OperationKind {
    pub(crate) fn cw_runtime(self) -> bool {
        matches!(self, Self::UpdateCwRuntime | Self::RollbackCwRuntime)
    }
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Start => "start",
            Self::Stop => "stop",
            Self::Restart => "restart",
            Self::UpdateWorkspace => "update_workspace",
            Self::RollbackWorkspace => "rollback_workspace",
            Self::UpdateEnvironmentSources => "update_environment_sources",
            Self::Delete => "delete",
            Self::GrowDisk => "grow_disk",
            Self::Reconcile => "reconcile",
            Self::UpdateCwRuntime => "update_cw_runtime",
            Self::RollbackCwRuntime => "rollback_cw_runtime",
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
            "update_environment_sources" => Some(Self::UpdateEnvironmentSources),
            "delete" => Some(Self::Delete),
            "grow_disk" => Some(Self::GrowDisk),
            "reconcile" => Some(Self::Reconcile),
            "update_cw_runtime" => Some(Self::UpdateCwRuntime),
            "rollback_cw_runtime" => Some(Self::RollbackCwRuntime),
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
        validate_readable_schema(&connection)?;
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
            upgrade_schema(&connection)?;
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
        // A live selector intent fences lifecycle births and disruption for
        // this UUID, while read/history/message paths remain available. The
        // check and admission share the same authoritative write transaction.
        if let Some(environment_id) = environment_id
            && kind != OperationKind::Reconcile
        {
            let collision: bool = transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM operations WHERE environment_id=?1
                 AND request_id!=?2 AND kind!='reconcile' AND phase NOT IN ('completed','failed','interrupted')
                 AND (kind IN ('update_cw_runtime','rollback_cw_runtime') OR ?3))",
                params![
                    environment_id.to_string(),
                    request_id.to_string(),
                    kind.cw_runtime()
                ],
                |row| row.get(0),
            )?;
            if collision {
                return Err(SupervisorStoreError::JournalConflict);
            }
        }
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

    /// Observation-only fence for live runtime controls. Do not dispatch the
    /// selected or any other environment's pending lifecycle work here.
    #[cfg(target_os = "linux")]
    pub(crate) fn has_pending_lifecycle_operation(
        &self,
        environment_id: Uuid,
    ) -> Result<bool, SupervisorStoreError> {
        validate_non_nil(environment_id)?;
        self.connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM operations WHERE environment_id=?1
                 AND kind NOT IN ('reconcile','update_cw_runtime','rollback_cw_runtime')
                 AND phase NOT IN ('completed','failed','interrupted'))",
                [environment_id.to_string()],
                |row| row.get(0),
            )
            .map_err(Into::into)
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

    #[cfg(target_os = "linux")]
    pub(crate) fn cw_runtime_operation_by_id(
        &self,
        operation_id: Uuid,
    ) -> Result<Option<OperationRecord>, SupervisorStoreError> {
        validate_non_nil(operation_id)?;
        operation_for_id(&self.connection, operation_id)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn completed_cw_runtime_operations(
        &self,
        environment_id: Uuid,
    ) -> Result<Vec<OperationRecord>, SupervisorStoreError> {
        let mut statement = self.connection.prepare(
            "SELECT operation_id, request_id, environment_id, kind, phase, checkpoint,
                    payload_json, result_json, error_code, created_unix_ms, updated_unix_ms
             FROM operations WHERE environment_id=?1
             AND kind IN ('update_cw_runtime','rollback_cw_runtime') AND phase='completed'
             ORDER BY created_unix_ms, operation_id LIMIT 129",
        )?;
        let records = statement
            .query_map([environment_id.to_string()], decode_operation_row)?
            .map(|row| row.map_err(Into::into))
            .collect::<Result<Vec<_>, SupervisorStoreError>>()?;
        if records.len() > 128 {
            return Err(SupervisorStoreError::InvalidOperation);
        }
        Ok(records)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn interrupted_cw_runtime_operations(
        &self,
        environment_id: Uuid,
    ) -> Result<Vec<OperationRecord>, SupervisorStoreError> {
        let mut statement = self.connection.prepare(
            "SELECT operation_id, request_id, environment_id, kind, phase, checkpoint,
                    payload_json, result_json, error_code, created_unix_ms, updated_unix_ms
             FROM operations WHERE environment_id=?1
             AND kind IN ('update_cw_runtime','rollback_cw_runtime') AND phase='interrupted'
             ORDER BY created_unix_ms, operation_id LIMIT 129",
        )?;
        let records = statement
            .query_map([environment_id.to_string()], decode_operation_row)?
            .map(|row| row.map_err(Into::into))
            .collect::<Result<Vec<_>, SupervisorStoreError>>()?;
        if records.len() > 128 {
            return Err(SupervisorStoreError::InvalidOperation);
        }
        Ok(records)
    }

    // A reboot invalidates the old process, not its possible selector effect.
    // Only an exact retained guest receipt may close that particular runtime
    // interruption. No ordinary terminal operation is rewound or replayed.
    #[cfg(target_os = "linux")]
    pub(crate) fn resolve_interrupted_cw_runtime(
        &self,
        operation: &OperationRecord,
        result: &serde_json::Value,
    ) -> Result<OperationRecord, SupervisorStoreError> {
        if !operation.kind.cw_runtime()
            || operation.phase != OperationPhase::Interrupted
            || !matches!(
                operation.error_code.as_deref(),
                Some("host_reboot" | "runtime_vm_birth_lost")
            )
        {
            return Err(SupervisorStoreError::JournalConflict);
        }
        let bytes = encode_operation_json(result)?;
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let updated = transaction.execute(
            "UPDATE operations SET phase='completed', result_json=?1, error_code=NULL,
             updated_unix_ms=MAX(updated_unix_ms,?2)
             WHERE operation_id=?3 AND phase='interrupted' AND checkpoint=?4 AND error_code IN ('host_reboot','runtime_vm_birth_lost')",
            params![bytes,unix_millis()?,operation.operation_id.to_string(),operation.checkpoint],
        )?;
        if updated != 1 {
            return Err(SupervisorStoreError::JournalConflict);
        }
        let record = operation_for_id(&transaction, operation.operation_id)?
            .ok_or(SupervisorStoreError::OperationNotFound)?;
        transaction.commit()?;
        let _ = self.operation_events.send(record.clone());
        Ok(record)
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
        load_state(&self.connection)
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
             WHERE phase NOT IN ('completed', 'failed', 'interrupted')
               AND kind != 'update_environment_sources'",
            [],
        )?;
        // Source metadata and its checkpoint commit in one transaction. A host
        // reboot destroys runtime, not this exact intent: repeat stop/CAS while
        // the old selection is authoritative, otherwise restart only from the
        // already committed target. All other operation kinds stay interrupted.
        let source_effect_count =
            u32::try_from(crate::lifecycle::effects(OperationKind::UpdateEnvironmentSources).len())
                .map_err(|_| SupervisorStoreError::InvalidOperation)?;
        let source_commit_checkpoint =
            crate::lifecycle::source_reboot_checkpoint(source_effect_count)
                .map_err(|_| SupervisorStoreError::InvalidOperation)?;
        let invalid_source_checkpoint: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM operations WHERE kind = 'update_environment_sources'
             AND phase NOT IN ('completed', 'failed', 'interrupted') AND checkpoint > ?1)",
            [source_effect_count],
            |row| row.get(0),
        )?;
        if invalid_source_checkpoint {
            return Err(SupervisorStoreError::InvalidOperation);
        }
        transaction.execute(
            "UPDATE operations
             SET checkpoint = CASE WHEN checkpoint < ?1 THEN 0 ELSE ?1 END,
                 phase = 'effect_applied', result_json = NULL, error_code = NULL
             WHERE kind = 'update_environment_sources'
               AND phase NOT IN ('completed', 'failed', 'interrupted')",
            [source_commit_checkpoint],
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
        validate_readable_schema(&connection)?;
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

fn initialize_schema(connection: &Connection) -> Result<(), SupervisorStoreError> {
    let transaction = Transaction::new_unchecked(connection, TransactionBehavior::Immediate)?;
    transaction.execute_batch(crate::supervisor_store_codec::SCHEMA_SQL)?;
    add_runtime_binding_column(&transaction)?;
    transaction.pragma_update(None, "application_id", DATABASE_APPLICATION_ID)?;
    transaction.pragma_update(None, "user_version", DATABASE_SCHEMA_VERSION)?;
    validate_schema(&transaction)?;
    validate_database(&transaction)?;
    validate_authority_rows(&transaction)?;
    load_state(&transaction)?;
    transaction.commit()?;
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MigrationCheckpoint {
    AfterAlter,
    BeforeCommit,
}

fn upgrade_schema(connection: &Connection) -> Result<(), SupervisorStoreError> {
    upgrade_schema_with_checkpoint(connection, |_, _| Ok(()))
}

fn upgrade_schema_with_checkpoint(
    connection: &Connection,
    checkpoint: impl Fn(MigrationCheckpoint, &Connection) -> Result<(), SupervisorStoreError>,
) -> Result<(), SupervisorStoreError> {
    // The writer lock fences the version, prior schema and prior state together.
    // No authority metadata or boot reconciliation runs before this commits.
    let transaction = Transaction::new_unchecked(connection, TransactionBehavior::Immediate)?;
    let version = readable_schema_version(&transaction)?;
    if version == LEGACY_DATABASE_SCHEMA_VERSION {
        validate_legacy_schema(&transaction)?;
        validate_database(&transaction)?;
        validate_authority_rows(&transaction)?;
        load_state(&transaction)?;
        add_runtime_binding_column(&transaction)?;
        checkpoint(MigrationCheckpoint::AfterAlter, &transaction)?;
        transaction.pragma_update(None, "user_version", DATABASE_SCHEMA_VERSION)?;
    }
    validate_schema(&transaction)?;
    validate_database(&transaction)?;
    validate_authority_rows(&transaction)?;
    load_state(&transaction)?;
    if version == LEGACY_DATABASE_SCHEMA_VERSION {
        checkpoint(MigrationCheckpoint::BeforeCommit, &transaction)?;
    }
    transaction.commit()?;
    Ok(())
}

fn add_runtime_binding_column(connection: &Connection) -> Result<(), SupervisorStoreError> {
    connection.execute_batch(&format!(
        "ALTER TABLE environments ADD COLUMN {RUNTIME_BINDING_COLUMN_SQL};"
    ))?;
    connection.execute(
        "INSERT OR IGNORE INTO supervisor_metadata(key, value) VALUES ('platform', ?1)",
        [LINUX_PLATFORM],
    )?;
    Ok(())
}

fn readable_schema_version(connection: &Connection) -> Result<i64, SupervisorStoreError> {
    let application_id: i64 =
        connection.pragma_query_value(None, "application_id", |row| row.get(0))?;
    let schema_version: i64 =
        connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if application_id != DATABASE_APPLICATION_ID
        || ![LEGACY_DATABASE_SCHEMA_VERSION, DATABASE_SCHEMA_VERSION].contains(&schema_version)
    {
        return Err(SupervisorStoreError::UnsupportedSchema {
            application_id,
            schema_version,
        });
    }
    Ok(schema_version)
}

fn validate_readable_schema(connection: &Connection) -> Result<(), SupervisorStoreError> {
    match readable_schema_version(connection)? {
        LEGACY_DATABASE_SCHEMA_VERSION => validate_legacy_schema(connection),
        DATABASE_SCHEMA_VERSION => validate_schema(connection),
        _ => unreachable!("readable_schema_version admits only closed versions"),
    }
}

fn validate_schema(connection: &Connection) -> Result<(), SupervisorStoreError> {
    let schema_version = readable_schema_version(connection)?;
    if schema_version != DATABASE_SCHEMA_VERSION {
        return Err(SupervisorStoreError::UnsupportedSchema {
            application_id: DATABASE_APPLICATION_ID,
            schema_version,
        });
    }
    validate_schema_shape(connection, true)?;
    if metadata_value(connection, "platform")?.as_deref() != Some(LINUX_PLATFORM) {
        return Err(SupervisorStoreError::InvalidDatabase);
    }
    Ok(())
}

fn validate_legacy_schema(connection: &Connection) -> Result<(), SupervisorStoreError> {
    let schema_version = readable_schema_version(connection)?;
    if schema_version != LEGACY_DATABASE_SCHEMA_VERSION {
        return Err(SupervisorStoreError::UnsupportedSchema {
            application_id: DATABASE_APPLICATION_ID,
            schema_version,
        });
    }
    validate_schema_shape(connection, false)?;
    if metadata_value(connection, "platform")?
        .as_deref()
        .is_some_and(|platform| platform != LINUX_PLATFORM)
    {
        return Err(SupervisorStoreError::InvalidDatabase);
    }
    Ok(())
}

fn validate_schema_shape(
    connection: &Connection,
    with_runtime_binding: bool,
) -> Result<(), SupervisorStoreError> {
    // Admission pins every old column, CHECK, foreign key and STRICT table. The
    // only Linux12 schema delta is the explicit nullable runtime binding column.
    let mut expected: BTreeMap<_, _> = crate::supervisor_store_codec::SCHEMA_SQL
        .split(';')
        .map(str::trim)
        .filter_map(|sql| {
            let tail = sql.strip_prefix("CREATE TABLE ")?;
            Some((tail.split_whitespace().next()?, sql))
        })
        .collect();
    let mut statement = connection
        .prepare("SELECT type, name, sql FROM sqlite_schema WHERE name NOT GLOB 'sqlite_*'")?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, Option<String>>(2)?,
        ))
    })?;
    for row in rows {
        let (kind, name, sql) = row?;
        let Some(expected_sql) = expected.remove(name.as_str()) else {
            return Err(SupervisorStoreError::InvalidDatabase);
        };
        let mut sql = sql.ok_or(SupervisorStoreError::InvalidDatabase)?;
        if kind != "table" {
            return Err(SupervisorStoreError::InvalidDatabase);
        }
        if with_runtime_binding && name == "environments" {
            let addition = format!(", {RUNTIME_BINDING_COLUMN_SQL}");
            if sql.matches(addition.as_str()).count() != 1 {
                return Err(SupervisorStoreError::InvalidDatabase);
            }
            sql = sql.replacen(addition.as_str(), "", 1);
        }
        if sql != expected_sql {
            return Err(SupervisorStoreError::InvalidDatabase);
        }
    }
    if !expected.is_empty() {
        return Err(SupervisorStoreError::InvalidDatabase);
    }
    if with_runtime_binding {
        let column = connection
            .query_row(
                "SELECT type, \"notnull\", dflt_value, pk, hidden
                 FROM pragma_table_xinfo('environments') WHERE name = 'cw_runtime_binding_json'",
                [],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                    ))
                },
            )
            .optional()?;
        if column != Some(("BLOB".to_owned(), 0, None, 0, 0)) {
            return Err(SupervisorStoreError::InvalidDatabase);
        }
    }
    Ok(())
}

fn load_state(connection: &Connection) -> Result<SupervisorState, SupervisorStoreError> {
    // Readers must observe the legacy columns and independent binding from the
    // same SQLite view, including a read-only reader racing a schema upgrade.
    if connection.is_autocommit() {
        let transaction = Transaction::new_unchecked(connection, TransactionBehavior::Deferred)?;
        let state = load_state_in_transaction(&transaction)?;
        transaction.commit()?;
        Ok(state)
    } else {
        load_state_in_transaction(connection)
    }
}

fn load_state_in_transaction(
    connection: &Connection,
) -> Result<SupervisorState, SupervisorStoreError> {
    validate_readable_schema(connection)?;
    let mut state = crate::supervisor_store_codec::load_state(connection)?;
    if readable_schema_version(connection)? == LEGACY_DATABASE_SCHEMA_VERSION {
        // The old codec denied this newly introduced runner field, even null.
        // Never reinterpret a relabeled new record as admitted old-writer state.
        let mut statement = connection.prepare("SELECT runner_json FROM environments")?;
        let rows = statement.query_map([], |row| row.get::<_, Option<Vec<u8>>>(0))?;
        for row in rows {
            if let Some(bytes) = row? {
                let value: serde_json::Value = serde_json::from_slice(&bytes)
                    .map_err(|_| SupervisorStoreError::InvalidState)?;
                if value.get("cw_runtime_catalog_generation").is_some() {
                    return Err(SupervisorStoreError::InvalidState);
                }
            }
        }
        return Ok(state);
    }
    let mut statement = connection.prepare(
        "SELECT id, name, typeof(cw_runtime_binding_json), length(cw_runtime_binding_json),
                CASE WHEN typeof(cw_runtime_binding_json) = 'blob'
                       AND length(cw_runtime_binding_json) BETWEEN 1 AND ?1
                     THEN cw_runtime_binding_json ELSE NULL END
         FROM environments ORDER BY name",
    )?;
    let rows = statement.query_map([MAXIMUM_RUNTIME_BINDING_BYTES as i64], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, Option<i64>>(3)?,
            row.get::<_, Option<Vec<u8>>>(4)?,
        ))
    })?;
    for row in rows {
        let (id, name, kind, length, bytes) = row?;
        let binding = match (kind.as_str(), length, bytes) {
            ("null", None, None) => None,
            ("blob", Some(length), Some(bytes))
                if (1..=MAXIMUM_RUNTIME_BINDING_BYTES as i64).contains(&length) =>
            {
                let binding: CwRuntimeBinding = serde_json::from_slice(&bytes)
                    .map_err(|_| SupervisorStoreError::InvalidState)?;
                binding
                    .validate()
                    .map_err(|_| SupervisorStoreError::InvalidState)?;
                Some(binding)
            }
            _ => return Err(SupervisorStoreError::InvalidState),
        };
        let environment = state
            .environments
            .get_mut(&name)
            .filter(|environment| environment.id.to_string() == id)
            .ok_or(SupervisorStoreError::InvalidState)?;
        environment.cw_runtime = binding;
    }
    state
        .validate()
        .map_err(|_| SupervisorStoreError::InvalidState)?;
    Ok(state)
}

fn validate_authority_rows(connection: &Connection) -> Result<(), SupervisorStoreError> {
    if let Some(namespace) = metadata_value(connection, "namespace_id")? {
        parse_uuid(&namespace)?;
    }
    if let Some(boot_id) = metadata_value(connection, "host_boot_id")? {
        validate_boot_id(&boot_id)?;
    }
    if let Some(encoded) = metadata_value(connection, HOST_REBOOT_WORKSPACE_TRANSITIONS_KEY)? {
        if encoded.len() > MAXIMUM_OPERATION_BYTES {
            return Err(SupervisorStoreError::InvalidOperation);
        }
        let ids: Vec<String> =
            serde_json::from_str(&encoded).map_err(|_| SupervisorStoreError::InvalidOperation)?;
        for id in ids {
            parse_uuid(&id)?;
        }
    }
    let mut statement = connection.prepare(
        "SELECT operation_id, request_id, environment_id, kind, phase, checkpoint,
                payload_json, result_json, error_code, created_unix_ms, updated_unix_ms
         FROM operations",
    )?;
    let rows = statement.query_map([], decode_operation_row)?;
    for row in rows {
        row?;
    }
    let mut statement = connection.prepare("PRAGMA foreign_key_check")?;
    if statement.query([])?.next()?.is_some() {
        return Err(SupervisorStoreError::InvalidDatabase);
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
        let workspace_plan_json = environment
            .workspace_plan
            .encode_canonical()
            .map_err(|_| SupervisorStoreError::InvalidState)?;
        validate_canonical_host_port_bindings(&environment.host_ports)
            .map_err(|_| SupervisorStoreError::InvalidState)?;
        let host_ports_json = serde_json::to_vec(&environment.host_ports)
            .map_err(|_| SupervisorStoreError::InvalidState)?;
        let mesh_attachment_json = environment
            .mesh
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
        let cw_runtime_binding_json = environment
            .cw_runtime
            .as_ref()
            .map(|binding| {
                binding
                    .validate()
                    .map_err(|_| SupervisorStoreError::InvalidState)?;
                let bytes =
                    serde_json::to_vec(binding).map_err(|_| SupervisorStoreError::InvalidState)?;
                if bytes.len() > MAXIMUM_RUNTIME_BINDING_BYTES {
                    return Err(SupervisorStoreError::InvalidState);
                }
                Ok(bytes)
            })
            .transpose()?;
        let encoded_access = encode_access_binding(environment)?;
        let platform_source_authority_json = environment
            .platform_source_authority
            .as_ref()
            .map(|authority| {
                authority
                    .validate()
                    .map_err(|_| SupervisorStoreError::InvalidState)?;
                serde_json::to_vec(authority).map_err(|_| SupervisorStoreError::InvalidState)
            })
            .transpose()?;
        let disk_bytes = i64::try_from(environment.disk_bytes)
            .map_err(|_| SupervisorStoreError::InvalidState)?;
        let docker_disk_bytes = i64::try_from(environment.docker_disk_bytes)
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
               disk_bytes, docker_disk_bytes, generation, host_ports_json, mesh_attachment_json,
               workspace_plan_json, runner_json,
               active_artifact_generation, staging_artifact_generation,
               project_spec_json, project_spec_sha256, access_profile_reference,
               access_profile_id, access_profile_revision,
               active_workspace_generation_json, staging_workspace_generation_json,
               rollback_workspace_generation_json, platform_source_authority_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24)
             ON CONFLICT(id) DO UPDATE SET
               name = excluded.name,
               desired_state = excluded.desired_state,
               observed_state = excluded.observed_state,
               vcpus = excluded.vcpus,
               memory_mib = excluded.memory_mib,
               disk_bytes = excluded.disk_bytes,
               docker_disk_bytes = excluded.docker_disk_bytes,
               generation = excluded.generation,
               host_ports_json = excluded.host_ports_json,
               mesh_attachment_json = excluded.mesh_attachment_json,
               workspace_plan_json = excluded.workspace_plan_json,
               runner_json = excluded.runner_json,
               active_artifact_generation = excluded.active_artifact_generation,
               staging_artifact_generation = excluded.staging_artifact_generation,
               project_spec_json = excluded.project_spec_json,
               project_spec_sha256 = excluded.project_spec_sha256,
               access_profile_reference = excluded.access_profile_reference,
               access_profile_id = excluded.access_profile_id,
               access_profile_revision = excluded.access_profile_revision,
               active_workspace_generation_json = excluded.active_workspace_generation_json,
               staging_workspace_generation_json = excluded.staging_workspace_generation_json,
               rollback_workspace_generation_json = excluded.rollback_workspace_generation_json,
               platform_source_authority_json = excluded.platform_source_authority_json",
            params![
                environment.id.to_string(),
                &environment.name,
                desired_state(environment.state),
                environment.state.as_str(),
                i64::from(environment.vcpus),
                i64::from(environment.memory_mib),
                disk_bytes,
                docker_disk_bytes,
                generation,
                host_ports_json,
                mesh_attachment_json,
                workspace_plan_json,
                runner_json,
                &environment.active_artifact_generation,
                &environment.staging_artifact_generation,
                &environment.project_spec_json,
                &environment.project_spec_sha256,
                encoded_access.reference,
                encoded_access.profile_id,
                encoded_access.profile_revision,
                active_workspace_generation_json,
                staging_workspace_generation_json,
                rollback_workspace_generation_json,
                platform_source_authority_json,
            ],
        )?;
        if transaction.execute(
            "UPDATE environments SET cw_runtime_binding_json = ?1 WHERE id = ?2",
            params![cw_runtime_binding_json, environment.id.to_string()],
        )? != 1
        {
            return Err(SupervisorStoreError::InvalidState);
        }
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
            (
                "hybrid_vsock",
                format!("{vm}/vsock/{}", crate::state::VSOCK_SOCKET_NAME),
                None,
            ),
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
        if environment.docker_disk_bytes != 0 {
            let relative_path = format!("{vm}/disks/docker.raw");
            transaction.execute(
                "INSERT INTO owned_objects(
                   environment_id, kind, relative_path, identity_json, lifecycle
                 ) VALUES (?1, 'docker_disk', ?2, NULL, 'active')",
                params![environment.id.to_string(), relative_path.as_bytes()],
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

struct EncodedAccessBinding {
    reference: Option<String>,
    profile_id: Option<String>,
    profile_revision: Option<i64>,
}

fn encode_access_binding(
    environment: &EnvironmentRecord,
) -> Result<EncodedAccessBinding, SupervisorStoreError> {
    let (Some(reference), Some(binding)) = (
        environment.access_profile.as_ref(),
        environment.access_binding.as_ref(),
    ) else {
        if environment.access_profile.is_none() && environment.access_binding.is_none() {
            return Ok(EncodedAccessBinding {
                reference: None,
                profile_id: None,
                profile_revision: None,
            });
        }
        return Err(SupervisorStoreError::InvalidState);
    };
    binding
        .validate()
        .map_err(|_| SupervisorStoreError::InvalidState)?;
    let environment_id = EnvironmentId::parse(environment.id.to_string())
        .map_err(|_| SupervisorStoreError::InvalidState)?;
    if binding.environment_id != environment_id {
        return Err(SupervisorStoreError::InvalidState);
    }
    let revision =
        i64::try_from(binding.profile_revision).map_err(|_| SupervisorStoreError::InvalidState)?;
    Ok(EncodedAccessBinding {
        reference: Some(reference.to_string()),
        profile_id: Some(binding.profile_id.to_string()),
        profile_revision: Some(revision),
    })
}

fn encode_workspace_generation(
    generation: Option<&WorkspaceGenerationRecord>,
) -> Result<Option<Vec<u8>>, SupervisorStoreError> {
    generation
        .map(WorkspaceGenerationRecord::encode_canonical)
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

#[cfg(target_os = "linux")]
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

/// Darwin's boot session UUID stands in for the Linux kernel boot ID.
#[cfg(target_os = "macos")]
fn current_boot_id() -> Result<String, SupervisorStoreError> {
    let boot_id = crate::host::process::BootSessionId::current()
        .map_err(|_| SupervisorStoreError::InvalidBootId)?
        .to_hyphenated();
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

fn path_error_is_not_found(error: &PathError) -> bool {
    match error {
        #[cfg(target_os = "linux")]
        PathError::Openat2 { source, .. } => *source == rustix::io::Errno::NOENT,
        PathError::Io { source, .. } => source.kind() == io::ErrorKind::NotFound,
        _ => false,
    }
}

pub use crate::supervisor_store_error::SupervisorStoreError;

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    use codewire_vmm_guest_probe::{SetupArchitecture, Sha256Value, oci_root_generation};
    use sha2::{Digest as _, Sha256};

    use crate::host::path::{FileIdentity, SocketIdentity, current_uid};
    use crate::host::process::ProcessIdentity;
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
            application_ports: vec![codewire_project::ApplicationPort {
                port: 3_000,
                label: "app".to_owned(),
                access: String::new(),
            }],
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
            schema_version: 4,
            root_generation,
            project_sha256: project_sha256.to_owned(),
            project_spec_json: String::from_utf8(project_spec_json.to_vec()).unwrap(),
            artifact_generation: "c".repeat(64),
            image,
            root_disk_bytes: crate::state::MINIMUM_ROOT_DISK_BYTES,
            skill_snapshot: None,
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
            cw_runtime_catalog_generation: None,
            error_code: None,
        });
        EnvironmentRecord {
            id: Uuid::new_v4(),
            name: "dev".to_owned(),
            state,
            vcpus: 2,
            memory_mib: 16 * 1024,
            disk_bytes: crate::state::MINIMUM_STATE_DISK_BYTES,
            docker_disk_bytes: 0,
            generation: 7,
            host_ports: vec![HostPortBinding::new(18_080, 3_000).unwrap()],
            mesh: None,
            workspace_plan: WorkspacePlan::local(&crate::workspace::WorkspaceSource {
                source_path: PathBuf::from("/workspace/source"),
                commit: "b".repeat(40),
                mode: crate::workspace::WorkspaceSourceMode::Clone,
            })
            .unwrap(),
            project_spec_json: Some(project_spec_json),
            project_spec_sha256: Some(project_spec_sha256),
            access_profile: None,
            access_binding: None,
            platform_source_authority: None,
            cw_runtime: None,
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

    // These statements are extracted from the accepted schema11 source, rather
    // than invoking the schema12 writer and relabeling its database as old.
    const FROZEN_SCHEMA_11: &str = include_str!("supervisor_store/testdata/schema-11.sql");
    const FROZEN_ENVIRONMENT_11: &str =
        include_str!("supervisor_store/testdata/schema-11-environment.sql");
    const FROZEN_OPERATION_11: &str =
        include_str!("supervisor_store/testdata/schema-11-operation.sql");

    fn legacy_database(root: &PrivateRoot) -> Connection {
        let (connection, initialize) = open_database(root).unwrap();
        assert!(initialize);
        configure_connection(&connection).unwrap();
        connection.execute_batch(FROZEN_SCHEMA_11).unwrap();
        connection
            .pragma_update(None, "application_id", DATABASE_APPLICATION_ID)
            .unwrap();
        connection
            .pragma_update(None, "user_version", LEGACY_DATABASE_SCHEMA_VERSION)
            .unwrap();
        connection
            .execute(
                "INSERT INTO supervisor_metadata(key, value) VALUES ('namespace_id', ?1)",
                ["11111111-1111-4111-8111-111111111111"],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO supervisor_metadata(key, value) VALUES ('host_boot_id', 'boot-a')",
                [],
            )
            .unwrap();
        connection.execute(
            "INSERT INTO supervisor_metadata(key, value) VALUES ('retained_fixture', 'opaque-prior-value')",
            [],
        ).unwrap();
        validate_legacy_schema(&connection).unwrap();
        connection
    }

    fn write_frozen_legacy_state(connection: &Connection, state: &SupervisorState) {
        state.validate().unwrap();
        let transaction = connection.unchecked_transaction().unwrap();
        for environment in state.environments.values() {
            assert!(environment.cw_runtime.is_none());
            assert!(
                environment
                    .runner
                    .as_ref()
                    .is_none_or(|runner| runner.cw_runtime_catalog_generation.is_none())
            );
            let access = environment.access_binding.as_ref();
            transaction
                .execute(
                    FROZEN_ENVIRONMENT_11,
                    params![
                        environment.id.to_string(),
                        &environment.name,
                        desired_state(environment.state),
                        environment.state.as_str(),
                        i64::from(environment.vcpus),
                        i64::from(environment.memory_mib),
                        i64::try_from(environment.disk_bytes).unwrap(),
                        i64::try_from(environment.docker_disk_bytes).unwrap(),
                        i64::try_from(environment.generation).unwrap(),
                        serde_json::to_vec(&environment.host_ports).unwrap(),
                        environment
                            .mesh
                            .as_ref()
                            .map(serde_json::to_vec)
                            .transpose()
                            .unwrap(),
                        environment.workspace_plan.encode_canonical().unwrap(),
                        environment
                            .runner
                            .as_ref()
                            .map(serde_json::to_vec)
                            .transpose()
                            .unwrap(),
                        &environment.active_artifact_generation,
                        &environment.staging_artifact_generation,
                        &environment.project_spec_json,
                        &environment.project_spec_sha256,
                        environment.access_profile.as_ref().map(ToString::to_string),
                        access.map(|binding| binding.profile_id.to_string()),
                        access.map(|binding| i64::try_from(binding.profile_revision).unwrap()),
                        environment
                            .active_workspace_generation
                            .as_ref()
                            .map(WorkspaceGenerationRecord::encode_canonical)
                            .transpose()
                            .unwrap(),
                        environment
                            .staging_workspace_generation
                            .as_ref()
                            .map(WorkspaceGenerationRecord::encode_canonical)
                            .transpose()
                            .unwrap(),
                        environment
                            .rollback_workspace_generation
                            .as_ref()
                            .map(WorkspaceGenerationRecord::encode_canonical)
                            .transpose()
                            .unwrap(),
                        environment
                            .platform_source_authority
                            .as_ref()
                            .map(serde_json::to_vec)
                            .transpose()
                            .unwrap(),
                    ],
                )
                .unwrap();
            for lifecycle in ["active", "staging", "trash"] {
                transaction.execute(
                    "INSERT INTO owned_objects(environment_id, kind, relative_path, identity_json, lifecycle)
                     VALUES (?1, 'prior_fixture', ?2, ?3, ?4)",
                    params![environment.id.to_string(), format!("retained/{lifecycle}").as_bytes(), b"{\"prior\":true}".as_slice(), lifecycle],
                ).unwrap();
            }
        }
        transaction
            .execute(
                "UPDATE supervisor_settings SET current_environment_id = ?1 WHERE singleton = 1",
                [state
                    .current
                    .as_ref()
                    .map(|name| state.environments[name].id.to_string())],
            )
            .unwrap();
        transaction.commit().unwrap();
    }

    fn legacy_pending_operation(
        connection: &Connection,
        environment: &EnvironmentRecord,
    ) -> OperationRecord {
        let operation_id = Uuid::new_v4();
        connection.execute(FROZEN_OPERATION_11, params![
            operation_id.to_string(), Uuid::new_v4().to_string(), environment.id.to_string(),
            "update_workspace", serde_json::to_vec(&serde_json::json!({"name": environment.name, "generation": environment.generation})).unwrap(), 17_i64,
        ]).unwrap();
        connection.execute(
            "UPDATE operations SET phase = 'effect_applied', checkpoint = 2, updated_unix_ms = 19 WHERE operation_id = ?1",
            [operation_id.to_string()],
        ).unwrap();
        operation_for_id(connection, operation_id).unwrap().unwrap()
    }

    fn runtime_column_present(connection: &Connection) -> bool {
        connection.query_row(
            "SELECT 1 FROM pragma_table_info('environments') WHERE name = 'cw_runtime_binding_json'",
            [], |_| Ok(()),
        ).optional().unwrap().is_some()
    }

    fn schema_version(connection: &Connection) -> i64 {
        connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap()
    }

    type RetainedRows = Vec<Vec<Vec<rusqlite::types::Value>>>;

    fn query_retained_rows(connection: &Connection, queries: &[&str]) -> RetainedRows {
        queries
            .iter()
            .map(|sql| {
                let mut statement = connection.prepare(sql).unwrap();
                let columns = statement.column_count();
                statement
                    .query_map([], |row| {
                        (0..columns).map(|column| row.get(column)).collect()
                    })
                    .unwrap()
                    .collect::<Result<Vec<_>, _>>()
                    .unwrap()
            })
            .collect()
    }

    fn legacy_retained_rows(connection: &Connection) -> RetainedRows {
        query_retained_rows(
            connection,
            &[
                "SELECT * FROM supervisor_metadata WHERE key != 'platform' ORDER BY key",
                "SELECT * FROM supervisor_settings ORDER BY singleton",
                "SELECT id, name, desired_state, observed_state, vcpus, memory_mib, disk_bytes,
                    docker_disk_bytes, generation, host_ports_json, mesh_attachment_json,
                    workspace_plan_json, project_spec_json, project_spec_sha256,
                    access_profile_reference, access_profile_id, access_profile_revision,
                    runner_json, active_artifact_generation, staging_artifact_generation,
                    active_workspace_generation_json, staging_workspace_generation_json,
                    rollback_workspace_generation_json, platform_source_authority_json
             FROM environments ORDER BY id",
                "SELECT * FROM owned_objects ORDER BY environment_id, kind, relative_path",
                "SELECT * FROM operations ORDER BY operation_id",
            ],
        )
    }

    fn all_retained_rows(connection: &Connection) -> RetainedRows {
        query_retained_rows(
            connection,
            &[
                "SELECT * FROM supervisor_metadata ORDER BY key",
                "SELECT * FROM supervisor_settings ORDER BY singleton",
                "SELECT * FROM environments ORDER BY id",
                "SELECT * FROM owned_objects ORDER BY environment_id, kind, relative_path",
                "SELECT * FROM operations ORDER BY operation_id",
                "SELECT type, name, tbl_name, sql FROM sqlite_schema ORDER BY name",
            ],
        )
    }

    fn rich_legacy_state() -> SupervisorState {
        let mut running = environment(StoredEnvironmentState::Running, Some("boot-a"));
        let mut project: codewire_project::ProjectSpec =
            serde_json::from_slice(running.project_spec_json.as_deref().unwrap()).unwrap();
        project.credentials = Some(codewire_project::CredentialBinding {
            profile: "platform:id:11111111-1111-4111-8111-111111111111".into(),
        });
        let project_json = project.canonical_json().unwrap();
        let project_sha256 = format!("{:x}", Sha256::digest(&project_json));
        running.project_spec_json = Some(project_json.clone());
        running.project_spec_sha256 = Some(project_sha256.clone());
        running.access_profile = Some("user/work".parse().unwrap());
        running.access_binding = Some(EnvironmentAccessBinding {
            environment_id: EnvironmentId::parse(running.id.to_string()).unwrap(),
            profile_id: AccessProfileId::parse("11111111-1111-4111-8111-111111111111").unwrap(),
            profile_revision: 7,
        });
        running.platform_source_authority = Some(
            crate::supervisor_metadata::PlatformSourceAuthority::from_proto(
                &crate::control::v1::PlatformSourceAuthority {
                    server_url: "https://synthetic.invalid".to_owned(),
                    organization_id: "synthetic-org".to_owned(),
                    user_id: "synthetic-owner".to_owned(),
                    profile_slots: vec!["codex".to_owned()],
                },
            )
            .unwrap(),
        );
        running.mesh = Some(
            MeshAttachment::new(
                "https://mesh.example.test",
                "org-test",
                "network-test",
                "dev",
                [3_000],
            )
            .unwrap(),
        );
        running.docker_disk_bytes = 4 * 1024 * 1024 * 1024;
        running.active_workspace_generation = Some(workspace_generation(
            &project_json,
            &project_sha256,
            b"active",
        ));
        let mut staging = workspace_generation(&project_json, &project_sha256, b"staging");
        staging.artifact_generation = "b".repeat(64);
        running.staging_artifact_generation = Some(staging.artifact_generation.clone());
        running.staging_workspace_generation = Some(staging);
        let mut rollback = workspace_generation(&project_json, &project_sha256, b"rollback");
        rollback.artifact_generation = "a".repeat(64);
        running.rollback_workspace_generation = Some(rollback);
        let mut stopped = environment(StoredEnvironmentState::Stopped, None);
        stopped.name = "parked".to_owned();
        let mut state = state(running);
        state.environments.insert(stopped.name.clone(), stopped);
        state.validate().unwrap();
        state
    }

    #[test]
    fn schema11_fixtures_are_bound_to_the_accepted_prior_source_bytes() {
        let manifest: serde_json::Value = serde_json::from_str(include_str!(
            "supervisor_store/testdata/schema-11-source.json"
        ))
        .unwrap();
        assert_eq!(
            manifest["source_commit"],
            "0588c11efc32902bd1baa0a54351cf5fc57b8579"
        );
        for (name, bytes, digest) in [
            (
                "schema-11.sql",
                FROZEN_SCHEMA_11,
                "59b3a93d1560788f8f60fbee86e00dcd864d7f9bcb58b6a1d5efb21ee126b37b",
            ),
            (
                "schema-11-environment.sql",
                FROZEN_ENVIRONMENT_11,
                "f59b91888de4055768b5a30a89ec27c6dfe2f90d53e905b352d44d184dbb8455",
            ),
            (
                "schema-11-operation.sql",
                FROZEN_OPERATION_11,
                "c8bccf954346969a2f176d2dfee333115c83f1a893c0a012b65e93c65925b153",
            ),
        ] {
            assert_eq!(format!("{:x}", Sha256::digest(bytes.as_bytes())), digest);
            assert_eq!(manifest["fixtures"][name]["sha256"], digest);
        }
        assert_eq!(crate::supervisor_store_codec::SCHEMA_SQL, FROZEN_SCHEMA_11);
    }

    #[test]
    fn schema11_readers_do_not_migrate_and_upgrade_preserves_all_prior_rows() {
        let (_parent, root) = root();
        let connection = legacy_database(&root);
        let expected = rich_legacy_state();
        write_frozen_legacy_state(&connection, &expected);
        let operation = legacy_pending_operation(&connection, &expected.environments["dev"]);
        let before = legacy_retained_rows(&connection);
        let (reader, inspected) = SupervisorStore::inspect(&root).unwrap();
        assert_eq!(inspected, expected);
        assert_eq!(
            schema_version(&reader.unwrap().connection),
            LEGACY_DATABASE_SCHEMA_VERSION
        );
        let operation_reader = SupervisorOperationReader::open(&root).unwrap();
        assert_eq!(
            operation_reader
                .operation_by_id(operation.operation_id)
                .unwrap(),
            Some(operation.clone())
        );
        assert_eq!(schema_version(&connection), LEGACY_DATABASE_SCHEMA_VERSION);
        assert!(!runtime_column_present(&connection));
        assert_eq!(legacy_retained_rows(&connection), before);
        drop(operation_reader);
        drop(connection);

        let (store, admitted) = SupervisorStore::open_for_boot(&root, "boot-a").unwrap();
        assert_eq!(admitted, expected);
        assert_eq!(schema_version(&store.connection), DATABASE_SCHEMA_VERSION);
        assert!(runtime_column_present(&store.connection));
        assert_eq!(store.metadata("platform").as_deref(), Some(LINUX_PLATFORM));
        assert_eq!(legacy_retained_rows(&store.connection), before);
        assert_eq!(store.pending_operations().unwrap(), vec![operation]);
        assert!(
            admitted
                .environments
                .values()
                .all(|environment| environment.cw_runtime.is_none())
        );
        let after = all_retained_rows(&store.connection);
        drop(store);
        let (reopened, admitted) = SupervisorStore::open_for_boot(&root, "boot-a").unwrap();
        assert_eq!(admitted, expected);
        assert_eq!(all_retained_rows(&reopened.connection), after);
    }

    #[test]
    fn schema11_upgrade_rolls_back_after_alter_and_before_version_commit() {
        for fault in [
            MigrationCheckpoint::AfterAlter,
            MigrationCheckpoint::BeforeCommit,
        ] {
            let (_parent, root) = root();
            let connection = legacy_database(&root);
            let expected = rich_legacy_state();
            write_frozen_legacy_state(&connection, &expected);
            legacy_pending_operation(&connection, &expected.environments["dev"]);
            let before = all_retained_rows(&connection);
            let result = upgrade_schema_with_checkpoint(&connection, |point, transaction| {
                assert!(runtime_column_present(transaction));
                assert_eq!(
                    schema_version(transaction),
                    if point == MigrationCheckpoint::AfterAlter {
                        LEGACY_DATABASE_SCHEMA_VERSION
                    } else {
                        DATABASE_SCHEMA_VERSION
                    }
                );
                if point == fault {
                    Err(SupervisorStoreError::InvalidDatabase)
                } else {
                    Ok(())
                }
            });
            assert!(matches!(result, Err(SupervisorStoreError::InvalidDatabase)));
            assert_eq!(schema_version(&connection), LEGACY_DATABASE_SCHEMA_VERSION);
            assert!(!runtime_column_present(&connection));
            assert!(metadata_value(&connection, "platform").unwrap().is_none());
            assert_eq!(all_retained_rows(&connection), before);
            assert_eq!(load_state(&connection).unwrap(), expected);
            drop(connection);
            let (recovered, admitted) = SupervisorStore::open_for_boot(&root, "boot-a").unwrap();
            assert_eq!(admitted, expected);
            assert_eq!(
                schema_version(&recovered.connection),
                DATABASE_SCHEMA_VERSION
            );
        }
    }

    #[test]
    fn schema11_upgrade_refuses_invalid_prior_state_and_unknown_schema_effects() {
        for corruption in [
            "UPDATE environments SET project_spec_json = X'7b7d'",
            "UPDATE operations SET payload_json = X'6e756c6c'",
            "UPDATE supervisor_metadata SET value = 'bad' WHERE key = 'namespace_id'",
            "INSERT INTO supervisor_metadata(key, value) VALUES ('platform', 'darwin-v1')",
            "ALTER TABLE environments ADD COLUMN unexpected BLOB NULL",
            "CREATE TRIGGER sqliteXunrecognized AFTER UPDATE ON environments BEGIN DELETE FROM operations; END",
        ] {
            let (_parent, root) = root();
            let connection = legacy_database(&root);
            let expected = state(environment(StoredEnvironmentState::Running, Some("boot-a")));
            write_frozen_legacy_state(&connection, &expected);
            legacy_pending_operation(&connection, &expected.environments["dev"]);
            connection.execute_batch(corruption).unwrap();
            let before = all_retained_rows(&connection);
            assert!(
                upgrade_schema(&connection).is_err(),
                "admitted {corruption}"
            );
            assert_eq!(schema_version(&connection), LEGACY_DATABASE_SCHEMA_VERSION);
            assert!(!runtime_column_present(&connection));
            assert_eq!(all_retained_rows(&connection), before);
        }
    }

    #[test]
    fn schema11_upgrade_refuses_new_runner_metadata_even_when_null() {
        let (_parent, root) = root();
        let connection = legacy_database(&root);
        let expected = state(environment(StoredEnvironmentState::Running, Some("boot-a")));
        write_frozen_legacy_state(&connection, &expected);
        let mut runner =
            serde_json::to_value(expected.environments["dev"].runner.as_ref().unwrap()).unwrap();
        runner.as_object_mut().unwrap().insert(
            "cw_runtime_catalog_generation".to_owned(),
            serde_json::Value::Null,
        );
        connection
            .execute(
                "UPDATE environments SET runner_json = ?1",
                [serde_json::to_vec(&runner).unwrap()],
            )
            .unwrap();
        let before = all_retained_rows(&connection);
        assert!(matches!(
            upgrade_schema(&connection),
            Err(SupervisorStoreError::InvalidState)
        ));
        assert_eq!(schema_version(&connection), LEGACY_DATABASE_SCHEMA_VERSION);
        assert!(!runtime_column_present(&connection));
        assert_eq!(all_retained_rows(&connection), before);
    }

    #[test]
    fn runtime_binding_and_runner_generation_round_trip_without_changing_boot_identity() {
        let (_parent, root) = root();
        let (store, _) = SupervisorStore::open_for_boot(&root, "boot-a").unwrap();
        let mut environment = environment(StoredEnvironmentState::Running, Some("boot-a"));
        environment.cw_runtime = Some(CwRuntimeBinding {
            schema_version: 1,
            active_catalog_generation: "1".repeat(64),
            staging_catalog_generation: Some("2".repeat(64)),
            rollback_catalog_generation: Some("3".repeat(64)),
        });
        environment
            .runner
            .as_mut()
            .unwrap()
            .cw_runtime_catalog_generation = Some("1".repeat(64));
        let expected = state(environment);
        store.replace_state(&expected).unwrap();
        let (kind, length): (String, i64) = store.connection.query_row(
            "SELECT typeof(cw_runtime_binding_json), length(cw_runtime_binding_json) FROM environments",
            [], |row| Ok((row.get(0)?, row.get(1)?)),
        ).unwrap();
        assert_eq!(kind, "blob");
        assert!((1..=MAXIMUM_RUNTIME_BINDING_BYTES as i64).contains(&length));
        drop(store);
        let (store, mut restored) = SupervisorStore::open_for_boot(&root, "boot-a").unwrap();
        assert_eq!(restored, expected);
        let environment = restored.environments.get_mut("dev").unwrap();
        // A binding rollback is state in schema12, never an old database image.
        environment.state = StoredEnvironmentState::Stopped;
        environment.runner = None;
        let binding = environment.cw_runtime.as_mut().unwrap();
        let prior = binding.active_catalog_generation.clone();
        binding.active_catalog_generation = binding.rollback_catalog_generation.take().unwrap();
        binding.rollback_catalog_generation = Some(prior);
        binding.staging_catalog_generation = None;
        assert_eq!(
            environment.active_artifact_generation,
            expected.environments["dev"].active_artifact_generation
        );
        assert_eq!(
            environment.workspace_plan,
            expected.environments["dev"].workspace_plan
        );
        store.replace_state(&restored).unwrap();
        assert_eq!(schema_version(&store.connection), DATABASE_SCHEMA_VERSION);
        drop(store);
        let (store, admitted) = SupervisorStore::open_for_boot(&root, "boot-a").unwrap();
        assert_eq!(admitted, restored);
        assert_eq!(schema_version(&store.connection), DATABASE_SCHEMA_VERSION);
    }

    #[test]
    fn malformed_runtime_bindings_refuse_read_and_boot_before_authority_changes() {
        let valid = CwRuntimeBinding {
            schema_version: 1,
            active_catalog_generation: "1".repeat(64),
            staging_catalog_generation: None,
            rollback_catalog_generation: None,
        };
        let mut unknown = serde_json::to_value(&valid).unwrap();
        unknown
            .as_object_mut()
            .unwrap()
            .insert("future".to_owned(), serde_json::Value::Null);
        let mut invalid_generation = valid.clone();
        invalid_generation.active_catalog_generation = "A".repeat(64);
        let mut invalid_schema = valid.clone();
        invalid_schema.schema_version = 2;
        let mut oversized = serde_json::to_vec(&valid).unwrap();
        oversized.resize(MAXIMUM_RUNTIME_BINDING_BYTES + 1, b' ');
        for bytes in [
            Vec::new(), vec![0xff], b"{}".to_vec(), b"null".to_vec(),
            serde_json::to_vec(&unknown).unwrap(),
            serde_json::to_vec(&invalid_generation).unwrap(),
            serde_json::to_vec(&invalid_schema).unwrap(), oversized,
            format!("{{\"schema_version\":1,\"schema_version\":1,\"active_catalog_generation\":\"{}\"}}", valid.active_catalog_generation).into_bytes(),
        ] {
            let (_parent, root) = root();
            let (store, _) = SupervisorStore::open_for_boot(&root, "boot-a").unwrap();
            let expected = state(environment(StoredEnvironmentState::Running, Some("boot-a")));
            store.replace_state(&expected).unwrap();
            store.begin_operation(Uuid::new_v4(), Some(expected.environments["dev"].id), OperationKind::Start, &serde_json::json!({"name":"dev"})).unwrap();
            store.connection.execute("UPDATE environments SET cw_runtime_binding_json = ?1", [bytes]).unwrap();
            let before = all_retained_rows(&store.connection);
            drop(store);
            assert!(matches!(SupervisorStore::inspect(&root), Err(SupervisorStoreError::InvalidState)));
            assert!(matches!(SupervisorStore::open_for_boot(&root, "boot-b"), Err(SupervisorStoreError::InvalidState)));
            let connection = Connection::open_with_flags(root.path().join(DATABASE_FILE), OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
            assert_eq!(schema_version(&connection), DATABASE_SCHEMA_VERSION);
            assert_eq!(metadata_value(&connection, "host_boot_id").unwrap().as_deref(), Some("boot-a"));
            assert_eq!(all_retained_rows(&connection), before);
        }
    }

    #[test]
    fn schema12_requires_the_runtime_column_and_closed_linux_platform() {
        let (_parent, root) = root();
        let connection = legacy_database(&root);
        let expected = state(environment(StoredEnvironmentState::Running, Some("boot-a")));
        write_frozen_legacy_state(&connection, &expected);
        connection
            .pragma_update(None, "user_version", DATABASE_SCHEMA_VERSION)
            .unwrap();
        connection
            .execute(
                "INSERT INTO supervisor_metadata(key, value) VALUES ('platform', ?1)",
                [LINUX_PLATFORM],
            )
            .unwrap();
        let before = all_retained_rows(&connection);
        drop(connection);
        assert!(matches!(
            SupervisorStore::inspect(&root),
            Err(SupervisorStoreError::InvalidDatabase)
        ));
        assert!(matches!(
            SupervisorStore::open_for_boot(&root, "boot-b"),
            Err(SupervisorStoreError::InvalidDatabase)
        ));
        let connection = Connection::open_with_flags(
            root.path().join(DATABASE_FILE),
            OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        assert_eq!(all_retained_rows(&connection), before);

        for platform in [None, Some("unknown-linux"), Some("darwin-v1")] {
            let (_parent, root) = self::root();
            let (store, _) = SupervisorStore::open_for_boot(&root, "boot-a").unwrap();
            match platform {
                Some(platform) => {
                    store
                        .connection
                        .execute(
                            "UPDATE supervisor_metadata SET value = ?1 WHERE key = 'platform'",
                            [platform],
                        )
                        .unwrap();
                }
                None => {
                    store
                        .connection
                        .execute("DELETE FROM supervisor_metadata WHERE key = 'platform'", [])
                        .unwrap();
                }
            }
            let before = all_retained_rows(&store.connection);
            drop(store);
            assert!(matches!(
                SupervisorStore::open_for_boot(&root, "boot-b"),
                Err(SupervisorStoreError::InvalidDatabase)
            ));
            let connection = Connection::open_with_flags(
                root.path().join(DATABASE_FILE),
                OpenFlags::SQLITE_OPEN_READ_ONLY,
            )
            .unwrap();
            assert_eq!(all_retained_rows(&connection), before);
        }
    }

    #[test]
    fn unsupported_application_or_schema_never_migrates_or_reconciles() {
        for (application_id, version) in [
            (0_i64, LEGACY_DATABASE_SCHEMA_VERSION),
            (DATABASE_APPLICATION_ID + 1, LEGACY_DATABASE_SCHEMA_VERSION),
            (DATABASE_APPLICATION_ID, 0),
            (DATABASE_APPLICATION_ID, 10),
            (DATABASE_APPLICATION_ID, DATABASE_SCHEMA_VERSION + 1),
        ] {
            let (_parent, root) = root();
            let connection = legacy_database(&root);
            let expected = state(environment(StoredEnvironmentState::Running, Some("boot-a")));
            write_frozen_legacy_state(&connection, &expected);
            legacy_pending_operation(&connection, &expected.environments["dev"]);
            connection
                .pragma_update(None, "application_id", application_id)
                .unwrap();
            connection
                .pragma_update(None, "user_version", version)
                .unwrap();
            let before = all_retained_rows(&connection);
            drop(connection);
            assert!(matches!(
                SupervisorStore::inspect(&root),
                Err(SupervisorStoreError::UnsupportedSchema { .. })
            ));
            assert!(matches!(
                SupervisorStore::open_for_boot(&root, "boot-b"),
                Err(SupervisorStoreError::UnsupportedSchema { .. })
            ));
            let connection = Connection::open_with_flags(
                root.path().join(DATABASE_FILE),
                OpenFlags::SQLITE_OPEN_READ_ONLY,
            )
            .unwrap();
            assert_eq!(schema_version(&connection), version);
            assert_eq!(
                connection
                    .pragma_query_value(None, "application_id", |row| row.get::<_, i64>(0))
                    .unwrap(),
                application_id
            );
            assert!(!runtime_column_present(&connection));
            assert_eq!(all_retained_rows(&connection), before);
        }
    }

    #[test]
    fn new_database_is_owner_only_wal_and_stable() {
        let (_parent, root) = root();
        let (store, state) = SupervisorStore::open_for_boot(&root, "boot-a").unwrap();
        assert_eq!(state, SupervisorState::default());
        assert_eq!(store.metadata("host_boot_id").as_deref(), Some("boot-a"));
        assert_eq!(schema_version(&store.connection), DATABASE_SCHEMA_VERSION);
        assert!(runtime_column_present(&store.connection));
        assert_eq!(store.metadata("platform").as_deref(), Some(LINUX_PLATFORM));
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
    fn darwin_format_rejects_before_linux_reboot_or_authority_writes() {
        fn retained_rows(connection: &Connection) -> Vec<Vec<Vec<rusqlite::types::Value>>> {
            [
                "SELECT * FROM supervisor_metadata ORDER BY key",
                "SELECT * FROM supervisor_settings ORDER BY singleton",
                "SELECT * FROM environments ORDER BY id",
                "SELECT * FROM owned_objects ORDER BY environment_id, kind, relative_path",
                "SELECT * FROM operations ORDER BY operation_id",
            ]
            .iter()
            .map(|sql| {
                let mut statement = connection.prepare(sql).unwrap();
                let columns = statement.column_count();
                statement
                    .query_map([], |row| {
                        (0..columns).map(|column| row.get(column)).collect()
                    })
                    .unwrap()
                    .collect::<Result<Vec<_>, _>>()
                    .unwrap()
            })
            .collect()
        }

        let (_parent, root) = root();
        let (store, _) = SupervisorStore::open_for_boot(&root, "boot-a").unwrap();
        let state = state(environment(StoredEnvironmentState::Running, Some("boot-a")));
        store.replace_state(&state).unwrap();
        store
            .begin_operation(
                Uuid::new_v4(),
                Some(state.environments["dev"].id),
                OperationKind::Start,
                &serde_json::json!({"name":"dev"}),
            )
            .unwrap();
        store.connection.execute_batch(
            "PRAGMA user_version = 12; UPDATE supervisor_metadata SET value = 'darwin-v1' WHERE key = 'platform';",
        ).unwrap();
        let before = retained_rows(&store.connection);
        drop(store);
        assert!(matches!(
            SupervisorStore::open_for_boot(&root, "boot-b"),
            Err(SupervisorStoreError::InvalidDatabase)
        ));
        let connection = Connection::open_with_flags(
            root.path().join(DATABASE_FILE),
            OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        assert_eq!(retained_rows(&connection), before);
        // The old writer can checkpoint WAL while rejecting a foreign schema;
        // this binds logical rows, not an unsupported physical-byte guarantee.
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
    fn host_reboot_resumes_only_pending_source_operations_at_the_derived_commit_boundary() {
        for checkpoint in 0..=9 {
            let (_parent, root) = root();
            let (store, _) = SupervisorStore::open_for_boot(&root, "boot-a").unwrap();
            let expected = state(environment(StoredEnvironmentState::Running, Some("boot-a")));
            let environment_id = expected.environments["dev"].id;
            store.replace_state(&expected).unwrap();
            let mut source = store
                .begin_operation(
                    Uuid::new_v4(),
                    Some(environment_id),
                    OperationKind::UpdateEnvironmentSources,
                    &serde_json::json!({"name": "dev", "fixture": "source-reboot"}),
                )
                .unwrap();
            for _ in 0..checkpoint {
                source = store
                    .advance_operation(
                        source.operation_id,
                        source.checkpoint,
                        OperationPhase::EffectApplied,
                        None,
                        None,
                    )
                    .unwrap();
            }
            let mut others = Vec::new();
            for kind in [
                OperationKind::Create,
                OperationKind::Start,
                OperationKind::Stop,
                OperationKind::Restart,
                OperationKind::UpdateWorkspace,
                OperationKind::RollbackWorkspace,
                OperationKind::Delete,
                OperationKind::GrowDisk,
                OperationKind::Reconcile,
            ] {
                others.push(
                    store
                        .begin_operation(
                            Uuid::new_v4(),
                            Some(environment_id),
                            kind,
                            &serde_json::json!({"name": "dev"}),
                        )
                        .unwrap(),
                );
            }
            drop(store);
            let (store, loaded) = SupervisorStore::open_for_boot(&root, "boot-b").unwrap();
            let resumed = store
                .operation_by_request(source.request_id)
                .unwrap()
                .unwrap();
            assert_eq!(resumed.operation_id, source.operation_id);
            assert_eq!(resumed.payload, source.payload);
            assert_eq!(
                resumed.checkpoint,
                crate::lifecycle::source_reboot_checkpoint(checkpoint).unwrap()
            );
            assert_eq!(resumed.phase, OperationPhase::EffectApplied);
            assert!(resumed.error_code.is_none());
            assert_eq!(
                loaded.environments["dev"].generation,
                expected.environments["dev"].generation
            );
            assert_eq!(
                loaded.environments["dev"].project_spec_json,
                expected.environments["dev"].project_spec_json
            );
            assert_eq!(
                loaded.environments["dev"].state,
                StoredEnvironmentState::Stopped
            );
            assert!(loaded.environments["dev"].runner.is_none());
            for other in others {
                let interrupted = store
                    .operation_by_request(other.request_id)
                    .unwrap()
                    .unwrap();
                assert_eq!(interrupted.phase, OperationPhase::Interrupted);
                assert_eq!(interrupted.checkpoint, other.checkpoint);
                assert_eq!(interrupted.error_code.as_deref(), Some("host_reboot"));
            }
            assert_eq!(store.pending_operations().unwrap(), vec![resumed]);
        }
    }

    #[test]
    fn host_reboot_never_rewinds_terminal_source_operations_or_accepts_retired_kind() {
        let (_parent, root) = root();
        let (store, _) = SupervisorStore::open_for_boot(&root, "boot-a").unwrap();
        let mut terminal = Vec::new();
        for phase in [
            OperationPhase::Completed,
            OperationPhase::Failed,
            OperationPhase::Interrupted,
        ] {
            let operation = store
                .begin_operation(
                    Uuid::new_v4(),
                    Some(Uuid::new_v4()),
                    OperationKind::UpdateEnvironmentSources,
                    &serde_json::json!({"name": "dev"}),
                )
                .unwrap();
            terminal.push(
                store
                    .advance_operation(
                        operation.operation_id,
                        operation.checkpoint,
                        phase,
                        (phase == OperationPhase::Completed)
                            .then_some(&serde_json::json!({"name":"dev"})),
                        if phase == OperationPhase::Completed {
                            None
                        } else {
                            Some("fixture_terminal")
                        },
                    )
                    .unwrap(),
            );
        }
        drop(store);
        let (store, _) = SupervisorStore::open_for_boot(&root, "boot-b").unwrap();
        for operation in terminal {
            assert_eq!(
                store
                    .operation_by_request(operation.request_id)
                    .unwrap()
                    .unwrap(),
                operation
            );
        }
        assert_eq!(OperationKind::parse("apply_environment_access"), None);
    }

    #[test]
    fn host_reboot_rejects_source_checkpoint_outside_its_effect_plan_atomically() {
        let (_parent, root) = root();
        let (store, _) = SupervisorStore::open_for_boot(&root, "boot-a").unwrap();
        let expected = state(environment(StoredEnvironmentState::Running, Some("boot-a")));
        store.replace_state(&expected).unwrap();
        let mut operation = store
            .begin_operation(
                Uuid::new_v4(),
                Some(expected.environments["dev"].id),
                OperationKind::UpdateEnvironmentSources,
                &serde_json::json!({"name": "dev"}),
            )
            .unwrap();
        for _ in 0..10 {
            operation = store
                .advance_operation(
                    operation.operation_id,
                    operation.checkpoint,
                    OperationPhase::EffectApplied,
                    None,
                    None,
                )
                .unwrap();
        }
        assert!(matches!(
            store.reconcile_host_boot("boot-b"),
            Err(SupervisorStoreError::InvalidOperation)
        ));
        assert_eq!(store.metadata("host_boot_id").as_deref(), Some("boot-a"));
        assert_eq!(
            store
                .operation_by_request(operation.request_id)
                .unwrap()
                .unwrap(),
            operation
        );
        let (_, retained) = SupervisorStore::inspect(&root).unwrap();
        assert_eq!(retained, expected);
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
            .pragma_update(None, "user_version", 6_i64)
            .unwrap();
        drop(store);
        let database = root.path().join(DATABASE_FILE);
        let before = fs::read(&database).unwrap();

        assert!(matches!(
            SupervisorStore::open_for_boot(&root, "boot-a"),
            Err(SupervisorStoreError::UnsupportedSchema {
                application_id: DATABASE_APPLICATION_ID,
                schema_version: 6,
            })
        ));
        assert_eq!(fs::read(database).unwrap(), before);
    }

    #[test]
    fn sqlite_inspection_opens_the_authority_read_only() {
        let (_parent, root) = root();
        let (store, _) = SupervisorStore::open_for_boot(&root, "boot-a").unwrap();
        let mut environment = environment(StoredEnvironmentState::Stopped, None);
        environment.mesh = Some(
            MeshAttachment::new(
                "https://mesh.example.test/base",
                "org-test",
                "network-test",
                "dev",
                [3_000],
            )
            .unwrap(),
        );
        let expected = state(environment);
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
    fn docker_disk_size_and_owned_object_survive_exact_database_reopen() {
        let (_parent, root) = root();
        let (store, _) = SupervisorStore::open_for_boot(&root, "boot-a").unwrap();
        let mut environment = environment(StoredEnvironmentState::Stopped, None);
        environment.docker_disk_bytes = crate::state::MINIMUM_DOCKER_DISK_BYTES;
        let environment_id = environment.id;
        let expected = state(environment);
        store.replace_state(&expected).unwrap();
        let object: (String, Vec<u8>, String) = store
            .connection
            .query_row(
                "SELECT kind, relative_path, lifecycle FROM owned_objects \
                 WHERE environment_id = ?1 AND kind = 'docker_disk'",
                [environment_id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(
            object,
            (
                "docker_disk".to_owned(),
                format!("engine/vms/{environment_id}/disks/docker.raw").into_bytes(),
                "active".to_owned(),
            )
        );
        drop(store);

        let (_reopened, loaded) = SupervisorStore::open_for_boot(&root, "boot-a").unwrap();
        assert_eq!(loaded, expected);
        assert_eq!(
            loaded.environments["dev"].docker_disk_bytes,
            crate::state::MINIMUM_DOCKER_DISK_BYTES
        );
    }

    #[test]
    fn exact_access_binding_survives_reopen_and_invalid_metadata_fails_closed() {
        let (_parent, root) = root();
        let (store, _) = SupervisorStore::open_for_boot(&root, "boot-a").unwrap();
        let mut environment = environment(StoredEnvironmentState::Stopped, None);
        let mut project: codewire_project::ProjectSpec =
            serde_json::from_slice(environment.project_spec_json.as_deref().unwrap()).unwrap();
        project.credentials = Some(codewire_project::CredentialBinding {
            profile: "local:id:11111111-1111-4111-8111-111111111111".into(),
        });
        let project_spec_json = project.canonical_json().unwrap();
        environment.project_spec_sha256 = Some(format!(
            "{:x}",
            Sha256::digest(project_spec_json.as_slice())
        ));
        environment.project_spec_json = Some(project_spec_json);
        let binding = EnvironmentAccessBinding {
            environment_id: EnvironmentId::parse(environment.id.to_string()).unwrap(),
            profile_id: AccessProfileId::parse("11111111-1111-4111-8111-111111111111").unwrap(),
            profile_revision: 7,
        };
        environment.access_profile = Some("user/work".parse().unwrap());
        environment.access_binding = Some(binding.clone());
        let expected = state(environment);
        store.replace_state(&expected).unwrap();
        drop(store);

        let (reopened, loaded) = SupervisorStore::open_for_boot(&root, "boot-a").unwrap();
        assert_eq!(
            loaded.environments["dev"]
                .access_profile
                .as_ref()
                .unwrap()
                .to_string(),
            "user/work"
        );
        assert_eq!(loaded.environments["dev"].access_binding, Some(binding));
        reopened
            .connection
            .execute(
                "UPDATE environments SET access_profile_id = 'INVALID' WHERE name = 'dev'",
                [],
            )
            .unwrap();
        drop(reopened);

        assert!(matches!(
            SupervisorStore::open_for_boot(&root, "boot-a"),
            Err(SupervisorStoreError::InvalidState)
        ));
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
        let crate::workspace_plan::WorkspaceInput::Local { source_path, .. } = &mut expanded
            .environments
            .get_mut("dev")
            .unwrap()
            .workspace_plan
            .inputs[0]
        else {
            panic!("test plan must be local");
        };
        *source_path = [vec![b'/'], vec![b'x'; 100 * 1024]].concat();

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
    #[test]
    fn live_runtime_journal_fences_only_mutations_for_the_exact_uuid() {
        let (_parent, root) = root();
        let (store, _) = SupervisorStore::open_for_boot(&root, "boot-a").unwrap();
        let id = Uuid::new_v4();
        let request_id = Uuid::new_v4();
        let payload = serde_json::json!({"environment_id":id,"expected_revision":1});
        let intent = store
            .begin_operation(
                request_id,
                Some(id),
                OperationKind::UpdateCwRuntime,
                &payload,
            )
            .unwrap();
        assert_eq!(
            store
                .begin_operation(
                    request_id,
                    Some(id),
                    OperationKind::UpdateCwRuntime,
                    &payload
                )
                .unwrap(),
            intent
        );
        for kind in [
            OperationKind::Start,
            OperationKind::Stop,
            OperationKind::Restart,
            OperationKind::Delete,
            OperationKind::GrowDisk,
            OperationKind::UpdateWorkspace,
            OperationKind::RollbackWorkspace,
            OperationKind::UpdateEnvironmentSources,
            OperationKind::RollbackCwRuntime,
        ] {
            assert!(
                matches!(
                    store.begin_operation(Uuid::new_v4(), Some(id), kind, &payload),
                    Err(SupervisorStoreError::JournalConflict)
                ),
                "{kind:?}"
            );
        }
        store
            .begin_operation(
                Uuid::new_v4(),
                Some(Uuid::new_v4()),
                OperationKind::Start,
                &serde_json::json!({"name":"neighbor"}),
            )
            .unwrap();
        store
            .begin_operation(
                Uuid::new_v4(),
                Some(id),
                OperationKind::Reconcile,
                &serde_json::json!({"name":"selected"}),
            )
            .unwrap();
        assert!(matches!(
            store.begin_operation(
                Uuid::new_v4(),
                Some(Uuid::nil()),
                OperationKind::Reconcile,
                &payload
            ),
            Err(SupervisorStoreError::InvalidOperation)
        ));
        store
            .advance_operation(
                intent.operation_id,
                0,
                OperationPhase::Completed,
                Some(&serde_json::json!({"component_effect":"observed"})),
                None,
            )
            .unwrap();
        store
            .begin_operation(
                Uuid::new_v4(),
                Some(id),
                OperationKind::Stop,
                &serde_json::json!({"name":"selected"}),
            )
            .unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn live_runtime_journal_reopens_without_replay_or_resetting_unknown_effect() {
        let (_parent, root) = root();
        let (store, _) = SupervisorStore::open_for_boot(&root, "boot-a").unwrap();
        let id = Uuid::new_v4();
        let request = Uuid::new_v4();
        let payload = serde_json::json!({"environment_id":id,"expected_revision":4,"target_sha256":"a".repeat(64)});
        let intent = store
            .begin_operation(request, Some(id), OperationKind::UpdateCwRuntime, &payload)
            .unwrap();
        let issued = store
            .advance_operation(
                intent.operation_id,
                0,
                OperationPhase::EffectApplied,
                None,
                None,
            )
            .unwrap();
        drop(store);
        let (store, _) = SupervisorStore::open_for_boot(&root, "boot-a").unwrap();
        assert_eq!(store.pending_operations().unwrap(), vec![issued.clone()]);
        drop(store);
        let (store, _) = SupervisorStore::open_for_boot(&root, "boot-b").unwrap();
        let interrupted = store.operation_by_request(request).unwrap().unwrap();
        assert_eq!(interrupted.phase, OperationPhase::Interrupted);
        assert_eq!(interrupted.error_code.as_deref(), Some("host_reboot"));
        assert_eq!(interrupted.checkpoint, issued.checkpoint);
        assert_eq!(interrupted.payload, payload);
        assert!(interrupted.result.is_none());
        assert_eq!(
            store.interrupted_cw_runtime_operations(id).unwrap(),
            vec![interrupted.clone()]
        );
        // Only the typed caller's exact retained receipt may close an old
        // birth. This storage component preserves that result atomically.
        let observed = serde_json::json!({"component_effect":"committed","selection_revision":5});
        let completed = store
            .resolve_interrupted_cw_runtime(&interrupted, &observed)
            .unwrap();
        assert_eq!(completed.phase, OperationPhase::Completed);
        assert_eq!(completed.checkpoint, issued.checkpoint);
        assert_eq!(completed.result, Some(observed));
        assert!(matches!(
            store.resolve_interrupted_cw_runtime(
                &interrupted,
                &serde_json::json!({"another_effect":true})
            ),
            Err(SupervisorStoreError::JournalConflict)
        ));
        drop(store);
        let (store, _) = SupervisorStore::open_for_boot(&root, "boot-b").unwrap();
        assert_eq!(
            store.operation_by_request(request).unwrap(),
            Some(completed)
        );
    }

    #[test]
    fn live_runtime_journal_keeps_secret_guards_and_closed_kinds() {
        let (_parent, root) = root();
        let (store, _) = SupervisorStore::open_for_boot(&root, "boot-a").unwrap();
        for key in ["credential", "capability", "auth_token"] {
            let request = Uuid::new_v4();
            let payload = serde_json::json!({key:"synthetic forbidden material"});
            assert!(
                store
                    .begin_operation(
                        request,
                        Some(Uuid::new_v4()),
                        OperationKind::UpdateCwRuntime,
                        &payload
                    )
                    .is_err()
            );
            assert!(store.operation_by_request(request).unwrap().is_none());
        }
        for kind in [
            OperationKind::UpdateCwRuntime,
            OperationKind::RollbackCwRuntime,
        ] {
            assert_eq!(OperationKind::parse(kind.as_str()), Some(kind));
            assert!(crate::lifecycle::effects(kind).is_empty());
        }
        for kind in ["root_exec", "publish_file", "update_runtime_arbitrary"] {
            assert!(OperationKind::parse(kind).is_none());
        }
    }
}
