//! Bounded qualified-host inspection of the native supervisor's private state.
//!
//! The native product smoke uses this binary instead of opening a live WAL
//! through the host's potentially different SQLite build. Only fixed,
//! non-secret fields needed by that smoke can be returned.

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("codewire-local-state-probe requires Linux");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
fn main() {
    if linux::run(std::env::args().skip(1)).is_err() {
        eprintln!("codewire-local-state-probe: ERROR: native state proof failed");
        std::process::exit(1);
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::error::Error;
    use std::fs::{self, File, OpenOptions};
    use std::io;
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    use codewire_local_vmm::cw_runtime::CwRuntimeJournalEvidence;
    use codewire_local_vmm::{LiveProcess, ProcessIdentity};
    use rusqlite::config::DbConfig;
    use rusqlite::{Connection, OpenFlags, OptionalExtension as _};
    use rustix::process::Signal;
    use serde::{Deserialize, Serialize};
    use sha2::{Digest as _, Sha256};
    use uuid::Uuid;

    const DATABASE_APPLICATION_ID: i64 = 0x4357_564d;
    const DATABASE_SCHEMA_VERSION: i64 = 12;
    const DATABASE_FILE: &str = "supervisor.db";
    const MAXIMUM_OPERATIONS: usize = 128;
    const MAXIMUM_WORKSPACE_METADATA_BYTES: usize = 512 * 1024;
    const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

    type ProbeResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Field {
        EnvironmentId,
        RunnerPid,
        RunnerErrorCode,
        ActiveArtifactGeneration,
        RunnerArtifactGeneration,
        BuiltWorkspaceIdentity,
        Empty,
        Contract,
        ResizeOperation,
        SourceOperation,
        JournalComplete,
        JournalSummary,
        Ownership,
    }

    enum Action {
        Value(Field),
        KillRunner,
    }

    struct Args {
        action: Action,
        state_root: PathBuf,
        name: String,
    }

    struct ProbeDatabase {
        connection: Connection,
        _root: File,
        _database: File,
    }

    #[derive(Debug, Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    struct RunnerRecord {
        process: ProcessIdentity,
        socket: SocketIdentity,
        artifact_generation: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cw_runtime_catalog_generation: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error_code: Option<String>,
    }

    #[derive(Debug, Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    struct SocketIdentity {
        device: u64,
        inode: u64,
        uid: u32,
        mode: u32,
    }

    #[derive(Debug)]
    struct OperationRow {
        kind: String,
        phase: String,
        checkpoint: u32,
        runtime_completed: Option<bool>,
    }

    #[derive(Deserialize)]
    struct BuiltWorkspaceIdentity {
        root_generation: String,
    }

    pub(super) fn run(arguments: impl IntoIterator<Item = String>) -> ProbeResult<()> {
        let mut arguments = arguments.into_iter().peekable();
        if arguments.peek().map(String::as_str) == Some("daemon-capability") {
            arguments.next();
            return daemon_capability::run(arguments);
        }
        let args = Args::parse(arguments)?;
        let database = ProbeDatabase::open(&args.state_root)?;
        match args.action {
            Action::Value(field) => println!("{}", database.value(field, &args.name)?),
            Action::KillRunner => {
                let runner = database.runner(&args.name)?;
                let pid = runner.process.pid;
                drop(database);
                let process = LiveProcess::recover(&runner.process)?;
                process.signal(Signal::KILL)?;
                println!("{pid}");
            }
        }
        Ok(())
    }

    /// `daemon-capability record|present` (#3046 R4 journey): record the
    /// running environment's daemon capability, or present a recorded one
    /// to its daemon now and say whether the daemon accepts it. Synthetic
    /// test environments only: `record` prints the capability.
    mod daemon_capability {
        use super::*;
        use codewire_local_vmm::supervisor_client::NativeSupervisorClient;
        use codewire_local_vmm::supervisor_config::NativeRuntimeConfig;

        pub(super) fn run(arguments: impl Iterator<Item = String>) -> ProbeResult<()> {
            let mut arguments = arguments;
            let action = arguments.next().ok_or_else(failed)?;
            let mut flags = std::collections::BTreeMap::new();
            while let Some(flag) = arguments.next() {
                let value = arguments.next().ok_or_else(failed)?;
                if flags.insert(flag, value).is_some() {
                    return Err(failed());
                }
            }
            let mut take = |flag: &str| flags.remove(flag).ok_or_else(failed);
            let config = NativeRuntimeConfig {
                root: PathBuf::from(take("--root")?),
                artifact_root: PathBuf::from(take("--artifact-root")?),
                artifact_lock: PathBuf::from(take("--artifact-lock")?),
                mesh_data_dir: PathBuf::from(take("--mesh-data-dir")?),
                platform_config_dir: PathBuf::from(take("--platform-config-dir")?),
                credential_authority_root: PathBuf::from(take("--credential-authority-root")?),
                executable: PathBuf::from(take("--cw-bin")?),
            };
            let name = take("--name")?;
            let capability_file = match action.as_str() {
                "record" => None,
                "present" => Some(PathBuf::from(take("--capability-file")?)),
                _ => return Err(failed()),
            };
            if !flags.is_empty() {
                return Err(failed());
            }
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            runtime.block_on(async move {
                let mut supervisor = NativeSupervisorClient::connect_runtime(&config).await?;
                let access = supervisor.daemon_access(&name).await?;
                match capability_file {
                    None => println!("{}", access.generation_capability),
                    Some(file) => {
                        let presented = fs::read_to_string(file)?.trim().to_owned();
                        let daemon = codewire_local_vmm::hybrid_vsock::connect_daemon(
                            Path::new(&access.hybrid_socket),
                            access.guest_port,
                            &presented,
                        )
                        .await?;
                        match daemon.get_capabilities(&[]).await {
                            Ok(_) => println!("accepted"),
                            Err(codewire_daemon::client::SessionClientError::Status(status))
                                if status.code() == tonic::Code::Unauthenticated =>
                            {
                                println!("refused: Unauthenticated");
                            }
                            Err(error) => return Err(Box::new(error) as Box<_>),
                        }
                    }
                }
                Ok::<_, Box<dyn Error + Send + Sync>>(())
            })
        }
    }

    impl Args {
        fn parse(arguments: impl IntoIterator<Item = String>) -> ProbeResult<Self> {
            let mut arguments = arguments.into_iter();
            let action = match arguments.next().as_deref() {
                Some("value") => Action::Value(Field::parse(
                    arguments.next().as_deref().ok_or_else(failed)?,
                )?),
                Some("kill-runner") => Action::KillRunner,
                _ => return Err(failed()),
            };
            let mut state_root = None;
            let mut name = None;
            while let Some(flag) = arguments.next() {
                let value = arguments.next().ok_or_else(failed)?;
                let slot = match flag.as_str() {
                    "--state-root" => &mut state_root,
                    "--name" => &mut name,
                    _ => return Err(failed()),
                };
                if slot.replace(value).is_some() {
                    return Err(failed());
                }
            }
            let state_root = PathBuf::from(state_root.ok_or_else(failed)?);
            require(state_root.is_absolute())?;
            let name = name
                .filter(|value| !value.is_empty() && value.len() <= 128 && !value.contains('\0'))
                .ok_or_else(failed)?;
            Ok(Self {
                action,
                state_root,
                name,
            })
        }
    }

    impl Field {
        fn parse(value: &str) -> ProbeResult<Self> {
            match value {
                "environment_id" => Ok(Self::EnvironmentId),
                "runner_pid" => Ok(Self::RunnerPid),
                "runner_error_code" => Ok(Self::RunnerErrorCode),
                "active_artifact_generation" => Ok(Self::ActiveArtifactGeneration),
                "runner_artifact_generation" => Ok(Self::RunnerArtifactGeneration),
                "built_workspace_identity" => Ok(Self::BuiltWorkspaceIdentity),
                "empty" => Ok(Self::Empty),
                "contract" => Ok(Self::Contract),
                "resize_operation" => Ok(Self::ResizeOperation),
                "source_operation" => Ok(Self::SourceOperation),
                "journal_complete" => Ok(Self::JournalComplete),
                "journal_summary" => Ok(Self::JournalSummary),
                "ownership" => Ok(Self::Ownership),
                _ => Err(failed()),
            }
        }
    }

    impl ProbeDatabase {
        fn open(root: &Path) -> ProbeResult<Self> {
            let root_handle = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(root)?;
            let root_metadata = root_handle.metadata()?;
            validate_owner_only(&root_metadata, true, 0o700)?;
            require(fs::canonicalize(root)? == root)?;

            let database_path = root.join(DATABASE_FILE);
            let database_handle = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&database_path)?;
            let database_metadata = database_handle.metadata()?;
            validate_owner_only(&database_metadata, false, 0o600)?;

            let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX;
            let connection = Connection::open_with_flags(&database_path, flags)?;
            connection.busy_timeout(BUSY_TIMEOUT)?;
            connection.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)?;
            connection.pragma_update(None, "foreign_keys", true)?;
            connection.pragma_update(None, "trusted_schema", false)?;
            require_persistent_wal(&connection)?;
            validate_schema(&connection)?;

            let named_root = fs::symlink_metadata(root)?;
            let named_database = fs::symlink_metadata(&database_path)?;
            require(same_file(&root_metadata, &named_root))?;
            require(same_file(&database_metadata, &named_database))?;
            validate_owner_only(&named_root, true, 0o700)?;
            validate_owner_only(&named_database, false, 0o600)?;
            Ok(Self {
                connection,
                _root: root_handle,
                _database: database_handle,
            })
        }

        fn value(&self, field: Field, name: &str) -> ProbeResult<String> {
            match field {
                Field::EnvironmentId => {
                    let id: String = self.environment_value(name, "id")?;
                    let parsed = Uuid::parse_str(&id)?;
                    require(!parsed.is_nil() && parsed.to_string() == id)?;
                    Ok(id)
                }
                Field::RunnerPid => Ok(self.runner(name)?.process.pid.to_string()),
                Field::RunnerErrorCode => self.runner(name)?.error_code.ok_or_else(failed),
                Field::ActiveArtifactGeneration => {
                    let generation: String =
                        self.environment_value(name, "active_artifact_generation")?;
                    require(valid_sha256(&generation))?;
                    Ok(generation)
                }
                Field::RunnerArtifactGeneration => {
                    let generation = self.runner(name)?.artifact_generation;
                    require(valid_sha256(&generation))?;
                    Ok(generation)
                }
                Field::BuiltWorkspaceIdentity => {
                    // Return only the immutable root identity and a digest of
                    // its complete build record, never the embedded project
                    // configuration. Bound the SQL result before allocation.
                    let encoded: Vec<u8> = self.connection.query_row(
                        "SELECT active_workspace_generation_json FROM environments \
                         WHERE name = ?1 AND length(active_workspace_generation_json) BETWEEN 1 AND ?2",
                        rusqlite::params![name, MAXIMUM_WORKSPACE_METADATA_BYTES],
                        |row| row.get(0),
                    )?;
                    let built: BuiltWorkspaceIdentity = serde_json::from_slice(&encoded)?;
                    require(valid_sha256(&built.root_generation))?;
                    Ok(format!(
                        "{}:{:x}",
                        built.root_generation,
                        Sha256::digest(&encoded)
                    ))
                }
                Field::Empty => {
                    let count: i64 = self.connection.query_row(
                        "SELECT count(*) FROM environments",
                        [],
                        |row| row.get(0),
                    )?;
                    let current: Option<String> = self.connection.query_row(
                        "SELECT current_environment_id FROM supervisor_settings WHERE singleton = 1",
                        [],
                        |row| row.get(0),
                    )?;
                    require(count >= 0)?;
                    Ok(if count == 0 && current.is_none() {
                        "yes"
                    } else {
                        "no"
                    }
                    .to_owned())
                }
                Field::Contract => {
                    let journal: String =
                        self.connection
                            .pragma_query_value(None, "journal_mode", |row| row.get(0))?;
                    let quick_check: String =
                        self.connection
                            .query_row("PRAGMA quick_check(1)", [], |row| row.get(0))?;
                    require(journal.eq_ignore_ascii_case("wal") && quick_check == "ok")?;
                    Ok(format!(
                        "{DATABASE_APPLICATION_ID}:{DATABASE_SCHEMA_VERSION}:wal:ok"
                    ))
                }
                Field::ResizeOperation => {
                    let row = self
                        .connection
                        .query_row(
                            "SELECT kind, phase, checkpoint FROM operations \
                             WHERE kind IN ('restart', 'grow_disk') \
                             ORDER BY created_unix_ms DESC LIMIT 1",
                            [],
                            decode_operation,
                        )
                        .optional()?
                        .ok_or_else(failed)?;
                    row.validate()?;
                    Ok(row.summary())
                }
                Field::SourceOperation => {
                    let row = self
                        .connection
                        .query_row(
                            "SELECT kind, phase, checkpoint FROM operations \
                             WHERE kind = 'update_environment_sources' AND environment_id = \
                             (SELECT id FROM environments WHERE name = ?1) \
                             ORDER BY created_unix_ms DESC, operation_id DESC LIMIT 1",
                            [name],
                            decode_operation,
                        )
                        .optional()?
                        .ok_or_else(failed)?;
                    row.validate()?;
                    Ok(row.summary())
                }
                Field::JournalComplete => {
                    let rows = self.operations()?;
                    let complete = !rows.is_empty()
                        && rows.iter().all(|row| {
                            row.phase == "completed"
                                && row.runtime_completed.unwrap_or_else(|| {
                                    terminal_checkpoint(&row.kind) == Some(row.checkpoint)
                                })
                        });
                    Ok(if complete { "yes" } else { "no" }.to_owned())
                }
                Field::JournalSummary => {
                    let rows = self.operations()?;
                    for row in &rows {
                        row.validate()?;
                    }
                    Ok(rows
                        .into_iter()
                        .map(|row| row.summary())
                        .collect::<Vec<_>>()
                        .join(","))
                }
                Field::Ownership => {
                    let (id, generation): (String, String) = self.connection.query_row(
                        "SELECT id, active_artifact_generation FROM environments WHERE name = ?1",
                        [name],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )?;
                    require(!Uuid::parse_str(&id)?.is_nil() && valid_sha256(&generation))?;
                    let count: i64 = self.connection.query_row(
                        "SELECT count(*) FROM owned_objects WHERE environment_id = ?1",
                        [id],
                        |row| row.get(0),
                    )?;
                    require(count >= 0)?;
                    Ok(format!("{}:{count}", generation.len()))
                }
            }
        }

        fn environment_value<T: rusqlite::types::FromSql>(
            &self,
            name: &str,
            column: &str,
        ) -> ProbeResult<T> {
            let sql = match column {
                "id" => "SELECT id FROM environments WHERE name = ?1",
                "active_artifact_generation" => {
                    "SELECT active_artifact_generation FROM environments WHERE name = ?1"
                }
                _ => return Err(failed()),
            };
            self.connection
                .query_row(sql, [name], |row| row.get(0))
                .map_err(Into::into)
        }

        fn runner(&self, name: &str) -> ProbeResult<RunnerRecord> {
            let encoded: Vec<u8> = self.connection.query_row(
                "SELECT runner_json FROM environments WHERE name = ?1",
                [name],
                |row| row.get(0),
            )?;
            require(encoded.len() <= 64 * 1024)?;
            let runner: RunnerRecord = serde_json::from_slice(&encoded)?;
            require(valid_sha256(&runner.artifact_generation) && runner.process.pid > 0)?;
            require(
                runner
                    .cw_runtime_catalog_generation
                    .as_deref()
                    .is_none_or(valid_sha256),
            )?;
            require(runner.error_code.as_deref().is_none_or(|error_code| {
                !error_code.is_empty()
                    && error_code.len() <= 64
                    && error_code
                        .bytes()
                        .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
            }))?;
            Ok(runner)
        }

        fn operations(&self) -> ProbeResult<Vec<OperationRow>> {
            let limit = i64::try_from(MAXIMUM_OPERATIONS + 1)?;
            let mut statement = self.connection.prepare(
                "SELECT kind, phase, checkpoint,
                   CASE WHEN kind IN ('update_cw_runtime', 'rollback_cw_runtime')
                     AND typeof(operation_id) = 'text' AND length(operation_id) = 36
                     THEN operation_id END,
                   CASE WHEN kind IN ('update_cw_runtime', 'rollback_cw_runtime')
                     AND typeof(environment_id) = 'text' AND length(environment_id) = 36
                     THEN environment_id END,
                   CASE WHEN kind IN ('update_cw_runtime', 'rollback_cw_runtime')
                     THEN typeof(payload_json) END,
                   CASE WHEN kind IN ('update_cw_runtime', 'rollback_cw_runtime')
                     THEN length(payload_json) END,
                   CASE WHEN kind IN ('update_cw_runtime', 'rollback_cw_runtime')
                     AND typeof(payload_json) = 'blob' AND length(payload_json) BETWEEN 1 AND ?2
                     THEN payload_json END,
                   CASE WHEN kind IN ('update_cw_runtime', 'rollback_cw_runtime')
                     THEN typeof(result_json) END,
                   CASE WHEN kind IN ('update_cw_runtime', 'rollback_cw_runtime')
                     THEN length(result_json) END,
                   CASE WHEN kind IN ('update_cw_runtime', 'rollback_cw_runtime')
                     AND typeof(result_json) = 'blob' AND length(result_json) BETWEEN 1 AND ?2
                     THEN result_json END,
                   CASE WHEN kind IN ('update_cw_runtime', 'rollback_cw_runtime')
                     THEN typeof(error_code) END,
                   CASE WHEN kind IN ('update_cw_runtime', 'rollback_cw_runtime')
                     THEN length(CAST(error_code AS BLOB)) END,
                   CASE WHEN kind IN ('update_cw_runtime', 'rollback_cw_runtime')
                     AND typeof(error_code) = 'text'
                     AND length(CAST(error_code AS BLOB)) BETWEEN 1 AND 64
                     THEN error_code END
                 FROM operations ORDER BY created_unix_ms, operation_id LIMIT ?1",
            )?;
            let rows = statement
                .query_map(
                    rusqlite::params![limit, CwRuntimeJournalEvidence::MAXIMUM_JSON_BYTES],
                    decode_journal_operation,
                )?
                .collect::<Result<Vec<_>, _>>()?;
            require(rows.len() <= MAXIMUM_OPERATIONS)?;
            Ok(rows)
        }
    }

    impl OperationRow {
        fn validate(&self) -> ProbeResult<()> {
            require(self.runtime_completed.is_some() || terminal_checkpoint(&self.kind).is_some())?;
            require(matches!(
                self.phase.as_str(),
                "intent" | "effect_applied" | "completed" | "failed" | "interrupted"
            ))?;
            require(self.checkpoint <= 16)
        }

        fn summary(self) -> String {
            format!("{}:{}:{}", self.kind, self.phase, self.checkpoint)
        }
    }

    fn decode_operation(row: &rusqlite::Row<'_>) -> rusqlite::Result<OperationRow> {
        let checkpoint = row.get::<_, i64>(2)?;
        let checkpoint = u32::try_from(checkpoint).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                2,
                rusqlite::types::Type::Integer,
                Box::new(error),
            )
        })?;
        Ok(OperationRow {
            kind: row.get(0)?,
            phase: row.get(1)?,
            checkpoint,
            runtime_completed: None,
        })
    }

    fn decode_journal_operation(row: &rusqlite::Row<'_>) -> rusqlite::Result<OperationRow> {
        let mut operation = decode_operation(row)?;
        if !matches!(
            operation.kind.as_str(),
            "update_cw_runtime" | "rollback_cw_runtime"
        ) {
            return Ok(operation);
        }
        let validate = || -> ProbeResult<bool> {
            let operation_id = canonical_uuid(row.get::<_, Option<String>>(3)?)?;
            let environment_id = canonical_uuid(row.get::<_, Option<String>>(4)?)?;
            let payload = journal_blob(row, 5, true)?.ok_or_else(failed)?;
            let result = journal_blob(row, 8, false)?;
            let error_type: String = row.get(11)?;
            let error_size: Option<i64> = row.get(12)?;
            let error_code: Option<String> = row.get(13)?;
            match error_type.as_str() {
                "null" => require(error_size.is_none() && error_code.is_none())?,
                "text" => require(
                    error_size.is_some_and(|size| (1..=64).contains(&size))
                        && error_code
                            .as_ref()
                            .is_some_and(|code| i64::try_from(code.len()).ok() == error_size),
                )?,
                _ => return Err(failed()),
            }
            require(operation.checkpoint <= 16)?;
            require(
                CwRuntimeJournalEvidence {
                    kind: &operation.kind,
                    operation_id,
                    environment_id,
                    phase: &operation.phase,
                    payload: &payload,
                    result: result.as_deref(),
                    error_code: error_code.as_deref(),
                }
                .validate(),
            )?;
            Ok(operation.phase == "completed")
        };
        // Validate and release each bounded JSON row before reading another;
        // the returned vector retains only fixed summary/completion fields.
        operation.runtime_completed = Some(validate().map_err(|_| {
            rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, failed())
        })?);
        Ok(operation)
    }

    fn canonical_uuid(value: Option<String>) -> ProbeResult<Uuid> {
        let value = value.ok_or_else(failed)?;
        let parsed = Uuid::parse_str(&value)?;
        require(!parsed.is_nil() && parsed.to_string() == value)?;
        Ok(parsed)
    }

    fn journal_blob(
        row: &rusqlite::Row<'_>,
        type_column: usize,
        required: bool,
    ) -> ProbeResult<Option<Vec<u8>>> {
        let storage_type: String = row.get(type_column)?;
        let size: Option<i64> = row.get(type_column + 1)?;
        let bytes: Option<Vec<u8>> = row.get(type_column + 2)?;
        match storage_type.as_str() {
            "null" if !required => require(size.is_none() && bytes.is_none())?,
            "blob" => require(
                size.is_some_and(|size| {
                    (1..=CwRuntimeJournalEvidence::MAXIMUM_JSON_BYTES as i64).contains(&size)
                }) && bytes
                    .as_ref()
                    .is_some_and(|bytes| i64::try_from(bytes.len()).ok() == size),
            )?,
            _ => return Err(failed()),
        }
        Ok(bytes)
    }

    fn terminal_checkpoint(kind: &str) -> Option<u32> {
        match kind {
            "create" => Some(9),
            "start" => Some(7),
            "stop" => Some(3),
            "restart" => Some(9),
            "grow_disk" => Some(6),
            "update_workspace" | "rollback_workspace" => Some(10),
            "update_environment_sources" => Some(10),
            "delete" => Some(6),
            "reconcile" => Some(2),
            _ => None,
        }
    }

    fn validate_schema(connection: &Connection) -> ProbeResult<()> {
        let application_id: i64 =
            connection.pragma_query_value(None, "application_id", |row| row.get(0))?;
        let schema_version: i64 =
            connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
        require(
            application_id == DATABASE_APPLICATION_ID && schema_version == DATABASE_SCHEMA_VERSION,
        )?;
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
            require(present)?;
        }
        let platform: (i64, Option<String>) = connection.query_row(
            "SELECT COUNT(*), MIN(value) FROM supervisor_metadata WHERE key = 'platform'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        require(platform == (1, Some("linux-v1".to_owned())))?;
        let runtime_binding = connection
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
        require(runtime_binding == Some(("BLOB".to_owned(), 0, None, 0, 0)))?;
        Ok(())
    }

    fn require_persistent_wal(connection: &Connection) -> ProbeResult<()> {
        fn control(connection: &Connection, value: &mut i32) -> i32 {
            // SAFETY: the connection stays borrowed, `main` is a static
            // NUL-terminated schema name, and SQLite reads or writes one i32.
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
        require(control(connection, &mut enabled) == rusqlite::ffi::SQLITE_OK)?;
        let mut observed = -1;
        require(control(connection, &mut observed) == rusqlite::ffi::SQLITE_OK && observed == 1)
    }

    fn validate_owner_only(metadata: &fs::Metadata, directory: bool, mode: u32) -> ProbeResult<()> {
        // SAFETY: geteuid has no preconditions and cannot mutate process state.
        let uid = unsafe { libc::geteuid() };
        require(metadata.uid() == uid)?;
        require(metadata.permissions().mode() & 0o777 == mode)?;
        require(if directory {
            metadata.is_dir()
        } else {
            metadata.is_file()
        })
    }

    fn same_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
        left.dev() == right.dev() && left.ino() == right.ino()
    }

    fn valid_sha256(value: &str) -> bool {
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }

    fn require(condition: bool) -> ProbeResult<()> {
        if condition { Ok(()) } else { Err(failed()) }
    }

    fn failed() -> Box<dyn Error + Send + Sync> {
        Box::new(io::Error::other("native state probe assertion failed"))
    }

    #[cfg(test)]
    mod tests {
        use std::io::Read as _;
        use std::os::unix::net::UnixStream;
        use std::os::unix::process::ExitStatusExt as _;
        use std::process::{Child, Command, Stdio};

        use codewire_vmm_guest_probe::cw_runtime::{
            CwImageDescriptor, CwImagePayload, CwRuntimeCatalog, CwRuntimeProvenance,
        };
        use codewire_vmm_guest_probe::cw_runtime_live::{
            RuntimeBinding, RuntimeReply, RuntimeSelection, SelectionOutcome, SelectionReceipt,
        };
        use rusqlite::params;

        use super::*;

        struct ChildGuard(Child);

        impl Drop for ChildGuard {
            fn drop(&mut self) {
                // The unreaped Child owns this process birth even if an
                // assertion fails before the pidfd is admitted.
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }

        struct Fixture {
            _parent: tempfile::TempDir,
            root: PathBuf,
            writer: Connection,
            environment_id: String,
        }

        impl Fixture {
            fn new(process: ProcessIdentity) -> Self {
                let parent = tempfile::tempdir().unwrap();
                let root = parent.path().join("state");
                fs::create_dir(&root).unwrap();
                fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
                let database = root.join(DATABASE_FILE);
                let writer = Connection::open(&database).unwrap();
                writer.pragma_update(None, "journal_mode", "WAL").unwrap();
                require_persistent_wal(&writer).unwrap();
                writer
                    .execute_batch(
                        "CREATE TABLE supervisor_metadata(key TEXT, value TEXT);
                         CREATE TABLE environments(
                           id TEXT, name TEXT, runner_json BLOB,
                           active_artifact_generation TEXT,
                           active_workspace_generation_json BLOB,
                           cw_runtime_binding_json BLOB NULL
                         );
                         CREATE TABLE supervisor_settings(
                           singleton INTEGER, current_environment_id TEXT
                         );
                         CREATE TABLE owned_objects(environment_id TEXT);
                         CREATE TABLE operations(
                           operation_id TEXT, kind TEXT, phase TEXT,
                           checkpoint INTEGER, created_unix_ms INTEGER,
                           environment_id TEXT, payload_json BLOB,
                           result_json BLOB, error_code TEXT
                         );
                         INSERT INTO supervisor_metadata VALUES ('platform', 'linux-v1');
                         INSERT INTO supervisor_settings VALUES (1, NULL);
                         PRAGMA application_id = 1129797197;
                         PRAGMA user_version = 12;",
                    )
                    .unwrap();
                fs::set_permissions(&database, fs::Permissions::from_mode(0o600)).unwrap();
                let environment_id = Uuid::new_v4().to_string();
                let runner = runner_record(process);
                writer
                    .execute(
                        "INSERT INTO environments
                         (id, name, runner_json, active_artifact_generation,
                          active_workspace_generation_json)
                         VALUES (?1, 'native-smoke', ?2, ?3, ?4)",
                        params![
                            environment_id,
                            serde_json::to_vec(&runner).unwrap(),
                            "a".repeat(64),
                            serde_json::to_vec(&serde_json::json!({
                                "root_generation": "c".repeat(64),
                                "project_spec_json": "synthetic-private-build-sentinel"
                            }))
                            .unwrap()
                        ],
                    )
                    .unwrap();
                writer
                    .execute("INSERT INTO owned_objects VALUES (?1)", [&environment_id])
                    .unwrap();
                writer
                    .execute(
                        "INSERT INTO operations
                         (operation_id, kind, phase, checkpoint, created_unix_ms, environment_id)
                         VALUES ('op-a', 'create', 'completed', 9, 1, ?1)",
                        [&environment_id],
                    )
                    .unwrap();
                Self {
                    _parent: parent,
                    root,
                    writer,
                    environment_id,
                }
            }

            fn database(&self) -> ProbeDatabase {
                ProbeDatabase::open(&self.root).unwrap()
            }
        }

        fn runner_record(process: ProcessIdentity) -> RunnerRecord {
            RunnerRecord {
                process,
                socket: SocketIdentity {
                    device: 1,
                    inode: 2,
                    uid: unsafe { libc::geteuid() },
                    mode: 0o140600,
                },
                artifact_generation: "b".repeat(64),
                cw_runtime_catalog_generation: None,
                error_code: None,
            }
        }

        struct RuntimeJournal {
            operation_id: Uuid,
            kind: &'static str,
            payload: serde_json::Value,
            result: serde_json::Value,
        }

        impl RuntimeJournal {
            fn new(fixture: &Fixture, rollback: bool, cancelled: bool) -> Self {
                let environment_id = Uuid::parse_str(&fixture.environment_id).unwrap();
                let binding = RuntimeBinding {
                    environment_id,
                    generation: 7,
                    bootstrap_catalog_sha256: "c".repeat(64),
                };
                let a = runtime_member('a');
                let b = runtime_member('b');
                let target = if cancelled {
                    runtime_member('d')
                } else if rollback {
                    a.clone()
                } else {
                    b.clone()
                };
                let mut runner =
                    runner_record(ProcessIdentity::capture(std::process::id()).unwrap());
                runner.cw_runtime_catalog_generation = Some("c".repeat(64));
                let payload = serde_json::json!({
                    "binding": binding,
                    "runner": runner,
                    "vmm": runner.process,
                    "vsock": runner.socket,
                    "expected_revision": 3,
                    "target": target,
                    "rollback": rollback,
                });
                let operation_id = Uuid::new_v4();
                let receipt = SelectionReceipt {
                    operation_id,
                    generation: 7,
                    expected_revision: 3,
                    target_sha256: target.payload.sha256.clone(),
                    outcome: if cancelled {
                        SelectionOutcome::Cancelled
                    } else {
                        SelectionOutcome::Committed
                    },
                    selection_revision: if cancelled { 3 } else { 4 },
                };
                let result = serde_json::to_value(RuntimeReply {
                    protocol_version: 1,
                    binding,
                    selection: RuntimeSelection {
                        schema_version: 1,
                        environment_id,
                        bootstrap_catalog_sha256: "c".repeat(64),
                        revision: receipt.selection_revision,
                        previous_sha256: if cancelled || rollback {
                            Some(b.payload.sha256.clone())
                        } else {
                            Some(a.payload.sha256.clone())
                        },
                        catalog: CwRuntimeCatalog {
                            schema_version: 1,
                            active_sha256: if cancelled {
                                a.payload.sha256.clone()
                            } else {
                                target.payload.sha256.clone()
                            },
                            runtimes: vec![a, b],
                        },
                        operations: vec![receipt.clone()],
                    },
                    observed: Some(receipt),
                })
                .unwrap();
                Self {
                    operation_id,
                    kind: if rollback {
                        "rollback_cw_runtime"
                    } else {
                        "update_cw_runtime"
                    },
                    payload,
                    result,
                }
            }

            fn insert(&self, fixture: &Fixture, checkpoint: u32) {
                fixture
                    .writer
                    .execute(
                        "INSERT INTO operations
                     (operation_id, kind, phase, checkpoint, created_unix_ms, environment_id,
                      payload_json, result_json, error_code)
                     VALUES (?1, ?2, 'completed', ?3, 2, ?4, ?5, ?6, NULL)",
                        params![
                            self.operation_id.to_string(),
                            self.kind,
                            checkpoint,
                            fixture.environment_id,
                            serde_json::to_vec(&self.payload).unwrap(),
                            serde_json::to_vec(&self.result).unwrap(),
                        ],
                    )
                    .unwrap();
            }

            fn update(&self, fixture: &Fixture) {
                fixture
                    .writer
                    .execute(
                        "UPDATE operations SET kind = ?2, phase = 'completed', checkpoint = 1,
                     environment_id = ?3, payload_json = ?4, result_json = ?5, error_code = NULL
                     WHERE operation_id = ?1",
                        params![
                            self.operation_id.to_string(),
                            self.kind,
                            fixture.environment_id,
                            serde_json::to_vec(&self.payload).unwrap(),
                            serde_json::to_vec(&self.result).unwrap(),
                        ],
                    )
                    .unwrap();
            }
        }

        fn runtime_member(byte: char) -> CwRuntimeProvenance {
            let descriptor = CwImageDescriptor {
                sha256: "a".repeat(64),
                size: 10240,
            };
            CwRuntimeProvenance {
                schema_version: 1,
                image_index_sha256: "b".repeat(64),
                image_manifest: descriptor.clone(),
                image_config: descriptor.clone(),
                image_layer: descriptor,
                layer_diff_id: "a".repeat(64),
                payload: CwImagePayload {
                    schema_version: 2,
                    protocol_version: 1,
                    record_version: 1,
                    package_version: "0.1.0".into(),
                    target: codewire_vmm_guest_probe::cw_runtime::CW_RUNTIME_TARGET.into(),
                    source_revision: "c".repeat(40),
                    source_tree_sha256: "d".repeat(64),
                    rustc: "rustc 1.93.0 (synthetic journal fixture)".into(),
                    sha256: byte.to_string().repeat(64),
                    size: 136,
                },
            }
        }

        fn assert_runtime_row_refused(fixture: &Fixture) {
            let database = fixture.database();
            for field in [Field::JournalComplete, Field::JournalSummary] {
                assert!(database.value(field, "native-smoke").is_err(), "{field:?}");
            }
        }

        #[test]
        fn runtime_journal_completed_receipts_preserve_lifecycle_completion() {
            let fixture = Fixture::new(ProcessIdentity::capture(std::process::id()).unwrap());
            for (rollback, cancelled, checkpoint) in [
                (false, false, 1),
                (true, false, 1),
                (false, false, 0),
                (false, true, 0),
                (false, false, 16),
            ] {
                let row = RuntimeJournal::new(&fixture, rollback, cancelled);
                row.insert(&fixture, checkpoint);
                let database = fixture.database();
                assert_eq!(
                    database
                        .value(Field::JournalComplete, "native-smoke")
                        .unwrap(),
                    "yes"
                );
                assert_eq!(
                    database
                        .value(Field::JournalSummary, "native-smoke")
                        .unwrap(),
                    format!("create:completed:9,{}:completed:{checkpoint}", row.kind)
                );
                let stored: Vec<u8> = fixture
                    .writer
                    .query_row(
                        "SELECT result_json FROM operations WHERE operation_id = ?1",
                        [row.operation_id.to_string()],
                        |value| value.get(0),
                    )
                    .unwrap();
                assert_eq!(stored, serde_json::to_vec(&row.result).unwrap());
                fixture
                    .writer
                    .execute(
                        "DELETE FROM operations WHERE operation_id = ?1",
                        [row.operation_id.to_string()],
                    )
                    .unwrap();
            }
        }

        #[test]
        fn runtime_journal_requires_exact_typed_intent_and_receipt() {
            let fixture = Fixture::new(ProcessIdentity::capture(std::process::id()).unwrap());
            let row = RuntimeJournal::new(&fixture, false, false);
            row.insert(&fixture, 1);
            for mutation in 0..13 {
                let mut result = row.result.clone();
                match mutation {
                    0 => result["observed"] = serde_json::Value::Null,
                    1 => result["binding"]["environment_id"] = serde_json::json!(Uuid::new_v4()),
                    2 => result["binding"]["generation"] = serde_json::json!(8),
                    3 => {
                        result["binding"]["bootstrap_catalog_sha256"] =
                            serde_json::json!("f".repeat(64))
                    }
                    4 => result["observed"]["operation_id"] = serde_json::json!(Uuid::new_v4()),
                    5 => {
                        result["observed"]["generation"] = serde_json::json!(8);
                        result["selection"]["operations"][0]["generation"] = serde_json::json!(8);
                    }
                    6 => {
                        result["observed"]["expected_revision"] = serde_json::json!(2);
                        result["selection"]["operations"][0]["expected_revision"] =
                            serde_json::json!(2);
                    }
                    7 => {
                        result["observed"]["target_sha256"] = serde_json::json!("a".repeat(64));
                        result["selection"]["operations"][0]["target_sha256"] =
                            serde_json::json!("a".repeat(64));
                    }
                    8 => result["observed"]["outcome"] = serde_json::json!("unknown"),
                    9 => result["extra"] = serde_json::json!(true),
                    10 => {
                        result["selection"]["catalog"]["runtimes"][1]["payload"]["source_revision"] =
                            serde_json::json!("e".repeat(40))
                    }
                    11 => {
                        result["selection"]["catalog"]["runtimes"][1]["payload"]["rustc"] =
                            serde_json::json!("rustc 1.91.1 (unadmitted)")
                    }
                    _ => result["selection"]["environment_id"] = serde_json::json!(Uuid::new_v4()),
                }
                fixture
                    .writer
                    .execute(
                        "UPDATE operations SET result_json = ?1 WHERE operation_id = ?2",
                        params![
                            serde_json::to_vec(&result).unwrap(),
                            row.operation_id.to_string()
                        ],
                    )
                    .unwrap();
                assert_runtime_row_refused(&fixture);
            }
            for mutation in 0..7 {
                row.update(&fixture);
                let mut payload = row.payload.clone();
                match mutation {
                    0 => payload["extra"] = serde_json::json!(true),
                    1 => payload["binding"]["environment_id"] = serde_json::json!(Uuid::new_v4()),
                    2 => payload["expected_revision"] = serde_json::json!(0),
                    3 => payload["rollback"] = serde_json::json!(true),
                    4 => payload["target"]["payload"]["sha256"] = serde_json::json!("x".repeat(64)),
                    5 => {
                        payload["runner"]["cw_runtime_catalog_generation"] =
                            serde_json::json!("f".repeat(64))
                    }
                    _ => {
                        payload["target"]["capability"] =
                            serde_json::json!("synthetic-refused-field")
                    }
                }
                fixture
                    .writer
                    .execute(
                        "UPDATE operations SET payload_json = ?1 WHERE operation_id = ?2",
                        params![
                            serde_json::to_vec(&payload).unwrap(),
                            row.operation_id.to_string()
                        ],
                    )
                    .unwrap();
                assert_runtime_row_refused(&fixture);
            }
            for (column, bad) in [
                ("operation_id", Uuid::nil().to_string()),
                ("operation_id", "not-an-operation-uuid".to_owned()),
                ("environment_id", Uuid::nil().to_string()),
                ("environment_id", Uuid::new_v4().to_string()),
            ] {
                row.update(&fixture);
                let sql =
                    format!("UPDATE operations SET {column} = ?1 WHERE kind = 'update_cw_runtime'");
                fixture.writer.execute(&sql, [bad]).unwrap();
                assert_runtime_row_refused(&fixture);
                fixture
                    .writer
                    .execute(
                        "UPDATE operations SET operation_id = ?1 WHERE kind = 'update_cw_runtime'",
                        [row.operation_id.to_string()],
                    )
                    .unwrap();
            }
            row.update(&fixture);
            fixture
                .writer
                .execute(
                    "UPDATE operations SET checkpoint = 17 WHERE kind = 'update_cw_runtime'",
                    [],
                )
                .unwrap();
            assert_runtime_row_refused(&fixture);
        }

        #[test]
        fn runtime_journal_sql_bounds_preserve_type_null_and_error_evidence() {
            use rusqlite::types::Value;
            let fixture = Fixture::new(ProcessIdentity::capture(std::process::id()).unwrap());
            let row = RuntimeJournal::new(&fixture, false, false);
            row.insert(&fixture, 1);
            let mut full_payload = serde_json::to_vec(&row.payload).unwrap();
            let mut full_result = serde_json::to_vec(&row.result).unwrap();
            full_payload.resize(2 * 1024 * 1024, b' ');
            full_result.resize(2 * 1024 * 1024, b' ');
            fixture.writer.execute(
                "UPDATE operations SET payload_json = ?1, result_json = ?2 WHERE operation_id = ?3",
                params![full_payload, full_result, row.operation_id.to_string()],
            ).unwrap();
            assert_eq!(
                fixture
                    .database()
                    .value(Field::JournalComplete, "native-smoke")
                    .unwrap(),
                "yes"
            );
            let bad_json = [
                Value::Null,
                Value::Integer(1),
                Value::Real(1.0),
                Value::Text(serde_json::to_string(&row.result).unwrap()),
                Value::Blob(Vec::new()),
                Value::Blob(b"{\"truncated\":".to_vec()),
                Value::Blob(vec![b' '; 2 * 1024 * 1024 + 1]),
            ];
            for column in ["payload_json", "result_json"] {
                for bad in &bad_json {
                    row.update(&fixture);
                    let sql =
                        format!("UPDATE operations SET {column} = ?1 WHERE operation_id = ?2");
                    fixture
                        .writer
                        .execute(&sql, params![bad, row.operation_id.to_string()])
                        .unwrap();
                    assert_runtime_row_refused(&fixture);
                }
            }
            for phase in ["intent", "effect_applied", "failed", "interrupted"] {
                row.update(&fixture);
                let error = matches!(phase, "failed" | "interrupted").then_some("runtime_unknown");
                fixture.writer.execute("UPDATE operations SET phase = ?1, result_json = NULL, error_code = ?2 WHERE operation_id = ?3",
                    params![phase, error, row.operation_id.to_string()]).unwrap();
                let database = fixture.database();
                assert_eq!(
                    database
                        .value(Field::JournalComplete, "native-smoke")
                        .unwrap(),
                    "no"
                );
                assert_eq!(
                    database
                        .value(Field::JournalSummary, "native-smoke")
                        .unwrap(),
                    format!("create:completed:9,update_cw_runtime:{phase}:1")
                );
                for bad in [
                    Value::Integer(1),
                    Value::Real(1.0),
                    Value::Text(serde_json::to_string(&row.result).unwrap()),
                    Value::Blob(Vec::new()),
                    Value::Blob(vec![b' '; 2 * 1024 * 1024 + 1]),
                ] {
                    fixture
                        .writer
                        .execute(
                            "UPDATE operations SET result_json = ?1 WHERE operation_id = ?2",
                            params![bad, row.operation_id.to_string()],
                        )
                        .unwrap();
                    assert_runtime_row_refused(&fixture);
                }
                let mut bad_intent = row.payload.clone();
                bad_intent["extra"] = serde_json::json!(true);
                fixture.writer.execute(
                    "UPDATE operations SET result_json = NULL, payload_json = ?1 WHERE operation_id = ?2",
                    params![serde_json::to_vec(&bad_intent).unwrap(), row.operation_id.to_string()],
                ).unwrap();
                assert_runtime_row_refused(&fixture);
            }
            for phase in ["completed", "intent", "failed", "interrupted"] {
                for bad in [
                    Value::Integer(1),
                    Value::Real(1.0),
                    Value::Blob(b"runtime_unknown".to_vec()),
                    Value::Text(String::new()),
                    Value::Text("X".to_owned()),
                    Value::Text("x".repeat(65)),
                    Value::Text("é".repeat(64)),
                ] {
                    row.update(&fixture);
                    fixture.writer.execute("UPDATE operations SET phase = ?1, error_code = ?2 WHERE operation_id = ?3",
                        params![phase, bad, row.operation_id.to_string()]).unwrap();
                    if phase != "completed" {
                        fixture
                            .writer
                            .execute(
                                "UPDATE operations SET result_json = NULL WHERE operation_id = ?1",
                                [row.operation_id.to_string()],
                            )
                            .unwrap();
                    }
                    assert_runtime_row_refused(&fixture);
                }
            }
            row.update(&fixture);
            fixture.writer.execute("UPDATE operations SET phase = 'failed', result_json = NULL WHERE operation_id = ?1", [row.operation_id.to_string()]).unwrap();
            assert_runtime_row_refused(&fixture);
            row.update(&fixture);
            fixture.writer.execute("UPDATE operations SET phase = 'intent', result_json = NULL, error_code = 'runtime_unknown' WHERE operation_id = ?1", [row.operation_id.to_string()]).unwrap();
            assert_runtime_row_refused(&fixture);
        }

        #[test]
        fn runtime_journal_never_filters_or_changes_lifecycle_predicates() {
            let fixture = Fixture::new(ProcessIdentity::capture(std::process::id()).unwrap());
            let row = RuntimeJournal::new(&fixture, false, false);
            row.insert(&fixture, 0);
            fixture
                .writer
                .execute(
                    "UPDATE operations SET checkpoint = 8 WHERE kind = 'create'",
                    [],
                )
                .unwrap();
            assert_eq!(
                fixture
                    .database()
                    .value(Field::JournalComplete, "native-smoke")
                    .unwrap(),
                "no"
            );
            assert_eq!(
                fixture
                    .database()
                    .value(Field::JournalSummary, "native-smoke")
                    .unwrap(),
                "create:completed:8,update_cw_runtime:completed:0"
            );
            for (kind, phase) in [
                ("unadmitted_lifecycle", "completed"),
                ("create", "unknown_phase"),
            ] {
                fixture
                    .writer
                    .execute(
                        "UPDATE operations SET kind = ?1, phase = ?2 WHERE operation_id = 'op-a'",
                        params![kind, phase],
                    )
                    .unwrap();
                assert_eq!(
                    fixture
                        .database()
                        .value(Field::JournalComplete, "native-smoke")
                        .unwrap(),
                    "no"
                );
                assert!(
                    fixture
                        .database()
                        .value(Field::JournalSummary, "native-smoke")
                        .is_err()
                );
            }
            fixture.writer.execute("UPDATE operations SET kind = 'create', phase = 'completed', checkpoint = 9 WHERE operation_id = 'op-a'", []).unwrap();
            assert_eq!(
                fixture
                    .database()
                    .value(Field::JournalComplete, "native-smoke")
                    .unwrap(),
                "yes"
            );
        }

        #[test]
        fn runtime_catalog_runner_records_preserve_old_and_new_closed_decoding() {
            let process = ProcessIdentity::capture(std::process::id()).unwrap();
            let fixture = Fixture::new(process.clone());
            let old = serde_json::to_value(runner_record(process.clone())).unwrap();
            assert!(old.get("cw_runtime_catalog_generation").is_none());
            let write = |record: &serde_json::Value| {
                fixture
                    .writer
                    .execute(
                        "UPDATE environments SET runner_json = ?1 WHERE name = 'native-smoke'",
                        [serde_json::to_vec(record).unwrap()],
                    )
                    .unwrap();
            };
            let assert_values = || {
                let database = fixture.database();
                assert_eq!(
                    database.value(Field::RunnerPid, "native-smoke").unwrap(),
                    process.pid.to_string()
                );
                assert_eq!(
                    database
                        .value(Field::RunnerArtifactGeneration, "native-smoke")
                        .unwrap(),
                    "b".repeat(64)
                );
            };
            assert_values();
            let mut current = old.clone();
            current["cw_runtime_catalog_generation"] = serde_json::json!("c".repeat(64));
            write(&current);
            assert_values();
            assert_eq!(
                fixture
                    .database()
                    .runner("native-smoke")
                    .unwrap()
                    .cw_runtime_catalog_generation
                    .as_deref(),
                Some("c".repeat(64).as_str())
            );
            let mut absent = old.clone();
            absent["cw_runtime_catalog_generation"] = serde_json::Value::Null;
            write(&absent);
            assert_values();
            for invalid in [
                serde_json::json!(""),
                serde_json::json!("C".repeat(64)),
                serde_json::json!(format!("sha256:{}", "c".repeat(64))),
                serde_json::json!(true),
            ] {
                let mut corrupt = current.clone();
                corrupt["cw_runtime_catalog_generation"] = invalid;
                write(&corrupt);
                assert!(
                    fixture
                        .database()
                        .value(Field::RunnerPid, "native-smoke")
                        .is_err()
                );
            }
            let mut unknown = current.clone();
            unknown["unadmitted_field"] = serde_json::json!("synthetic-unknown-field");
            write(&unknown);
            assert!(
                fixture
                    .database()
                    .value(Field::RunnerPid, "native-smoke")
                    .is_err()
            );
            let still_saved: Vec<u8> = fixture
                .writer
                .query_row(
                    "SELECT runner_json FROM environments WHERE name = 'native-smoke'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(still_saved, serde_json::to_vec(&unknown).unwrap());
            write(&old);
            assert_values();
            assert!(
                fixture
                    .database()
                    .runner("native-smoke")
                    .unwrap()
                    .cw_runtime_catalog_generation
                    .is_none()
            );
        }

        #[test]
        fn reads_a_live_wal_with_the_runtime_sqlite_build() {
            let first = ProcessIdentity::capture(std::process::id()).unwrap();
            let fixture = Fixture::new(first.clone());
            let database = fixture.database();
            assert_eq!(
                database
                    .value(Field::EnvironmentId, "native-smoke")
                    .unwrap(),
                fixture.environment_id
            );
            assert_eq!(
                database.value(Field::RunnerPid, "native-smoke").unwrap(),
                first.pid.to_string()
            );
            assert!(
                database
                    .value(Field::RunnerErrorCode, "native-smoke")
                    .is_err()
            );
            assert_eq!(
                database
                    .value(Field::JournalComplete, "native-smoke")
                    .unwrap(),
                "yes"
            );
            assert!(
                database
                    .connection
                    .execute("DELETE FROM operations", [])
                    .is_err()
            );
            drop(database);

            let mut replacement = first;
            replacement.pid += 1;
            fixture
                .writer
                .execute(
                    "UPDATE environments SET runner_json = ?1 WHERE name = 'native-smoke'",
                    [serde_json::to_vec(&runner_record(replacement.clone())).unwrap()],
                )
                .unwrap();
            assert_eq!(
                fixture
                    .database()
                    .value(Field::RunnerPid, "native-smoke")
                    .unwrap(),
                replacement.pid.to_string()
            );
            let mut failed = runner_record(replacement);
            failed.error_code = Some("guest_ready_timeout".to_owned());
            fixture
                .writer
                .execute(
                    "UPDATE environments SET runner_json = ?1 WHERE name = 'native-smoke'",
                    [serde_json::to_vec(&failed).unwrap()],
                )
                .unwrap();
            assert_eq!(
                fixture
                    .database()
                    .value(Field::RunnerErrorCode, "native-smoke")
                    .unwrap(),
                "guest_ready_timeout"
            );
            assert!(fixture.root.join("supervisor.db-wal").is_file());
            assert!(fixture.root.join("supervisor.db-shm").is_file());
        }

        #[test]
        fn kills_only_the_persisted_process_birth() {
            const CHILD_MARKER: &str = "CODEWIRE_STATE_PROBE_TEST_CHILD";
            if std::env::var_os(CHILD_MARKER).is_some() {
                // stdin is a private bidirectional socket, not the owner's
                // terminal. Acknowledge only after entering this exact test;
                // remain alive until the parent kills us or closes its end.
                let input = std::io::stdin();
                assert_eq!(rustix::io::write(&input, b"R").unwrap(), 1);
                assert_eq!(rustix::io::read(&input, &mut [0_u8; 1]).unwrap(), 0);
                return;
            }
            let executable = std::env::current_exe().unwrap();
            let (mut readiness, child_socket) = UnixStream::pair().unwrap();
            readiness
                .set_read_timeout(Some(Duration::from_secs(30)))
                .unwrap();
            let mut child = ChildGuard(
                Command::new(&executable)
                    .args([
                        "--exact",
                        "linux::tests::kills_only_the_persisted_process_birth",
                    ])
                    .env_clear()
                    .env(CHILD_MARKER, "1")
                    .stdin(Stdio::from(std::os::fd::OwnedFd::from(child_socket)))
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .unwrap(),
            );
            let mut ready = [0_u8; 1];
            readiness.read_exact(&mut ready).unwrap();
            assert_eq!(ready, *b"R");
            let admitted = LiveProcess::capture_child(child.0.id(), &executable).unwrap();
            let identity = admitted.identity().clone();
            let fixture = Fixture::new(identity.clone());
            let mut wrong = identity.clone();
            wrong.start_time_ticks += 1;
            fixture
                .writer
                .execute(
                    "UPDATE environments SET runner_json = ?1 WHERE name = 'native-smoke'",
                    [serde_json::to_vec(&runner_record(wrong)).unwrap()],
                )
                .unwrap();
            let runner = fixture.database().runner("native-smoke").unwrap();
            assert!(matches!(
                LiveProcess::recover(&runner.process),
                Err(codewire_local_vmm::RecoveryError::IdentityMismatch)
            ));
            assert!(child.0.try_wait().unwrap().is_none());
            assert!(!admitted.is_exited().unwrap());

            fixture
                .writer
                .execute(
                    "UPDATE environments SET runner_json = ?1 WHERE name = 'native-smoke'",
                    [serde_json::to_vec(&runner_record(identity)).unwrap()],
                )
                .unwrap();
            let database = fixture.database();
            let runner = database.runner("native-smoke").unwrap();
            drop(database);
            let process = LiveProcess::recover(&runner.process).unwrap();
            process.signal(Signal::KILL).unwrap();
            assert_eq!(child.0.wait().unwrap().signal(), Some(libc::SIGKILL));
        }

        #[test]
        fn rejects_non_private_or_symlinked_state() {
            let process = ProcessIdentity::capture(std::process::id()).unwrap();
            let fixture = Fixture::new(process);
            fs::set_permissions(&fixture.root, fs::Permissions::from_mode(0o755)).unwrap();
            assert!(ProbeDatabase::open(&fixture.root).is_err());

            let link = fixture._parent.path().join("state-link");
            std::os::unix::fs::symlink(&fixture.root, &link).unwrap();
            assert!(ProbeDatabase::open(&link).is_err());
        }

        #[test]
        fn requires_the_current_schema_without_an_implicit_upgrade() {
            let fixture = Fixture::new(ProcessIdentity::capture(std::process::id()).unwrap());
            assert_eq!(
                fixture
                    .database()
                    .value(Field::Contract, "native-smoke")
                    .unwrap(),
                "1129797197:12:wal:ok"
            );
            for version in [0, 10, 11, 13] {
                fixture
                    .writer
                    .pragma_update(None, "user_version", version)
                    .unwrap();
                assert!(ProbeDatabase::open(&fixture.root).is_err());
                assert_eq!(
                    fixture
                        .writer
                        .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
                        .unwrap(),
                    version
                );
            }
        }

        #[test]
        fn rejects_a_mislabeled_runtime_schema_without_repairing_it() {
            for column in [
                "unrelated BLOB NULL",
                "cw_runtime_binding_json TEXT NULL",
                "cw_runtime_binding_json BLOB NOT NULL",
                "cw_runtime_binding_json BLOB NULL DEFAULT NULL",
                "cw_runtime_binding_json BLOB PRIMARY KEY",
                "other BLOB, cw_runtime_binding_json BLOB GENERATED ALWAYS AS (other) VIRTUAL",
            ] {
                let fixture = Fixture::new(ProcessIdentity::capture(std::process::id()).unwrap());
                let schema = format!("CREATE TABLE environments ({column})");
                fixture
                    .writer
                    .execute_batch(&format!("DROP TABLE environments; {schema};"))
                    .unwrap();
                assert!(ProbeDatabase::open(&fixture.root).is_err(), "{column}");
                assert_eq!(
                    fixture
                        .writer
                        .query_row(
                            "SELECT sql FROM sqlite_schema WHERE name = 'environments'",
                            [],
                            |row| row.get::<_, String>(0),
                        )
                        .unwrap(),
                    schema
                );
                assert_eq!(
                    fixture
                        .writer
                        .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
                        .unwrap(),
                    12
                );
            }
        }

        #[test]
        fn refuses_a_foreign_or_ambiguous_platform_without_changing_it() {
            for platform in ["darwin-v1", "linux-v2", ""] {
                let fixture = Fixture::new(ProcessIdentity::capture(std::process::id()).unwrap());
                fixture
                    .writer
                    .execute("UPDATE supervisor_metadata SET value = ?1", [platform])
                    .unwrap();
                assert!(ProbeDatabase::open(&fixture.root).is_err());
                assert_eq!(
                    fixture
                        .writer
                        .query_row("SELECT value FROM supervisor_metadata", [], |row| {
                            row.get::<_, String>(0)
                        })
                        .unwrap(),
                    platform
                );
            }
            let fixture = Fixture::new(ProcessIdentity::capture(std::process::id()).unwrap());
            fixture
                .writer
                .execute("DELETE FROM supervisor_metadata", [])
                .unwrap();
            assert!(ProbeDatabase::open(&fixture.root).is_err());
            fixture
                .writer
                .execute_batch(
                    "INSERT INTO supervisor_metadata VALUES ('platform', 'linux-v1');
                     INSERT INTO supervisor_metadata VALUES ('platform', 'linux-v1');",
                )
                .unwrap();
            assert!(ProbeDatabase::open(&fixture.root).is_err());
            assert_eq!(
                fixture
                    .writer
                    .query_row("SELECT COUNT(*) FROM supervisor_metadata", [], |row| {
                        row.get::<_, i64>(0)
                    })
                    .unwrap(),
                2
            );
        }

        #[test]
        fn build_identity_is_a_bounded_digest_not_project_configuration() {
            let fixture = Fixture::new(ProcessIdentity::capture(std::process::id()).unwrap());
            let encoded: Vec<u8> = fixture.writer.query_row(
                "SELECT active_workspace_generation_json FROM environments WHERE name = 'native-smoke'",
                [], |row| row.get(0),
            ).unwrap();
            let original = fixture
                .database()
                .value(Field::BuiltWorkspaceIdentity, "native-smoke")
                .unwrap();
            assert_eq!(
                original,
                format!("{}:{:x}", "c".repeat(64), Sha256::digest(&encoded))
            );
            assert!(!original.contains("synthetic-private-build-sentinel"));
            assert_eq!(original.len(), 129);
            let changed = serde_json::to_vec(&serde_json::json!({
                "root_generation": "c".repeat(64),
                "project_spec_json": "another-synthetic-private-build-sentinel"
            }))
            .unwrap();
            fixture
                .writer
                .execute(
                    "UPDATE environments SET active_workspace_generation_json = ?1",
                    [changed],
                )
                .unwrap();
            assert_ne!(
                fixture
                    .database()
                    .value(Field::BuiltWorkspaceIdentity, "native-smoke")
                    .unwrap(),
                original
            );
        }

        #[test]
        fn build_identity_rejects_missing_malformed_or_unbounded_metadata() {
            let fixture = Fixture::new(ProcessIdentity::capture(std::process::id()).unwrap());
            for encoded in [
                None,
                Some(b"not-json".to_vec()),
                Some(b"{}".to_vec()),
                Some(br#"{"root_generation":"../outside"}"#.to_vec()),
                Some(vec![b' '; MAXIMUM_WORKSPACE_METADATA_BYTES + 1]),
            ] {
                fixture
                    .writer
                    .execute(
                        "UPDATE environments SET active_workspace_generation_json = ?1",
                        [encoded],
                    )
                    .unwrap();
                assert!(
                    fixture
                        .database()
                        .value(Field::BuiltWorkspaceIdentity, "native-smoke")
                        .is_err()
                );
            }
        }

        #[test]
        fn source_receipt_is_environment_scoped_and_completion_is_exact() {
            let fixture = Fixture::new(ProcessIdentity::capture(std::process::id()).unwrap());
            assert!(
                fixture
                    .database()
                    .value(Field::SourceOperation, "native-smoke")
                    .is_err()
            );
            fixture.writer.execute(
                "INSERT INTO operations (operation_id, kind, phase, checkpoint, created_unix_ms, environment_id)
                 VALUES ('source-a', 'update_environment_sources', 'completed', 9, 2, ?1)",
                [&fixture.environment_id],
            ).unwrap();
            fixture.writer.execute(
                "INSERT INTO operations (operation_id, kind, phase, checkpoint, created_unix_ms, environment_id)
                 VALUES ('source-other', 'update_environment_sources', 'completed', 10, 3, ?1)",
                [Uuid::new_v4().to_string()],
            ).unwrap();
            assert_eq!(
                fixture
                    .database()
                    .value(Field::SourceOperation, "native-smoke")
                    .unwrap(),
                "update_environment_sources:completed:9"
            );
            assert_eq!(
                fixture
                    .database()
                    .value(Field::JournalComplete, "native-smoke")
                    .unwrap(),
                "no"
            );
            fixture
                .writer
                .execute(
                    "UPDATE operations SET checkpoint = 10 WHERE operation_id = 'source-a'",
                    [],
                )
                .unwrap();
            assert_eq!(
                fixture
                    .database()
                    .value(Field::SourceOperation, "native-smoke")
                    .unwrap(),
                "update_environment_sources:completed:10"
            );
            assert_eq!(
                fixture
                    .database()
                    .value(Field::JournalComplete, "native-smoke")
                    .unwrap(),
                "yes"
            );
            assert!(
                fixture
                    .database()
                    .value(Field::SourceOperation, "missing-environment")
                    .is_err()
            );
            assert_eq!(terminal_checkpoint("apply_environment_access"), None);
        }

        #[test]
        fn parser_accepts_only_fixed_actions_and_fields() {
            let args = Args::parse([
                "value".to_owned(),
                "runner_pid".to_owned(),
                "--state-root".to_owned(),
                "/tmp/state".to_owned(),
                "--name".to_owned(),
                "native-smoke".to_owned(),
            ])
            .unwrap();
            assert!(matches!(args.action, Action::Value(Field::RunnerPid)));
            assert!(Args::parse(["value".to_owned(), "payload".to_owned()]).is_err());
            assert_eq!(
                Field::parse("built_workspace_identity").unwrap(),
                Field::BuiltWorkspaceIdentity
            );
            assert_eq!(
                Field::parse("source_operation").unwrap(),
                Field::SourceOperation
            );
            assert!(Field::parse("project_spec_json").is_err());
            assert!(Field::parse("apply_environment_access").is_err());
        }
    }
}
