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

    use codewire_local_vmm::{LiveProcess, ProcessIdentity};
    use rusqlite::config::DbConfig;
    use rusqlite::{Connection, OpenFlags, OptionalExtension as _};
    use rustix::process::Signal;
    use serde::{Deserialize, Serialize};
    use uuid::Uuid;

    const DATABASE_APPLICATION_ID: i64 = 0x4357_564d;
    const DATABASE_SCHEMA_VERSION: i64 = 10;
    const DATABASE_FILE: &str = "supervisor.db";
    const MAXIMUM_OPERATIONS: usize = 128;
    const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

    type ProbeResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Field {
        EnvironmentId,
        RunnerPid,
        RunnerErrorCode,
        ActiveArtifactGeneration,
        RunnerArtifactGeneration,
        Empty,
        Contract,
        ResizeOperation,
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
    }

    pub(super) fn run(arguments: impl IntoIterator<Item = String>) -> ProbeResult<()> {
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
                "empty" => Ok(Self::Empty),
                "contract" => Ok(Self::Contract),
                "resize_operation" => Ok(Self::ResizeOperation),
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
                Field::JournalComplete => {
                    let rows = self.operations()?;
                    let complete = !rows.is_empty()
                        && rows.iter().all(|row| {
                            row.phase == "completed"
                                && terminal_checkpoint(&row.kind) == Some(row.checkpoint)
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
                "SELECT kind, phase, checkpoint FROM operations \
                 ORDER BY created_unix_ms, operation_id LIMIT ?1",
            )?;
            let rows = statement
                .query_map([limit], decode_operation)?
                .collect::<Result<Vec<_>, _>>()?;
            require(rows.len() <= MAXIMUM_OPERATIONS)?;
            Ok(rows)
        }
    }

    impl OperationRow {
        fn validate(&self) -> ProbeResult<()> {
            require(terminal_checkpoint(&self.kind).is_some())?;
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
        })
    }

    fn terminal_checkpoint(kind: &str) -> Option<u32> {
        match kind {
            "create" => Some(9),
            "start" => Some(7),
            "stop" => Some(3),
            "restart" => Some(9),
            "grow_disk" => Some(6),
            "update_workspace" | "rollback_workspace" => Some(10),
            "apply_environment_access" => Some(3),
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
        use std::process::Command;

        use rusqlite::params;

        use super::*;

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
                           active_artifact_generation TEXT
                         );
                         CREATE TABLE supervisor_settings(
                           singleton INTEGER, current_environment_id TEXT
                         );
                         CREATE TABLE owned_objects(environment_id TEXT);
                         CREATE TABLE operations(
                           operation_id TEXT, kind TEXT, phase TEXT,
                           checkpoint INTEGER, created_unix_ms INTEGER
                         );
                         INSERT INTO supervisor_settings VALUES (1, NULL);
                         PRAGMA application_id = 1129797197;
                         PRAGMA user_version = 10;",
                    )
                    .unwrap();
                fs::set_permissions(&database, fs::Permissions::from_mode(0o600)).unwrap();
                let environment_id = Uuid::new_v4().to_string();
                let runner = runner_record(process);
                writer
                    .execute(
                        "INSERT INTO environments VALUES (?1, 'native-smoke', ?2, ?3)",
                        params![
                            environment_id,
                            serde_json::to_vec(&runner).unwrap(),
                            "a".repeat(64)
                        ],
                    )
                    .unwrap();
                writer
                    .execute("INSERT INTO owned_objects VALUES (?1)", [&environment_id])
                    .unwrap();
                writer
                    .execute(
                        "INSERT INTO operations VALUES ('op-a', 'create', 'completed', 9, 1)",
                        [],
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
                error_code: None,
            }
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
            let mut child = Command::new("/usr/bin/sleep").arg("30").spawn().unwrap();
            let identity = ProcessIdentity::capture(child.id()).unwrap();
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
            assert!(LiveProcess::recover(&runner.process).is_err());
            assert!(child.try_wait().unwrap().is_none());

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
            assert!(!child.wait().unwrap().success());
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
        }
    }
}
