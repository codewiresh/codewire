//! Native stopped-state admission. No lifecycle, replay, or resource writer.

use std::fs;
use std::path::Path;
use std::time::Duration;

use rusqlite::config::DbConfig;
use rusqlite::{Connection, OpenFlags, TransactionBehavior, params};
use uuid::Uuid;

use super::path::{ConfinedFile, PathError, PrivateRoot};
use crate::supervisor_metadata::{StoredEnvironmentState, SupervisorState};
use crate::supervisor_store_codec::{SCHEMA_SQL, load_state, require_persistent_wal};
use crate::supervisor_store_error::SupervisorStoreError;
use crate::workspace_plan::WorkspaceInput;

const DATABASE: &str = "supervisor.db";
const SIDECARS: [&str; 2] = ["supervisor.db-wal", "supervisor.db-shm"];
const APPLICATION_ID: i64 = 0x4357_564d;
const SCHEMA_VERSION: i64 = 12;
const PLATFORM: &str = "darwin-v1";

pub(super) struct NativeStore {
    connection: Connection,
    root: PrivateRoot,
    // Fields drop in declaration order: connection must close before these.
    files: [ConfinedFile; 3],
}

impl NativeStore {
    /// The caller must retain the supervisor singleton for this store's lifetime.
    pub(super) fn open(root: PrivateRoot, boot: Uuid) -> Result<Self, StoreError> {
        if boot.is_nil() {
            return Err(StoreError::InvalidMetadata);
        }
        let existing = match root.open_regular(Path::new(DATABASE), false, None, false, Some(0o600))
        {
            Ok(file) => {
                if file.identity().size == 0 {
                    // SQLite can remove a WAL beside an empty main file. Reject
                    // the ambiguity before opening SQLite or touching sidecars.
                    return Err(StoreError::IncompleteInitialization);
                }
                Some(file)
            }
            Err(error) if missing(&error) => None,
            Err(error) => return Err(error.into()),
        };
        let initialize_new = existing.is_none();
        admit_directory(&root, !initialize_new)?;
        let database = match existing {
            Some(file) => file,
            None => root.create_regular(Path::new(DATABASE), 0o600, true)?,
        };
        // Pre-pin all three inodes before SQLite acquires any POSIX locks.
        // Creating absent empty coordination files is admitted; never truncate
        // or replace an existing WAL/SHM. SQLite rebuilds SHM under its own lock.
        let files = [
            database,
            retain_sidecar(&root, SIDECARS[0])?,
            retain_sidecar(&root, SIDECARS[1])?,
        ];
        revalidate_files(&root, &files)?;

        if !initialize_new {
            // READ_ONLY can still update coordination files. Do not omit WAL or
            // claim immutable observation. This connection is dropped before
            // the retained handles on success and every error path.
            let connection = Connection::open_with_flags(
                root.path().join(DATABASE),
                OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
            )?;
            configure_reader(&connection)?;
            require_persistent_wal(&connection)?;
            let transaction = connection.unchecked_transaction()?;
            admit_original(&transaction)?;
            transaction.commit()?;
            connection.close().map_err(|(_, error)| error)?;
            revalidate_files(&root, &files)?;
        }

        // Declaration and field ordering ensure SQLite closes before the extra
        // file handles. No unrelated same-process SQLite connection may outlive
        // this guard. Other processes remain governed by SQLite's own locks.
        let connection = Connection::open_with_flags(
            root.path().join(DATABASE),
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        revalidate_files(&root, &files)?;
        configure_reader(&connection)?;
        if !initialize_new {
            let transaction = connection.unchecked_transaction()?;
            admit_original(&transaction)?;
            transaction.commit()?;
        }
        configure_writer(&connection)?;
        if initialize_new {
            initialize(&connection, boot)?;
        }
        let transaction = connection.unchecked_transaction()?;
        admit_original(&transaction)?;
        transaction.commit()?;
        revalidate_files(&root, &files)?;
        Ok(Self {
            connection,
            root,
            files,
        })
    }

    pub(super) fn state(&self) -> Result<SupervisorState, StoreError> {
        self.revalidate()?;
        let transaction = self.connection.unchecked_transaction()?;
        let state = admit_original(&transaction)?;
        transaction.commit()?;
        self.revalidate()?;
        Ok(state)
    }

    pub(super) fn select(
        &mut self,
        name: &str,
        expected: Option<Uuid>,
    ) -> Result<SupervisorState, StoreError> {
        self.revalidate()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut state = admit_original(&transaction)?;
        let selected = if name.is_empty() {
            state.current.as_deref().ok_or(StoreError::NotFound)?
        } else {
            name
        };
        let record = state
            .environments
            .get(selected)
            .ok_or(StoreError::NotFound)?;
        if expected.is_some_and(|expected| expected != record.id) {
            return Err(StoreError::NotFound);
        }
        let selected = selected.to_owned();
        if state.current.as_deref() != Some(selected.as_str()) {
            let changed = transaction.execute(
                "UPDATE supervisor_settings SET current_environment_id = (SELECT id FROM environments WHERE name = ?1) WHERE singleton = 1",
                [&selected],
            )?;
            if changed != 1 {
                return Err(StoreError::InvalidMetadata);
            }
        }
        transaction.commit()?;
        // No state publication or successful response can precede durable commit.
        self.revalidate()?;
        state.current = Some(selected);
        Ok(state)
    }

    fn revalidate(&self) -> Result<(), StoreError> {
        revalidate_files(&self.root, &self.files)?;
        admit_directory(&self.root, true)?;
        Ok(())
    }
}

fn configure_reader(connection: &Connection) -> Result<(), StoreError> {
    connection.busy_timeout(Duration::from_secs(5))?;
    connection.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)?;
    connection.pragma_update(None, "trusted_schema", false)?;
    connection.pragma_update(None, "foreign_keys", true)?;
    Ok(())
}

fn configure_writer(connection: &Connection) -> Result<(), StoreError> {
    connection.pragma_update(None, "fullfsync", true)?;
    connection.pragma_update(None, "synchronous", "FULL")?;
    let journal: String =
        connection.pragma_update_and_check(None, "journal_mode", "WAL", |row| row.get(0))?;
    let fullfsync: i64 = connection.pragma_query_value(None, "fullfsync", |row| row.get(0))?;
    let synchronous: i64 = connection.pragma_query_value(None, "synchronous", |row| row.get(0))?;
    if !journal.eq_ignore_ascii_case("wal") || fullfsync != 1 || synchronous != 2 {
        return Err(StoreError::DurabilityUnavailable);
    }
    connection.pragma_update(None, "wal_autocheckpoint", 100_i64)?;
    require_persistent_wal(connection)?;
    Ok(())
}

fn initialize(connection: &Connection, boot: Uuid) -> Result<(), StoreError> {
    let transaction = connection.unchecked_transaction()?;
    transaction.execute_batch(SCHEMA_SQL)?;
    transaction.pragma_update(None, "application_id", APPLICATION_ID)?;
    transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    for (key, value) in [
        ("namespace_id", Uuid::new_v4().to_string()),
        ("host_boot_id", boot.to_string()),
        ("platform", PLATFORM.to_owned()),
    ] {
        transaction.execute(
            "INSERT INTO supervisor_metadata(key, value) VALUES (?1, ?2)",
            params![key, value],
        )?;
    }
    transaction.commit()?;
    Ok(())
}

type Catalog = Vec<(String, String, String, Option<String>)>;

fn catalog(connection: &Connection) -> Result<Catalog, StoreError> {
    let mut statement = connection
        .prepare("SELECT type, name, tbl_name, sql FROM sqlite_schema ORDER BY type, name")?;
    let rows = statement.query_map([], |row| {
        Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
    })?;
    Ok(rows.collect::<Result<_, _>>()?)
}

fn admit_original(connection: &Connection) -> Result<SupervisorState, StoreError> {
    let application: i64 =
        connection.pragma_query_value(None, "application_id", |row| row.get(0))?;
    let schema: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if application != APPLICATION_ID || schema != SCHEMA_VERSION {
        return Err(StoreError::UnsupportedFormat);
    }
    let journal: String = connection.pragma_query_value(None, "journal_mode", |row| row.get(0))?;
    if !journal.eq_ignore_ascii_case("wal") {
        return Err(StoreError::UnsupportedFormat);
    }
    // Compare with the complete checked-in schema through the same SQLite
    // implementation. Include autoindexes, exact constraints and every catalog
    // object: trusted_schema=OFF alone does not disable ordinary SQL triggers.
    let reference = Connection::open_in_memory()?;
    reference.execute_batch(SCHEMA_SQL)?;
    if catalog(connection)? != catalog(&reference)? {
        return Err(StoreError::UnsupportedCatalog);
    }
    let integrity: String = connection.query_row("PRAGMA quick_check(1)", [], |row| row.get(0))?;
    if integrity != "ok" {
        return Err(StoreError::InvalidMetadata);
    }
    let mut statement =
        connection.prepare("SELECT key, value FROM supervisor_metadata ORDER BY key")?;
    let metadata = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    if metadata.len() != 3
        || metadata[0].0 != "host_boot_id"
        || metadata[1].0 != "namespace_id"
        || metadata[2] != ("platform".to_owned(), PLATFORM.to_owned())
        || !canonical_uuid(&metadata[0].1)
        || !canonical_uuid(&metadata[1].1)
    {
        return Err(StoreError::InvalidMetadata);
    }
    let settings: i64 =
        connection.query_row("SELECT count(*) FROM supervisor_settings", [], |row| {
            row.get(0)
        })?;
    if settings != 1 {
        return Err(StoreError::InvalidMetadata);
    }
    let unsupported: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM operations) OR EXISTS(SELECT 1 FROM owned_objects) OR EXISTS(SELECT 1 FROM environments WHERE desired_state != 'stopped' OR observed_state != 'stopped')",
        [], |row| row.get(0),
    )?;
    if unsupported {
        return Err(StoreError::UnsupportedAuthority);
    }
    let state = load_state(connection)?;
    if state.environments.values().any(|record| {
        record.state != StoredEnvironmentState::Stopped
            || record.runner.is_some()
            || record.staging_artifact_generation.is_some()
            || record.staging_workspace_generation.is_some()
            || record
                .workspace_plan
                .inputs
                .iter()
                .any(|input| matches!(input, WorkspaceInput::Direct { .. }))
    }) {
        return Err(StoreError::UnsupportedAuthority);
    }
    Ok(state)
}

fn canonical_uuid(value: &str) -> bool {
    Uuid::parse_str(value).is_ok_and(|id| !id.is_nil() && id.to_string() == value)
}

fn admit_directory(root: &PrivateRoot, existing: bool) -> Result<(), StoreError> {
    root.revalidate_named()?;
    let entries = fs::read_dir(root.path()).map_err(StoreError::Directory)?;
    for entry in entries {
        let name = entry.map_err(StoreError::Directory)?.file_name();
        let allowed = name == "supervisor.lock"
            || (existing
                && [DATABASE, "supervisor.sock", SIDECARS[0], SIDECARS[1]]
                    .iter()
                    .any(|allowed| name == *allowed));
        if !allowed {
            return Err(StoreError::UnsupportedAuthority);
        }
    }
    root.revalidate_named()?;
    Ok(())
}

fn retain_sidecar(root: &PrivateRoot, name: &str) -> Result<ConfinedFile, StoreError> {
    match root.open_regular(Path::new(name), true, None, false, Some(0o600)) {
        Ok(file) => Ok(file),
        Err(error) if missing(&error) => Ok(root.create_regular(Path::new(name), 0o600, true)?),
        Err(error) => Err(error.into()),
    }
}

fn revalidate_files(root: &PrivateRoot, files: &[ConfinedFile; 3]) -> Result<(), StoreError> {
    for (name, file) in [DATABASE, SIDECARS[0], SIDECARS[1]].iter().zip(files) {
        root.revalidate_regular(Path::new(name), file)?;
    }
    Ok(())
}

fn missing(error: &PathError) -> bool {
    matches!(error, PathError::Io { source, .. } if source.kind() == std::io::ErrorKind::NotFound)
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error(
        "native supervisor database initialization is incomplete; retained state requires recovery"
    )]
    IncompleteInitialization,
    #[error("native supervisor database has an unsupported platform or format")]
    UnsupportedFormat,
    #[error("native supervisor database catalog differs from the supported schema")]
    UnsupportedCatalog,
    #[error("native supervisor database retains unsupported lifecycle or resource authority")]
    UnsupportedAuthority,
    #[error("native supervisor metadata is invalid")]
    InvalidMetadata,
    #[error("native supervisor durability settings are unavailable")]
    DurabilityUnavailable,
    #[error("native supervisor database or sidecar identity changed")]
    IdentityChanged,
    #[error("local environment not found")]
    NotFound,
    #[error("inspect native supervisor directory: {0}")]
    Directory(#[source] std::io::Error),
    #[error(transparent)]
    Path(#[from] PathError),
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error(transparent)]
    Codec(#[from] SupervisorStoreError),
}

#[cfg(test)]
pub(super) mod tests;
