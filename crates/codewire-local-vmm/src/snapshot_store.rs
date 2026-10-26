//! The host's local disk snapshot index (#3046 R1).
//!
//! Each snapshot is a directory of disk copies and a manifest under
//! `engine/snapshots/<id>`; this store names them. It is its own SQLite file
//! in the supervisor's private root, beside `network-policies.db`, owned by
//! the supervisor process, the one writer. A row is either `ready` or
//! `deleting`; restores and journals use ids, names are labels. Each row also
//! keeps what garbage collection must retain for the snapshot to boot: its
//! runtime artifact generation and the content its root generation and
//! workspace plan reference. The rows and directories are reconciled with
//! each other when the supervisor first uses the store (`supervisor::snapshots`).

// Snapshots are Linux only, so most of this module is unused on other
// targets.
#![cfg_attr(not(target_os = "linux"), allow(dead_code, unused_imports))]

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Mutex;

use rusqlite::config::DbConfig;
use rusqlite::{
    Connection, OpenFlags, OptionalExtension as _, Transaction, TransactionBehavior, params,
};
use uuid::Uuid;

use crate::host::path::{PathError, PrivateRoot};
use crate::oci::Sha256Digest;
use crate::supervisor_metadata::{valid_environment_name, valid_sha256};

pub(crate) const DATABASE_FILE: &str = "snapshots.db";
const APPLICATION_ID: i64 = 0x4357_534e; // "CWSN"
/// 1: snapshots. 2: capture intents.
const SCHEMA_VERSION: i64 = 2;
const BUSY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
/// The most snapshots one host keeps.
pub(crate) const MAX_SNAPSHOTS: usize = 256;

const SCHEMA: [(&str, &str); 2] = [
    // A capture about to publish `snapshots/<id>`: a directory with an
    // intent and no row is a capture that never finished, which may go. A
    // directory with neither is a snapshot whose row was lost, rebuilt from
    // its manifest.
    (
        "capture_intents",
        "CREATE TABLE capture_intents (
  id TEXT PRIMARY KEY NOT NULL CHECK (length(id) = 36),
  created_unix_ms INTEGER NOT NULL
) STRICT",
    ),
    (
        "snapshots",
        "CREATE TABLE snapshots (
  id TEXT PRIMARY KEY NOT NULL CHECK (length(id) = 36),
  name TEXT NOT NULL UNIQUE CHECK (length(name) BETWEEN 1 AND 63),
  state TEXT NOT NULL CHECK (state IN ('ready', 'deleting')),
  created_unix_ms INTEGER NOT NULL,
  manifest_sha256 TEXT NOT NULL CHECK (length(manifest_sha256) = 64),
  retained TEXT NOT NULL
) STRICT",
    ),
];

#[derive(Debug, thiserror::Error)]
pub(crate) enum SnapshotStoreError {
    #[error(
        "a snapshot named {0} already exists; choose another name or remove it first (`cw snapshot rm {0}`)"
    )]
    AlreadyExists(String),
    #[error(
        "this host already keeps {MAX_SNAPSHOTS} snapshots; remove one first (`cw snapshot rm NAME`)"
    )]
    TooManySnapshots,
    #[error("the snapshot database is not one this cw can read")]
    InvalidDatabase,
    #[error("the snapshot database changed identity while opening")]
    DatabaseIdentityChanged,
    #[error(transparent)]
    Path(#[from] PathError),
    #[error(transparent)]
    Database(#[from] rusqlite::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SnapshotState {
    Ready,
    Deleting,
}

impl SnapshotState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Deleting => "deleting",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "ready" => Some(Self::Ready),
            "deleting" => Some(Self::Deleting),
            _ => None,
        }
    }
}

/// What garbage collection keeps for one snapshot.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Retained {
    pub(crate) artifact_generations: BTreeSet<String>,
    pub(crate) content: BTreeMap<Sha256Digest, u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SnapshotRow {
    pub(crate) id: Uuid,
    pub(crate) name: String,
    pub(crate) state: SnapshotState,
    pub(crate) created_unix_ms: i64,
    pub(crate) manifest_sha256: String,
    pub(crate) retained: Retained,
}

pub(crate) struct SnapshotStore {
    connection: Mutex<Connection>,
}

impl SnapshotStore {
    pub(crate) fn open(root: &PrivateRoot) -> Result<Self, SnapshotStoreError> {
        let relative = Path::new(DATABASE_FILE);
        let identity = match root.open_regular(relative, true, None, false, Some(0o600)) {
            Ok(opened) => opened.identity().clone(),
            Err(error) if not_found(&error) => root
                .create_regular(relative, 0o600, true)?
                .identity()
                .clone(),
            Err(error) => return Err(error.into()),
        };
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        let connection = Connection::open_with_flags(root.path().join(relative), flags)?;
        let reopened = root.open_regular(relative, true, None, false, Some(0o600))?;
        if reopened.identity() != &identity {
            return Err(SnapshotStoreError::DatabaseIdentityChanged);
        }
        Self::from_connection(connection)
    }

    fn from_connection(connection: Connection) -> Result<Self, SnapshotStoreError> {
        connection.busy_timeout(BUSY_TIMEOUT)?;
        connection.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)?;
        connection.pragma_update(None, "trusted_schema", false)?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        let transaction = Transaction::new_unchecked(&connection, TransactionBehavior::Immediate)?;
        let application_id: i64 =
            transaction.pragma_query_value(None, "application_id", |row| row.get(0))?;
        let user_version: i64 =
            transaction.pragma_query_value(None, "user_version", |row| row.get(0))?;
        let objects: i64 =
            transaction.query_row("SELECT count(*) FROM sqlite_schema", [], |row| row.get(0))?;
        if application_id == 0 && user_version == 0 && objects == 0 {
            for (_, statement) in SCHEMA {
                transaction.execute_batch(&format!("{statement};"))?;
            }
            transaction.pragma_update(None, "application_id", APPLICATION_ID)?;
            transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        } else if application_id == APPLICATION_ID && user_version == 1 {
            // Version 1 came in two shapes: the snapshots table alone, and
            // later with capture_intents too, still stamped 1. Add the
            // intents only where they are missing, in the transaction that
            // decided it holds version 1; the exact schema is validated
            // after.
            let intents: i64 = transaction.query_row(
                "SELECT count(*) FROM sqlite_schema WHERE type = 'table' AND name = ?1",
                params![SCHEMA[0].0],
                |row| row.get(0),
            )?;
            if intents == 0 {
                transaction.execute_batch(&format!("{};", SCHEMA[0].1))?;
            }
            transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        }
        transaction.commit()?;
        validate_schema(&connection)?;
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    #[cfg(test)]
    pub(crate) fn in_memory() -> Result<Self, SnapshotStoreError> {
        Self::from_connection(Connection::open_in_memory()?)
    }

    fn connection(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.connection
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Whether `name` is free for a new snapshot.
    pub(crate) fn require_free(&self, name: &str) -> Result<(), SnapshotStoreError> {
        let connection = self.connection();
        let taken: i64 = connection.query_row(
            "SELECT count(*) FROM snapshots WHERE name = ?1",
            params![name],
            |row| row.get(0),
        )?;
        if taken != 0 {
            return Err(SnapshotStoreError::AlreadyExists(name.to_owned()));
        }
        let count: i64 =
            connection.query_row("SELECT count(*) FROM snapshots", [], |row| row.get(0))?;
        if count as usize >= MAX_SNAPSHOTS {
            return Err(SnapshotStoreError::TooManySnapshots);
        }
        Ok(())
    }

    /// Record that a capture is about to publish `snapshots/<id>`.
    pub(crate) fn record_intent(&self, id: Uuid) -> Result<(), SnapshotStoreError> {
        self.connection().execute(
            "INSERT OR IGNORE INTO capture_intents(id, created_unix_ms) VALUES (?1, ?2)",
            params![id.to_string(), now_unix_ms()],
        )?;
        Ok(())
    }

    /// Every capture that recorded its intent and has no row yet.
    pub(crate) fn intents(&self) -> Result<BTreeSet<Uuid>, SnapshotStoreError> {
        let connection = self.connection();
        let mut statement = connection.prepare("SELECT id FROM capture_intents")?;
        let ids = statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        ids.iter()
            .map(|id| Uuid::parse_str(id).map_err(|_| SnapshotStoreError::InvalidDatabase))
            .collect()
    }

    pub(crate) fn remove_intent(&self, id: Uuid) -> Result<(), SnapshotStoreError> {
        self.connection().execute(
            "DELETE FROM capture_intents WHERE id = ?1",
            params![id.to_string()],
        )?;
        Ok(())
    }

    /// Record a snapshot whose directory is complete, as `ready`, and end its
    /// capture intent, in one transaction.
    pub(crate) fn insert(&self, row: &SnapshotRow) -> Result<(), SnapshotStoreError> {
        if !valid_row(row) {
            return Err(SnapshotStoreError::InvalidDatabase);
        }
        let mut connection = self.connection();
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let taken: i64 = transaction.query_row(
            "SELECT count(*) FROM snapshots WHERE name = ?1",
            params![row.name],
            |row| row.get(0),
        )?;
        if taken != 0 {
            return Err(SnapshotStoreError::AlreadyExists(row.name.clone()));
        }
        let count: i64 =
            transaction.query_row("SELECT count(*) FROM snapshots", [], |row| row.get(0))?;
        if count as usize >= MAX_SNAPSHOTS {
            return Err(SnapshotStoreError::TooManySnapshots);
        }
        transaction.execute(
            "INSERT INTO snapshots(id, name, state, created_unix_ms, manifest_sha256, retained)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                row.id.to_string(),
                row.name,
                row.state.as_str(),
                row.created_unix_ms,
                row.manifest_sha256,
                serde_json::to_string(&row.retained)
                    .map_err(|_| SnapshotStoreError::InvalidDatabase)?,
            ],
        )?;
        transaction.execute(
            "DELETE FROM capture_intents WHERE id = ?1",
            params![row.id.to_string()],
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// Every snapshot, by name.
    pub(crate) fn list(&self) -> Result<Vec<SnapshotRow>, SnapshotStoreError> {
        let connection = self.connection();
        let mut statement = connection.prepare(
            "SELECT id, name, state, created_unix_ms, manifest_sha256, retained
             FROM snapshots ORDER BY name",
        )?;
        let rows = statement
            .query_map([], read_row)?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter()
            .map(|row| row.ok_or(SnapshotStoreError::InvalidDatabase))
            .collect()
    }

    /// The snapshot `selector` names: an id, else a name.
    pub(crate) fn find(&self, selector: &str) -> Result<Option<SnapshotRow>, SnapshotStoreError> {
        let connection = self.connection();
        let column = if Uuid::parse_str(selector)
            .is_ok_and(|id| !id.is_nil() && id.to_string() == selector)
        {
            "id"
        } else {
            "name"
        };
        let row = connection
            .query_row(
                &format!(
                    "SELECT id, name, state, created_unix_ms, manifest_sha256, retained
                     FROM snapshots WHERE {column} = ?1"
                ),
                params![selector],
                read_row,
            )
            .optional()?;
        row.map(|row| row.ok_or(SnapshotStoreError::InvalidDatabase))
            .transpose()
    }

    /// Mark a `ready` snapshot `deleting`. `false` when it was not ready.
    pub(crate) fn mark_deleting(&self, id: Uuid) -> Result<bool, SnapshotStoreError> {
        let changed = self.connection().execute(
            "UPDATE snapshots SET state = 'deleting' WHERE id = ?1 AND state = 'ready'",
            params![id.to_string()],
        )?;
        Ok(changed == 1)
    }

    pub(crate) fn remove(&self, id: Uuid) -> Result<(), SnapshotStoreError> {
        self.connection().execute(
            "DELETE FROM snapshots WHERE id = ?1",
            params![id.to_string()],
        )?;
        Ok(())
    }

    /// What collection keeps for every snapshot.
    pub(crate) fn retained(&self) -> Result<Retained, SnapshotStoreError> {
        let mut all = Retained::default();
        for row in self.list()? {
            all.artifact_generations
                .extend(row.retained.artifact_generations);
            for (digest, size) in row.retained.content {
                match all.content.get(&digest) {
                    Some(existing) if *existing != size => {
                        return Err(SnapshotStoreError::InvalidDatabase);
                    }
                    _ => {
                        all.content.insert(digest, size);
                    }
                }
            }
        }
        Ok(all)
    }
}

fn now_unix_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX)
        })
}

fn valid_row(row: &SnapshotRow) -> bool {
    !row.id.is_nil()
        && valid_environment_name(&row.name)
        && valid_sha256(&row.manifest_sha256)
        && row
            .retained
            .artifact_generations
            .iter()
            .all(|generation| valid_sha256(generation))
}

/// `None` for a row this cw did not write.
fn read_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Option<SnapshotRow>> {
    let id: String = row.get(0)?;
    let name: String = row.get(1)?;
    let state: String = row.get(2)?;
    let created_unix_ms: i64 = row.get(3)?;
    let manifest_sha256: String = row.get(4)?;
    let retained: String = row.get(5)?;
    let parsed = (|| {
        let snapshot = SnapshotRow {
            id: Uuid::parse_str(&id).ok().filter(|id| !id.is_nil())?,
            name,
            state: SnapshotState::parse(&state)?,
            created_unix_ms,
            manifest_sha256,
            retained: serde_json::from_str(&retained).ok()?,
        };
        valid_row(&snapshot).then_some(snapshot)
    })();
    Ok(parsed)
}

fn validate_schema(connection: &Connection) -> Result<(), SnapshotStoreError> {
    let application_id: i64 =
        connection.pragma_query_value(None, "application_id", |row| row.get(0))?;
    let user_version: i64 =
        connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if application_id != APPLICATION_ID || user_version != SCHEMA_VERSION {
        return Err(SnapshotStoreError::InvalidDatabase);
    }
    let mut statement = connection
        .prepare("SELECT name, sql FROM sqlite_schema WHERE sql IS NOT NULL ORDER BY name")?;
    let objects = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let expected = SCHEMA
        .iter()
        .map(|(name, sql)| ((*name).to_owned(), (*sql).to_owned()))
        .collect::<Vec<_>>();
    if objects != expected {
        return Err(SnapshotStoreError::InvalidDatabase);
    }
    Ok(())
}

fn not_found(error: &PathError) -> bool {
    match error {
        PathError::Io { source, .. } => source.kind() == std::io::ErrorKind::NotFound,
        #[cfg(target_os = "linux")]
        PathError::Openat2 { source, .. } => *source == rustix::io::Errno::NOENT,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    fn row(name: &str) -> SnapshotRow {
        SnapshotRow {
            id: Uuid::new_v4(),
            name: name.to_owned(),
            state: SnapshotState::Ready,
            created_unix_ms: 1,
            manifest_sha256: "a".repeat(64),
            retained: Retained {
                artifact_generations: BTreeSet::from(["b".repeat(64)]),
                content: BTreeMap::from([(
                    Sha256Digest::parse(&format!("sha256:{}", "c".repeat(64))).unwrap(),
                    7,
                )]),
            },
        }
    }

    #[test]
    fn names_are_unique_and_rows_round_trip() {
        let store = SnapshotStore::in_memory().unwrap();
        let first = row("good-toolchain");
        store.insert(&first).unwrap();
        assert!(matches!(
            store.insert(&row("good-toolchain")),
            Err(SnapshotStoreError::AlreadyExists(name)) if name == "good-toolchain"
        ));
        assert!(matches!(
            store.require_free("good-toolchain"),
            Err(SnapshotStoreError::AlreadyExists(_))
        ));
        store.require_free("other").unwrap();
        assert_eq!(store.find("good-toolchain").unwrap().unwrap(), first);
        assert_eq!(store.find(&first.id.to_string()).unwrap().unwrap(), first);
        assert_eq!(store.find("missing").unwrap(), None);
        assert_eq!(store.list().unwrap(), vec![first.clone()]);
        assert_eq!(store.retained().unwrap(), first.retained);
    }

    #[test]
    fn delete_marks_only_a_ready_snapshot_then_removes_it() {
        let store = SnapshotStore::in_memory().unwrap();
        let snapshot = row("s1");
        store.insert(&snapshot).unwrap();
        assert!(store.mark_deleting(snapshot.id).unwrap());
        assert!(!store.mark_deleting(snapshot.id).unwrap());
        assert_eq!(
            store.find("s1").unwrap().unwrap().state,
            SnapshotState::Deleting
        );
        store.remove(snapshot.id).unwrap();
        assert_eq!(store.find("s1").unwrap(), None);
        store.require_free("s1").unwrap();
    }

    #[test]
    fn an_insert_ends_its_capture_intent() {
        let store = SnapshotStore::in_memory().unwrap();
        let snapshot = row("s1");
        let other = Uuid::new_v4();
        store.record_intent(snapshot.id).unwrap();
        store.record_intent(other).unwrap();
        assert_eq!(
            store.intents().unwrap(),
            BTreeSet::from([snapshot.id, other])
        );
        store.insert(&snapshot).unwrap();
        assert_eq!(store.intents().unwrap(), BTreeSet::from([other]));
        store.remove_intent(other).unwrap();
        assert!(store.intents().unwrap().is_empty());
    }

    #[test]
    fn a_version_one_store_gains_capture_intents_and_keeps_its_rows() {
        // The first version 1: the snapshots table alone.
        version_one_store_migrates(&[SCHEMA[1].1]);
    }

    #[test]
    fn a_version_one_store_that_already_has_capture_intents_migrates() {
        // The later version 1: both tables, still stamped 1.
        version_one_store_migrates(&[SCHEMA[0].1, SCHEMA[1].1]);
    }

    fn version_one_store_migrates(statements: &[&str]) {
        let parent = tempfile::tempdir().unwrap();
        let path = parent.path().join("runtime");
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let root = PrivateRoot::open(&path).unwrap();
        let snapshot = row("s1");
        let intent = Uuid::new_v4();
        {
            // Exactly what that version 1 created.
            let connection = Connection::open(path.join(DATABASE_FILE)).unwrap();
            for statement in statements {
                connection.execute_batch(&format!("{statement};")).unwrap();
            }
            if statements.len() == 2 {
                connection
                    .execute(
                        "INSERT INTO capture_intents(id, created_unix_ms) VALUES (?1, 1)",
                        params![intent.to_string()],
                    )
                    .unwrap();
            }
            connection
                .pragma_update(None, "application_id", APPLICATION_ID)
                .unwrap();
            connection.pragma_update(None, "user_version", 1).unwrap();
            connection
                .execute(
                    "INSERT INTO snapshots(id, name, state, created_unix_ms, manifest_sha256, retained)
                     VALUES (?1, ?2, 'ready', ?3, ?4, ?5)",
                    params![
                        snapshot.id.to_string(),
                        snapshot.name,
                        snapshot.created_unix_ms,
                        snapshot.manifest_sha256,
                        serde_json::to_string(&snapshot.retained).unwrap()
                    ],
                )
                .unwrap();
        }
        std::fs::set_permissions(
            path.join(DATABASE_FILE),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let store = SnapshotStore::open(&root).unwrap();
        assert_eq!(store.list().unwrap(), vec![snapshot]);
        let kept = if statements.len() == 2 { 1 } else { 0 };
        assert_eq!(
            store.intents().unwrap().len(),
            kept,
            "existing intents kept"
        );
        store.record_intent(Uuid::new_v4()).unwrap();
        assert_eq!(store.intents().unwrap().len(), kept + 1);
        drop(store);
        // Reopening finds version 2 and validates it.
        SnapshotStore::open(&root).unwrap();
    }

    #[test]
    fn an_invalid_row_is_refused() {
        let store = SnapshotStore::in_memory().unwrap();
        let mut invalid = row("s1");
        invalid.name = "-bad".to_owned();
        assert!(matches!(
            store.insert(&invalid),
            Err(SnapshotStoreError::InvalidDatabase)
        ));
    }

    #[test]
    fn the_database_is_private_and_reopens_with_its_rows() {
        let parent = tempfile::tempdir().unwrap();
        let path = parent.path().join("runtime");
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let root = PrivateRoot::open(&path).unwrap();
        let snapshot = row("s1");
        SnapshotStore::open(&root)
            .unwrap()
            .insert(&snapshot)
            .unwrap();
        let mode = std::fs::metadata(path.join(DATABASE_FILE))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        assert_eq!(
            SnapshotStore::open(&root).unwrap().list().unwrap(),
            vec![snapshot]
        );
    }
}
