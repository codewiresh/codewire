//! The host's local network policy store (#2537 step 3).
//!
//! A network policy is a named object with immutable revisions. Each revision
//! is one document in the typed rule subset of [`codewire_egress_policy`]:
//! default deny plus allow rules, stored in its canonical form with the digest
//! the brokers enforce. Every edit appends a revision; a revision is never
//! changed. `open` and `locked` are built-ins compiled from the crate, never
//! stored and never editable.
//!
//! The store is its own SQLite file in the supervisor's private root, owned by
//! the supervisor process, the one writer. It holds no secret: a policy is
//! owner-controlled configuration, so it lives beside the environments it
//! governs, not in the credential authority.

use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use codewire_egress_policy::reference::{PolicyId, PolicyName};
use codewire_egress_policy::typed::{AllowRule, AllowTarget, TypedPolicy, TypedPolicyError};
use codewire_egress_policy::{CompiledPolicy, PolicyDigest, PolicyDocument, PolicyError};
use rusqlite::config::DbConfig;
use rusqlite::{
    Connection, OpenFlags, OptionalExtension as _, Transaction, TransactionBehavior, params,
};
use uuid::Uuid;

use crate::host::path::{PathError, PrivateRoot};

pub(crate) const DATABASE_FILE: &str = "network-policies.db";
const APPLICATION_ID: i64 = 0x4357_4e50; // "CWNP"
/// 1: policies and revisions. 2: which policy each environment selects.
const SCHEMA_VERSION: i64 = 2;
const BUSY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
/// The TCP ports a rule gets when its target names none: those `open` allows,
/// so an allowed Git host also works over SSH.
pub const DEFAULT_ALLOW_PORTS: [u16; 3] = [22, 80, 443];
/// The most policies one host keeps.
pub const MAX_POLICIES: usize = 256;
/// The most revisions one policy keeps. Every edit adds one.
pub const MAX_REVISIONS: u32 = 10_000;

/// `(name, CREATE statement)`, exactly as SQLite keeps them.
const SCHEMA: [(&str, &str); 4] = [
    (
        "policies",
        "CREATE TABLE policies (
  id TEXT PRIMARY KEY NOT NULL CHECK (length(id) = 36),
  name TEXT NOT NULL UNIQUE CHECK (length(name) BETWEEN 1 AND 64),
  current_revision INTEGER NOT NULL CHECK (current_revision > 0),
  created_unix_ms INTEGER NOT NULL
) STRICT",
    ),
    (
        "policy_revisions",
        "CREATE TABLE policy_revisions (
  policy_id TEXT NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
  revision INTEGER NOT NULL CHECK (revision > 0),
  document BLOB NOT NULL,
  digest BLOB NOT NULL CHECK (length(digest) = 32),
  created_unix_ms INTEGER NOT NULL,
  PRIMARY KEY (policy_id, revision)
) STRICT",
    ),
    (
        "policy_revisions_are_immutable",
        "CREATE TRIGGER policy_revisions_are_immutable BEFORE UPDATE ON policy_revisions
BEGIN SELECT RAISE(ABORT, 'a policy revision is immutable'); END",
    ),
    // An environment with no row uses `open`. A row names a stored policy,
    // which it follows to its current revision, or a built-in; never both.
    (
        "environment_policies",
        "CREATE TABLE environment_policies (
  environment_id TEXT PRIMARY KEY NOT NULL CHECK (length(environment_id) = 36),
  policy_id TEXT NULL REFERENCES policies(id) ON DELETE RESTRICT,
  builtin TEXT NULL CHECK (builtin IN ('open', 'locked')),
  enforced_revision INTEGER NULL CHECK (enforced_revision IS NULL OR enforced_revision > 0),
  enforced_digest BLOB NULL CHECK (enforced_digest IS NULL OR length(enforced_digest) = 32),
  CHECK ((policy_id IS NULL) != (builtin IS NULL))
) STRICT",
    ),
];
/// The schema version 1 had: every statement but the last.
const SCHEMA_V1_STATEMENTS: usize = 3;

#[derive(Debug, thiserror::Error)]
pub enum NetworkPolicyStoreError {
    #[error("no local network policy is named {0}")]
    NotFound(String),
    #[error("local network policy {name} has no revision {revision}")]
    RevisionNotFound { name: String, revision: u32 },
    #[error("a local network policy named {0} already exists")]
    AlreadyExists(String),
    #[error("this host already keeps {MAX_POLICIES} local network policies")]
    TooManyPolicies,
    #[error("local network policy {0} already has {MAX_REVISIONS} revisions")]
    TooManyRevisions(String),
    #[error("local network policy {name} is selected by {}", environments.join(", "))]
    InUse {
        name: String,
        environments: Vec<String>,
    },
    #[error("{0}")]
    Unchanged(String),
    #[error(transparent)]
    Rule(#[from] TypedPolicyError),
    #[error("a stored network policy document is invalid")]
    InvalidDocument,
    #[error("the network policy database is not one this cw can read")]
    InvalidDatabase,
    #[error("the network policy database changed identity while opening")]
    DatabaseIdentityChanged,
    #[error(transparent)]
    Path(#[from] PathError),
    #[error(transparent)]
    Database(#[from] rusqlite::Error),
}

impl From<PolicyError> for NetworkPolicyStoreError {
    fn from(_: PolicyError) -> Self {
        Self::InvalidDocument
    }
}

/// Which stored policy an operation names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicySelector {
    Name(PolicyName),
    Id(PolicyId),
}

impl std::fmt::Display for PolicySelector {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Name(name) => write!(formatter, "{name}"),
            Self::Id(id) => write!(formatter, "id:{id}"),
        }
    }
}

/// What a new policy starts from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicyBase {
    /// The built-in `locked`: no rules.
    Locked,
    /// Another stored policy's current revision.
    Policy(PolicySelector),
}

/// One revision of a stored policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredPolicy {
    pub id: PolicyId,
    pub name: PolicyName,
    pub revision: u32,
    pub current_revision: u32,
    pub policy: TypedPolicy,
    pub digest: PolicyDigest,
    pub created_unix_ms: i64,
}

impl StoredPolicy {
    /// The engine's compiled form of this revision.
    pub fn compile(&self) -> CompiledPolicy {
        self.policy.compile()
    }
}

/// What an environment asks for: the built-in `locked` or a stored policy.
/// `open` is the absence of a selection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicySelection {
    Locked,
    Stored(PolicySelector),
}

/// What an environment selects, resolved: a built-in, or a stored policy at
/// its current revision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SelectedPolicy {
    Open,
    Locked,
    Stored(StoredPolicy),
}

impl SelectedPolicy {
    /// The engine form the egress broker enforces.
    pub fn compile(&self) -> CompiledPolicy {
        match self {
            Self::Open => CompiledPolicy::developer_baseline(),
            Self::Locked => TypedPolicy::default().compile(),
            Self::Stored(stored) => stored.compile(),
        }
    }

    /// `open`, `locked`, or the stored policy's exact `local:id:` reference.
    pub fn reference(&self) -> String {
        match self {
            Self::Open => "open".to_owned(),
            Self::Locked => "locked".to_owned(),
            Self::Stored(stored) => format!("local:id:{}", stored.id),
        }
    }

    /// `open`, `locked` or the stored policy's name.
    pub fn display_name(&self) -> String {
        match self {
            Self::Open => "open".to_owned(),
            Self::Locked => "locked".to_owned(),
            Self::Stored(stored) => stored.name.to_string(),
        }
    }

    /// The stored policy's current revision; built-ins have none.
    pub fn revision(&self) -> Option<u32> {
        match self {
            Self::Stored(stored) => Some(stored.revision),
            Self::Open | Self::Locked => None,
        }
    }
}

/// An environment's selection and what its running VM last started with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnvironmentPolicy {
    pub selected: SelectedPolicy,
    /// The digest, and the stored revision if any, the egress broker of the
    /// environment's last started boot enforces.
    pub enforced: Option<(Option<u32>, PolicyDigest)>,
}

impl EnvironmentPolicy {
    /// Whether the last boot enforces something other than the selection's
    /// current revision.
    pub fn enforcement_is_stale(&self) -> bool {
        self.enforced
            .is_some_and(|(_, digest)| digest != self.selected.compile().digest())
    }
}

/// The supervisor's network policy store.
pub struct NetworkPolicyStore {
    connection: Mutex<Connection>,
}

impl NetworkPolicyStore {
    /// Open or create `network-policies.db` in the supervisor's private root.
    pub fn open(root: &PrivateRoot) -> Result<Self, NetworkPolicyStoreError> {
        let relative = Path::new(DATABASE_FILE);
        let identity = match root.open_regular(relative, true, None, false, Some(0o600)) {
            Ok(opened) => opened.identity().clone(),
            Err(error) if path_error_is_not_found(&error) => root
                .create_regular(relative, 0o600, true)?
                .identity()
                .clone(),
            Err(error) => return Err(error.into()),
        };
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        let connection = Connection::open_with_flags(root.path().join(relative), flags)?;
        let reopened = root.open_regular(relative, true, None, false, Some(0o600))?;
        if reopened.identity() != &identity {
            return Err(NetworkPolicyStoreError::DatabaseIdentityChanged);
        }
        Self::from_connection(connection)
    }

    /// Create the schema in a database that has none, then validate it. The
    /// decision reads the database inside the transaction that creates it, so
    /// a first creation interrupted at any point is rolled back by SQLite and
    /// created again on the next open; a database with anything in it is
    /// only ever validated.
    fn from_connection(connection: Connection) -> Result<Self, NetworkPolicyStoreError> {
        connection.busy_timeout(BUSY_TIMEOUT)?;
        connection.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)?;
        connection.pragma_update(None, "foreign_keys", true)?;
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
        } else if user_version == 1 {
            upgrade_from_version_one(&transaction)?;
        }
        transaction.commit()?;
        validate_schema(&connection)?;
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    #[cfg(test)]
    pub(crate) fn in_memory() -> Result<Self, NetworkPolicyStoreError> {
        Self::from_connection(Connection::open_in_memory()?)
    }

    /// Create `name` at revision 1: `base` plus `rules`.
    pub fn create(
        &self,
        name: &PolicyName,
        base: &PolicyBase,
        rules: Vec<AllowRule>,
    ) -> Result<StoredPolicy, NetworkPolicyStoreError> {
        let mut connection = self.connection.lock().expect("policy store lock");
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if find_policy(&transaction, &PolicySelector::Name(name.clone()))?.is_some() {
            return Err(NetworkPolicyStoreError::AlreadyExists(name.to_string()));
        }
        let count: i64 =
            transaction.query_row("SELECT count(*) FROM policies", [], |row| row.get(0))?;
        if count as usize >= MAX_POLICIES {
            return Err(NetworkPolicyStoreError::TooManyPolicies);
        }
        let start = match base {
            PolicyBase::Locked => TypedPolicy::default(),
            PolicyBase::Policy(selector) => load_current(&transaction, selector)?.policy,
        };
        let policy = start.with_rules(rules)?;
        let id = PolicyId::parse(&Uuid::new_v4().to_string())
            .expect("a v4 UUID is a canonical policy id");
        let now = now_unix_ms();
        transaction.execute(
            "INSERT INTO policies(id, name, current_revision, created_unix_ms) VALUES (?1, ?2, 1, ?3)",
            params![id.as_str(), name.as_str(), now],
        )?;
        insert_revision(&transaction, &id, 1, &policy, now)?;
        let stored = load_revision(&transaction, &PolicySelector::Id(id), None)?;
        transaction.commit()?;
        Ok(stored)
    }

    /// Append a revision to `selector`: its current rules plus `add`, minus
    /// the rules for `remove`. An edit that changes nothing is refused.
    pub fn update(
        &self,
        selector: &PolicySelector,
        add: Vec<AllowRule>,
        remove: &[AllowTarget],
    ) -> Result<StoredPolicy, NetworkPolicyStoreError> {
        let mut connection = self.connection.lock().expect("policy store lock");
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = load_current(&transaction, selector)?;
        let edited = current
            .policy
            .with_rules(add)?
            .without_targets(remove)
            .map_err(|missing| {
                NetworkPolicyStoreError::Unchanged(format!("the policy has no rule for {missing}"))
            })?;
        if edited == current.policy {
            return Err(NetworkPolicyStoreError::Unchanged(format!(
                "{} already allows exactly that",
                current.name
            )));
        }
        if current.current_revision >= MAX_REVISIONS {
            return Err(NetworkPolicyStoreError::TooManyRevisions(
                current.name.to_string(),
            ));
        }
        let next = current.current_revision + 1;
        let now = now_unix_ms();
        insert_revision(&transaction, &current.id, next, &edited, now)?;
        transaction.execute(
            "UPDATE policies SET current_revision = ?1 WHERE id = ?2",
            params![next, current.id.as_str()],
        )?;
        let stored = load_revision(&transaction, &PolicySelector::Id(current.id), None)?;
        transaction.commit()?;
        Ok(stored)
    }

    /// `selector` at `revision`, or at its current revision.
    pub fn get(
        &self,
        selector: &PolicySelector,
        revision: Option<u32>,
    ) -> Result<StoredPolicy, NetworkPolicyStoreError> {
        let connection = self.connection.lock().expect("policy store lock");
        load_revision(&connection, selector, revision)
    }

    /// Every stored policy at its current revision, by name.
    pub fn list(&self) -> Result<Vec<StoredPolicy>, NetworkPolicyStoreError> {
        let connection = self.connection.lock().expect("policy store lock");
        let ids: Vec<String> = connection
            .prepare("SELECT id FROM policies ORDER BY name")?
            .query_map([], |row| row.get(0))?
            .collect::<Result<_, _>>()?;
        ids.into_iter()
            .map(|id| {
                let id =
                    PolicyId::parse(&id).map_err(|_| NetworkPolicyStoreError::InvalidDatabase)?;
                load_revision(&connection, &PolicySelector::Id(id), None)
            })
            .collect()
    }

    /// Delete `selector` and every revision of it, unless an environment
    /// selects it: then the refusal names them, through `names`, which maps
    /// environment ids to the names the owner knows. `names` must not use
    /// this store.
    pub fn delete(
        &self,
        selector: &PolicySelector,
        names: impl FnOnce(&[Uuid]) -> Vec<String>,
    ) -> Result<StoredPolicy, NetworkPolicyStoreError> {
        let mut connection = self.connection.lock().expect("policy store lock");
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = load_current(&transaction, selector)?;
        let selecting = selecting_environments(&transaction, &current.id)?;
        if !selecting.is_empty() {
            let mut environments = names(&selecting);
            if environments.is_empty() {
                environments = selecting.iter().map(Uuid::to_string).collect();
            }
            return Err(NetworkPolicyStoreError::InUse {
                name: current.name.to_string(),
                environments,
            });
        }
        transaction.execute(
            "DELETE FROM policies WHERE id = ?1",
            params![current.id.as_str()],
        )?;
        transaction.commit()?;
        Ok(current)
    }
}

impl NetworkPolicyStore {
    /// Select `selection` for `environment_id`, or `open` with `None`. The
    /// selection follows its stored policy's current revision; what an
    /// earlier boot enforced is kept until the next boot replaces it.
    pub fn select(
        &self,
        environment_id: Uuid,
        selection: Option<&PolicySelection>,
    ) -> Result<SelectedPolicy, NetworkPolicyStoreError> {
        let mut connection = self.connection.lock().expect("policy store lock");
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let id = environment_id.to_string();
        let selected = match selection {
            None => SelectedPolicy::Open,
            Some(PolicySelection::Locked) => SelectedPolicy::Locked,
            Some(PolicySelection::Stored(selector)) => {
                SelectedPolicy::Stored(load_current(&transaction, selector)?)
            }
        };
        let (policy_id, builtin) = match &selected {
            SelectedPolicy::Open => (None, Some("open")),
            SelectedPolicy::Locked => (None, Some("locked")),
            SelectedPolicy::Stored(stored) => (Some(stored.id.to_string()), None),
        };
        transaction.execute(
            "INSERT INTO environment_policies(environment_id, policy_id, builtin)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(environment_id) DO UPDATE SET policy_id = ?2, builtin = ?3",
            params![id, policy_id, builtin],
        )?;
        transaction.commit()?;
        Ok(selected)
    }

    /// `environment_id`'s selection, `open` when it has none.
    pub fn environment_policy(
        &self,
        environment_id: Uuid,
    ) -> Result<EnvironmentPolicy, NetworkPolicyStoreError> {
        let connection = self.connection.lock().expect("policy store lock");
        let row = connection
            .query_row(
                "SELECT policy_id, builtin, enforced_revision, enforced_digest
                 FROM environment_policies WHERE environment_id = ?1",
                [environment_id.to_string()],
                |row| {
                    Ok((
                        row.get::<_, Option<String>>(0)?,
                        row.get::<_, Option<String>>(1)?,
                        row.get::<_, Option<u32>>(2)?,
                        row.get::<_, Option<Vec<u8>>>(3)?,
                    ))
                },
            )
            .optional()?;
        let Some((policy_id, builtin, enforced_revision, enforced_digest)) = row else {
            return Ok(EnvironmentPolicy {
                selected: SelectedPolicy::Open,
                enforced: None,
            });
        };
        let selected = match (policy_id, builtin.as_deref()) {
            (Some(id), None) => SelectedPolicy::Stored(load_current(
                &connection,
                &PolicySelector::Id(
                    PolicyId::parse(&id).map_err(|_| NetworkPolicyStoreError::InvalidDatabase)?,
                ),
            )?),
            (None, Some("locked")) => SelectedPolicy::Locked,
            (None, Some("open")) => SelectedPolicy::Open,
            _ => return Err(NetworkPolicyStoreError::InvalidDatabase),
        };
        let enforced = enforced_digest
            .map(|digest| {
                <[u8; 32]>::try_from(digest.as_slice())
                    .map(|bytes| (enforced_revision, PolicyDigest::from_bytes(bytes)))
                    .map_err(|_| NetworkPolicyStoreError::InvalidDatabase)
            })
            .transpose()?;
        Ok(EnvironmentPolicy { selected, enforced })
    }

    /// Record what `environment_id`'s just-started boot enforces.
    pub fn record_enforced(
        &self,
        environment_id: Uuid,
        selected: &SelectedPolicy,
    ) -> Result<(), NetworkPolicyStoreError> {
        let connection = self.connection.lock().expect("policy store lock");
        let (policy_id, builtin) = match selected {
            SelectedPolicy::Open => (None, Some("open")),
            SelectedPolicy::Locked => (None, Some("locked")),
            SelectedPolicy::Stored(stored) => (Some(stored.id.to_string()), None),
        };
        // An environment that never selected anything still records what its
        // boot enforces, so a later selection can show it is not yet applied.
        connection.execute(
            "INSERT INTO environment_policies
               (environment_id, policy_id, builtin, enforced_revision, enforced_digest)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(environment_id) DO UPDATE
               SET enforced_revision = ?4, enforced_digest = ?5",
            params![
                environment_id.to_string(),
                policy_id,
                builtin,
                selected.revision(),
                selected.compile().digest().as_bytes().as_slice()
            ],
        )?;
        Ok(())
    }

    /// Forget a deleted environment's selection.
    pub fn clear_environment(&self, environment_id: Uuid) -> Result<(), NetworkPolicyStoreError> {
        let connection = self.connection.lock().expect("policy store lock");
        connection.execute(
            "DELETE FROM environment_policies WHERE environment_id = ?1",
            [environment_id.to_string()],
        )?;
        Ok(())
    }

    /// The environments that select `policy`, by id.
    pub fn environments_selecting(
        &self,
        policy: &PolicyId,
    ) -> Result<Vec<Uuid>, NetworkPolicyStoreError> {
        let connection = self.connection.lock().expect("policy store lock");
        selecting_environments(&connection, policy)
    }
}

fn selecting_environments(
    connection: &Connection,
    policy: &PolicyId,
) -> Result<Vec<Uuid>, NetworkPolicyStoreError> {
    let ids: Vec<String> = connection
        .prepare("SELECT environment_id FROM environment_policies WHERE policy_id = ?1")?
        .query_map([policy.as_str()], |row| row.get(0))?
        .collect::<Result<_, _>>()?;
    ids.iter()
        .map(|id| Uuid::parse_str(id).map_err(|_| NetworkPolicyStoreError::InvalidDatabase))
        .collect()
}

fn path_error_is_not_found(error: &PathError) -> bool {
    match error {
        #[cfg(target_os = "linux")]
        PathError::Openat2 { source, .. } => *source == rustix::io::Errno::NOENT,
        PathError::Io { source, .. } => source.kind() == std::io::ErrorKind::NotFound,
        _ => false,
    }
}

/// Version 1 (#2537 slice A) gains the selection table, after its exact
/// schema is checked, in one transaction.
/// Add selections to a version 1 store, inside the transaction that
/// decided it holds version 1. Its policies and revisions are kept.
fn upgrade_from_version_one(connection: &Connection) -> Result<(), NetworkPolicyStoreError> {
    validate_schema_statements(connection, 1, &SCHEMA[..SCHEMA_V1_STATEMENTS])?;
    for (_, statement) in &SCHEMA[SCHEMA_V1_STATEMENTS..] {
        connection.execute_batch(&format!("{statement};"))?;
    }
    connection.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    Ok(())
}

fn validate_schema(connection: &Connection) -> Result<(), NetworkPolicyStoreError> {
    validate_schema_statements(connection, SCHEMA_VERSION, &SCHEMA)
}

fn validate_schema_statements(
    connection: &Connection,
    expected_version: i64,
    statements: &[(&str, &str)],
) -> Result<(), NetworkPolicyStoreError> {
    let application_id: i64 =
        connection.pragma_query_value(None, "application_id", |row| row.get(0))?;
    let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if application_id != APPLICATION_ID || version != expected_version {
        return Err(NetworkPolicyStoreError::InvalidDatabase);
    }
    let expected: std::collections::BTreeMap<&str, &str> = statements.iter().copied().collect();
    let mut actual = std::collections::BTreeMap::new();
    let mut statement =
        connection.prepare("SELECT name, sql FROM sqlite_schema WHERE name NOT GLOB 'sqlite_*'")?;
    for row in statement.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?))
    })? {
        let (name, sql) = row?;
        actual.insert(name, sql.unwrap_or_default());
    }
    let matches = actual.len() == expected.len()
        && expected
            .iter()
            .all(|(name, sql)| actual.get(*name).map(|actual| actual.trim()) == Some(sql.trim()));
    if !matches {
        return Err(NetworkPolicyStoreError::InvalidDatabase);
    }
    Ok(())
}

fn now_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

fn insert_revision(
    connection: &Connection,
    id: &PolicyId,
    revision: u32,
    policy: &TypedPolicy,
    now: i64,
) -> Result<(), NetworkPolicyStoreError> {
    let compiled = policy.compile();
    connection.execute(
        "INSERT INTO policy_revisions(policy_id, revision, document, digest, created_unix_ms)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            id.as_str(),
            revision,
            compiled.canonical_json()?,
            compiled.digest().as_bytes().as_slice(),
            now
        ],
    )?;
    Ok(())
}

/// `(id, name, current_revision)` of the policy `selector` names.
fn find_policy(
    connection: &Connection,
    selector: &PolicySelector,
) -> Result<Option<(PolicyId, PolicyName, u32)>, NetworkPolicyStoreError> {
    let (sql, key) = match selector {
        PolicySelector::Name(name) => (
            "SELECT id, name, current_revision FROM policies WHERE name = ?1",
            name.as_str(),
        ),
        PolicySelector::Id(id) => (
            "SELECT id, name, current_revision FROM policies WHERE id = ?1",
            id.as_str(),
        ),
    };
    let row = connection
        .query_row(sql, [key], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, u32>(2)?,
            ))
        })
        .optional()?;
    row.map(|(id, name, current)| {
        Ok((
            PolicyId::parse(&id).map_err(|_| NetworkPolicyStoreError::InvalidDatabase)?,
            PolicyName::parse(&name).map_err(|_| NetworkPolicyStoreError::InvalidDatabase)?,
            current,
        ))
    })
    .transpose()
}

fn load_current(
    connection: &Connection,
    selector: &PolicySelector,
) -> Result<StoredPolicy, NetworkPolicyStoreError> {
    load_revision(connection, selector, None)
}

fn load_revision(
    connection: &Connection,
    selector: &PolicySelector,
    revision: Option<u32>,
) -> Result<StoredPolicy, NetworkPolicyStoreError> {
    let (id, name, current_revision) = find_policy(connection, selector)?
        .ok_or_else(|| NetworkPolicyStoreError::NotFound(selector.to_string()))?;
    let revision = revision.unwrap_or(current_revision);
    let (document, digest, created_unix_ms) = connection
        .query_row(
            "SELECT document, digest, created_unix_ms FROM policy_revisions
             WHERE policy_id = ?1 AND revision = ?2",
            params![id.as_str(), revision],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| NetworkPolicyStoreError::RevisionNotFound {
            name: name.to_string(),
            revision,
        })?;
    let document: PolicyDocument =
        serde_json::from_slice(&document).map_err(|_| NetworkPolicyStoreError::InvalidDocument)?;
    let policy = TypedPolicy::from_document(&document)
        .map_err(|_| NetworkPolicyStoreError::InvalidDocument)?;
    // The stored digest must be the one the document compiles to: a revision
    // is enforced by digest, so a mismatch is a damaged store, never a policy.
    if policy.compile().digest().as_bytes().as_slice() != digest.as_slice() {
        return Err(NetworkPolicyStoreError::InvalidDocument);
    }
    Ok(StoredPolicy {
        digest: policy.compile().digest(),
        id,
        name,
        revision,
        current_revision,
        policy,
        created_unix_ms,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(value: &str) -> PolicyName {
        PolicyName::parse(value).unwrap()
    }

    fn rule(target: &str, ports: &[u16]) -> AllowRule {
        AllowRule::new(AllowTarget::parse(target).unwrap(), ports.iter().copied()).unwrap()
    }

    fn targets(stored: &StoredPolicy) -> Vec<(String, Vec<u16>)> {
        stored
            .policy
            .rules()
            .iter()
            .map(|rule| (rule.target().to_string(), rule.ports().to_vec()))
            .collect()
    }

    /// What a revision of these rules is, byte for byte. The platform store
    /// asserts the same two values for the same rules
    /// (codewire-orchestration `api::network_policies` database tests, #4000).
    const SHARED_DOCUMENT: &str = r#"{"version":1,"default":"deny","rules":[{"id":"allow-5901884b7857ae99.tcp","action":"allow","protocols":["tcp"],"ports":[443],"cidrs":["93.184.216.0/24"],"destinations":[],"route_classes":["general"]},{"id":"allow-a6ad0e232c75e1ac.dns","action":"allow","protocols":["dns"],"ports":[53],"cidrs":[],"destinations":["github.com"],"route_classes":["general"]},{"id":"allow-a6ad0e232c75e1ac.tcp","action":"allow","protocols":["tcp"],"ports":[22,443],"cidrs":[],"destinations":["github.com"],"route_classes":["general"]}]}"#;
    const SHARED_DIGEST: &str = "90edf3723213a00ccc8639cc0386f5261c9128c281f2a73dc3805a0bfef1df35";

    #[test]
    fn a_revision_is_the_document_and_digest_the_platform_store_writes() {
        let store = NetworkPolicyStore::in_memory().unwrap();
        let shared = store
            .create(
                &name("shared"),
                &PolicyBase::Locked,
                vec![
                    rule("github.com", &[443, 22]),
                    rule("93.184.216.0/24", &[443]),
                ],
            )
            .unwrap();
        let connection = store.connection.lock().expect("policy store lock");
        let (document, digest): (Vec<u8>, Vec<u8>) = connection
            .query_row(
                "SELECT document, digest FROM policy_revisions WHERE policy_id = ?1",
                [shared.id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(String::from_utf8(document).unwrap(), SHARED_DOCUMENT);
        let digest: [u8; 32] = digest.try_into().unwrap();
        assert_eq!(PolicyDigest::from_bytes(digest).to_hex(), SHARED_DIGEST);
        assert_eq!(shared.digest.to_hex(), SHARED_DIGEST);
    }

    #[test]
    fn a_policy_starts_from_locked_or_another_policy_at_revision_one() {
        let store = NetworkPolicyStore::in_memory().unwrap();
        let work = store
            .create(
                &name("work"),
                &PolicyBase::Locked,
                vec![
                    rule("github.com", &DEFAULT_ALLOW_PORTS),
                    rule("*.npmjs.org", &[443]),
                ],
            )
            .unwrap();
        assert_eq!((work.revision, work.current_revision), (1, 1));
        assert_eq!(
            targets(&work),
            // Canonical order: exact names, then `*.` patterns, then ranges.
            [
                ("github.com".to_owned(), vec![22, 80, 443]),
                ("*.npmjs.org".to_owned(), vec![443]),
            ]
        );
        let plus = store
            .create(
                &name("work-plus"),
                &PolicyBase::Policy(PolicySelector::Name(name("work"))),
                vec![rule("extra.example.org", &[443])],
            )
            .unwrap();
        assert_eq!(targets(&plus).len(), 3);
        assert_ne!(plus.id, work.id);
        assert_ne!(plus.digest, work.digest);

        let empty = store
            .create(&name("nothing"), &PolicyBase::Locked, vec![])
            .unwrap();
        assert_eq!(
            empty.digest,
            TypedPolicy::default().compile().digest(),
            "a policy with no rules is `locked`"
        );
        assert!(matches!(
            store.create(&name("work"), &PolicyBase::Locked, vec![]),
            Err(NetworkPolicyStoreError::AlreadyExists(_))
        ));
        assert!(matches!(
            store.create(
                &name("other"),
                &PolicyBase::Policy(PolicySelector::Name(name("missing"))),
                vec![]
            ),
            Err(NetworkPolicyStoreError::NotFound(_))
        ));
    }

    #[test]
    fn every_edit_is_a_new_immutable_revision() {
        let store = NetworkPolicyStore::in_memory().unwrap();
        let selector = PolicySelector::Name(name("work"));
        let one = store
            .create(
                &name("work"),
                &PolicyBase::Locked,
                vec![rule("github.com", &[443])],
            )
            .unwrap();
        let two = store
            .update(
                &selector,
                vec![rule("github.com", &[22]), rule("pypi.org", &[443])],
                &[],
            )
            .unwrap();
        assert_eq!(two.revision, 2);
        assert_eq!(
            targets(&two),
            [
                ("github.com".to_owned(), vec![22, 443]),
                ("pypi.org".to_owned(), vec![443]),
            ]
        );
        let three = store
            .update(
                &selector,
                vec![],
                &[AllowTarget::parse("pypi.org").unwrap()],
            )
            .unwrap();
        assert_eq!(three.revision, 3);
        assert_eq!(targets(&three), [("github.com".to_owned(), vec![22, 443])]);

        // Old revisions read back unchanged, with their own digests.
        assert_eq!(store.get(&selector, Some(1)).unwrap().digest, one.digest);
        assert_eq!(store.get(&selector, Some(2)).unwrap().digest, two.digest);
        assert_eq!(store.get(&selector, None).unwrap().revision, 3);
        assert!(matches!(
            store.get(&selector, Some(4)),
            Err(NetworkPolicyStoreError::RevisionNotFound { revision: 4, .. })
        ));

        // A revision cannot be rewritten in place, even by direct SQL.
        let connection = store.connection.lock().unwrap();
        assert!(
            connection
                .execute("UPDATE policy_revisions SET created_unix_ms = 0", [])
                .is_err()
        );
    }

    #[test]
    fn an_edit_that_changes_nothing_or_names_a_missing_rule_is_refused() {
        let store = NetworkPolicyStore::in_memory().unwrap();
        let selector = PolicySelector::Name(name("work"));
        store
            .create(
                &name("work"),
                &PolicyBase::Locked,
                vec![rule("github.com", &[443])],
            )
            .unwrap();
        assert!(matches!(
            store.update(&selector, vec![rule("github.com", &[443])], &[]),
            Err(NetworkPolicyStoreError::Unchanged(_))
        ));
        assert!(matches!(
            store.update(
                &selector,
                vec![],
                &[AllowTarget::parse("pypi.org").unwrap()]
            ),
            Err(NetworkPolicyStoreError::Unchanged(_))
        ));
        assert_eq!(store.get(&selector, None).unwrap().revision, 1);
    }

    /// `hosted-default` names the hosted D2 policy, but only the platform
    /// store reserves it (#4000): a local policy that has that name, made
    /// before it meant anything, still lists, selects and deletes.
    #[test]
    fn a_local_policy_named_hosted_default_stays_usable() {
        let store = NetworkPolicyStore::in_memory().unwrap();
        let selector = PolicySelector::Name(name("hosted-default"));
        store
            .create(
                &name("hosted-default"),
                &PolicyBase::Locked,
                vec![rule("github.com", &[443])],
            )
            .unwrap();
        let listed = store.list().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name.as_str(), "hosted-default");
        let environment = Uuid::new_v4();
        let selected = store
            .select(
                environment,
                Some(&PolicySelection::Stored(selector.clone())),
            )
            .unwrap();
        assert_eq!(selected.display_name(), "hosted-default");
        store.select(environment, None).unwrap();
        store.delete(&selector, |_| Vec::new()).unwrap();
        assert!(store.list().unwrap().is_empty());
    }

    #[test]
    fn a_selected_policy_cannot_be_deleted_and_deletion_removes_every_revision() {
        let store = NetworkPolicyStore::in_memory().unwrap();
        let selector = PolicySelector::Name(name("work"));
        store
            .create(
                &name("work"),
                &PolicyBase::Locked,
                vec![rule("github.com", &[443])],
            )
            .unwrap();
        store
            .update(&selector, vec![rule("pypi.org", &[443])], &[])
            .unwrap();
        let team = Uuid::new_v4();
        store
            .select(team, Some(&PolicySelection::Stored(selector.clone())))
            .unwrap();
        match store.delete(&selector, |ids| {
            assert_eq!(ids, [team]);
            vec!["team".to_owned()]
        }) {
            Err(NetworkPolicyStoreError::InUse { name, environments }) => {
                assert_eq!(
                    (name.as_str(), environments),
                    ("work", vec!["team".to_owned()])
                );
            }
            other => panic!("deleted a selected policy: {other:?}"),
        }
        store.select(team, None).unwrap();
        let deleted = store.delete(&selector, |_| Vec::new()).unwrap();
        assert_eq!(deleted.revision, 2);
        assert!(store.list().unwrap().is_empty());
        let revisions: i64 = store
            .connection
            .lock()
            .unwrap()
            .query_row("SELECT count(*) FROM policy_revisions", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(revisions, 0);
    }

    #[test]
    fn a_first_creation_that_did_not_finish_is_created_on_the_next_open() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.path().join(DATABASE_FILE);
        // A database file SQLite has written but that holds no schema, as an
        // interrupted first creation leaves it once SQLite rolls it back.
        let interrupted = Connection::open(&path).unwrap();
        interrupted
            .execute_batch("CREATE TABLE partial (id INTEGER); DROP TABLE partial;")
            .unwrap();
        drop(interrupted);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(std::fs::metadata(&path).unwrap().len() > 0);

        let root = PrivateRoot::open(directory.path()).unwrap();
        let store = NetworkPolicyStore::open(&root).unwrap();
        store
            .create(
                &name("work"),
                &PolicyBase::Locked,
                vec![rule("github.com", &[443])],
            )
            .unwrap();
        drop(store);
        let reopened = NetworkPolicyStore::open(&root).unwrap();
        assert_eq!(
            reopened.list().unwrap().len(),
            1,
            "an existing store is kept"
        );

        // A database that names a schema it does not hold is never created over.
        let claimed = Connection::open_in_memory().unwrap();
        claimed
            .pragma_update(None, "user_version", SCHEMA_VERSION)
            .unwrap();
        assert!(matches!(
            NetworkPolicyStore::from_connection(claimed),
            Err(NetworkPolicyStoreError::InvalidDatabase)
        ));
    }

    #[test]
    fn an_environment_follows_its_policy_and_knows_what_its_boot_enforces() {
        let store = NetworkPolicyStore::in_memory().unwrap();
        let selector = PolicySelector::Name(name("work"));
        store
            .create(
                &name("work"),
                &PolicyBase::Locked,
                vec![rule("github.com", &[443])],
            )
            .unwrap();
        let environment = Uuid::new_v4();
        assert_eq!(
            store.environment_policy(environment).unwrap(),
            EnvironmentPolicy {
                selected: SelectedPolicy::Open,
                enforced: None
            }
        );

        let selected = store
            .select(
                environment,
                Some(&PolicySelection::Stored(selector.clone())),
            )
            .unwrap();
        assert_eq!(selected.revision(), Some(1));
        store.record_enforced(environment, &selected).unwrap();
        let current = store.environment_policy(environment).unwrap();
        assert!(!current.enforcement_is_stale());
        assert_eq!(current.enforced.unwrap().0, Some(1));

        // An edit moves the selection to the new revision; the running boot
        // still enforces revision 1 until it is replaced.
        store
            .update(&selector, vec![rule("pypi.org", &[443])], &[])
            .unwrap();
        let edited = store.environment_policy(environment).unwrap();
        assert_eq!(edited.selected.revision(), Some(2));
        assert!(edited.enforcement_is_stale());
        store
            .record_enforced(environment, &edited.selected)
            .unwrap();
        assert!(
            !store
                .environment_policy(environment)
                .unwrap()
                .enforcement_is_stale()
        );

        // A selected policy cannot be deleted, here or by its foreign key.
        let id = edited_id(&edited);
        assert_eq!(store.environments_selecting(&id).unwrap(), [environment]);
        assert!(store.delete(&selector, |_| Vec::new()).is_err());

        // Built-ins: `locked` compiles to no rules, and switching to `open`
        // keeps what the running boot enforces.
        let locked = store
            .select(environment, Some(&PolicySelection::Locked))
            .unwrap();
        assert_eq!(
            locked.compile().digest(),
            TypedPolicy::default().compile().digest()
        );
        assert!(
            store
                .environment_policy(environment)
                .unwrap()
                .enforcement_is_stale()
        );
        assert_eq!(
            store.select(environment, None).unwrap(),
            SelectedPolicy::Open
        );
        let open = store.environment_policy(environment).unwrap();
        assert_eq!(open.selected, SelectedPolicy::Open);
        assert!(open.enforcement_is_stale());
        assert!(store.environments_selecting(&id).unwrap().is_empty());
        store.delete(&selector, |_| Vec::new()).unwrap();

        store.clear_environment(environment).unwrap();
        assert_eq!(
            store.environment_policy(environment).unwrap().selected,
            SelectedPolicy::Open
        );
        assert!(matches!(
            store.select(environment, Some(&PolicySelection::Stored(selector))),
            Err(NetworkPolicyStoreError::NotFound(_))
        ));
    }

    fn edited_id(policy: &EnvironmentPolicy) -> PolicyId {
        match &policy.selected {
            SelectedPolicy::Stored(stored) => stored.id.clone(),
            other => panic!("not a stored policy: {other:?}"),
        }
    }

    #[test]
    fn a_version_one_store_gains_selections_and_keeps_its_policies() {
        let connection = Connection::open_in_memory().unwrap();
        for (_, statement) in &SCHEMA[..SCHEMA_V1_STATEMENTS] {
            connection.execute_batch(&format!("{statement};")).unwrap();
        }
        connection
            .pragma_update(None, "application_id", APPLICATION_ID)
            .unwrap();
        connection
            .pragma_update(None, "user_version", 1_i64)
            .unwrap();
        let policy = TypedPolicy::default();
        let id = PolicyId::parse(&Uuid::new_v4().to_string()).unwrap();
        connection
            .execute(
                "INSERT INTO policies(id, name, current_revision, created_unix_ms) VALUES (?1, 'work', 1, 0)",
                [id.as_str()],
            )
            .unwrap();
        insert_revision(&connection, &id, 1, &policy, 0).unwrap();

        let store = NetworkPolicyStore::from_connection(connection).unwrap();
        assert_eq!(store.list().unwrap().len(), 1);
        let environment = Uuid::new_v4();
        store
            .select(
                environment,
                Some(&PolicySelection::Stored(PolicySelector::Id(id))),
            )
            .unwrap();
        let version: i64 = store
            .connection
            .lock()
            .unwrap()
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);
    }

    #[test]
    fn a_damaged_revision_or_foreign_database_is_refused() {
        let store = NetworkPolicyStore::in_memory().unwrap();
        let selector = PolicySelector::Name(name("work"));
        store
            .create(
                &name("work"),
                &PolicyBase::Locked,
                vec![rule("github.com", &[443])],
            )
            .unwrap();
        let connection = store.connection.into_inner().unwrap();
        // Swap the digest under the trigger by recreating the row.
        connection
            .execute_batch(
                "CREATE TEMP TABLE r AS SELECT * FROM policy_revisions;
                 DELETE FROM policy_revisions;
                 UPDATE r SET digest = zeroblob(32);
                 INSERT INTO policy_revisions SELECT * FROM r;",
            )
            .unwrap();
        let store = NetworkPolicyStore::from_connection(connection).unwrap();
        assert!(matches!(
            store.get(&selector, None),
            Err(NetworkPolicyStoreError::InvalidDocument)
        ));

        let foreign = Connection::open_in_memory().unwrap();
        foreign
            .execute_batch("CREATE TABLE policies (id TEXT) STRICT;")
            .unwrap();
        assert!(matches!(
            NetworkPolicyStore::from_connection(foreign),
            Err(NetworkPolicyStoreError::InvalidDatabase)
        ));
    }
}
