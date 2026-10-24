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
const SCHEMA_VERSION: i64 = 1;
const BUSY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
/// The TCP ports a rule gets when its target names none: those `open` allows,
/// so an allowed Git host also works over SSH.
pub const DEFAULT_ALLOW_PORTS: [u16; 3] = [22, 80, 443];
/// The most policies one host keeps.
pub const MAX_POLICIES: usize = 256;
/// The most revisions one policy keeps. Every edit adds one.
pub const MAX_REVISIONS: u32 = 10_000;

/// `(name, CREATE statement)`, exactly as SQLite keeps them.
const SCHEMA: [(&str, &str); 3] = [
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
];

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

/// Add `rules` to `policy`. A target it already allows gains the new ports.
pub fn with_rules(
    policy: &TypedPolicy,
    rules: impl IntoIterator<Item = AllowRule>,
) -> Result<TypedPolicy, TypedPolicyError> {
    let mut merged: Vec<AllowRule> = policy.rules().to_vec();
    for rule in rules {
        match merged
            .iter_mut()
            .find(|existing| existing.target() == rule.target())
        {
            Some(existing) => {
                let ports = existing
                    .ports()
                    .iter()
                    .chain(rule.ports())
                    .copied()
                    .collect::<std::collections::BTreeSet<_>>();
                *existing = AllowRule::new(existing.target().clone(), ports)?;
            }
            None => merged.push(rule),
        }
    }
    TypedPolicy::new(merged)
}

/// Remove the rules for `targets` from `policy`. Every target must have a rule.
pub fn without_targets(
    policy: &TypedPolicy,
    targets: &[AllowTarget],
) -> Result<TypedPolicy, NetworkPolicyStoreError> {
    if let Some(missing) = targets
        .iter()
        .find(|target| !policy.rules().iter().any(|rule| rule.target() == *target))
    {
        return Err(NetworkPolicyStoreError::Unchanged(format!(
            "the policy has no rule for {missing}"
        )));
    }
    Ok(TypedPolicy::new(
        policy
            .rules()
            .iter()
            .filter(|rule| !targets.contains(rule.target()))
            .cloned(),
    )?)
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
        let policy = with_rules(&start, rules)?;
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
        let edited = without_targets(&with_rules(&current.policy, add)?, remove)?;
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

    /// Delete `selector` and every revision of it, unless `selected_by` names
    /// an environment that selects it.
    pub fn delete(
        &self,
        selector: &PolicySelector,
        selected_by: impl FnOnce(&PolicyId) -> Vec<String>,
    ) -> Result<StoredPolicy, NetworkPolicyStoreError> {
        let mut connection = self.connection.lock().expect("policy store lock");
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = load_current(&transaction, selector)?;
        let environments = selected_by(&current.id);
        if !environments.is_empty() {
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

fn path_error_is_not_found(error: &PathError) -> bool {
    match error {
        #[cfg(target_os = "linux")]
        PathError::Openat2 { source, .. } => *source == rustix::io::Errno::NOENT,
        PathError::Io { source, .. } => source.kind() == std::io::ErrorKind::NotFound,
        _ => false,
    }
}

fn validate_schema(connection: &Connection) -> Result<(), NetworkPolicyStoreError> {
    let application_id: i64 =
        connection.pragma_query_value(None, "application_id", |row| row.get(0))?;
    let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if application_id != APPLICATION_ID || version != SCHEMA_VERSION {
        return Err(NetworkPolicyStoreError::InvalidDatabase);
    }
    let expected: std::collections::BTreeMap<&str, &str> = SCHEMA.into_iter().collect();
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
        match store.delete(&selector, |_| vec!["team".to_owned()]) {
            Err(NetworkPolicyStoreError::InUse { name, environments }) => {
                assert_eq!(
                    (name.as_str(), environments),
                    ("work", vec!["team".to_owned()])
                );
            }
            other => panic!("deleted a selected policy: {other:?}"),
        }
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
