//! A credential's name is unique per provider, ignoring case, not across
//! providers (docs/dev/SECRETS-AND-CREDENTIALS.md, "Credential names";
//! #4928). Store schema 7 holds the rule; names are resolved only here, at
//! the authority's edge, and nothing internal refers to a credential by name.

use super::*;

use codewire_access::reserves_provider_prefix;

/// The `credentials` table's columns and constraints, after `CREATE TABLE
/// name(`. Stores before schema 7 had the name unique across providers.
pub(crate) const CREDENTIALS_TABLE_BODY: &str = "
               id TEXT PRIMARY KEY NOT NULL,
               provider TEXT NOT NULL,
               authentication_kind TEXT NOT NULL,
               display_name TEXT NOT NULL COLLATE NOCASE,
               account_hint TEXT NULL,
               ssh_public_key_openssh TEXT NULL,
               ssh_public_key_fingerprint TEXT NULL
                 CHECK((ssh_public_key_openssh IS NULL) = (ssh_public_key_fingerprint IS NULL)),
               status TEXT NOT NULL CHECK(status IN ('active', 'expired', 'refresh_failed', 'revoked')),
               expires_at_unix INTEGER NULL CHECK(expires_at_unix IS NULL OR expires_at_unix >= 0),
               revocation_generation INTEGER NOT NULL CHECK(revocation_generation > 0),
               material_generation INTEGER NOT NULL CHECK(material_generation > 0),
               protected_entry_id TEXT NOT NULL UNIQUE,
               store_persistence TEXT NOT NULL CHECK(store_persistence IN ('operating_system', 'process_lifetime')),
               material_state TEXT NOT NULL CHECK(material_state IN ('pending_write', 'ready', 'pending_delete')),
               created_at_unix_ms INTEGER NOT NULL CHECK(created_at_unix_ms >= 0),
               updated_at_unix_ms INTEGER NOT NULL CHECK(updated_at_unix_ms >= created_at_unix_ms),
               UNIQUE(provider, display_name COLLATE NOCASE)
             ) STRICT;";

/// Every `credentials` column, named so a copy never depends on column
/// order: a store upgraded from schema 3 has its SSH columns last.
const CREDENTIALS_COLUMNS: &str = "id, provider, authentication_kind, display_name, account_hint,
    ssh_public_key_openssh, ssh_public_key_fingerprint, status, expires_at_unix,
    revocation_generation, material_generation, protected_entry_id, store_persistence,
    material_state, created_at_unix_ms, updated_at_unix_ms";

/// Refuse a name a credential is created with or renamed to when it starts
/// with a provider id and `/`, which `PROVIDER/NAME` would read as another
/// credential. A credential an older Codewire saved with such a name keeps it.
pub(crate) fn admit_new_name(name: &str) -> Result<(), LocalCredentialError> {
    if reserves_provider_prefix(name) {
        Err(LocalCredentialError::CredentialNameReservesProvider)
    } else {
        Ok(())
    }
}

struct NameMatch {
    id: String,
    provider: String,
}

impl<S: ProtectedStore> LocalCredentialAuthority<S> {
    /// The ready credential with this name, ignoring case. A name is unique
    /// only within a provider, so without `provider` a name two providers
    /// share is [`LocalCredentialError::CredentialNameAmbiguous`], never a
    /// guess.
    pub fn resolve_credential(
        &self,
        display_name: &str,
        provider: Option<&ProviderId>,
    ) -> Result<CredentialRecord, LocalCredentialError> {
        let connection = self.connection()?;
        let mut statement = connection
            .prepare(
                "SELECT id, provider FROM credentials
                 WHERE display_name = ?1 COLLATE NOCASE AND material_state = 'ready'
                   AND (?2 IS NULL OR provider = ?2)
                 ORDER BY provider",
            )
            .map_err(database_error)?;
        let mut matches = statement
            .query_map(
                params![display_name, provider.map(ProviderId::as_str)],
                |row| {
                    Ok(NameMatch {
                        id: row.get(0)?,
                        provider: row.get(1)?,
                    })
                },
            )
            .map_err(database_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(database_error)?;
        let id = match matches.len() {
            0 => return Err(LocalCredentialError::CredentialNotFound),
            1 => matches.remove(0).id,
            _ => {
                let providers = matches
                    .into_iter()
                    .map(|found| {
                        ProviderId::parse(found.provider)
                            .map_err(|_| LocalCredentialError::CorruptMetadata)
                    })
                    .collect::<Result<BTreeSet<_>, _>>()?;
                return Err(LocalCredentialError::CredentialNameAmbiguous {
                    providers: providers.into_iter().collect(),
                });
            }
        };
        drop(statement);
        let id = CredentialId::parse(id).map_err(|_| LocalCredentialError::CorruptMetadata)?;
        load_internal_credential(&connection, &id, Some(MaterialState::Ready))
            .map(|record| record.public)
    }
}

struct IndexKeyColumn {
    name: String,
    collation: String,
}

/// Whether `credentials` has schema 7's name constraint: a full unique index
/// on (provider, display_name NOCASE), and none on the name alone.
pub(crate) fn credential_names_unique_per_provider(
    connection: &Connection,
) -> Result<bool, LocalCredentialError> {
    let mut indexes = connection
        .prepare(
            "SELECT name FROM pragma_index_list('credentials')
             WHERE \"unique\" AND NOT partial",
        )
        .map_err(database_error)?;
    let indexes = indexes
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(database_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(database_error)?;
    let mut columns = connection
        .prepare("SELECT name, coll FROM pragma_index_xinfo(?1) WHERE key ORDER BY seqno")
        .map_err(database_error)?;
    let mut per_provider = false;
    for index in indexes {
        let key = columns
            .query_map([index], |row| {
                Ok(IndexKeyColumn {
                    name: row.get(0)?,
                    collation: row.get(1)?,
                })
            })
            .map_err(database_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(database_error)?;
        let key: Vec<(&str, &str)> = key
            .iter()
            .map(|column| (column.name.as_str(), column.collation.as_str()))
            .collect();
        match key.as_slice() {
            [("display_name", _)] => return Ok(false),
            [("provider", "BINARY"), ("display_name", "NOCASE")] => per_provider = true,
            _ => {}
        }
    }
    Ok(per_provider)
}

/// Version 6 to 7: a credential's name is unique per provider, not across
/// providers. The inline UNIQUE on `display_name` is an index SQLite cannot
/// drop, so this rebuilds `credentials` the way SQLite documents for a
/// changed constraint (<https://www.sqlite.org/lang_altertable.html>, "Making
/// Other Kinds Of Table Schema Changes"). Every schema 6 row is unique by name
/// already, so each is copied as it is.
///
/// Foreign keys go off for the rebuild, outside its transaction where the
/// pragma has no effect: with them on, dropping the old table would cascade
/// into `protected_entry_journal`. The transaction checks every foreign key
/// before it commits, so a failure at any step leaves schema 6 as it was.
pub(crate) fn upgrade_credential_names_schema(
    connection: &Connection,
) -> Result<(), LocalCredentialError> {
    connection
        .pragma_update(None, "foreign_keys", false)
        .map_err(database_error)?;
    let rebuilt = rebuild_credentials_table(connection);
    let restored = connection
        .pragma_update(None, "foreign_keys", true)
        .map_err(database_error);
    rebuilt.and(restored)
}

fn rebuild_credentials_table(connection: &Connection) -> Result<(), LocalCredentialError> {
    let foreign_keys: bool = connection
        .pragma_query_value(None, "foreign_keys", |row| row.get(0))
        .map_err(database_error)?;
    if foreign_keys {
        return Err(LocalCredentialError::InvalidDatabase);
    }
    let transaction = crate::immediate(connection)?;
    transaction
        .execute_batch(&format!(
            "CREATE TABLE credentials_schema_7({CREDENTIALS_TABLE_BODY}
             INSERT INTO credentials_schema_7({CREDENTIALS_COLUMNS})
               SELECT {CREDENTIALS_COLUMNS} FROM credentials;
             DROP TABLE credentials;
             ALTER TABLE credentials_schema_7 RENAME TO credentials;
             {GITHUB_SINGLETON_INDEX}"
        ))
        .map_err(database_error)?;
    let violation = transaction
        .query_row("SELECT 1 FROM pragma_foreign_key_check LIMIT 1", [], |_| {
            Ok(())
        })
        .optional()
        .map_err(database_error)?
        .is_some();
    if violation {
        return Err(LocalCredentialError::InvalidDatabase);
    }
    transaction
        .pragma_update(None, "user_version", DATABASE_SCHEMA_VERSION)
        .map_err(database_error)?;
    transaction.commit().map_err(database_error)
}
