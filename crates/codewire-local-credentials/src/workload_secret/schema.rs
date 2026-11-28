//! The workload-secret tables, as a new store creates them, and schema 8's
//! upgrade, which adds a secret's binding (#4003;
//! docs/dev/SECRETS-AND-CREDENTIALS.md, "The record").

use rusqlite::Connection;

use crate::{LocalCredentialError, database_error};

/// `workload_secrets` and its cleanup journal. Values are never here: a row
/// names the protected-store entry that holds its value.
pub(crate) const WORKLOAD_SECRETS_SCHEMA: &str = "
    CREATE TABLE workload_secrets(
      id TEXT PRIMARY KEY NOT NULL,
      scope_kind TEXT NOT NULL CHECK(scope_kind IN ('user', 'project')),
      scope_id TEXT NOT NULL,
      project_id TEXT NULL,
      key TEXT NOT NULL,
      material_generation INTEGER NOT NULL CHECK(material_generation > 0),
      protected_entry_id TEXT NOT NULL UNIQUE,
      material_state TEXT NOT NULL CHECK(material_state IN ('pending_write', 'ready', 'pending_delete')),
      created_at_unix_ms INTEGER NOT NULL CHECK(created_at_unix_ms >= 0),
      updated_at_unix_ms INTEGER NOT NULL CHECK(updated_at_unix_ms >= created_at_unix_ms),
      binding_id TEXT NULL,
      binding_generation INTEGER NOT NULL DEFAULT 0 CHECK(binding_generation >= 0),
      binding TEXT NULL CHECK(binding IS NULL OR binding_id IS NOT NULL),
      UNIQUE(scope_kind, scope_id, key),
      CHECK((scope_kind = 'user' AND project_id IS NULL) OR
            (scope_kind = 'project' AND project_id = scope_id)),
      FOREIGN KEY(project_id) REFERENCES secret_projects(id) ON DELETE RESTRICT
    ) STRICT;
    CREATE INDEX workload_secrets_scope
      ON workload_secrets(scope_kind, scope_id, key);
    CREATE TABLE workload_secret_journal(
      secret_id TEXT PRIMARY KEY NOT NULL,
      operation TEXT NOT NULL CHECK(operation IN ('rollback_write', 'delete_retired')),
      protected_entry_id TEXT NOT NULL UNIQUE,
      created_at_unix_ms INTEGER NOT NULL CHECK(created_at_unix_ms >= 0),
      FOREIGN KEY(secret_id) REFERENCES workload_secrets(id) ON DELETE CASCADE
    ) STRICT;";

/// The binding columns, as schema 8 adds them to an older store's table.
/// `binding` is a `StoredBinding` as JSON, absent for a plain secret.
/// `binding_id` is made at the first bind and kept until the secret is
/// deleted, so a plain secret that was bound keeps it. A secret's value
/// version is its `material_generation`, which moves with every new value.
/// Each is a column constraint, never a table one, so a column can be
/// dropped again (SQLite refuses to drop one a table constraint names).
const SECRET_BINDING_COLUMNS: &str = "
    ALTER TABLE workload_secrets ADD COLUMN binding_id TEXT NULL;
    ALTER TABLE workload_secrets ADD COLUMN binding_generation INTEGER NOT NULL DEFAULT 0
      CHECK(binding_generation >= 0);
    ALTER TABLE workload_secrets ADD COLUMN binding TEXT NULL
      CHECK(binding IS NULL OR binding_id IS NOT NULL);";

/// Version 7 to 8: every secret plain, as it was. One atomic step.
pub(crate) fn upgrade_secret_bindings_schema(
    connection: &Connection,
) -> Result<(), LocalCredentialError> {
    let transaction = crate::immediate(connection)?;
    transaction
        .execute_batch(SECRET_BINDING_COLUMNS)
        .map_err(database_error)?;
    transaction
        .pragma_update(None, "user_version", crate::DATABASE_SCHEMA_VERSION)
        .map_err(database_error)?;
    transaction.commit().map_err(database_error)
}

/// Whether `workload_secrets` has schema 8's binding columns.
pub(crate) fn has_secret_binding_columns(
    connection: &Connection,
) -> Result<bool, LocalCredentialError> {
    let columns: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM pragma_table_info('workload_secrets')
             WHERE name IN ('binding_id', 'binding_generation', 'binding')",
            [],
            |row| row.get(0),
        )
        .map_err(database_error)?;
    Ok(columns == 3)
}
