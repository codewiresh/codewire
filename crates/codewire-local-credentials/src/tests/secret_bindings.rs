//! A schema 7 store becomes schema 8, every secret plain and every row kept
//! (#4003).

use super::*;

/// Give a current store schema 7's `workload_secrets`, rows unchanged.
pub(super) fn downgrade_to_schema_seven(connection: &Connection) {
    connection
        .execute_batch(
            "ALTER TABLE workload_secrets DROP COLUMN binding;
             ALTER TABLE workload_secrets DROP COLUMN binding_generation;
             ALTER TABLE workload_secrets DROP COLUMN binding_id;
             PRAGMA user_version = 7;",
        )
        .expect("construct exact schema-seven fixture");
}

fn open_builtin(
    root: &std::path::Path,
    store: &TestProtectedStore,
) -> LocalCredentialAuthority<TestProtectedStore> {
    LocalCredentialAuthority::open(
        root,
        store.clone(),
        codewire_access::builtin_provider_catalog(),
    )
    .expect("open authority")
}

fn user_version(connection: &Connection) -> i64 {
    connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .expect("schema version")
}

/// Every workload-secret row, as the columns schema 7 has.
fn secret_rows(connection: &Connection) -> Vec<String> {
    let mut statement = connection
        .prepare(
            "SELECT id || scope_kind || scope_id || key || material_generation ||
                    protected_entry_id || material_state || updated_at_unix_ms
             FROM workload_secrets ORDER BY id",
        )
        .expect("prepare rows");
    statement
        .query_map([], |row| row.get::<_, String>(0))
        .expect("rows")
        .map(|row| row.expect("row"))
        .collect()
}

fn value(value: &str) -> ProtectedValue {
    ProtectedValue::from_slice(value.as_bytes()).expect("synthetic value")
}

fn schema_seven_store(root: &std::path::Path, store: &TestProtectedStore) -> uuid::Uuid {
    let authority = open_builtin(root, store);
    authority
        .set_user_workload_secret("DATABASE_URL", value("synthetic-user"))
        .expect("user secret");
    let project = authority
        .create_secret_project("walk")
        .expect("secret project");
    authority
        .set_project_workload_secret(project.id, "API_TOKEN", value("synthetic-project"))
        .expect("project secret");
    drop(authority);
    let connection = Connection::open(root.join(DATABASE_FILE)).expect("open database");
    downgrade_to_schema_seven(&connection);
    assert!(!has_secret_binding_columns(&connection).unwrap());
    project.id
}

#[test]
fn schema_seven_becomes_eight_with_every_secret_plain_and_kept() {
    let temp = TempDir::new().expect("temporary directory");
    let root = authority_root(&temp);
    let store = TestProtectedStore::new(ProtectedStorePersistence::OperatingSystem);
    let project = schema_seven_store(&root, &store);
    let connection = Connection::open(root.join(DATABASE_FILE)).expect("open database");
    let before = secret_rows(&connection);
    assert_eq!(before.len(), 2);
    drop(connection);

    for _ in 0..2 {
        let authority = open_builtin(&root, &store);
        let user = authority.list_user_workload_secrets().unwrap();
        assert_eq!(user.len(), 1);
        assert_eq!(
            (user[0].binding.clone(), user[0].binding_generation),
            (None, 0)
        );
        let listed = authority.list_project_workload_secrets(project).unwrap();
        assert_eq!(listed[0].key, "API_TOKEN");
        assert_eq!(listed[0].binding, None);
        drop(authority);
        let connection = Connection::open(root.join(DATABASE_FILE)).expect("open database");
        assert_eq!(user_version(&connection), DATABASE_SCHEMA_VERSION);
        assert!(has_secret_binding_columns(&connection).unwrap());
        assert_eq!(secret_rows(&connection), before);
        let unbound: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM workload_secrets
                 WHERE binding IS NULL AND binding_id IS NULL AND binding_generation = 0",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(unbound, 2);
    }

    // An upgraded secret binds as a new one does.
    let authority = open_builtin(&root, &store);
    let bound = authority
        .write_user_workload_secret(
            "DATABASE_URL",
            Some(value("synthetic-user")),
            BindingWrite::Bind(codewire_access::StoredBinding {
                hosts: vec!["db.example.com".into()],
                presentation: codewire_access::StoredPresentation::BasicUser,
                prefix: None,
                preset: None,
            }),
            true,
        )
        .expect("bind an upgraded secret");
    assert_eq!(bound.binding_generation, 1);
}

#[test]
fn a_schema_seven_upgrade_that_fails_leaves_schema_seven() {
    let temp = TempDir::new().expect("temporary directory");
    let root = authority_root(&temp);
    let store = TestProtectedStore::new(ProtectedStorePersistence::OperatingSystem);
    schema_seven_store(&root, &store);
    // A column already there fails the upgrade's second statement, after its
    // first has added one.
    let connection = Connection::open(root.join(DATABASE_FILE)).expect("open database");
    connection
        .execute_batch("ALTER TABLE workload_secrets ADD COLUMN binding_generation INTEGER NULL;")
        .expect("a stray column");
    let before = secret_rows(&connection);
    drop(connection);

    for _ in 0..2 {
        assert!(
            LocalCredentialAuthority::open(
                &root,
                store.clone(),
                codewire_access::builtin_provider_catalog(),
            )
            .is_err()
        );
        let connection = Connection::open(root.join(DATABASE_FILE)).expect("open database");
        assert_eq!(
            user_version(&connection),
            CREDENTIAL_NAMES_DATABASE_SCHEMA_VERSION
        );
        assert_eq!(secret_rows(&connection), before);
        let binding_id: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('workload_secrets') WHERE name = 'binding_id'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(binding_id, 0, "the upgrade's first column was rolled back");
    }
}

#[test]
fn schema_eight_without_the_binding_columns_is_refused() {
    let temp = TempDir::new().expect("temporary directory");
    let root = authority_root(&temp);
    let store = TestProtectedStore::new(ProtectedStorePersistence::OperatingSystem);
    schema_seven_store(&root, &store);
    let connection = Connection::open(root.join(DATABASE_FILE)).expect("open database");
    connection
        .pragma_update(None, "user_version", DATABASE_SCHEMA_VERSION)
        .expect("claim schema 8");
    drop(connection);
    assert!(matches!(
        LocalCredentialAuthority::open(&root, store, codewire_access::builtin_provider_catalog()),
        Err(LocalCredentialError::InvalidDatabase)
    ));
}
