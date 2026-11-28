//! A local credential's name is unique per provider, ignoring case, and a
//! schema 6 store becomes schema 7 keeping every row (#4928).

use super::*;

/// The `credentials` table exactly as schema 6 created it: the name unique
/// across providers.
const SCHEMA_SIX_CREDENTIALS: &str = "
    CREATE TABLE credentials_schema_6(
      id TEXT PRIMARY KEY NOT NULL,
      provider TEXT NOT NULL,
      authentication_kind TEXT NOT NULL,
      display_name TEXT NOT NULL COLLATE NOCASE UNIQUE,
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
      updated_at_unix_ms INTEGER NOT NULL CHECK(updated_at_unix_ms >= created_at_unix_ms)
    ) STRICT;";

/// Give a current store schema 6's `credentials` table, rows unchanged.
pub(super) fn downgrade_to_schema_six(connection: &Connection) {
    super::secret_bindings::downgrade_to_schema_seven(connection);
    connection
        .pragma_update(None, "foreign_keys", false)
        .expect("foreign keys off for the fixture");
    connection
        .execute_batch(&format!(
            "BEGIN;
             {SCHEMA_SIX_CREDENTIALS}
             INSERT INTO credentials_schema_6 SELECT
               id, provider, authentication_kind, display_name, account_hint,
               ssh_public_key_openssh, ssh_public_key_fingerprint, status, expires_at_unix,
               revocation_generation, material_generation, protected_entry_id,
               store_persistence, material_state, created_at_unix_ms, updated_at_unix_ms
             FROM credentials;
             DROP TABLE credentials;
             ALTER TABLE credentials_schema_6 RENAME TO credentials;
             {GITHUB_SINGLETON_INDEX}
             PRAGMA user_version = 6;
             COMMIT;"
        ))
        .expect("construct exact schema-six fixture");
}

fn api_key(provider_id: &str, name: &str) -> NewCredential {
    NewCredential {
        provider: provider(provider_id),
        authentication_kind: CredentialAuthKind::ApiKey,
        display_name: name.to_owned(),
        account_hint: None,
        expires_at_unix: None,
    }
}

fn sign_in(provider_id: &str, name: &str) -> NewCredential {
    let authentication_kind = match provider_id {
        "anthropic" => CredentialAuthKind::ClaudeSignIn,
        _ => CredentialAuthKind::OAuth,
    };
    NewCredential {
        authentication_kind,
        ..api_key(provider_id, name)
    }
}

fn open_builtin(
    root: &Path,
    store: &TestProtectedStore,
) -> LocalCredentialAuthority<TestProtectedStore> {
    LocalCredentialAuthority::open(
        root,
        store.clone(),
        codewire_access::builtin_provider_catalog(),
    )
    .expect("open authority")
}

fn count(connection: &Connection, table: &str) -> i64 {
    connection
        .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
            row.get(0)
        })
        .expect("count rows")
}

fn user_version(connection: &Connection) -> i64 {
    connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .expect("schema version")
}

#[test]
fn one_name_labels_a_credential_of_each_provider_and_a_bare_name_they_share_is_refused() {
    let temp = TempDir::new().expect("temporary directory");
    let store = TestProtectedStore::new(ProtectedStorePersistence::OperatingSystem);
    let authority = open_builtin(&authority_root(&temp), &store);
    let claude = authority
        .add_credential(
            sign_in("anthropic", "n@example.com"),
            material(b"synthetic-claude"),
        )
        .expect("Claude sign-in");
    let codex = authority
        .add_credential(
            sign_in("openai", "N@Example.com"),
            material(b"synthetic-codex"),
        )
        .expect("a Codex sign-in may share the Claude sign-in's name");
    let github = authority
        .add_credential(
            sign_in("github", "n@EXAMPLE.com"),
            material(b"synthetic-github"),
        )
        .expect("GitHub may share it too");

    // Within one provider a name stays unique, ignoring case and kind: a
    // Claude sign-in and an Anthropic API key can't share one.
    for taken in [
        api_key("anthropic", "N@EXAMPLE.COM"),
        api_key("openai", "n@example.com"),
    ] {
        assert_eq!(
            authority.add_credential(taken, material(b"synthetic-other")),
            Err(LocalCredentialError::AlreadyExists)
        );
    }

    // The providers are sorted, and nothing names a credential's ID.
    let ambiguous = authority.resolve_credential("n@example.com", None);
    assert_eq!(
        ambiguous,
        Err(LocalCredentialError::CredentialNameAmbiguous {
            providers: vec![
                provider("anthropic"),
                provider("github"),
                provider("openai")
            ],
        })
    );
    for (provider_id, expected) in [
        ("anthropic", &claude),
        ("openai", &codex),
        ("github", &github),
    ] {
        let found = authority
            .resolve_credential("N@example.COM", Some(&provider(provider_id)))
            .expect("a provider names one credential");
        assert_eq!(found.metadata.id, expected.metadata.id);
    }
    assert_eq!(
        authority.resolve_credential("n@example.com", Some(&provider("ssh"))),
        Err(LocalCredentialError::CredentialNotFound)
    );

    // A name only one provider holds needs no provider.
    let spare = authority
        .add_credential(api_key("openai", "spare"), material(b"synthetic-spare"))
        .expect("spare key");
    assert_eq!(
        authority
            .resolve_credential("SPARE", None)
            .expect("a bare unique name")
            .metadata
            .id,
        spare.metadata.id
    );
    // Renaming follows the same rule, and a taken name's refusal says only
    // that it exists.
    assert_eq!(
        authority.rename_credential(&spare.metadata.id, "n@example.com".into()),
        Err(LocalCredentialError::AlreadyExists)
    );
    let anthropic_key = authority
        .add_credential(
            api_key("anthropic", "anthropic-key"),
            material(b"synthetic-key"),
        )
        .expect("Anthropic API key");
    let renamed = authority
        .rename_credential(&anthropic_key.metadata.id, "SPARE".into())
        .expect("another provider's name is free in this one");
    assert_eq!(renamed.metadata.display_name, "SPARE");
    assert_eq!(renamed.metadata.id, anthropic_key.metadata.id);
}

#[test]
fn a_new_name_may_not_start_with_a_provider_and_slash_but_an_old_one_keeps_working() {
    let temp = TempDir::new().expect("temporary directory");
    let store = TestProtectedStore::new(ProtectedStorePersistence::OperatingSystem);
    let authority = open_builtin(&authority_root(&temp), &store);
    for name in [
        "github/work",
        "GitHub/work",
        "anthropic/n@example.com",
        "ssh/",
    ] {
        assert_eq!(
            authority.add_credential(api_key("openai", name), material(b"synthetic")),
            Err(LocalCredentialError::CredentialNameReservesProvider),
            "{name}"
        );
    }
    assert_eq!(store.entry_count(), 0, "a refused name stores nothing");
    let other = authority
        .add_credential(api_key("openai", "gitlab/work"), material(b"synthetic"))
        .expect("only the four provider ids are reserved");
    assert_eq!(
        authority.rename_credential(&other.metadata.id, "openai/work".into()),
        Err(LocalCredentialError::CredentialNameReservesProvider)
    );

    // A literal `github/work` an older Codewire saved, beside the GitHub
    // credential named `work` that `github/work` now also reads as.
    let legacy = authority
        .add_credential(api_key("openai", "legacy"), material(b"synthetic-legacy"))
        .expect("legacy key");
    authority
        .connection()
        .expect("credential database")
        .execute(
            "UPDATE credentials SET display_name = 'github/work' WHERE id = ?1",
            [legacy.metadata.id.as_str()],
        )
        .expect("give the key an older Codewire's name");
    let github = authority
        .add_credential(sign_in("github", "work"), material(b"synthetic-github"))
        .expect("GitHub credential named work");
    assert_eq!(
        authority
            .resolve_credential("github/work", None)
            .expect("the literal name")
            .metadata
            .id,
        legacy.metadata.id
    );
    assert_eq!(
        authority
            .resolve_credential("work", Some(&provider("github")))
            .expect("the provider reading")
            .metadata
            .id,
        github.metadata.id
    );
    // The old name keeps working: renaming to it again changes nothing, and
    // it can be renamed away, but not back.
    authority
        .rename_credential(&legacy.metadata.id, "github/work".into())
        .expect("an existing name stays");
    authority
        .rename_credential(&legacy.metadata.id, "legacy".into())
        .expect("rename away");
    assert_eq!(
        authority.rename_credential(&legacy.metadata.id, "github/work".into()),
        Err(LocalCredentialError::CredentialNameReservesProvider)
    );
}

/// A schema 6 store: two credentials, one GitHub connection, a profile that
/// selects one, the default profile, and a journal row on a credential.
fn schema_six_store(root: &Path, store: &TestProtectedStore) -> CredentialRecord {
    let authority = open_builtin(root, store);
    let codex = authority
        .add_credential(sign_in("openai", "work"), material(b"synthetic-codex"))
        .expect("Codex sign-in");
    authority
        .add_credential(api_key("anthropic", "personal"), material(b"synthetic-key"))
        .expect("Anthropic API key");
    authority
        .add_credential(sign_in("github", "github"), material(b"synthetic-github"))
        .expect("GitHub connection");
    authority
        .create_profile(
            AccessProfileName::parse("work").expect("profile name"),
            BTreeMap::from([(CapabilitySlot::codex(), codex.metadata.id.clone())]),
        )
        .expect("profile");
    drop(authority);
    let connection = Connection::open(root.join(DATABASE_FILE)).expect("open database");
    downgrade_to_schema_six(&connection);
    // An interrupted rotation's journal: the next generation's entry is to
    // be rolled back. The open after the upgrade reconciles it.
    let staged = protected_entry_id(&codex.metadata.id, 2).expect("staged entry");
    connection
        .execute(
            "INSERT INTO protected_entry_journal(
               credential_id, operation, protected_entry_id, created_at_unix_ms)
             VALUES (?1, 'rollback_write', ?2, 0)",
            params![codex.metadata.id.as_str(), staged.expose_reference()],
        )
        .expect("journal row");
    codex
}

/// Every row of the tables a rebuild of `credentials` could touch.
fn snapshot(connection: &Connection) -> Vec<String> {
    let mut rows = Vec::new();
    for query in [
        "SELECT id || provider || authentication_kind || display_name || status ||
                material_generation || protected_entry_id || material_state
         FROM credentials ORDER BY id",
        "SELECT credential_id || operation || protected_entry_id FROM protected_entry_journal",
        "SELECT profile_id || revision || capability_slot || credential_id FROM profile_entries",
        "SELECT owner_id || profile_id FROM default_profiles",
    ] {
        let mut statement = connection.prepare(query).expect("prepare snapshot");
        rows.extend(
            statement
                .query_map([], |row| row.get::<_, String>(0))
                .expect("snapshot rows")
                .map(|row| row.expect("snapshot row")),
        );
    }
    rows
}

#[test]
fn schema_six_becomes_seven_keeping_every_row_and_journal_entry() {
    let temp = TempDir::new().expect("temporary directory");
    let root = authority_root(&temp);
    let store = TestProtectedStore::new(ProtectedStorePersistence::OperatingSystem);
    schema_six_store(&root, &store);

    // The upgrade alone, so the journal row is still there to compare: the
    // authority's open reconciles it afterwards.
    let connection = Connection::open(root.join(DATABASE_FILE)).expect("open database");
    let before = snapshot(&connection);
    assert_eq!(count(&connection, "protected_entry_journal"), 1);
    assert!(!credential_names_unique_per_provider(&connection).unwrap());
    configure_database(&connection).expect("configure");
    upgrade_schema(&connection).expect("upgrade to schema 7");
    assert_eq!(user_version(&connection), DATABASE_SCHEMA_VERSION);
    assert_eq!(snapshot(&connection), before);
    assert!(credential_names_unique_per_provider(&connection).unwrap());
    let foreign_keys: bool = connection
        .pragma_query_value(None, "foreign_keys", |row| row.get(0))
        .unwrap();
    assert!(foreign_keys, "foreign keys are back on after the rebuild");
    validate_database(&connection).expect("a consistent database");
    drop(connection);

    let authority = open_builtin(&root, &store);
    assert_eq!(authority.list_credentials().unwrap().len(), 3);
    // GitHub stays one connection per store.
    assert_eq!(
        authority.add_credential(sign_in("github", "second"), material(b"synthetic")),
        Err(LocalCredentialError::GitHubAlreadyConnected)
    );
    authority
        .add_credential(sign_in("anthropic", "work"), material(b"synthetic-claude"))
        .expect("after the upgrade a name may repeat across providers");
    assert_eq!(
        authority.add_credential(api_key("openai", "WORK"), material(b"synthetic")),
        Err(LocalCredentialError::AlreadyExists)
    );
}

#[test]
fn a_schema_six_upgrade_that_fails_at_its_last_step_leaves_schema_six() {
    let temp = TempDir::new().expect("temporary directory");
    let root = authority_root(&temp);
    let store = TestProtectedStore::new(ProtectedStorePersistence::OperatingSystem);
    schema_six_store(&root, &store);
    // A journal row whose credential is gone fails the rebuild's foreign key
    // check, after it has copied, dropped and renamed.
    let connection = Connection::open(root.join(DATABASE_FILE)).expect("open database");
    connection
        .pragma_update(None, "foreign_keys", false)
        .expect("foreign keys off for the fixture");
    connection
        .execute(
            "INSERT INTO protected_entry_journal(
               credential_id, operation, protected_entry_id, created_at_unix_ms)
             VALUES ('gone', 'delete_retired', 'synthetic-orphan-entry', 0)",
            [],
        )
        .expect("orphan journal row");
    let before = snapshot(&connection);
    drop(connection);

    for _ in 0..2 {
        assert!(matches!(
            LocalCredentialAuthority::open(
                &root,
                store.clone(),
                codewire_access::builtin_provider_catalog(),
            ),
            Err(LocalCredentialError::InvalidDatabase)
        ));
        let connection = Connection::open(root.join(DATABASE_FILE)).expect("open database");
        assert_eq!(
            user_version(&connection),
            DEFAULT_PROFILE_DATABASE_SCHEMA_VERSION
        );
        assert_eq!(snapshot(&connection), before);
        assert!(!credential_names_unique_per_provider(&connection).unwrap());
        assert_eq!(
            count(
                &connection,
                "sqlite_schema WHERE name = 'credentials_schema_7'"
            ),
            0
        );
    }
}

#[test]
fn schema_seven_without_the_per_provider_constraint_is_refused() {
    let temp = TempDir::new().expect("temporary directory");
    let root = authority_root(&temp);
    let store = TestProtectedStore::new(ProtectedStorePersistence::OperatingSystem);
    drop(open_builtin(&root, &store));
    let connection = Connection::open(root.join(DATABASE_FILE)).expect("open database");
    downgrade_to_schema_six(&connection);
    // Schema 8's columns, and its version, over schema 6's name constraint.
    crate::workload_secret::upgrade_secret_bindings_schema(&connection)
        .expect("claim the current schema");
    drop(connection);
    assert!(matches!(
        LocalCredentialAuthority::open(&root, store, codewire_access::builtin_provider_catalog()),
        Err(LocalCredentialError::InvalidDatabase)
    ));
}
