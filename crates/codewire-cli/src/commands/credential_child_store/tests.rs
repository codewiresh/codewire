use std::path::PathBuf;

use clap::Parser as _;

use super::*;

#[derive(clap::Parser)]
struct Harness {
    #[command(flatten)]
    store: ChildStoreArgs,
}

fn parsed(store: &[&str]) -> anyhow::Result<ChildStore> {
    let mut argv = vec!["child"];
    argv.extend_from_slice(store);
    ChildStore::from_args(&Harness::try_parse_from(argv)?.store)
}

fn round_trip(store: &AuthorityProtectedStore) -> ChildStore {
    let arguments = child_store_arguments(store, Path::new("/private/root")).unwrap();
    let mut argv = vec![OsString::from("child")];
    argv.extend(arguments);
    ChildStore::from_args(&Harness::try_parse_from(argv).unwrap().store).unwrap()
}

#[test]
fn a_linux_child_is_told_its_store_and_reads_exactly_that_one() {
    let secret_service = AuthorityProtectedStore {
        backend: ProtectedStoreBackend::SecretService,
        keychain: None,
    };
    assert_eq!(round_trip(&secret_service), ChildStore::SecretService);
    assert_eq!(ChildStore::SecretService.file_directory(), None);
    let file = AuthorityProtectedStore {
        backend: ProtectedStoreBackend::File,
        keychain: None,
    };
    let directory = PathBuf::from("/private/root/protected-v1");
    assert_eq!(
        round_trip(&file),
        ChildStore::File {
            directory: directory.clone()
        }
    );
    assert_eq!(
        round_trip(&file).file_directory(),
        Some(directory.as_path())
    );
}

#[test]
fn a_linux_child_refuses_any_other_store_description() {
    for refused in [
        &[][..],
        &["--protected-store", "keychain"],
        &["--protected-store", "file"],
        &[
            "--protected-store",
            "file",
            "--protected-store-directory",
            "root/protected-v1",
        ],
        &[
            "--protected-store",
            "file",
            "--protected-store-directory",
            "/private/root/other",
        ],
        &[
            "--protected-store",
            "file",
            "--protected-store-directory",
            "/private/root/../protected-v1",
        ],
        &[
            "--protected-store",
            "secret-service",
            "--protected-store-directory",
            "/private/root/protected-v1",
        ],
    ] {
        assert!(parsed(refused).is_err(), "{refused:?}");
    }
}

#[test]
fn a_childs_store_refuses_every_write() {
    let root = tempfile::tempdir().unwrap();
    let store = ChildStore::File {
        directory: root.path().join(FILE_STORE_DIRECTORY),
    }
    .open()
    .unwrap();
    let id = ProtectedEntryId::parse("local/credentials/synthetic/material-v1").unwrap();
    let value = ProtectedValue::new(b"synthetic".to_vec()).unwrap();
    assert_eq!(
        store.put(&id, &value),
        Err(ProtectedStoreError::AccessDenied)
    );
    assert_eq!(store.delete(&id), Err(ProtectedStoreError::AccessDenied));
    assert!(!root.path().join(FILE_STORE_DIRECTORY).exists());
}

/// A `file` child only reads `protected-v1`, as the broker's Landlock domain
/// does, and its refresh still lands: the authority stages the bundle it sends
/// in Commit (#5539).
#[tokio::test]
async fn a_file_childs_refresh_is_staged_by_the_authority() {
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join(FILE_STORE_DIRECTORY);
    let authority_store =
        SelectedProtectedStore::open(ProtectedStoreBackend::File, &directory, None).unwrap();
    let child = ChildStore::File {
        directory: directory.clone(),
    }
    .open()
    .unwrap();
    let refreshed = codewire_local_credentials::refresh_testing::refresh_through(
        &root.path().join("authority"),
        authority_store,
        child.clone(),
        b"synthetic-rotated-oauth-bundle",
    )
    .await
    .unwrap();
    assert_eq!(refreshed.material_generation, 2);
    assert_eq!(refreshed.material, b"synthetic-rotated-oauth-bundle");
    let next = ProtectedEntryId::parse("local/credentials/synthetic/material-v3").unwrap();
    let value = ProtectedValue::new(b"synthetic".to_vec()).unwrap();
    assert_eq!(
        child.put(&next, &value),
        Err(ProtectedStoreError::AccessDenied)
    );
    assert_eq!(child.delete(&next), Err(ProtectedStoreError::AccessDenied));
}

/// A real refresh commit with the broker's opened Secret Service store: the
/// authority stages and promotes the bundle, and the child's own `put` and
/// `delete` still refuse every entry (#5539). It needs a private
/// Secret Service, never the host's, so it runs only under
/// `scripts/ci/tests/test-child-store-secret-service.sh`.
#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "needs a private Secret Service: scripts/ci/tests/test-child-store-secret-service.sh"]
async fn a_secret_service_childs_refresh_is_staged_by_the_authority() {
    let private = std::env::var("CODEWIRE_PRIVATE_SECRET_SERVICE_BUS").unwrap_or_default();
    assert!(
        !private.is_empty()
            && std::env::var("DBUS_SESSION_BUS_ADDRESS").as_deref() == Ok(private.as_str()),
        "run this only through its script, on a private session bus"
    );
    let root = tempfile::tempdir().unwrap();
    let authority_store =
        SelectedProtectedStore::open(ProtectedStoreBackend::SecretService, Path::new("/"), None)
            .unwrap();
    let child = ChildStore::SecretService.open().unwrap();
    let refreshed = codewire_local_credentials::refresh_testing::refresh_through(
        &root.path().join("authority"),
        authority_store,
        child.clone(),
        b"synthetic-rotated-oauth-bundle",
    )
    .await
    .unwrap();
    assert_eq!(refreshed.material_generation, 2);
    assert_eq!(refreshed.material, b"synthetic-rotated-oauth-bundle");
    let other = ProtectedEntryId::parse("local/credentials/synthetic/material-v3").unwrap();
    let value = ProtectedValue::new(b"synthetic".to_vec()).unwrap();
    assert_eq!(
        child.put(&other, &value),
        Err(ProtectedStoreError::AccessDenied)
    );
    assert_eq!(child.delete(&other), Err(ProtectedStoreError::AccessDenied));
}
