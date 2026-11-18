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
