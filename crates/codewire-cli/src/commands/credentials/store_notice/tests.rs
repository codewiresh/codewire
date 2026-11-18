use super::*;

#[test]
fn a_file_store_is_named_as_not_encrypted_by_cw() {
    assert_eq!(
        file_store_line(Path::new("/scratch/home/.codewire/credentials-v1")),
        "Store: files in /scratch/home/.codewire/credentials-v1/protected-v1, not encrypted by cw \
         (protected by file permissions and your disk encryption)"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn only_another_roots_keyring_write_is_warned() {
    let account = tempfile::tempdir().unwrap();
    let scratch = tempfile::tempdir().unwrap();
    let own = account.path().join(".codewire").join("credentials-v1");
    let other = scratch.path().join(".codewire").join("credentials-v1");
    let warning = keyring_warning(&other, ProtectedStoreBackend::SecretService, account.path());
    assert_eq!(
        warning.as_deref(),
        Some(
            format!(
                "Saving to your desktop keyring (Secret Service), not inside {}. Set \
                 local_credential_store = \"file\" to keep this root's credentials with it.",
                other.display()
            )
            .as_str()
        )
    );
    assert_eq!(
        keyring_warning(&own, ProtectedStoreBackend::SecretService, account.path()),
        None
    );
    assert_eq!(
        keyring_warning(&other, ProtectedStoreBackend::File, account.path()),
        None
    );
    // A link to the account's own `.codewire` is the account's own root.
    std::fs::create_dir(account.path().join(".codewire")).unwrap();
    let link = scratch.path().join("link");
    std::os::unix::fs::symlink(account.path().join(".codewire"), &link).unwrap();
    assert_eq!(
        keyring_warning(
            &link.join("credentials-v1"),
            ProtectedStoreBackend::SecretService,
            account.path()
        ),
        None
    );
}
