use super::*;

/// A delete's revoke (#6128) is refused before any change while a profile,
/// or a VM bound to an earlier revision, selects the credential. Once the
/// credential is free, it is revoked and moved out of `ready`, so no profile
/// can take it up; the provider's read sees that generation; and a delete
/// finishes it, as a retry after a failure would.
#[test]
fn a_revoke_for_delete_refuses_a_credential_in_use_and_marks_a_free_one() {
    let temp = TempDir::new().expect("temporary directory");
    let store = TestProtectedStore::new(ProtectedStorePersistence::OperatingSystem);
    let authority = LocalCredentialAuthority::open(&authority_root(&temp), store, catalog())
        .expect("open authority");
    let first = authority
        .add_credential(new_credential("first"), material(b"first-token"))
        .expect("add first credential");
    let second = authority
        .add_credential(new_credential("second"), material(b"second-token"))
        .expect("add second credential");
    let profile = authority
        .create_profile(
            AccessProfileName::parse("work").expect("profile name"),
            profile_entries(&first.metadata.id),
        )
        .expect("create profile");
    let unchanged = |authority: &LocalCredentialAuthority<TestProtectedStore>| {
        let record = authority
            .get_credential(&first.metadata.id)
            .expect("credential");
        assert_eq!(record.metadata.status, CredentialStatus::Active);
        assert_eq!(
            authority
                .executor_lease_material(&first.metadata.id, 1, CredentialStatus::Active)
                .expect("ready material")
                .expose_secret(),
            b"first-token"
        );
    };

    // The profile selects it.
    assert_eq!(
        authority.revoke_for_delete(&first.metadata.id).map(|_| ()),
        Err(LocalCredentialError::CredentialInUse)
    );
    unchanged(&authority);

    // Only a VM's earlier revision selects it.
    let environment_id = environment("env-one");
    authority
        .create_environment_access_binding(EnvironmentAccessBinding {
            environment_id: environment_id.clone(),
            profile_id: profile.profile.id.clone(),
            profile_revision: profile.profile.revision,
        })
        .expect("create binding");
    let updated = authority
        .update_profile(
            &profile.profile.id,
            profile.profile.revision,
            profile_entries(&second.metadata.id),
        )
        .expect("update profile");
    assert_eq!(
        authority.revoke_for_delete(&first.metadata.id).map(|_| ()),
        Err(LocalCredentialError::CredentialInUse)
    );
    unchanged(&authority);

    // Moved to the profile as it is now, the VM frees it.
    authority
        .replace_environment_access_binding(
            &environment_id,
            &profile.profile.id,
            profile.profile.revision,
            profile.profile.id.clone(),
            updated.profile.revision,
        )
        .expect("replace binding");
    let (record, generation, was_active) = authority
        .revoke_for_delete(&first.metadata.id)
        .expect("revoke for delete");
    assert_eq!(record.metadata.status, CredentialStatus::Revoked);
    assert!(was_active);
    assert_eq!(generation, Some(1));
    // No profile can take it up now.
    assert!(
        authority
            .update_profile(
                &profile.profile.id,
                updated.profile.revision,
                profile_entries(&first.metadata.id),
            )
            .is_err()
    );
    // The provider's read sees the delete's generation, and only that.
    assert_eq!(
        authority
            .deleting_lease_material(&first.metadata.id, 1)
            .expect("deleting material")
            .expose_secret(),
        b"first-token"
    );
    assert_eq!(
        authority
            .executor_lease_material(&first.metadata.id, 1, CredentialStatus::Revoked)
            .map(|_| ()),
        Err(LocalCredentialError::CredentialUnavailable)
    );
    // A second revoke for delete finds it already marked, and changes nothing.
    assert!(authority.revoke_for_delete(&first.metadata.id).is_err());
    authority
        .delete_credential(&first.metadata.id)
        .expect("delete finishes it");
    assert!(authority.get_credential(&first.metadata.id).is_err());
    assert_eq!(
        authority
            .get_credential(&second.metadata.id)
            .expect("second stays")
            .metadata
            .status,
        CredentialStatus::Active
    );
}
