use codewire_protected_store::EphemeralProtectedStore;

use super::*;
use crate::test_store::*;

/// The two connections are configured alike: the same open flags and the
/// same `configure_database`, so they differ only in the paths that use
/// them (#5413).
#[test]
fn both_connections_are_configured_alike() {
    let (_temp, authority) = authority(HeldStore::default());
    let pragmas = |connection: &Connection| {
        [
            "foreign_keys",
            "trusted_schema",
            "synchronous",
            "temp_store",
            "journal_mode",
            "busy_timeout",
        ]
        .map(|pragma| {
            connection
                .query_row(&format!("PRAGMA {pragma}"), [], |row| {
                    row.get::<_, rusqlite::types::Value>(0)
                })
                .unwrap()
        })
    };
    let metadata = pragmas(&authority.connection().unwrap());
    let material = pragmas(&authority.material_connection().unwrap());
    assert_eq!(metadata, material);
    assert_eq!(
        metadata[4],
        rusqlite::types::Value::Text("delete".to_owned())
    );
}

/// A store call inside an open transaction is refused before it reaches the
/// store, so the write lock is never held while a keyring waits (#5413).
#[test]
fn a_store_call_inside_a_transaction_is_refused() {
    let connection = Connection::open_in_memory().unwrap();
    let store = EphemeralProtectedStore::default();
    let entry = ProtectedEntryId::parse("local/credentials/test/1").unwrap();
    let value = ProtectedValue::from_slice(b"synthetic").unwrap();
    let material = MaterialStore::new(&connection, &store);
    material.put(&entry, &value).unwrap();

    let transaction = crate::immediate(&connection).unwrap();
    for refused in [
        material.get(&entry).map(|_| ()),
        material.put(&entry, &value),
        material.delete(&entry),
    ] {
        assert_eq!(refused, Err(LocalCredentialError::StoreCallInTransaction));
    }
    drop(transaction);
    assert!(material.get(&entry).unwrap().is_some());
}

/// While a refresh's admission waits on the store to check its next entry, a
/// revoke of the same credential and the listing answer at once. The revoke
/// wins: the reservation, admitted again in its transaction, finds the
/// credential withheld as revoked and reserves nothing (#5413, #5545).
#[test]
fn a_revoke_answers_while_a_refresh_admission_waits_on_the_store_and_wins() {
    use std::sync::Arc;

    let store = HeldStore::default();
    let (_temp, authority) = authority(store.clone());
    let work = authority.add_credential(codex("work"), material()).unwrap();
    let lease = bound_environment(&authority, &work.metadata.id);
    let grant = authority
        .admit_environment_credential_operation(&lease)
        .unwrap()
        .grant;
    store.hold_next(Call::Get);
    let beginning = {
        let authority = Arc::clone(&authority);
        let lease = lease.clone();
        std::thread::spawn(move || {
            authority.begin_environment_credential_refresh(
                uuid::Uuid::new_v4(),
                uuid::Uuid::new_v4(),
                uuid::Uuid::new_v4(),
                &lease,
                &grant,
                1,
            )
        })
    };
    store.wait_for_held();

    {
        let authority = Arc::clone(&authority);
        let id = work.metadata.id.clone();
        within(move || {
            authority.revoke_credential(&id).unwrap();
            authority.list_credentials().unwrap();
        });
    }
    assert!(store.is_held());
    store.release();
    let began = within(move || beginning.join().unwrap());
    assert!(
        matches!(
            began,
            Err(LocalCredentialError::CredentialWithheld(
                codewire_access::WithheldReason::Revoked
            ))
        ),
        "{:?}",
        began.err()
    );
    let marker = crate::load_credential_refresh_marker(
        &authority.material_connection().unwrap(),
        &work.metadata.id,
    )
    .unwrap();
    assert!(marker.is_none());
}

/// A refresh of `credential`, reserved and started for its environment: the
/// refresh's ids, the lease request and the grant it was admitted with.
fn started_refresh(
    authority: &crate::LocalCredentialAuthority<HeldStore>,
    credential: &codewire_access::CredentialId,
) -> (
    (uuid::Uuid, uuid::Uuid, uuid::Uuid),
    crate::CredentialOperationLeaseRequest,
    codewire_access::DerivedGrant,
) {
    let lease = bound_environment(authority, credential);
    let grant = authority
        .admit_environment_credential_operation(&lease)
        .unwrap()
        .grant;
    let ids = (
        uuid::Uuid::new_v4(),
        uuid::Uuid::new_v4(),
        uuid::Uuid::new_v4(),
    );
    assert!(matches!(
        authority.begin_environment_credential_refresh(ids.0, ids.1, ids.2, &lease, &grant, 1),
        Ok(crate::CredentialRefreshAdmission::Reserved(_))
    ));
    authority
        .start_environment_credential_refresh(ids.0, ids.1, ids.2)
        .unwrap();
    (ids, lease, grant)
}

/// While a refresh's promotion waits on the store to delete the retired
/// entry, another credential's revoke and the listing answer at once; the
/// promotion then completes (#5413).
#[test]
fn a_revoke_answers_while_a_refresh_promotion_waits_on_the_store() {
    use std::sync::Arc;

    let store = HeldStore::default();
    let (_temp, authority) = authority(store.clone());
    let work = authority.add_credential(codex("work"), material()).unwrap();
    let other = authority
        .add_credential(codex("other"), material())
        .unwrap();
    let (ids, _, _) = started_refresh(&authority, &work.metadata.id);
    store.hold_next(Call::Delete);
    let committing = {
        let authority = Arc::clone(&authority);
        std::thread::spawn(move || {
            authority.commit_environment_credential_refresh(
                ids.0,
                ids.1,
                ids.2,
                &ProtectedValue::from_slice(b"synthetic-new-sign-in").unwrap(),
            )
        })
    };
    store.wait_for_held();

    {
        let authority = Arc::clone(&authority);
        let id = other.metadata.id.clone();
        within(move || {
            authority.revoke_credential(&id).unwrap();
            authority.list_credentials().unwrap();
        });
    }
    assert!(store.is_held());
    store.release();
    let (record, generation) = within(move || committing.join().unwrap()).unwrap();
    assert_eq!(record.metadata.id, work.metadata.id);
    assert_eq!(generation, 2);
}

/// While a refresh's admission reconciles an earlier refresh whose channel
/// went away after its bundle was staged, and waits on the store to check
/// that entry, another credential's revoke and the listing answer at once.
/// The reconcile then promotes the staged bundle, and the admission reads
/// it as recovered (#5413).
#[test]
fn a_revoke_answers_while_a_refresh_admission_reconciles_on_the_store() {
    use std::sync::Arc;

    let store = HeldStore::default();
    let (_temp, authority) = authority(store.clone());
    let work = authority.add_credential(codex("work"), material()).unwrap();
    let other = authority
        .add_credential(codex("other"), material())
        .unwrap();
    let (ids, lease, grant) = started_refresh(&authority, &work.metadata.id);
    // The earlier refresh's bundle landed, then its channel went away.
    store
        .inner
        .put(
            &crate::protected_entry_id(&work.metadata.id, 2).unwrap(),
            &ProtectedValue::from_slice(b"synthetic-staged-sign-in").unwrap(),
        )
        .unwrap();
    authority
        .release_channel_credential_refreshes(ids.0)
        .unwrap();
    store.hold_next(Call::Get);
    let beginning = {
        let authority = Arc::clone(&authority);
        std::thread::spawn(move || {
            authority.begin_environment_credential_refresh(
                uuid::Uuid::new_v4(),
                uuid::Uuid::new_v4(),
                uuid::Uuid::new_v4(),
                &lease,
                &grant,
                1,
            )
        })
    };
    store.wait_for_held();

    {
        let authority = Arc::clone(&authority);
        let id = other.metadata.id.clone();
        within(move || {
            authority.revoke_credential(&id).unwrap();
            authority.list_credentials().unwrap();
        });
    }
    assert!(store.is_held());
    store.release();
    let began = within(move || beginning.join().unwrap());
    assert_eq!(began, Ok(crate::CredentialRefreshAdmission::Recovered));
    let after = authority.get_credential(&work.metadata.id).unwrap();
    assert_eq!(after.metadata.revocation_generation, 2);
}
