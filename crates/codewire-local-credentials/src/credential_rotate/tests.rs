//! A rotation's store calls hold no lock another request waits on, and a
//! revoke that lands meanwhile wins (#5413).

use std::sync::Arc;
use std::time::{Duration, Instant};

use tempfile::TempDir;

use super::*;
use crate::test_store::*;

fn next_material() -> ProtectedValue {
    ProtectedValue::from_slice(b"synthetic-rotated-token").unwrap()
}

/// Rotates `record` on a thread of its own, against the revision it read.
fn rotating(
    authority: &Arc<LocalCredentialAuthority<HeldStore>>,
    record: &CredentialRecord,
) -> std::thread::JoinHandle<Result<CredentialRecord, LocalCredentialError>> {
    let authority = Arc::clone(authority);
    let id = record.metadata.id.clone();
    let revision = record.metadata.revocation_generation;
    std::thread::spawn(move || {
        authority.rotate_credential_material(&id, revision, next_material(), None, None)
    })
}

/// While a rotation's write waits on the store, a revoke, a listing and a VM's
/// lease admission answer at once. The revoke wins: the rotation's guarded
/// update changes no row, so it rolls back its own next entry and journal
/// row, and the current entry stays.
#[test]
fn a_revoke_during_a_rotation_write_wins_and_the_rotation_rolls_back() {
    let store = HeldStore::default();
    let (_temp, authority) = authority(store.clone());
    let work = authority.add_credential(codex("work"), material()).unwrap();
    let lease = bound_environment(&authority, &work.metadata.id);
    store.hold_next(Call::Put);
    let rotation = rotating(&authority, &work);
    store.wait_for_held();

    let revoked = {
        let authority = Arc::clone(&authority);
        let id = work.metadata.id.clone();
        within(move || {
            authority.list_credentials().unwrap();
            authority
                .admit_environment_credential_operation(&lease)
                .unwrap();
            authority.revoke_credential(&id).unwrap()
        })
    };
    assert!(store.put_is_held());
    store.release();

    assert_eq!(
        within(move || rotation.join().unwrap()).unwrap_err(),
        LocalCredentialError::StaleCredentialRevision
    );
    let after = authority.get_credential(&work.metadata.id).unwrap();
    assert_eq!(after.metadata, revoked.metadata);
    assert!(!after.protected_store_cleanup_pending);
    assert!(store.entries(&protected_entry_id(&work.metadata.id, 1).unwrap()));
    assert!(!store.entries(&protected_entry_id(&work.metadata.id, 2).unwrap()));
}

/// A rollback whose delete fails keeps the journal row, the only record of
/// the entry it could not delete, and start-up recovery deletes the entry.
#[test]
fn a_rollback_that_cannot_delete_keeps_its_journal_for_recovery() {
    let store = HeldStore::default();
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("authority");
    let open = || {
        Arc::new(
            LocalCredentialAuthority::open(
                &root,
                store.clone(),
                codewire_access::builtin_provider_catalog(),
            )
            .unwrap(),
        )
    };
    let authority = open();
    let work = authority.add_credential(codex("work"), material()).unwrap();
    store.hold_next(Call::Put);
    let rotation = rotating(&authority, &work);
    store.wait_for_held();
    authority.revoke_credential(&work.metadata.id).unwrap();
    store.refuse(false, true);
    store.release();

    assert_eq!(
        within(move || rotation.join().unwrap()).unwrap_err(),
        LocalCredentialError::StaleCredentialRevision
    );
    let next = protected_entry_id(&work.metadata.id, 2).unwrap();
    assert!(store.entries(&next));
    assert!(
        authority
            .get_credential(&work.metadata.id)
            .unwrap()
            .protected_store_cleanup_pending
    );

    drop(authority);
    store.refuse(false, false);
    let reopened = open();
    assert!(!store.entries(&next));
    assert!(
        !reopened
            .get_credential(&work.metadata.id)
            .unwrap()
            .protected_store_cleanup_pending
    );
}

/// A rotation that finds its credential no longer `ready`, as a deletion
/// leaves it, rolls back and answers unavailable. Through the API a deletion
/// waits for the rotation instead, so the row is moved on a raw connection
/// here to reach that branch (#5413).
#[test]
fn a_rotation_that_finds_its_credential_leaving_rolls_back_as_unavailable() {
    let store = HeldStore::default();
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("authority");
    let authority = Arc::new(
        LocalCredentialAuthority::open(
            &root,
            store.clone(),
            codewire_access::builtin_provider_catalog(),
        )
        .unwrap(),
    );
    let work = authority.add_credential(codex("work"), material()).unwrap();
    store.hold_next(Call::Put);
    let rotation = rotating(&authority, &work);
    store.wait_for_held();
    let raw = Connection::open(root.join(DATABASE_FILE)).unwrap();
    raw.execute(
        "UPDATE credentials SET material_state = 'pending_delete' WHERE id = ?1",
        [work.metadata.id.as_str()],
    )
    .unwrap();
    store.release();

    assert_eq!(
        within(move || rotation.join().unwrap()).unwrap_err(),
        LocalCredentialError::CredentialUnavailable
    );
    assert!(!store.entries(&protected_entry_id(&work.metadata.id, 2).unwrap()));
    let journal: i64 = raw
        .query_row(
            "SELECT COUNT(*) FROM protected_entry_journal WHERE credential_id = ?1",
            [work.metadata.id.as_str()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(journal, 0);
}

/// A deletion waits behind a rotation of the same credential, since both
/// change its material, and then deletes it; material changes queue behind
/// one another's store calls, never a metadata request.
#[test]
fn a_deletion_waits_for_a_rotation_and_then_deletes() {
    let store = HeldStore::default();
    let (_temp, authority) = authority(store.clone());
    let work = authority.add_credential(codex("work"), material()).unwrap();
    store.hold_next(Call::Put);
    let rotation = rotating(&authority, &work);
    store.wait_for_held();
    let deletion = {
        let authority = Arc::clone(&authority);
        let id = work.metadata.id.clone();
        std::thread::spawn(move || authority.delete_credential(&id))
    };
    std::thread::sleep(Duration::from_millis(200));
    assert!(!deletion.is_finished());
    assert_eq!(
        {
            let authority = Arc::clone(&authority);
            within(move || authority.list_credentials().unwrap().len())
        },
        1
    );
    assert!(store.is_held());

    store.release();
    within(move || rotation.join().unwrap()).unwrap();
    within(move || deletion.join().unwrap()).unwrap();
    assert!(authority.list_credentials().unwrap().is_empty());
    assert!(!store.entries(&protected_entry_id(&work.metadata.id, 2).unwrap()));
}

/// While a deletion waits on the store to delete its material, another
/// credential's revoke and the listing answer at once, and the credential
/// being deleted is no longer listed.
#[test]
fn a_revoke_answers_while_a_deletion_waits_on_the_store() {
    let store = HeldStore::default();
    let (_temp, authority) = authority(store.clone());
    let work = authority.add_credential(codex("work"), material()).unwrap();
    let other = authority
        .add_credential(codex("other"), material())
        .unwrap();
    store.hold_next(Call::Delete);
    let deletion = {
        let authority = Arc::clone(&authority);
        let id = work.metadata.id.clone();
        std::thread::spawn(move || authority.delete_credential(&id))
    };
    store.wait_for_held();

    let listed = {
        let authority = Arc::clone(&authority);
        let id = other.metadata.id.clone();
        within(move || {
            authority.revoke_credential(&id).unwrap();
            authority.list_credentials().unwrap()
        })
    };
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].metadata.id, other.metadata.id);
    assert!(store.is_held());
    store.release();
    within(move || deletion.join().unwrap()).unwrap();
}

/// Another connection's write does not hold up a VM's lease admission, which
/// only reads. A database locked exclusively past the busy timeout is a failed
/// step: admission refuses in bounded time, and a rotation whose publication
/// cannot begin rolls its next entry back.
#[test]
fn a_busy_database_refuses_admission_and_rolls_a_rotation_back() {
    let store = HeldStore::default();
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("authority");
    let authority = Arc::new(
        LocalCredentialAuthority::open(
            &root,
            store.clone(),
            codewire_access::builtin_provider_catalog(),
        )
        .unwrap(),
    );
    let work = authority.add_credential(codex("work"), material()).unwrap();
    let lease = bound_environment(&authority, &work.metadata.id);
    store.hold_next(Call::Put);
    let rotation = rotating(&authority, &work);
    store.wait_for_held();

    let holder = Connection::open(root.join(DATABASE_FILE)).unwrap();
    holder.execute_batch("BEGIN IMMEDIATE").unwrap();
    {
        let authority = Arc::clone(&authority);
        let lease = lease.clone();
        within(move || authority.admit_environment_credential_operation(&lease)).unwrap();
    }
    holder.execute_batch("ROLLBACK; BEGIN EXCLUSIVE").unwrap();
    let started = Instant::now();
    let refused = {
        let authority = Arc::clone(&authority);
        let (answer, answered) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = answer.send(authority.admit_environment_credential_operation(&lease));
        });
        answered.recv_timeout(Duration::from_secs(30)).unwrap()
    };
    assert_eq!(
        refused.unwrap_err(),
        LocalCredentialError::DatabaseUnavailable
    );
    assert!(started.elapsed() < Duration::from_secs(30));

    store.release();
    let rotated = {
        let (answer, answered) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = answer.send(rotation.join().unwrap());
        });
        answered.recv_timeout(Duration::from_secs(30)).unwrap()
    };
    assert_eq!(
        rotated.unwrap_err(),
        LocalCredentialError::DatabaseUnavailable
    );
    holder.execute_batch("ROLLBACK").unwrap();
    let next = protected_entry_id(&work.metadata.id, 2).unwrap();
    assert!(!store.entries(&next));
    let after = authority.get_credential(&work.metadata.id).unwrap();
    assert_eq!(
        after.metadata.revocation_generation,
        work.metadata.revocation_generation
    );
    assert!(store.entries(&protected_entry_id(&work.metadata.id, 1).unwrap()));
}

/// Metadata writes and rotations on the two connections never meet
/// SQLITE_BUSY: every write transaction begins IMMEDIATE, so each waits its
/// turn within the busy timeout instead of failing an upgrade at once.
#[test]
fn writes_on_both_connections_wait_their_turn() {
    let (_temp, authority) = authority(HeldStore::default());
    let work = authority.add_credential(codex("work"), material()).unwrap();
    let other = authority
        .add_credential(codex("other"), material())
        .unwrap();
    let renaming = {
        let authority = Arc::clone(&authority);
        let id = other.metadata.id.clone();
        std::thread::spawn(move || {
            for round in 0..40 {
                authority
                    .rename_credential(&id, format!("other-{round}"))
                    .unwrap();
            }
        })
    };
    let mut current = work;
    for _ in 0..20 {
        current = authority
            .rotate_credential_material(
                &current.metadata.id,
                current.metadata.revocation_generation,
                next_material(),
                None,
                None,
            )
            .unwrap();
    }
    renaming.join().unwrap();
}
