//! An add's store write holds no lock another request waits on, and ends in
//! exactly one outcome (#5413).

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use codewire_protected_store::ProtectedStoreError;

use super::*;
use crate::test_store::*;

/// While one add's write waits on the store, another command's listing and
/// a running VM's lease admission answer at once; the add then publishes.
#[test]
fn listing_and_lease_admission_answer_while_an_add_waits_on_the_store() {
    let store = HeldStore::default();
    let (_temp, authority) = authority(store.clone());
    let work = authority.add_credential(codex("work"), material()).unwrap();
    let lease = bound_environment(&authority, &work.metadata.id);

    store.hold_next_put();
    let adding = {
        let authority = Arc::clone(&authority);
        std::thread::spawn(move || authority.add_credential(codex("later"), material()))
    };
    store.wait_for_held_put();

    let listed = {
        let authority = Arc::clone(&authority);
        let id = work.metadata.id.clone();
        within(move || {
            authority
                .admit_environment_credential_operation(&lease)
                .unwrap();
            authority.get_credential(&id).unwrap();
            authority.list_credentials().unwrap()
        })
    };
    // They answered while the write was still waiting on the store.
    assert!(store.put_is_held());
    // The add being written is pending, so nothing lists it yet.
    assert_eq!(
        listed
            .iter()
            .map(|record| record.metadata.display_name.as_str())
            .collect::<Vec<_>>(),
        ["work"]
    );

    store.release();
    let later = within(move || adding.join().unwrap()).unwrap();
    assert!(store.entries(&protected_entry_id(&later.metadata.id, 1).unwrap()));
    assert_eq!(authority.list_credentials().unwrap().len(), 2);
}

/// An add whose request lapsed during the write, its deadline passed or the
/// authority shutting down, is not published: its material and its row are
/// gone, and the name is free again.
#[test]
fn an_add_whose_checks_fail_at_publication_is_not_published() {
    let store = HeldStore::default();
    let (_temp, authority) = authority(store.clone());
    let checks = AtomicUsize::new(0);
    let lapsing = || match checks.fetch_add(1, Ordering::SeqCst) {
        0 => Ok(()),
        _ => Err(LocalCredentialError::SshEnrollmentClosed),
    };

    let refused = authority
        .add_credential_inner(codex("work"), material(), None, lapsing)
        .unwrap_err();

    assert_eq!(refused, LocalCredentialError::SshEnrollmentClosed);
    assert_eq!(checks.load(Ordering::SeqCst), 2);
    assert_eq!(rows(&authority), 0);
    let written = store.written.lock().unwrap().clone();
    assert_eq!(written.len(), 1);
    assert!(!store.entries(&written[0]));
    authority.add_credential(codex("work"), material()).unwrap();
}

/// A second add of a name another add is still writing is refused as in
/// progress at once, instead of waiting behind it.
#[test]
fn an_add_of_a_name_still_being_written_is_refused_as_in_progress() {
    let store = HeldStore::default();
    let (_temp, authority) = authority(store.clone());
    store.hold_next_put();
    let adding = {
        let authority = Arc::clone(&authority);
        std::thread::spawn(move || authority.add_credential(codex("work"), material()))
    };
    store.wait_for_held_put();

    let refused = {
        let authority = Arc::clone(&authority);
        within(move || authority.add_credential(codex("WORK"), material()))
    }
    .unwrap_err();
    assert_eq!(refused, LocalCredentialError::CredentialAddInProgress);
    // Refused while the other add's write was still waiting on the store.
    assert!(store.put_is_held());

    store.release();
    within(move || adding.join().unwrap()).unwrap();
    assert_eq!(
        authority
            .add_credential(codex("work"), material())
            .unwrap_err(),
        LocalCredentialError::AlreadyExists
    );
}

/// A pending row no add is writing, left when the store refused both the
/// write and its cleanup (#5271), is refused as unfinished, never as one to
/// wait for: only start-up recovery removes it.
#[test]
fn a_pending_row_nothing_is_writing_is_refused_as_unfinished() {
    let store = HeldStore::default();
    let (_temp, authority) = authority(store.clone());
    store.refuse(true, true);
    assert_eq!(
        authority
            .add_credential(codex("work"), material())
            .unwrap_err(),
        LocalCredentialError::ProtectedStore(ProtectedStoreError::TimedOut)
    );
    assert_eq!(rows(&authority), 1);
    store.refuse(false, false);

    assert_eq!(
        authority
            .add_credential(codex("work"), material())
            .unwrap_err(),
        LocalCredentialError::CredentialAddUnfinished
    );
    assert!(authority.list_credentials().unwrap().is_empty());
}

/// An add whose caller goes away during the write still ends in one outcome:
/// the service runs it on a blocking worker, which publishes it.
#[test]
fn an_add_finishes_after_its_caller_is_gone() {
    let store = HeldStore::default();
    let (_temp, authority) = authority(store.clone());
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .unwrap();
    store.hold_next_put();
    let caller = {
        let authority = Arc::clone(&authority);
        runtime.spawn(crate::service::run_blocking(move || {
            authority.add_credential(codex("work"), material())
        }))
    };
    store.wait_for_held_put();
    caller.abort();
    runtime.block_on(async {
        assert!(caller.await.unwrap_err().is_cancelled());
    });

    store.release();
    let deadline = Instant::now() + PROMPT;
    while authority.list_credentials().unwrap().is_empty() {
        assert!(Instant::now() < deadline, "the add never finished");
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(rows(&authority), 1);
}
