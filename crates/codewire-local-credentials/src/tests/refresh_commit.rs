//! The authority stages a started refresh's bundle itself, from the bytes the
//! child sends in Commit (#5539).

use super::refresh_crash::{SignIn, open, reserve_refresh};
use super::*;
use crate::refresh_commit::stage_once;

/// A Codex sign-in whose refresh has started, and its channel, refresh and
/// request IDs.
struct Started {
    _temp: TempDir,
    store: TestProtectedStore,
    authority: LocalCredentialAuthority<TestProtectedStore>,
    id: CredentialId,
    ids: (Uuid, Uuid, Uuid),
}

fn started() -> Started {
    let temp = TempDir::new().expect("temporary directory");
    let store = TestProtectedStore::new(ProtectedStorePersistence::OperatingSystem);
    let authority = open(&authority_root(&temp), &store).expect("open authority");
    let request = SignIn::Codex.request(&environment("env-refresh-commit"));
    let (id, ids) = reserve_refresh(&authority, SignIn::Codex, &request);
    let (channel_id, refresh_id, request_id) = ids;
    authority
        .start_environment_credential_refresh(channel_id, refresh_id, request_id)
        .expect("durable start");
    Started {
        _temp: temp,
        store,
        authority,
        id,
        ids,
    }
}

impl Started {
    fn commit(&self, bundle: &[u8]) -> Result<(CredentialRecord, u64), LocalCredentialError> {
        let (channel_id, refresh_id, request_id) = self.ids;
        self.authority.commit_environment_credential_refresh(
            channel_id,
            refresh_id,
            request_id,
            &material(bundle),
        )
    }

    fn next_entry(&self) -> ProtectedEntryId {
        protected_entry_id(&self.id, 2).expect("next entry")
    }

    fn staged(&self) -> Option<Vec<u8>> {
        self.store
            .get(&self.next_entry())
            .expect("read the next entry")
            .map(|value| value.expose_secret().to_vec())
    }
}

#[test]
fn a_commit_stages_and_promotes_the_bundle_the_child_sends() {
    let refresh = started();
    let (record, generation) = refresh.commit(b"synthetic-new-sign-in").expect("commit");
    assert_eq!(generation, 2);
    assert_eq!(record.metadata.revocation_generation, 2);
    assert_eq!(
        refresh.store.entry_values(),
        vec![b"synthetic-new-sign-in".to_vec()]
    );
}

#[test]
fn a_put_that_landed_but_failed_goes_on_when_the_same_bytes_are_sent_again() {
    let refresh = started();
    refresh.store.set_put_fault(Fault::AfterEffect);
    assert!(matches!(
        refresh.commit(b"synthetic-new-sign-in"),
        Err(LocalCredentialError::ProtectedStore(_))
    ));
    refresh.store.clear_faults();
    let (_, generation) = refresh
        .commit(b"synthetic-new-sign-in")
        .expect("retried commit");
    assert_eq!(generation, 2);
}

#[test]
fn other_bytes_already_staged_are_refused_and_left_for_reconcile() {
    let refresh = started();
    refresh
        .store
        .put(&refresh.next_entry(), &material(b"synthetic-other-bundle"))
        .expect("stage other bytes");
    assert!(matches!(
        refresh.commit(b"synthetic-new-sign-in"),
        Err(LocalCredentialError::ProtectedEntryCollision)
    ));
    assert_eq!(refresh.staged(), Some(b"synthetic-other-bundle".to_vec()));
    let current = refresh.authority.get_credential(&refresh.id).expect("read");
    assert_eq!(current.metadata.revocation_generation, 1);
}

#[test]
fn a_locked_store_refuses_the_write_until_it_is_unlocked() {
    let refresh = started();
    refresh.store.set_put_denied(true);
    assert!(matches!(
        refresh.commit(b"synthetic-new-sign-in"),
        Err(LocalCredentialError::ProtectedStore(
            ProtectedStoreError::AccessDenied
        ))
    ));
    assert_eq!(refresh.staged(), None);
    refresh.store.set_put_denied(false);
    let (_, generation) = refresh
        .commit(b"synthetic-new-sign-in")
        .expect("commit once unlocked");
    assert_eq!(generation, 2);
}

#[test]
fn a_commit_for_another_channels_refresh_is_refused_and_stages_nothing() {
    let refresh = started();
    let (_, refresh_id, request_id) = refresh.ids;
    assert!(matches!(
        refresh.authority.commit_environment_credential_refresh(
            Uuid::new_v4(),
            refresh_id,
            request_id,
            &material(b"synthetic-new-sign-in"),
        ),
        Err(LocalCredentialError::StaleCredentialRefresh)
    ));
    assert_eq!(refresh.staged(), None);
}

#[test]
fn a_write_after_the_started_deadline_is_refused_and_stages_nothing() {
    let refresh = started();
    let elapsed = unix_millis().expect("clock") - 1;
    assert!(matches!(
        stage_once(
            &refresh.store,
            &refresh.next_entry(),
            &material(b"synthetic-new-sign-in"),
            elapsed,
        ),
        Err(LocalCredentialError::StaleCredentialRefresh)
    ));
    assert_eq!(refresh.staged(), None);
}

#[test]
fn a_fail_after_a_landed_write_is_refused_so_reconcile_promotes_it() {
    let refresh = started();
    refresh
        .store
        .put(&refresh.next_entry(), &material(b"synthetic-new-sign-in"))
        .expect("the authority's write landed");
    let (channel_id, refresh_id, request_id) = refresh.ids;
    assert!(matches!(
        refresh
            .authority
            .fail_environment_credential_refresh(channel_id, refresh_id, request_id),
        Err(LocalCredentialError::CorruptMetadata)
    ));
    assert_eq!(refresh.staged(), Some(b"synthetic-new-sign-in".to_vec()));
}

/// A Commit that timed out, was cancelled or ended unknown may still be
/// writing on the authority, so it never hands its refresh back to be failed
/// beside that write; one the authority answered does.
#[test]
fn only_a_commit_the_authority_answered_hands_its_refresh_back() {
    use crate::refresh_commit::commit_was_answered;
    for unanswered in [
        tonic::Status::cancelled("timeout expired"),
        tonic::Status::deadline_exceeded("deadline"),
        tonic::Status::unknown("transport"),
    ] {
        assert!(!commit_was_answered(&unanswered), "{unanswered:?}");
    }
    for answered in [
        tonic::Status::unavailable("store locked"),
        tonic::Status::failed_precondition("other material"),
        tonic::Status::out_of_range("stale"),
        tonic::Status::invalid_argument("empty"),
    ] {
        assert!(commit_was_answered(&answered), "{answered:?}");
    }
}

/// A Commit's bundle is bounded by the store's own limit before anything
/// else is read, and an empty one is refused the same way.
#[test]
fn an_empty_or_oversized_bundle_is_refused_before_anything_is_read() {
    use crate::refresh_commit::refresh_commit_material;
    let mut over = vec![7_u8; codewire_protected_store::MAX_PROTECTED_VALUE_BYTES + 1];
    let mut empty = Vec::new();
    for bundle in [&mut over, &mut empty] {
        let refused = refresh_commit_material(bundle).unwrap_err();
        assert_eq!(refused.code(), tonic::Code::InvalidArgument);
    }
}
