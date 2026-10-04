use super::*;
use crate::api::cw_runtime::service_test_support as fixture;
use futures_util::stream;
use std::fs;
use std::os::unix::fs::{PermissionsExt as _, symlink};

fn owned_parent() -> tempfile::TempDir {
    let parent = tempfile::tempdir().unwrap();
    fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o700)).unwrap();
    parent
}

#[tokio::test]
async fn complete_record_only_static_payload_is_admitted_through_held_file_and_removed() {
    let parent = owned_parent();
    let (identity, bytes) = fixture::payload(&vec![9; 3 * MAX_CHUNK]);
    let mut chunks = stream::iter(bytes.chunks(MAX_CHUNK).map(|v| Ok(v.to_vec())));
    let mut candidate = receive_in(parent.path(), identity.clone(), &mut chunks)
        .await
        .unwrap();
    assert_eq!(candidate.identity(), &identity);
    candidate.check().unwrap();
    assert_eq!(fs::metadata(&candidate.path).unwrap().mode() & 0o777, 0o600);
    candidate.rewind().unwrap();
    let mut observed = Vec::new();
    loop {
        let part = candidate.read_chunk().unwrap();
        if part.is_empty() {
            break;
        }
        observed.extend(part);
    }
    assert_eq!(observed, bytes);
    let held = candidate.path.clone();
    drop(candidate);
    assert!(!held.exists());
    assert_eq!(fs::read_dir(parent.path()).unwrap().count(), 0);
}

#[tokio::test]
async fn empty_oversized_short_extra_and_digest_mismatched_streams_refuse_before_admission() {
    let parent = owned_parent();
    let (identity, bytes) = fixture::payload(b"intake");
    let mut bad_hash = identity.clone();
    bad_hash.sha256 = "d".repeat(64);
    for (identity, parts) in [
        (identity.clone(), vec![vec![]]),
        (identity.clone(), vec![vec![0; MAX_CHUNK + 1]]),
        (identity.clone(), vec![bytes[..bytes.len() - 1].to_vec()]),
        (identity.clone(), vec![bytes.clone(), vec![0]]),
        (bad_hash, vec![bytes.clone()]),
    ] {
        let mut chunks = stream::iter(parts.into_iter().map(Ok));
        assert!(
            receive_in(parent.path(), identity, &mut chunks)
                .await
                .is_err()
        );
        assert_eq!(fs::read_dir(parent.path()).unwrap().count(), 0);
    }
}

#[tokio::test]
async fn wrong_record_dynamic_interpreter_and_duplicate_marker_refuse_even_with_matching_hash() {
    for case in 0..3 {
        let parent = owned_parent();
        let (mut identity, mut bytes) = fixture::payload(b"record-negative");
        match case {
            0 => identity.source_revision = "f".repeat(40),
            1 => bytes[64] = 3,
            2 => bytes.extend_from_slice(BUILD_MARKER),
            _ => unreachable!(),
        }
        identity.size = bytes.len() as u64;
        identity.sha256 = format!("{:x}", Sha256::digest(&bytes));
        let mut chunks = stream::iter([Ok(bytes)]);
        assert!(
            receive_in(parent.path(), identity, &mut chunks)
                .await
                .is_err()
        );
        assert_eq!(fs::read_dir(parent.path()).unwrap().count(), 0);
    }
}

#[tokio::test]
async fn cancelled_stream_removes_only_its_own_partial_candidate() {
    let parent = owned_parent();
    let sentinel = parent.path().join("unrelated");
    fs::write(&sentinel, b"preserve").unwrap();
    let (identity, _) = fixture::payload(b"cancelled");
    let mut chunks = stream::iter([Ok(vec![0; 64])]).chain(stream::pending());
    assert!(
        tokio::time::timeout(
            Duration::from_millis(15),
            receive_in(parent.path(), identity, &mut chunks)
        )
        .await
        .is_err()
    );
    assert_eq!(fs::read(&sentinel).unwrap(), b"preserve");
    assert_eq!(fs::read_dir(parent.path()).unwrap().count(), 1);
}

#[test]
fn writable_symlink_parent_and_changed_ancestry_refuse() {
    let parent = owned_parent();
    let unsafe_parent = parent.path().join("writable");
    fs::create_dir(&unsafe_parent).unwrap();
    fs::set_permissions(&unsafe_parent, fs::Permissions::from_mode(0o777)).unwrap();
    assert!(Candidate::create(&unsafe_parent, fixture::identity('a')).is_err());
    let link = parent.path().join("link");
    symlink(parent.path(), &link).unwrap();
    assert!(Candidate::create(&link, fixture::identity('a')).is_err());
    let candidate = Candidate::create(parent.path(), fixture::identity('a')).unwrap();
    let original = candidate.path.parent().unwrap().to_path_buf();
    let retained = parent.path().join("retained");
    fs::rename(&original, &retained).unwrap();
    fs::create_dir(&original).unwrap();
    fs::write(original.join("sentinel"), b"foreign").unwrap();
    assert!(candidate.check().is_err());
    drop(candidate);
    assert_eq!(fs::read(original.join("sentinel")).unwrap(), b"foreign");
    assert!(retained.join("candidate.cw").exists());
}

#[test]
fn linked_replaced_or_rewritten_candidate_is_never_followed_or_cleaned_as_owned() {
    for case in 0..3 {
        let parent = owned_parent();
        let candidate = Candidate::create(parent.path(), fixture::identity('a')).unwrap();
        let path = candidate.path.clone();
        match case {
            0 => fs::hard_link(&path, parent.path().join("link")).unwrap(),
            1 => {
                fs::rename(&path, parent.path().join("retained-candidate")).unwrap();
                symlink(parent.path().join("sentinel"), &path).unwrap();
                fs::write(parent.path().join("sentinel"), b"preserve").unwrap();
            }
            2 => fs::write(&path, b"changed bytes").unwrap(),
            _ => unreachable!(),
        }
        assert!(candidate.check().is_err());
        drop(candidate);
        assert!(fs::symlink_metadata(&path).is_ok());
        if case == 1 {
            assert_eq!(
                fs::read(parent.path().join("sentinel")).unwrap(),
                b"preserve"
            );
        }
    }
}

#[test]
fn unknown_scratch_member_is_preserved() {
    let parent = owned_parent();
    let candidate = Candidate::create(parent.path(), fixture::identity('a')).unwrap();
    let sentinel = candidate.path.parent().unwrap().join("unrelated");
    fs::write(&sentinel, b"keep").unwrap();
    drop(candidate);
    assert_eq!(fs::read(sentinel).unwrap(), b"keep");
}
