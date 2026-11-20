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

/// A staging mount and the server's private directory below it.
struct Mount {
    root: tempfile::TempDir,
    staging: Staging,
}

impl Mount {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let staging = Staging::open(root.path()).unwrap();
        Self { root, staging }
    }

    fn private(&self) -> std::path::PathBuf {
        self.root.path().join("cw-runtime")
    }

    fn uploads(&self) -> usize {
        fs::read_dir(self.private()).unwrap().count()
    }
}

fn create(mount: &Mount) -> AppResult<Candidate> {
    Candidate::create(
        &mount.staging,
        mount.staging.reserve()?,
        fixture::identity('a'),
    )
}

#[test]
fn held_metadata_matches_native_stat_and_refuses_mode_change_or_replacement() {
    let parent = owned_parent();
    let directory = File::open(parent.path()).unwrap();
    let path = parent.path().join("candidate.cw");
    let held = File::create(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let named = rfs::statat(&directory, "candidate.cw", AtFlags::SYMLINK_NOFOLLOW).unwrap();
    assert!(named_matches_held(&named, &held.metadata().unwrap()));

    fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
    assert!(!named_matches_held(&named, &held.metadata().unwrap()));
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::rename(&path, parent.path().join("retained")).unwrap();
    fs::write(&path, b"replacement").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let replaced = rfs::statat(&directory, "candidate.cw", AtFlags::SYMLINK_NOFOLLOW).unwrap();
    assert!(!named_matches_held(&replaced, &held.metadata().unwrap()));
}

#[tokio::test]
async fn complete_record_only_static_payload_is_admitted_through_held_file_and_removed() {
    let mount = Mount::new();
    let (identity, bytes) = fixture::payload(&vec![9; 3 * MAX_CHUNK]);
    let mut chunks = stream::iter(bytes.chunks(MAX_CHUNK).map(|v| Ok(v.to_vec())));
    let mut candidate = receive_in(&mount.staging, identity.clone(), &mut chunks)
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
    assert_eq!(mount.uploads(), 0);
}

#[tokio::test]
async fn empty_oversized_short_extra_and_digest_mismatched_streams_refuse_before_admission() {
    let mount = Mount::new();
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
            receive_in(&mount.staging, identity, &mut chunks)
                .await
                .is_err()
        );
        assert_eq!(mount.uploads(), 0);
    }
}

#[tokio::test]
async fn wrong_record_dynamic_interpreter_and_duplicate_marker_refuse_even_with_matching_hash() {
    for case in 0..3 {
        let mount = Mount::new();
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
            receive_in(&mount.staging, identity, &mut chunks)
                .await
                .is_err()
        );
        assert_eq!(mount.uploads(), 0);
    }
}

#[tokio::test]
async fn cancelled_stream_removes_only_its_own_partial_candidate() {
    let mount = Mount::new();
    let sentinel = mount.private().join("unrelated");
    fs::write(&sentinel, b"preserve").unwrap();
    let (identity, _) = fixture::payload(b"cancelled");
    let mut chunks = stream::iter([Ok(vec![0; 64])]).chain(stream::pending());
    assert!(
        tokio::time::timeout(
            Duration::from_millis(15),
            receive_in(&mount.staging, identity, &mut chunks)
        )
        .await
        .is_err()
    );
    assert_eq!(fs::read(&sentinel).unwrap(), b"preserve");
    assert_eq!(mount.uploads(), 1);
}

#[tokio::test]
async fn an_upload_arriving_at_the_drain_deadline_ends_retryably_and_removes_its_candidate() {
    let mount = Mount::new();
    let (identity, _) = fixture::payload(b"restarted");
    let mut chunks = stream::iter([Ok(vec![0; 64])]).chain(stream::pending());
    let deadline = Box::pin(tokio::time::sleep(Duration::from_millis(15)));
    match receive_before(&mount.staging, identity, &mut chunks, deadline).await {
        Err(AppError::ServiceUnavailable(detail)) => assert!(detail.contains("send it again")),
        Err(other) => panic!("expected a retryable restart, got {other:?}"),
        Ok(_) => panic!("an upload still arriving at the deadline must end"),
    }
    assert_eq!(mount.uploads(), 0);
}

#[test]
fn changed_ancestry_refuses() {
    let mount = Mount::new();
    let candidate = create(&mount).unwrap();
    let original = candidate.path.parent().unwrap().to_path_buf();
    let retained = mount.private().join("retained");
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
        let mount = Mount::new();
        let parent = mount.private();
        let candidate = create(&mount).unwrap();
        let path = candidate.path.clone();
        match case {
            0 => fs::hard_link(&path, parent.join("link")).unwrap(),
            1 => {
                fs::rename(&path, parent.join("retained-candidate")).unwrap();
                symlink(parent.join("sentinel"), &path).unwrap();
                fs::write(parent.join("sentinel"), b"preserve").unwrap();
            }
            2 => fs::write(&path, b"changed bytes").unwrap(),
            _ => unreachable!(),
        }
        assert!(candidate.check().is_err());
        drop(candidate);
        assert!(fs::symlink_metadata(&path).is_ok());
        if case == 1 {
            assert_eq!(fs::read(parent.join("sentinel")).unwrap(), b"preserve");
        }
    }
}

#[test]
fn unknown_scratch_member_is_preserved() {
    let mount = Mount::new();
    let candidate = create(&mount).unwrap();
    let sentinel = candidate.path.parent().unwrap().join("unrelated");
    fs::write(&sentinel, b"keep").unwrap();
    drop(candidate);
    assert_eq!(fs::read(sentinel).unwrap(), b"keep");
}

#[tokio::test]
async fn stages_under_the_private_directory_below_a_setgid_2777_mount() {
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o2777)).unwrap();
    assert_eq!(fs::metadata(root.path()).unwrap().mode() & 0o7777, 0o2777);
    let staging = Staging::open(root.path()).unwrap();
    let (identity, bytes) = fixture::payload(b"setgid");
    let mut chunks = stream::iter([Ok(bytes)]);
    let candidate = receive_in(&staging, identity, &mut chunks).await.unwrap();
    let leaf = candidate.path.parent().unwrap();
    let private = root.path().join("cw-runtime");
    assert_eq!(leaf.parent().unwrap(), private);
    assert_eq!(fs::metadata(&private).unwrap().mode() & 0o7777, 0o700);
    assert_eq!(fs::metadata(leaf).unwrap().mode() & 0o7777, 0o700);
    assert_eq!(
        fs::read_dir(root.path()).unwrap().count(),
        1,
        "nothing is staged in the mount's root"
    );
    drop(candidate);
    assert_eq!(fs::read_dir(&private).unwrap().count(), 0);
}

#[tokio::test]
async fn an_upload_is_refused_without_512_mib_free_and_records_nothing() {
    let mount = Mount::new();
    assert_eq!(mount.staging.min_free(), 512 * 1024 * 1024);
    let full = mount.staging.clone().with_min_free(u64::MAX);
    let (identity, bytes) = fixture::payload(b"no room");
    let mut chunks = stream::iter([Ok(bytes.clone())]);
    assert!(matches!(
        receive_in(&full, identity.clone(), &mut chunks).await,
        Err(AppError::ServiceUnavailable(_))
    ));
    assert_eq!(mount.uploads(), 0);
    // The refusal released its slot: three more still fit.
    let mut held = Vec::new();
    for _ in 0..3 {
        let mut chunks = stream::iter([Ok(bytes.clone())]);
        held.push(
            receive_in(&mount.staging, identity.clone(), &mut chunks)
                .await
                .unwrap(),
        );
    }
}

/// One upload in flight: its chunks arrive only when the test sends them,
/// and a drain ends it only when the test fires it.
struct InFlight {
    chunks: tokio::sync::mpsc::Sender<AppResult<Vec<u8>>>,
    drain: tokio::sync::oneshot::Sender<()>,
    task: tokio::task::JoinHandle<AppResult<Candidate>>,
}

enum Ending {
    Success,
    Refusal,
    Error,
    Drain,
    DroppedConnection,
}

/// Starts an upload and returns it once it holds a slot, or its result if
/// it was refused before reading a chunk.
async fn start(staging: &Staging, identity: &CwPayloadIdentity) -> Result<InFlight, AppError> {
    let (chunks, receiver) = tokio::sync::mpsc::channel(1);
    let (drain, drained) = tokio::sync::oneshot::channel::<()>();
    let staging = staging.clone();
    let identity = identity.clone();
    let task = tokio::spawn(async move {
        let mut stream = tokio_stream::wrappers::ReceiverStream::new(receiver);
        let restart: RestartSignal = Box::pin(async move {
            // A dropped trigger means the test ended the upload another way.
            if drained.await.is_err() {
                std::future::pending::<()>().await;
            }
        });
        receive_before(&staging, identity, &mut stream, restart).await
    });
    // With room for one, the second send completes only once the upload
    // has taken the first chunk, so after its slot; a refused upload drops
    // the stream instead.
    // A refused upload has dropped the stream, which the next send reports.
    let _ = chunks.send(Ok(vec![0x7f])).await;
    if chunks.send(Ok(b"E".to_vec())).await.is_err() {
        return Err(task.await.unwrap().err().unwrap());
    }
    Ok(InFlight {
        chunks,
        drain,
        task,
    })
}

async fn end(upload: InFlight, ending: Ending, bytes: &[u8]) {
    match ending {
        Ending::Success => {
            upload.chunks.send(Ok(bytes[2..].to_vec())).await.unwrap();
            drop(upload.chunks);
            drop(upload.task.await.unwrap().unwrap());
        }
        Ending::Refusal => {
            drop(upload.chunks);
            assert!(matches!(
                upload.task.await.unwrap(),
                Err(AppError::BadRequest(_))
            ));
        }
        Ending::Error => {
            let failed = Err(AppError::BadRequest("connection failed".into()));
            upload.chunks.send(failed).await.unwrap();
            assert!(upload.task.await.unwrap().is_err());
        }
        Ending::Drain => {
            upload.drain.send(()).unwrap();
            assert!(matches!(
                upload.task.await.unwrap(),
                Err(AppError::ServiceUnavailable(detail)) if detail.contains("send it again")
            ));
        }
        Ending::DroppedConnection => {
            upload.task.abort();
            match upload.task.await {
                Err(error) => assert!(error.is_cancelled()),
                Ok(_) => panic!("an aborted upload must end as cancelled"),
            }
        }
    }
}

#[tokio::test]
async fn a_fourth_concurrent_upload_is_refused_until_one_of_three_ends_however_it_ends() {
    let mount = Mount::new();
    let (identity, bytes) = fixture::payload(b"concurrent");
    let mut in_flight = Vec::new();
    for _ in 0..3 {
        in_flight.push(start(&mount.staging, &identity).await.unwrap());
    }
    for ending in [
        Ending::Success,
        Ending::Refusal,
        Ending::Error,
        Ending::Drain,
        Ending::DroppedConnection,
    ] {
        assert!(matches!(
            start(&mount.staging, &identity).await,
            Err(AppError::ServiceUnavailable(_))
        ));
        assert_eq!(mount.uploads(), 3, "the fourth staged nothing");
        end(in_flight.remove(0), ending, &bytes).await;
        assert_eq!(mount.uploads(), 2);
        in_flight.push(start(&mount.staging, &identity).await.unwrap());
        assert_eq!(mount.uploads(), 3);
    }
}

#[test]
fn no_upload_path_names_the_process_temporary_directory() {
    for (name, source) in [
        ("intake.rs", include_str!("intake.rs")),
        ("staging.rs", include_str!("staging.rs")),
        ("service.rs", include_str!("service.rs")),
        ("execute.rs", include_str!("execute.rs")),
    ] {
        let shipped = source.split("#[cfg(test)]").next().unwrap();
        for banned in ["temp_dir", "TMPDIR", "\"/tmp", "tempfile", "env::temp"] {
            assert!(
                !shipped.contains(banned),
                "{name} names {banned} outside its tests"
            );
        }
    }
}
