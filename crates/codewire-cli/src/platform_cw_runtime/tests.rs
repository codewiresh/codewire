//! Record-only executable fixtures exercise actual Store/FD/filesystem effects.
//! The controlled Rust test child supplies kernel cancellation evidence; these
//! tests neither execute an incoming CW nor claim a real platform Pod journey.
use std::fs::{self as stdfs, Permissions};
use std::io::Cursor;
use std::os::fd::{AsRawFd as _, FromRawFd as _};
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _, symlink};
use std::os::unix::net::UnixStream;
use std::os::unix::process::{CommandExt as _, ExitStatusExt as _};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Barrier};
use std::thread;

use codewire_cw_release::store::{PendingSelection, Selection};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use super::wire::ObservedSelection;
use super::*;

/// A deadline for IO, locks and child waits whose timing is not the subject.
/// The event ends them; this only turns a hang into a failure. A slow CI slot
/// can stall a thread for more than a second between taking a deadline and
/// polling, which a 1 s deadline reported as a timeout (#3312).
const HANG: Duration = Duration::from_secs(60);
const TARGET: &str = "x86_64-unknown-linux-musl";
const CHILD_ROOT: &str = "CW_PLATFORM_ROLE_TEST_ROOT";
const CHILD_MODE: &str = "CW_PLATFORM_ROLE_TEST_MODE";

struct Payload {
    bytes: Vec<u8>,
    identity: CwPayloadIdentity,
}

impl Payload {
    fn new(version: &str) -> Self {
        let record = crate::build_record::tests::framed(&crate::build_record::tests::json(
            version, TARGET, true,
        ));
        let bytes = crate::build_record::tests::release_executable(&[&record]);
        Self::with_bytes(version, bytes)
    }

    fn with_bytes(version: &str, bytes: Vec<u8>) -> Self {
        Self {
            identity: CwPayloadIdentity {
                schema_version: 2,
                protocol_version: 1,
                record_version: 1,
                package_version: version.to_owned(),
                target: TARGET.to_owned(),
                source_revision: crate::build_record::tests::REVISION.to_owned(),
                source_tree_sha256: crate::build_record::tests::TREE.to_owned(),
                rustc: "rustc 1.93.0 (synthetic 2026-01-01)".to_owned(),
                sha256: format!("{:x}", Sha256::digest(&bytes)),
                size: bytes.len() as u64,
            },
            bytes,
        }
    }
}

struct Fixture {
    root: tempfile::TempDir,
    paths: Paths,
    image: PathBuf,
    a: Payload,
    b: Payload,
    request: Uuid,
    pod: Uuid,
}

impl Fixture {
    fn new() -> Self {
        let base = std::env::var_os("CARGO_TARGET_TMPDIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                Path::new(env!("CARGO_MANIFEST_DIR")).join(".tmp/platform-runtime-fixtures")
            });
        stdfs::create_dir_all(&base).unwrap();
        // Test placement must satisfy the same held ancestry policy; it never
        // makes a foreign-writable temporary parent appear private.
        assert_eq!(stdfs::symlink_metadata(&base).unwrap().uid(), user().0);
        assert_eq!(stdfs::symlink_metadata(&base).unwrap().mode() & 0o022, 0);
        let root = tempfile::Builder::new()
            .prefix("cw-platform-role-")
            .tempdir_in(base)
            .unwrap();
        let home = root.path().join("home");
        stdfs::create_dir(&home).unwrap();
        chmod(&home, 0o700);
        let a = Payload::new("v1.2.3");
        let b = Payload::new("v1.2.4");
        let image = root.path().join("image-a");
        write(&image, &a.bytes, 0o500);
        Self {
            root,
            paths: Paths::fixture(&home),
            image,
            a,
            b,
            request: Uuid::new_v4(),
            pod: Uuid::new_v4(),
        }
    }

    fn request(&self, action: Action) -> Request {
        Request {
            schema_version: 1,
            request_id: self.request,
            pod_uid: self.pod,
            binding_sha256: "b".repeat(64),
            action,
        }
    }

    fn engine(&self) -> Engine {
        let mut engine = Engine::new(self.paths.clone(), Instant::now() + HANG);
        engine.image_fixture = Some((self.image.clone(), self.a.identity.clone()));
        engine
    }

    fn execute(&self, action: Action, bytes: &[u8]) -> (Result<ReplyBody>, bool) {
        let mut engine = self.engine();
        let result = engine.execute(&self.request(action), &mut Cursor::new(bytes));
        (result, engine.effects_started)
    }

    fn bootstrap(&self) {
        assert_selected(
            self.execute(
                Action::Bootstrap {
                    identity: self.a.identity.clone(),
                    expected: absent(),
                },
                &[],
            )
            .0
            .unwrap(),
            &self.a.identity,
            1,
            None,
            true,
        );
    }

    fn expected(&self) -> SelectionExpectation {
        let status = self.store().status().unwrap();
        SelectionExpectation {
            generation: status.generation,
            current: status.current,
            previous: status.previous,
        }
    }

    fn store(&self) -> Store {
        Store::open(&self.paths.store, LOCK_BUDGET).unwrap()
    }

    fn stage(&self) {
        assert_eq!(
            self.execute(
                Action::Stage {
                    identity: self.b.identity.clone(),
                    expected: self.expected(),
                },
                &self.b.bytes
            )
            .0
            .unwrap(),
            ReplyBody::Staged {
                sha256: self.b.identity.sha256.clone(),
                size: self.b.identity.size,
            }
        );
    }

    fn job_path(&self) -> PathBuf {
        self.paths
            .store
            .parent()
            .unwrap()
            .join("cw-runtime-staging")
            .join(self.pod.to_string())
            .join(self.request.to_string())
    }

    fn lock_path(&self) -> PathBuf {
        self.paths.store.parent().unwrap().join("cw-runtime.lock")
    }

    fn status(&self) -> ObservedSelection {
        match self.execute(Action::Status, &[]).0.unwrap() {
            ReplyBody::Status { selection, .. } => *selection,
            other => panic!("unexpected status {other:?}"),
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if thread::panicking() {
            eprintln!(
                "retained synthetic role failure root: {}",
                self.root.path().display()
            );
            let keep = std::mem::replace(&mut self.root, tempfile::tempdir().unwrap());
            let _ = keep.keep();
            return;
        }
        // Only this test-created tree is made writable after all owned children
        // have died. Production never rewrites Store version modes or removes it.
        make_fixture_directories_writable(self.root.path());
    }
}

fn make_fixture_directories_writable(path: &Path) {
    let metadata = stdfs::symlink_metadata(path).unwrap();
    if !metadata.is_dir() {
        return;
    }
    assert_eq!(metadata.uid(), user().0);
    chmod(path, 0o700);
    for item in stdfs::read_dir(path).unwrap() {
        let item = item.unwrap();
        if item.file_type().unwrap().is_dir() {
            make_fixture_directories_writable(&item.path())
        }
    }
}

fn chmod(path: &Path, mode: u32) {
    stdfs::set_permissions(path, Permissions::from_mode(mode)).unwrap()
}
fn write(path: &Path, bytes: &[u8], mode: u32) {
    if let Ok(metadata) = stdfs::symlink_metadata(path) {
        assert!(metadata.is_file());
        assert_eq!(metadata.uid(), user().0);
        assert_eq!(metadata.nlink(), 1);
        // Deliberate corruption of this known synthetic fixture only.
        chmod(path, 0o600);
    }
    stdfs::write(path, bytes).unwrap();
    chmod(path, mode);
}
fn absent() -> SelectionExpectation {
    SelectionExpectation {
        generation: 0,
        current: None,
        previous: None,
    }
}
fn framed(request: &Request) -> Vec<u8> {
    frame_bytes(&canonical_json(request).unwrap())
}
fn frame_bytes(bytes: &[u8]) -> Vec<u8> {
    let mut result = (bytes.len() as u32).to_le_bytes().to_vec();
    result.extend_from_slice(bytes);
    result
}
fn assert_selected(
    body: ReplyBody,
    identity: &CwPayloadIdentity,
    generation: u64,
    previous: Option<&str>,
    changed: bool,
) {
    assert_eq!(
        body,
        ReplyBody::Selected {
            sha256: identity.sha256.clone(),
            generation,
            previous_sha256: previous.map(str::to_owned),
            changed
        }
    );
}
fn selected_files(f: &Fixture) -> (Vec<u8>, PathBuf) {
    (
        stdfs::read(f.paths.store.join("selection.json")).unwrap(),
        stdfs::read_link(&f.paths.entry).unwrap(),
    )
}
fn assert_no_home_effect(f: &Fixture) {
    assert!(!f.paths.home_for_test().join(".local").exists());
}

#[test]
fn private_role_refuses_extra_arguments_before_standard_io_or_settings() {
    assert_eq!(run_from(["cw", ROLE, "--arbitrary-path"]), 2);
    assert_eq!(run_from(["cw", "status"]), 2);
    assert_eq!(run_from(["cw"]), 2);
    assert_eq!(run_from(["cw", ROLE, "status", "extra", "more"]), 2);
}

#[test]
fn closed_frames_refuse_duplicates_unknown_fields_noncanonical_and_bad_scalars() {
    let f = Fixture::new();
    let request = f.request(Action::Status);
    let valid = canonical_json(&request).unwrap();
    assert_eq!(
        wire::read_request(&mut Cursor::new(frame_bytes(&valid))).unwrap(),
        request
    );
    let raw = String::from_utf8(valid).unwrap();
    let invalid = [
        raw.replacen('{', "{\"command\":\"sh\",", 1),
        raw.replacen('{', "{\"path\":\"/tmp/cw\",", 1),
        raw.replacen('{', "{\"environment\":{},", 1),
        raw.replacen('{', "{\"token\":\"synthetic\",", 1),
        raw.replace("\"schema_version\":1", "\"schema_version\":true"),
        raw.replace("\"schema_version\":1", "\"schema_version\":2"),
        raw.replace(
            "\"schema_version\":1",
            "\"schema_version\":1,\"schema_version\":1",
        ),
        raw.replace(':', ": "),
        raw.trim_end().to_owned(),
        raw.replace(&request.pod_uid.to_string(), &Uuid::nil().to_string()),
        raw.replace(&"b".repeat(64), &"B".repeat(64)),
        raw.replace("\"status\"", "\"status\",\"command\":\"sh\""),
    ];
    for value in invalid {
        assert!(wire::read_request(&mut Cursor::new(frame_bytes(value.as_bytes()))).is_err());
    }
    for length in [0, wire::MAX_JSON as u32 + 1, u32::MAX] {
        assert_eq!(
            wire::read_request(&mut Cursor::new(length.to_le_bytes())).unwrap_err(),
            Code::InvalidFrame
        );
    }
    let mut truncated = framed(&request);
    truncated.pop();
    assert_eq!(
        wire::read_request(&mut Cursor::new(truncated)).unwrap_err(),
        Code::InputIncomplete
    );
    assert_no_home_effect(&f);
}

#[test]
fn generation_is_lossless_and_only_current_noop_is_valid_at_u64_maximum() {
    let f = Fixture::new();
    let expectation = SelectionExpectation {
        generation: u64::MAX,
        current: Some(f.a.identity.sha256.clone()),
        previous: None,
    };
    let request = f.request(Action::Update {
        identity: f.a.identity.clone(),
        expected: expectation.clone(),
    });
    assert_eq!(
        wire::read_request(&mut Cursor::new(framed(&request))).unwrap(),
        request
    );
    assert_eq!(
        f.request(Action::Update {
            identity: f.b.identity.clone(),
            expected: expectation
        })
        .validate(),
        Err(Code::InvalidFrame)
    );
    let mut value = serde_json::to_value(request).unwrap();
    value["action"]["expected"]["generation"] = serde_json::Value::Bool(true);
    assert!(
        wire::read_request(&mut Cursor::new(frame_bytes(
            &canonical_json(&value).unwrap()
        )))
        .is_err()
    );
}

#[test]
fn bootstrap_update_rollback_noop_and_identified_cleanup_use_actual_store() {
    let f = Fixture::new();
    let sentinel = f.root.path().join("unrelated");
    write(&sentinel, b"preserve", 0o600);
    f.bootstrap();
    assert_eq!(
        f.store().verify(&f.a.identity.sha256).unwrap().payload,
        Some(f.a.identity.clone())
    );
    f.stage();
    assert_selected(
        f.execute(
            Action::Update {
                identity: f.b.identity.clone(),
                expected: f.expected(),
            },
            &[],
        )
        .0
        .unwrap(),
        &f.b.identity,
        2,
        Some(&f.a.identity.sha256),
        true,
    );
    assert_selected(
        f.execute(
            Action::Rollback {
                identity: f.a.identity.clone(),
                expected: f.expected(),
            },
            &[],
        )
        .0
        .unwrap(),
        &f.a.identity,
        3,
        Some(&f.b.identity.sha256),
        true,
    );
    assert_selected(
        f.execute(
            Action::Rollback {
                identity: f.a.identity.clone(),
                expected: f.expected(),
            },
            &[],
        )
        .0
        .unwrap(),
        &f.a.identity,
        3,
        Some(&f.b.identity.sha256),
        false,
    );
    let before = selected_files(&f);
    assert_eq!(
        f.execute(
            Action::Cleanup {
                bootstrap: Some(f.a.identity.clone()),
                candidate: Some(f.b.identity.clone()),
            },
            &[]
        ),
        (Ok(ReplyBody::Cleaned), true)
    );
    assert!(!f.job_path().exists());
    assert_eq!(selected_files(&f), before);
    assert_eq!(f.store().status().unwrap().versions.len(), 2);
    assert_eq!(stdfs::read(sentinel).unwrap(), b"preserve");
    assert_eq!(
        f.execute(
            Action::Cleanup {
                bootstrap: None,
                candidate: None
            },
            &[]
        ),
        (Ok(ReplyBody::Cleaned), false)
    );
}

#[test]
fn readonly_absent_status_does_not_create_parents_or_lock() {
    let f = Fixture::new();
    let before = stdfs::read_dir(f.paths.home_for_test()).unwrap().count();
    assert_eq!(f.status(), ObservedSelection::absent());
    assert_eq!(
        stdfs::read_dir(f.paths.home_for_test()).unwrap().count(),
        before
    );
    assert_no_home_effect(&f);
}

#[test]
fn status_reports_but_never_recovers_pending_selection() {
    let f = Fixture::new();
    f.bootstrap();
    let before_link = stdfs::read_link(&f.paths.entry).unwrap();
    let path = f.paths.store.join("selection.json");
    let mut state: Selection = serde_json::from_slice(&stdfs::read(&path).unwrap()).unwrap();
    state.pending = Some(PendingSelection {
        operation: Uuid::new_v4().to_string(),
        generation: state.generation,
        from: state.current.clone(),
        to: f.b.identity.sha256.clone(),
    });
    let bytes = canonical_json(&state).unwrap();
    write(&path, &bytes, 0o644);
    let status = f.status();
    assert!(status.pending);
    assert!(!status.consistent);
    assert_eq!(status.current, Some(f.a.identity.clone()));
    assert_eq!(stdfs::read(&path).unwrap(), bytes);
    assert_eq!(stdfs::read_link(&f.paths.entry).unwrap(), before_link);
    assert_eq!(
        f.execute(
            Action::Stage {
                identity: f.b.identity.clone(),
                expected: f.expected()
            },
            &f.b.bytes
        ),
        (Err(Code::PendingSelection), false)
    );
    assert_eq!(stdfs::read(&path).unwrap(), bytes);
}

#[test]
fn readonly_status_refuses_selected_or_previous_provenance_not_in_the_actual_record() {
    let f = Fixture::new();
    f.bootstrap();
    let c = Payload::new("v1.2.5");
    let path = f.root.path().join("generic-store-record");
    write(&path, &c.bytes, 0o500);
    let mut claimed = c.identity.clone();
    claimed.package_version = "v9.9.9".to_owned();
    let store = f.store();
    // Generic Store admission is intentionally only hash/header/payload-based.
    // The platform role must not inherit that as complete build provenance.
    store
        .publish_and_select(
            &Candidate {
                executable: path,
                admission: Admission::Pinned {
                    identity: claimed,
                    sha256: c.identity.sha256.clone(),
                },
            },
            Some(1),
        )
        .unwrap();
    let current_before = selected_files(&f);
    assert_eq!(
        f.execute(Action::Status, &[]),
        (Err(Code::CandidateRefused), false)
    );
    assert_eq!(selected_files(&f), current_before);
    store.rollback(Some(&f.a.identity.sha256), Some(2)).unwrap();
    let previous_before = selected_files(&f);
    assert_eq!(
        f.execute(Action::Status, &[]),
        (Err(Code::CandidateRefused), false)
    );
    assert_eq!(selected_files(&f), previous_before);
}

#[test]
fn readonly_status_never_recreates_either_missing_lock() {
    let f = Fixture::new();
    f.bootstrap();
    let before = selected_files(&f);
    stdfs::remove_file(f.lock_path()).unwrap();
    assert_eq!(f.status().generation, 1);
    assert!(!f.lock_path().exists());
    let store_lock = f.paths.store.join("lock");
    stdfs::remove_file(&store_lock).unwrap();
    assert_eq!(
        f.execute(Action::Status, &[]),
        (Err(Code::UnsafeState), false)
    );
    assert!(!store_lock.exists());
    assert!(!f.lock_path().exists());
    assert_eq!(selected_files(&f), before);
}

#[test]
fn shared_home_volume_root_is_an_anchor_but_runtime_directories_stay_private() {
    // A Kubernetes home volume is root-owned 0777 (local-path) or a setgid
    // 2775 fsGroup root; the workspace user cannot change either.
    let f = Fixture::new();
    let home = f.root.path().join("home");
    let created = [
        ".local",
        ".local/bin",
        ".local/share",
        ".local/share/codewire",
        ".local/share/codewire/cw-runtime-staging",
    ];
    for mode in [0o777, 0o2775] {
        chmod(&home, mode);
        drop(Tree::open(&f.paths, true).unwrap());
        for name in created {
            let path = home.join(name);
            if path.exists() {
                assert_eq!(
                    stdfs::metadata(&path).unwrap().mode() & 0o7777,
                    0o700,
                    "{name}"
                );
            }
        }
        assert!(Tree::open(&f.paths, false).is_ok());
        stdfs::remove_dir_all(home.join(".local")).unwrap();
    }
    // The same sharing on a runtime directory below the home still refuses.
    drop(Tree::open(&f.paths, true).unwrap());
    chmod(&home.join(".local"), 0o770);
    assert!(matches!(
        Tree::open(&f.paths, false),
        Err(Code::UnsafeState)
    ));
    chmod(&home.join(".local"), 0o700);
    chmod(&home, 0o700);
}

#[test]
fn root_owned_shared_home_is_writable_through_effective_access() {
    // A root-owned world-writable /tmp stands in for a local-path volume root.
    let tmp = Path::new("/tmp");
    let shared = stdfs::symlink_metadata(tmp).unwrap();
    assert!(shared.is_dir() && shared.uid() == 0 && shared.mode() & 0o003 == 0o003);
    assert!(Paths::fixture(tmp).check_home_for_test(true).is_ok());
    if rustix::process::geteuid().as_raw() != 0 {
        // A root-owned home this user cannot write is admitted read-only.
        let usr = Paths::fixture(Path::new("/usr"));
        assert!(usr.check_home_for_test(false).is_ok());
        assert!(matches!(usr.check_home_for_test(true), Err(Code::ReadOnly)));
    }
}

#[test]
fn symlinked_or_non_directory_home_refuses() {
    let f = Fixture::new();
    let real = f.root.path().join("real-home");
    stdfs::create_dir(&real).unwrap();
    let linked = f.root.path().join("linked-home");
    symlink(&real, &linked).unwrap();
    let file = f.root.path().join("file-home");
    write(&file, b"", 0o600);
    for home in [&linked, &file] {
        assert!(matches!(
            Tree::open(&Paths::fixture(home), false),
            Err(Code::UnsafeState)
        ));
    }
}

#[test]
fn existing_unmanaged_entry_and_readonly_parent_refuse_before_publication() {
    let f = Fixture::new();
    let tree = Tree::open(&f.paths, true).unwrap();
    drop(tree);
    write(&f.paths.entry, b"foreign installed command", 0o500);
    let before = stdfs::read(&f.paths.entry).unwrap();
    assert_eq!(
        f.execute(
            Action::Bootstrap {
                identity: f.a.identity.clone(),
                expected: absent()
            },
            &[]
        ),
        (Err(Code::UnmanagedEntry), false)
    );
    assert_eq!(stdfs::read(&f.paths.entry).unwrap(), before);
    assert!(!f.paths.store.exists());
    assert!(!f.lock_path().exists());
    stdfs::remove_file(&f.paths.entry).unwrap();
    let bin = f.paths.entry.parent().unwrap();
    chmod(bin, 0o500);
    assert_eq!(
        f.execute(
            Action::Bootstrap {
                identity: f.a.identity.clone(),
                expected: absent()
            },
            &[]
        ),
        (Err(Code::ReadOnly), false)
    );
    assert!(!f.paths.store.exists());
    assert!(!f.lock_path().exists());
    chmod(bin, 0o700);
}

#[test]
fn unsafe_parent_symlink_and_foreign_writable_ancestor_are_not_repaired() {
    let f = Fixture::new();
    let local = f.paths.home_for_test().join(".local");
    let outside = f.root.path().join("outside");
    stdfs::create_dir(&outside).unwrap();
    chmod(&outside, 0o700);
    write(&outside.join("sentinel"), b"preserve", 0o600);
    symlink(&outside, &local).unwrap();
    assert_eq!(
        f.execute(
            Action::Bootstrap {
                identity: f.a.identity.clone(),
                expected: absent()
            },
            &[]
        ),
        (Err(Code::UnsafeState), false)
    );
    assert_eq!(stdfs::read(outside.join("sentinel")).unwrap(), b"preserve");
    assert!(stdfs::symlink_metadata(&local).unwrap().is_symlink());
    stdfs::remove_file(&local).unwrap();
    // The home itself is a shared volume anchor; a runtime directory below it
    // must stay private and is never repaired.
    stdfs::create_dir(&local).unwrap();
    chmod(&local, 0o722);
    assert_eq!(
        f.execute(Action::Status, &[]),
        (Err(Code::UnsafeState), false)
    );
    assert_eq!(
        stdfs::symlink_metadata(&local).unwrap().mode() & 0o777,
        0o722
    );
    chmod(&local, 0o700);
}

#[test]
fn fifo_linked_and_replaced_control_files_are_bounded_refusals() {
    let f = Fixture::new();
    Tree::open(&f.paths, true).unwrap();
    let path = f.lock_path();
    rustix::fs::mknodat(
        rustix::fs::CWD,
        &path,
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::from_raw_mode(0o600),
        0,
    )
    .unwrap();
    let began = Instant::now();
    assert_eq!(
        f.execute(Action::Status, &[]),
        (Err(Code::UnsafeState), false)
    );
    assert!(began.elapsed() < Duration::from_secs(1));
    assert!(
        stdfs::symlink_metadata(&path)
            .unwrap()
            .file_type()
            .is_fifo()
    );
    stdfs::remove_file(&path).unwrap();
    let sentinel = f.root.path().join("lock-sentinel");
    write(&sentinel, b"", 0o600);
    symlink(&sentinel, &path).unwrap();
    assert_eq!(
        f.execute(Action::Status, &[]),
        (Err(Code::UnsafeState), false)
    );
    stdfs::remove_file(&path).unwrap();
    stdfs::hard_link(&sentinel, &path).unwrap();
    assert_eq!(
        f.execute(Action::Status, &[]),
        (Err(Code::UnsafeState), false)
    );
    assert_eq!(stdfs::symlink_metadata(&sentinel).unwrap().nlink(), 2);
    assert!(!f.paths.store.exists());
}

#[test]
fn interrupted_stage_retains_receiving_identity_and_refuses_replay() {
    let f = Fixture::new();
    f.bootstrap();
    let before = selected_files(&f);
    assert_eq!(
        f.execute(
            Action::Stage {
                identity: f.b.identity.clone(),
                expected: f.expected()
            },
            &f.b.bytes[..f.b.bytes.len() / 2]
        ),
        (Err(Code::InputIncomplete), true)
    );
    let tree = Tree::open(&f.paths, false).unwrap();
    let directory = tree
        .existing_job(&f.request(Action::Status).correlation())
        .unwrap()
        .unwrap();
    let job = Job::read(&directory, &f.request(Action::Status).correlation()).unwrap();
    assert_eq!(job.candidate.as_ref().unwrap().state, SlotState::Receiving);
    let partial = stdfs::read(f.job_path().join(".candidate.pending")).unwrap();
    // read_exact fails before the first buffer is written in this small fixture.
    assert!(partial.len() < f.b.bytes.len());
    assert_eq!(
        f.execute(
            Action::Stage {
                identity: f.b.identity.clone(),
                expected: f.expected()
            },
            &f.b.bytes
        ),
        (Err(Code::StageExists), true)
    );
    assert_eq!(
        stdfs::read(f.job_path().join(".candidate.pending")).unwrap(),
        partial
    );
    assert_eq!(selected_files(&f), before);
    assert_eq!(
        f.execute(
            Action::Cleanup {
                bootstrap: Some(f.a.identity.clone()),
                candidate: Some(f.b.identity.clone())
            },
            &[]
        ),
        (Ok(ReplyBody::Cleaned), true)
    );
    assert_eq!(selected_files(&f), before);
}

#[test]
fn staged_bytes_bind_all_record_fields_hash_size_static_header_and_single_marker() {
    for field in [
        "version",
        "revision",
        "tree",
        "rustc",
        "sha",
        "interpreter",
        "marker",
        "source",
        "trailing",
    ] {
        let f = Fixture::new();
        f.bootstrap();
        let before = selected_files(&f);
        let mut bytes = f.b.bytes.clone();
        let mut identity = f.b.identity.clone();
        match field {
            "version" => identity.package_version = "v1.2.5".to_owned(),
            "revision" => identity.source_revision = "a".repeat(40),
            "tree" => identity.source_tree_sha256 = "d".repeat(64),
            "rustc" => identity.rustc = "rustc 1.94.0 (synthetic)".to_owned(),
            "sha" => identity.sha256 = "e".repeat(64),
            "interpreter" => bytes[64..68].copy_from_slice(&3_u32.to_le_bytes()),
            "marker" => bytes.extend_from_slice(&crate::build_record::tests::framed(
                &crate::build_record::tests::json("v1.2.4", TARGET, true),
            )),
            "source" => {
                bytes = crate::build_record::tests::release_executable(&[
                    &crate::build_record::tests::framed(&crate::build_record::tests::json(
                        "v1.2.4", TARGET, false,
                    )),
                ])
            }
            "trailing" => bytes.push(0),
            _ => unreachable!(),
        }
        if ["interpreter", "marker", "source"].contains(&field) {
            identity.sha256 = format!("{:x}", Sha256::digest(&bytes));
            identity.size = bytes.len() as u64;
        }
        let result = f.execute(
            Action::Stage {
                identity: identity.clone(),
                expected: f.expected(),
            },
            &bytes,
        );
        assert!(result.0.is_err(), "{field}");
        assert!(result.1, "{field}");
        assert_eq!(selected_files(&f), before, "{field}");
        assert!(f.job_path().join(".candidate.pending").exists(), "{field}");
        assert!(!f.job_path().join("candidate.cw").exists(), "{field}");
    }
}

#[test]
fn nonstage_trailing_input_and_unknown_or_gnu_image_refuse_before_effects() {
    let f = Fixture::new();
    assert_eq!(
        f.execute(
            Action::Bootstrap {
                identity: f.a.identity.clone(),
                expected: absent()
            },
            b"x"
        ),
        (Err(Code::InvalidFrame), false)
    );
    let mut engine = Engine::new(f.paths.clone(), Instant::now() + HANG);
    assert_eq!(
        engine.execute(
            &f.request(Action::Bootstrap {
                identity: f.a.identity.clone(),
                expected: absent()
            }),
            &mut Cursor::new([])
        ),
        Err(Code::UnsupportedImage)
    );
    assert!(!engine.effects_started);
    let mut identity = f.a.identity.clone();
    identity.target = "x86_64-unknown-linux-gnu".to_owned();
    assert_eq!(
        f.execute(
            Action::Bootstrap {
                identity,
                expected: absent()
            },
            &[]
        ),
        (Err(Code::CandidateRefused), false)
    );
    assert_no_home_effect(&f);
}

#[test]
fn current_previous_and_generation_mismatches_refuse_without_stage_effects() {
    let f = Fixture::new();
    f.bootstrap();
    let before = selected_files(&f);
    for field in ["current", "previous", "generation"] {
        let mut expected = f.expected();
        match field {
            "current" => expected.current = Some("c".repeat(64)),
            "previous" => expected.previous = Some("d".repeat(64)),
            _ => expected.generation += 1,
        }
        assert_eq!(
            f.execute(
                Action::Stage {
                    identity: f.b.identity.clone(),
                    expected
                },
                &f.b.bytes
            ),
            (Err(Code::StaleSelection), false)
        );
        assert_eq!(selected_files(&f), before);
        assert!(!f.job_path().join("candidate.cw").exists());
    }
}

#[test]
fn ordinary_store_change_after_stage_is_not_retargeted_or_published() {
    let f = Fixture::new();
    f.bootstrap();
    f.stage();
    let original = f.expected();
    let c = Payload::new("v1.2.5");
    let c_path = f.root.path().join("ordinary-c");
    write(&c_path, &c.bytes, 0o500);
    let store = f.store();
    store
        .publish_and_select(
            &Candidate {
                executable: c_path,
                admission: Admission::Pinned {
                    identity: c.identity.clone(),
                    sha256: c.identity.sha256.clone(),
                },
            },
            Some(1),
        )
        .unwrap();
    let before = selected_files(&f);
    assert_eq!(
        f.execute(
            Action::Update {
                identity: f.b.identity.clone(),
                expected: original
            },
            &[]
        ),
        (Err(Code::StaleSelection), false)
    );
    assert_eq!(selected_files(&f), before);
    assert!(!store.version_executable(&f.b.identity.sha256).exists());
}

#[test]
fn bootstrap_does_not_adopt_or_overwrite_an_ordinary_writer_after_absent_preflight() {
    for before_creation in [true, false] {
        let f = Fixture::new();
        let b_path = f.root.path().join("ordinary-initial-b");
        write(&b_path, &f.b.bytes, 0o500);
        let paths = f.paths.clone();
        let b = f.b.identity.clone();
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
        let (done_tx, done_rx) = std::sync::mpsc::sync_channel(1);
        let ordinary = thread::spawn(move || {
            ready_rx.recv_timeout(HANG).unwrap();
            let result = store::install(
                &paths.store,
                &paths.entry,
                &Candidate {
                    executable: b_path,
                    admission: Admission::Pinned {
                        identity: b.clone(),
                        sha256: b.sha256.clone(),
                    },
                },
                LOCK_BUDGET,
            )
            .map(|installed| {
                assert_eq!(installed.selected.current, b.sha256);
                assert_eq!(installed.selected.generation, 1);
            })
            .map_err(|_| Code::UnsafeState);
            done_tx.send(result).unwrap();
        });
        let mut engine = f.engine();
        let pause: Box<dyn FnOnce() -> Result<()> + Send> = Box::new(move || {
            // Both snapshots saw absence and A is already fully copied/admitted.
            // The unrelated ordinary updater does not take the role-only lock.
            ready_tx.send(()).map_err(|_| Code::Io)?;
            done_rx.recv_timeout(HANG).map_err(|_| Code::Deadline)?
        });
        if before_creation {
            engine.before_bootstrap_publication = Some(pause);
        } else {
            engine.before_bootstrap_selection = Some(pause);
        }
        assert_eq!(
            engine.execute(
                &f.request(Action::Bootstrap {
                    identity: f.a.identity.clone(),
                    expected: absent(),
                }),
                &mut Cursor::new([])
            ),
            Err(if before_creation {
                Code::UnmanagedEntry
            } else {
                Code::StaleSelection
            })
        );
        assert!(engine.effects_started);
        ordinary.join().unwrap();
        let selection = f.store().status().unwrap();
        assert_eq!(selection.generation, 1);
        assert_eq!(selection.current.as_ref(), Some(&f.b.identity.sha256));
        assert_eq!(selection.versions.len(), 1);
        assert!(!f.store().version_executable(&f.a.identity.sha256).exists());
        assert!(f.job_path().join("bootstrap.cw").exists());

        // Actual old publication API at this exact race boundary silently selects
        // A over B. Its late postcondition notices only after the default changed.
        let tree = Tree::open(&f.paths, false).unwrap();
        let directory = tree
            .existing_job(&f.request(Action::Status).correlation())
            .unwrap()
            .unwrap();
        let a = candidate(&directory, true, &f.a.identity).unwrap();
        let old = store::install(&f.paths.store, &f.paths.entry, &a, LOCK_BUDGET).unwrap();
        assert_eq!(old.selected.current, f.a.identity.sha256);
        assert_eq!(old.selected.generation, 2);
        assert_eq!(
            selected_reply(&old.store, &absent(), &f.a.identity, &old.selected),
            Err(Code::StaleSelection)
        );
        assert_eq!(
            f.store().status().unwrap().current,
            Some(f.a.identity.sha256.clone())
        );
    }
}

#[test]
fn cleanup_refuses_unknown_member_links_and_missing_lock_before_any_unlink() {
    let f = Fixture::new();
    f.bootstrap();
    f.stage();
    let action = Action::Cleanup {
        bootstrap: Some(f.a.identity.clone()),
        candidate: Some(f.b.identity.clone()),
    };
    let path = f.job_path();
    let original = stdfs::read(path.join(JOB)).unwrap();
    write(&path.join("unknown"), b"preserve", 0o600);
    assert_eq!(
        f.execute(action.clone(), &[]),
        (Err(Code::UnsafeState), false)
    );
    assert_eq!(stdfs::read(path.join(JOB)).unwrap(), original);
    assert!(path.join("bootstrap.cw").exists());
    assert!(path.join("candidate.cw").exists());
    stdfs::remove_file(path.join("unknown")).unwrap();
    let linked = f.root.path().join("candidate-link");
    stdfs::hard_link(path.join("candidate.cw"), &linked).unwrap();
    assert_eq!(
        f.execute(action.clone(), &[]),
        (Err(Code::UnsafeState), false)
    );
    assert_eq!(stdfs::read(path.join(JOB)).unwrap(), original);
    stdfs::remove_file(linked).unwrap();
    stdfs::remove_file(f.lock_path()).unwrap();
    assert_eq!(f.execute(action, &[]), (Err(Code::UnsafeState), false));
    assert!(!f.lock_path().exists());
    assert_eq!(stdfs::read(path.join(JOB)).unwrap(), original);
    assert!(path.join("bootstrap.cw").exists());
    assert!(path.join("candidate.cw").exists());
}

#[test]
fn changed_binding_directory_birth_and_legacy_manifest_remain_untouched() {
    let f = Fixture::new();
    f.bootstrap();
    let path = f.job_path();
    let before = stdfs::read(path.join(JOB)).unwrap();
    let action = Action::Cleanup {
        bootstrap: Some(f.a.identity.clone()),
        candidate: None,
    };
    let mut request = f.request(action.clone());
    request.binding_sha256 = "d".repeat(64);
    let mut engine = f.engine();
    assert_eq!(
        engine.execute(&request, &mut Cursor::new([])),
        Err(Code::UnsafeState)
    );
    assert!(!engine.effects_started);
    assert_eq!(stdfs::read(path.join(JOB)).unwrap(), before);
    let held = f.root.path().join("original-job");
    stdfs::rename(&path, &held).unwrap();
    stdfs::create_dir(&path).unwrap();
    chmod(&path, 0o700);
    write(&path.join(JOB), &before, 0o400);
    write(&path.join("bootstrap.cw"), &f.a.bytes, 0o500);
    assert_eq!(
        f.execute(action.clone(), &[]),
        (Err(Code::UnsafeState), false)
    );
    assert!(held.join("bootstrap.cw").exists());
    assert!(path.join("bootstrap.cw").exists());
    write(&path.join(JOB), b"{\"pid\":1234}\n", 0o400);
    assert_eq!(f.execute(action, &[]), (Err(Code::UnsafeState), false));
    assert!(held.join("bootstrap.cw").exists());
    assert!(path.join("bootstrap.cw").exists());
}

#[test]
fn replaced_directory_and_file_names_fail_held_fd_validation() {
    let f = Fixture::new();
    let tree = Tree::open(&f.paths, true).unwrap();
    let correlation = f.request(Action::Status).correlation();
    let directory = tree.new_job(&correlation).unwrap();
    let file = directory.create_file("test", 0o600).unwrap();
    drop(file);
    let held = directory.held_file("test", 0, 0o600).unwrap();
    stdfs::rename(directory.path().join("test"), directory.path().join("old")).unwrap();
    write(&directory.path().join("test"), b"", 0o600);
    assert_eq!(held.check(), Err(Code::UnsafeState));
    let old = f.root.path().join("held-job");
    stdfs::rename(directory.path(), &old).unwrap();
    stdfs::create_dir(directory.path()).unwrap();
    chmod(directory.path(), 0o700);
    assert_eq!(directory.check(false), Err(Code::UnsafeState));
    assert_eq!(
        tree.remove_job(&correlation, &directory),
        Err(Code::UnsafeState)
    );
    assert!(old.join("old").exists());
}

#[test]
fn concurrent_bootstraps_serialize_and_only_one_absent_selection_wins() {
    let f = Fixture::new();
    let barrier = Arc::new(Barrier::new(3));
    let mut threads = Vec::new();
    for _ in 0..2 {
        let barrier = Arc::clone(&barrier);
        let paths = f.paths.clone();
        let image = f.image.clone();
        let identity = f.a.identity.clone();
        let mut request = f.request(Action::Bootstrap {
            identity: identity.clone(),
            expected: absent(),
        });
        request.request_id = Uuid::new_v4();
        threads.push(thread::spawn(move || {
            let mut engine = Engine::new(paths, Instant::now() + HANG);
            engine.image_fixture = Some((image, identity));
            barrier.wait();
            engine.execute(&request, &mut Cursor::new([]))
        }));
    }
    barrier.wait();
    let results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert!(results.contains(&Err(Code::StaleSelection)));
    assert_eq!(f.status().generation, 1);
    assert_eq!(f.status().retained_count, 1);
}

#[test]
fn real_flock_blocks_mutation_until_bounded_deadline_without_creating_job() {
    let f = Fixture::new();
    f.bootstrap();
    let tree = Tree::open(&f.paths, false).unwrap();
    let _lock = tree
        .existing_mutation_lock(Instant::now() + HANG)
        .unwrap()
        .unwrap();
    let mut engine = f.engine();
    engine.deadline = Instant::now() + Duration::from_millis(100);
    let began = Instant::now();
    assert_eq!(
        engine.execute(
            &f.request(Action::Stage {
                identity: f.b.identity.clone(),
                expected: f.expected()
            }),
            &mut Cursor::new(&f.b.bytes)
        ),
        Err(Code::Deadline)
    );
    assert!(began.elapsed() >= Duration::from_millis(80));
    assert!(began.elapsed() < Duration::from_secs(1));
    assert!(!f.job_path().join("candidate.cw").exists());
}

#[test]
fn actual_nonblocking_fd_timeout_eof_and_flags_are_preserved() {
    let (mut peer, input) = UnixStream::pair().unwrap();
    let original = unsafe { libc::fcntl(input.as_raw_fd(), libc::F_GETFL) };
    let started = Instant::now();
    {
        let mut bounded =
            BoundedInput::fixture(input.as_raw_fd(), started + Duration::from_millis(80)).unwrap();
        let mut byte = [0];
        assert_eq!(
            bounded.read(&mut byte).unwrap_err().kind(),
            std::io::ErrorKind::TimedOut
        );
    }
    assert!(started.elapsed() < Duration::from_secs(1));
    assert_eq!(
        unsafe { libc::fcntl(input.as_raw_fd(), libc::F_GETFL) },
        original
    );
    peer.write_all(b"x").unwrap();
    drop(peer);
    let mut bounded = BoundedInput::fixture(input.as_raw_fd(), Instant::now() + HANG).unwrap();
    let mut byte = [0];
    assert_eq!(bounded.read(&mut byte).unwrap(), 1);
    assert_eq!(byte, *b"x");
    assert_eq!(bounded.read(&mut byte).unwrap(), 0);
}

struct OwnedChild {
    child: Child,
    pidfd: File,
    birth: String,
}

impl OwnedChild {
    fn spawn(f: &Fixture, mode: &'static str) -> Self {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--ignored",
                "--exact",
                "platform_cw_runtime::tests::owned_stage_subprocess",
                "--test-threads=1",
            ])
            .env_clear()
            .env(CHILD_ROOT, f.root.path())
            .env(CHILD_MODE, mode)
            .env("RUST_BACKTRACE", "0")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        // SAFETY: the child is single-threaded after fork; fixed scalar syscalls
        // preserve its parent and make only its own process group/session.
        unsafe {
            command.pre_exec(move || {
                let parent = libc::getppid();
                if parent <= 1
                    || libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0
                    || libc::getppid() != parent
                    || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
                    || libc::setsid() < 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                if mode != "stage" {
                    let mut blocked: libc::sigset_t = std::mem::zeroed();
                    if libc::signal(libc::SIGALRM, libc::SIG_IGN) == libc::SIG_ERR
                        || libc::sigemptyset(&raw mut blocked) != 0
                        || libc::sigaddset(&raw mut blocked, libc::SIGALRM) != 0
                        || libc::sigprocmask(
                            libc::SIG_BLOCK,
                            &raw const blocked,
                            std::ptr::null_mut(),
                        ) != 0
                    {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
        let child = command.spawn().unwrap();
        let birth = child_birth(child.id());
        // SAFETY: pidfd_open binds this already-proven direct child; the owned
        // descriptor is checked against the same birth before any signal.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, child.id(), 0) } as i32;
        assert!(fd >= 0);
        let pidfd = unsafe { File::from_raw_fd(fd) };
        assert_eq!(child_birth(child.id()), birth);
        Self {
            child,
            pidfd,
            birth,
        }
    }

    fn signal(&self, signal: i32) {
        // No numeric PID/group signal is used; this descriptor never retargets.
        let result = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.pidfd.as_raw_fd(),
                signal,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        };
        assert!(result == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH));
    }

    fn terminal(&self) -> bool {
        let mut p = libc::pollfd {
            fd: self.pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        unsafe { libc::poll(&raw mut p, 1, 0) > 0 && p.revents & libc::POLLIN != 0 }
    }

    fn wait(&mut self) -> std::process::ExitStatus {
        let until = Instant::now() + HANG;
        while !self.terminal() && Instant::now() < until {
            thread::sleep(Duration::from_millis(10))
        }
        assert!(self.terminal(), "owned child cleanup unknown");
        self.child.wait().unwrap()
    }

    /// Blocks until a child bounded by its own deadline ends. Its stdin stays
    /// open until then: `Child::wait` would close it first, ending a child
    /// that reads its input before its deadline could.
    fn wait_for_its_end(&mut self) -> std::process::ExitStatus {
        let mut p = libc::pollfd {
            fd: self.pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one pollfd for the owned pidfd, which outlives this call.
        while unsafe { libc::poll(&raw mut p, 1, -1) } != 1 {
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EINTR)
            );
        }
        self.child.wait().unwrap()
    }
}

impl Drop for OwnedChild {
    fn drop(&mut self) {
        self.signal(libc::SIGKILL);
        let _ = self.wait();
    }
}

fn child_birth(pid: u32) -> String {
    let stat = stdfs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
    let fields: Vec<_> = stat
        .rsplit_once(") ")
        .unwrap()
        .1
        .split_whitespace()
        .collect();
    assert_eq!(fields[1].parse::<u32>().unwrap(), std::process::id());
    fields[19].to_owned()
}

#[test]
fn actual_owned_child_cancellation_retains_stage_and_does_not_select_or_replay() {
    let f = Fixture::new();
    f.bootstrap();
    let before = selected_files(&f);
    let mut child = OwnedChild::spawn(&f, "stage");
    let request = f.request(Action::Stage {
        identity: f.b.identity.clone(),
        expected: f.expected(),
    });
    let stdin = child.child.stdin.as_mut().unwrap();
    stdin.write_all(&framed(&request)).unwrap();
    stdin.write_all(&f.b.bytes[..16]).unwrap();
    let until = Instant::now() + HANG;
    loop {
        let manifest = stdfs::read(f.job_path().join(JOB)).unwrap();
        let job: Job = serde_json::from_slice(&manifest).unwrap();
        if job
            .candidate
            .as_ref()
            .is_some_and(|slot| slot.state == SlotState::Receiving)
        {
            break;
        }
        assert!(
            !child.terminal(),
            "owned child exited before receiving evidence"
        );
        assert!(
            Instant::now() < until,
            "owned child did not enter receiving state"
        );
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(child_birth(child.child.id()), child.birth);
    let status = stdfs::read_to_string(format!("/proc/{}/status", child.child.id())).unwrap();
    assert!(status.lines().any(|line| line == "NoNewPrivs:\t1"));
    child.signal(libc::SIGTERM);
    assert_eq!(child.wait().signal(), Some(libc::SIGTERM));
    assert!(child.terminal());
    assert_eq!(selected_files(&f), before);
    assert_eq!(f.store().status().unwrap().versions.len(), 1);
    assert!(f.job_path().join(".candidate.pending").exists());
    assert!(!f.job_path().join("candidate.cw").exists());
    assert_eq!(
        f.execute(
            Action::Stage {
                identity: f.b.identity.clone(),
                expected: f.expected()
            },
            &f.b.bytes
        ),
        (Err(Code::StageExists), true)
    );
    // The identified cleanup is only attempted after exact pidfd death/reap.
    assert_eq!(
        f.execute(
            Action::Cleanup {
                bootstrap: Some(f.a.identity.clone()),
                candidate: Some(f.b.identity.clone())
            },
            &[]
        ),
        (Ok(ReplyBody::Cleaned), true)
    );
    assert_eq!(selected_files(&f), before);
}

#[test]
fn inherited_ignored_blocked_alarm_is_replaced_by_an_actual_kernel_deadline() {
    let f = Fixture::new();
    let mut original = OwnedChild::spawn(&f, "old-deadline");
    wait_alarm_ready(&f, &original, "old-deadline");
    // Past the old alarm's 1 s. After its witness the child only parks, so a
    // terminal child here can only be that alarm, however long this thread
    // was descheduled.
    thread::sleep(Duration::from_millis(1250));
    assert!(
        !original.terminal(),
        "the old ignored/blocked alarm unexpectedly fired"
    );
    assert_eq!(child_birth(original.child.id()), original.birth);
    original.signal(libc::SIGKILL);
    assert_eq!(original.wait().signal(), Some(libc::SIGKILL));
    // The repaired deadline proves itself: it alone ends this child, with
    // SIGALRM. There is no readiness witness to wait for, because a child
    // descheduled past its 1 s deadline before writing one would end without
    // it. Without the deadline the child ends at its own 8 s input deadline,
    // not by SIGALRM, so this waits for its end with no bound of its own.
    let mut repaired = OwnedChild::spawn(&f, "deadline");
    assert_eq!(repaired.wait_for_its_end().signal(), Some(libc::SIGALRM));
    assert_no_home_effect(&f);
}

/// Waits for the old-alarm child's witness, published after its alarm. That
/// child ends only by a signal, so this waits for the witness or the child's
/// end rather than a wall-clock bound that load can exceed. The end is read
/// before the witness: a witness published just before an end still counts.
fn wait_alarm_ready(f: &Fixture, child: &OwnedChild, mode: &str) {
    let path = f.root.path().join(format!("alarm-ready-{mode}"));
    loop {
        let ended = child.terminal();
        if path.exists() {
            break;
        }
        assert!(!ended, "alarm child died before its readiness witness");
        thread::sleep(Duration::from_millis(10));
    }
    let mut file = HeldFile::open(&path, 5, 0o600).unwrap();
    let mut bytes = Vec::new();
    file.file_mut().read_to_end(&mut bytes).unwrap();
    file.check().unwrap();
    assert_eq!(bytes, b"ready");
}

/// Publishes a complete witness: written and synced under a private name,
/// then renamed into place, so the owner never reads a partial one.
fn publish_witness(path: &Path) {
    let partial = path.with_extension("partial");
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&partial)
        .unwrap();
    file.write_all(b"ready").unwrap();
    file.sync_all().unwrap();
    stdfs::rename(&partial, path).unwrap();
}

#[test]
#[ignore = "only the controlled owner-cancellation fixture spawns this test"]
fn owned_stage_subprocess() {
    let root = PathBuf::from(std::env::var_os(CHILD_ROOT).expect("synthetic fixture root"));
    let a = Payload::new("v1.2.3");
    match std::env::var(CHILD_MODE).as_deref() {
        Ok("old-deadline") => {
            // Exact old alarm-only behavior, deliberately under the inherited
            // ignore/block state. The owner proves it stays live, then reaps it.
            unsafe { libc::alarm(1) };
            publish_witness(&root.join("alarm-ready-old-deadline"));
            // Only that alarm, the owner's kill or its death signal ends it.
            loop {
                thread::park();
            }
        }
        Ok("deadline") => arm_deadline(1).unwrap(),
        Ok("stage") => {}
        Ok("fd-exec") => {
            // Low-level held-FD execution witness only, not CW release intake.
            let path = root.join("fd-executable");
            let mut held = HeldFile::open(&path, 256 * 1024 * 1024, 0o555).unwrap();
            held.check().unwrap();
            write(&root.join("fd-ready"), b"ready", 0o600);
            let mut input = BoundedInput::stdin(Instant::now() + Duration::from_secs(5)).unwrap();
            let mut byte = [0];
            input.read_exact(&mut byte).unwrap();
            assert_eq!(byte, *b"E");
            super::launcher::execute(
                held.file_mut(),
                &[std::ffi::OsString::from("retained-true")],
            )
            .unwrap();
            panic!("held executable did not replace the child");
        }
        _ => panic!("unknown synthetic child mode"),
    }
    let deadline = Instant::now() + Duration::from_secs(8);
    let mut input = BoundedInput::stdin(deadline).unwrap();
    let request = wire::read_request(&mut input).unwrap();
    let mut engine = Engine::new(Paths::fixture(&root.join("home")), deadline);
    engine.image_fixture = Some((root.join("image-a"), a.identity));
    let _ = engine.execute(&request, &mut input);
    panic!("controlled cancellation child must not finish without the owner");
}

#[test]
fn platform_image_dispatch_host_musl_context_never_reads_store() {
    use std::ffi::{OsStr, OsString};
    use std::os::unix::ffi::OsStringExt as _;
    let invalid_unicode = OsString::from_vec(vec![0xff]);
    // Public musl cw can legitimately live at this image alias on a normal
    // UID1000 host. The context gate must skip before any fixed Store read.
    assert!(super::launcher::image_alias(Path::new("/usr/local/bin/cw")));
    for home in [
        None,
        Some(OsStr::new("")),
        Some(OsStr::new("/home/user")),
        Some(OsStr::new("/")),
        Some(OsStr::new("/home/codewire/")),
        Some(OsStr::new("/home/codewire/../codewire")),
        Some(invalid_unicode.as_os_str()),
    ] {
        assert!(
            super::launcher::admit_context::<()>((1000, 1000), home, || {
                panic!("host musl CW touched fixed platform Store");
            })
            .unwrap()
            .is_none()
        );
    }
    let platform_home = Some(OsStr::new("/home/codewire"));
    for owner in [(0, 0), (1000, 0), (0, 1000), (1001, 1000)] {
        assert!(
            super::launcher::admit_context::<()>(owner, platform_home, || {
                panic!("wrong owner touched fixed platform Store");
            })
            .unwrap()
            .is_none()
        );
    }
    assert_eq!(
        super::launcher::admit_context((1000, 1000), platform_home, || Ok(Some(7_u32))),
        Ok(Some(7))
    );
}

#[test]
fn platform_image_dispatch_private_roles_skip_all_admission() {
    use std::ffi::OsString;
    for role in [
        "_host-daemon",
        "_agent-driver",
        "_agent-control",
        "_agent-peer",
        "__platform-cw-runtime",
        "__hosted-daemon",
        "__hosted-exec",
        "__host-agent-control",
        "__environment-launch",
        "__native-network-worker",
        "__local-mesh",
        "__host-member",
        "__local-derp",
        "__local-credential-broker",
        "__local-git-repository-executor",
        "__unknown-future-helper",
    ] {
        assert!(
            super::launcher::admit_arguments::<()>(
                &[OsString::from("/codewire/bin/cw"), OsString::from(role)],
                || panic!("private role read selection/configuration"),
            )
            .unwrap()
            .is_none()
        );
    }
    assert!(
        super::launcher::admit_arguments::<()>(
            &[
                OsString::from(codewire_local_credentials::SSH_HELPER_BASENAME),
                OsString::from("host")
            ],
            || panic!("SSH helper read selection/configuration"),
        )
        .unwrap()
        .is_none()
    );
    assert_eq!(
        super::launcher::admit_arguments(
            &[
                OsString::from("/codewire/bin/cw"),
                OsString::from("--version")
            ],
            || Ok(Some(7_u32)),
        ),
        Ok(Some(7))
    );
    for path in ["/codewire/bin/cw", "/usr/local/bin/cw"] {
        assert!(super::launcher::image_alias(Path::new(path)));
    }
    for path in [
        "/home/codewire/.local/bin/cw",
        "/home/codewire/.local/share/codewire/cli/versions/a/cw",
        "/usr/bin/cw",
        "/codewire/bin/../bin/cw",
    ] {
        assert!(!super::launcher::image_alias(Path::new(path)));
    }
}

#[test]
fn platform_image_dispatch_absence_is_read_only_and_foreign_entry_refuses() {
    let f = Fixture::new();
    assert!(
        super::launcher::select(&f.paths, Instant::now() + Duration::from_secs(5))
            .unwrap()
            .is_none()
    );
    assert_no_home_effect(&f);
    let _tree = Tree::open(&f.paths, true).unwrap();
    write(&f.paths.entry, b"foreign command", 0o500);
    let before = stdfs::read(&f.paths.entry).unwrap();
    assert!(matches!(
        super::launcher::select(&f.paths, Instant::now() + Duration::from_secs(5)),
        Err(Code::UnmanagedEntry)
    ));
    assert_eq!(stdfs::read(&f.paths.entry).unwrap(), before);
    assert!(!f.paths.store.exists());
    assert!(!f.lock_path().exists());
}

#[test]
fn platform_image_dispatch_actual_store_selects_a_b_a_without_recovery() {
    let f = Fixture::new();
    f.bootstrap();
    f.stage();
    for (index, payload) in [&f.a, &f.b, &f.a].into_iter().enumerate() {
        if index == 1 {
            assert!(
                f.execute(
                    Action::Update {
                        identity: f.b.identity.clone(),
                        expected: f.expected()
                    },
                    &[]
                )
                .0
                .is_ok()
            );
        } else if index == 2 {
            assert!(
                f.execute(
                    Action::Rollback {
                        identity: f.a.identity.clone(),
                        expected: f.expected()
                    },
                    &[]
                )
                .0
                .is_ok()
            );
        }
        let before = selected_files(&f);
        let mut held = super::launcher::select(&f.paths, Instant::now() + Duration::from_secs(5))
            .unwrap()
            .unwrap();
        held.check().unwrap();
        held.file_mut().seek(SeekFrom::Start(0)).unwrap();
        let mut bytes = Vec::new();
        held.file_mut().read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, payload.bytes);
        assert_eq!(held.file_mut().metadata().unwrap().mode() & 0o7777, 0o555);
        assert_eq!(selected_files(&f), before);
    }
}

#[test]
fn platform_image_dispatch_pending_and_corrupt_current_are_preserved() {
    let f = Fixture::new();
    f.bootstrap();
    let path = f.paths.store.join("selection.json");
    let before = stdfs::read(&path).unwrap();
    let mut selection: Selection = serde_json::from_slice(&before).unwrap();
    selection.pending = Some(PendingSelection {
        operation: Uuid::new_v4().to_string(),
        generation: 1,
        from: Some(f.a.identity.sha256.clone()),
        to: f.b.identity.sha256.clone(),
    });
    write(&path, &serde_json::to_vec(&selection).unwrap(), 0o644);
    let intent = stdfs::read(&path).unwrap();
    assert!(matches!(
        super::launcher::select(&f.paths, Instant::now() + Duration::from_secs(5)),
        Err(Code::PendingSelection)
    ));
    assert_eq!(stdfs::read(&path).unwrap(), intent);
    write(&path, &before, 0o644);
    let executable = f.store().version_executable(&f.a.identity.sha256);
    chmod(&executable, 0o755);
    write(&executable, b"corrupt", 0o555);
    assert!(super::launcher::select(&f.paths, Instant::now() + Duration::from_secs(5)).is_err());
    assert_eq!(stdfs::read(&executable).unwrap(), b"corrupt");
    assert_eq!(stdfs::read(&path).unwrap(), before);
}

#[test]
fn platform_image_dispatch_unsafe_ancestry_and_linked_or_fifo_member_refuse() {
    for kind in ["ancestor", "symlink", "hardlink", "fifo"] {
        let f = Fixture::new();
        f.bootstrap();
        let selected = f.store().version_executable(&f.a.identity.sha256);
        let sentinel = f.root.path().join("sentinel");
        write(&sentinel, &f.a.bytes, 0o555);
        match kind {
            "ancestor" => chmod(&f.paths.home_for_test().join(".local"), 0o720),
            "symlink" | "hardlink" | "fifo" => {
                chmod(selected.parent().unwrap(), 0o755);
                stdfs::remove_file(&selected).unwrap();
                match kind {
                    "symlink" => symlink(&sentinel, &selected).unwrap(),
                    "hardlink" => stdfs::hard_link(&sentinel, &selected).unwrap(),
                    _ => {
                        let path = std::ffi::CString::new(selected.as_os_str().as_encoded_bytes())
                            .unwrap();
                        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o555) }, 0);
                    }
                }
                chmod(selected.parent().unwrap(), 0o555);
            }
            _ => unreachable!(),
        }
        assert!(
            super::launcher::select(&f.paths, Instant::now() + Duration::from_secs(5)).is_err(),
            "{kind}"
        );
        assert_eq!(stdfs::read(&sentinel).unwrap(), f.a.bytes);
    }
}

#[test]
fn platform_image_dispatch_full_intake_rejects_nonstatic_or_duplicate_record() {
    for kind in ["interpreter", "record"] {
        let f = Fixture::new();
        f.bootstrap();
        let mut bytes = f.b.bytes.clone();
        if kind == "interpreter" {
            bytes[64..68].copy_from_slice(&3_u32.to_le_bytes());
        } else {
            bytes.extend_from_slice(&crate::build_record::tests::framed(
                &crate::build_record::tests::json("v1.2.4", TARGET, true),
            ));
        }
        let payload = Payload::with_bytes("v1.2.4", bytes);
        let path = f.root.path().join("ordinary-writer-candidate");
        write(&path, &payload.bytes, 0o500);
        f.store()
            .publish_and_select(
                &Candidate {
                    executable: path,
                    admission: Admission::Pinned {
                        identity: payload.identity.clone(),
                        sha256: payload.identity.sha256.clone(),
                    },
                },
                Some(1),
            )
            .unwrap();
        let before = selected_files(&f);
        assert!(
            matches!(
                super::launcher::select(&f.paths, Instant::now() + Duration::from_secs(5)),
                Err(Code::CandidateRefused)
            ),
            "{kind}"
        );
        assert_eq!(selected_files(&f), before);
    }
}

#[test]
fn platform_image_dispatch_concurrent_ordinary_selection_refuses_mixed_tuple() {
    let f = Fixture::new();
    f.bootstrap();
    let source = f.root.path().join("ordinary-b");
    write(&source, &f.b.bytes, 0o500);
    let result = super::launcher::select_before_recheck(
        &f.paths,
        Instant::now() + Duration::from_secs(5),
        || {
            f.store()
                .publish_and_select(
                    &Candidate {
                        executable: source,
                        admission: Admission::Pinned {
                            identity: f.b.identity.clone(),
                            sha256: f.b.identity.sha256.clone(),
                        },
                    },
                    Some(1),
                )
                .unwrap();
        },
    );
    assert!(matches!(result, Err(Code::StaleSelection)));
    assert_eq!(f.expected().current, Some(f.b.identity.sha256.clone()));
}

#[test]
fn platform_image_dispatch_held_fd_exec_does_not_reopen_replaced_name() {
    let f = Fixture::new();
    let path = f.root.path().join("fd-executable");
    write(&path, &stdfs::read("/usr/bin/true").unwrap(), 0o555);
    let mut child = OwnedChild::spawn(&f, "fd-exec");
    let deadline = Instant::now() + Duration::from_secs(5);
    while !f.root.path().join("fd-ready").exists() {
        assert!(!child.terminal(), "owned child died before holding the FD");
        assert!(Instant::now() < deadline, "owned FD readiness deadline");
        thread::sleep(Duration::from_millis(10));
    }
    // The old inode remains held after replacement. Reopening this exact
    // pathname would run false; the original FD must still run true.
    stdfs::rename(&path, f.root.path().join("original-true")).unwrap();
    write(&path, &stdfs::read("/usr/bin/false").unwrap(), 0o555);
    child.child.stdin.as_mut().unwrap().write_all(b"E").unwrap();
    assert_eq!(child.wait().code(), Some(0));
    assert_eq!(
        stdfs::read(&path).unwrap(),
        stdfs::read("/usr/bin/false").unwrap()
    );
}

#[test]
fn platform_image_dispatch_missing_or_linked_store_lock_is_not_created_or_repaired() {
    for linked in [false, true] {
        let f = Fixture::new();
        f.bootstrap();
        let path = f.paths.store.join("lock");
        stdfs::remove_file(&path).unwrap();
        let sentinel = f.root.path().join("lock-sentinel");
        write(&sentinel, b"", 0o600);
        if linked {
            stdfs::hard_link(&sentinel, &path).unwrap();
        }
        let before = selected_files(&f);
        assert!(
            super::launcher::select(&f.paths, Instant::now() + Duration::from_secs(5)).is_err()
        );
        assert_eq!(selected_files(&f), before);
        assert_eq!(stdfs::symlink_metadata(&path).is_ok(), linked);
        assert_eq!(stdfs::read(&sentinel).unwrap(), b"");
        assert_eq!(
            stdfs::symlink_metadata(&sentinel).unwrap().nlink(),
            if linked { 2 } else { 1 }
        );
    }
}
