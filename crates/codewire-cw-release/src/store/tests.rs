use std::os::unix::fs::symlink;
use std::sync::{Arc, Barrier};

use super::*;
use crate::identity::{Arch, Os, tests::identity as base_identity};

struct Fixture {
    _dir: tempfile::TempDir,
    root: PathBuf,
    bin: PathBuf,
    entry: PathBuf,
    inputs: PathBuf,
}

impl Drop for Fixture {
    /// Immutable version directories are 0555; make them removable first.
    fn drop(&mut self) {
        make_removable(self._dir.path());
    }
}

fn make_removable(path: &Path) {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return;
    };
    if metadata.is_dir() {
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o700));
        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.flatten() {
                make_removable(&entry.path());
            }
        }
    }
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("bin");
    let inputs = dir.path().join("inputs");
    fs::create_dir(&bin).unwrap();
    fs::create_dir(&inputs).unwrap();
    Fixture {
        root: dir.path().join("share/codewire/cli"),
        entry: bin.join("cw"),
        bin,
        inputs,
        _dir: dir,
    }
}

fn host() -> Platform {
    Platform::host().expect("tests run on a release platform")
}

/// Bytes whose header is admitted for the host platform. They are never run.
fn executable(tag: u8) -> Vec<u8> {
    let mut bytes = vec![tag; 4096];
    match host().os {
        Os::Linux => {
            bytes[..8].copy_from_slice(b"\x7fELF\x02\x01\x01\x00");
            bytes[16..18].copy_from_slice(&3_u16.to_le_bytes());
            let machine: u16 = if host().arch == Arch::X86_64 { 62 } else { 183 };
            bytes[18..20].copy_from_slice(&machine.to_le_bytes());
        }
        Os::Macos => {
            bytes[..4].copy_from_slice(&0xfeed_facf_u32.to_le_bytes());
            let cpu: u32 = if host().arch == Arch::X86_64 {
                0x0100_0007
            } else {
                0x0100_000c
            };
            bytes[4..8].copy_from_slice(&cpu.to_le_bytes());
            bytes[12..16].copy_from_slice(&2_u32.to_le_bytes());
        }
    }
    bytes
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn pinned(fixture: &Fixture, version: &str, bytes: &[u8]) -> Candidate {
    let path = fixture.inputs.join(version);
    fs::write(&path, bytes).unwrap();
    let mut identity = base_identity(host().release_target().as_str());
    identity.package_version = version.into();
    identity.sha256 = digest(bytes);
    identity.size = bytes.len() as u64;
    Candidate {
        executable: path,
        admission: Admission::Pinned {
            sha256: identity.sha256.clone(),
            identity,
        },
    }
}

fn install_a(fixture: &Fixture) -> (Store, String) {
    let installed = install(
        &fixture.root,
        &fixture.entry,
        &pinned(fixture, "1.0.0-a", &executable(b'a')),
        DEFAULT_LOCK_TIMEOUT,
    )
    .unwrap();
    assert!(installed.created_store);
    assert_eq!(installed.selected.generation, 1);
    let sha = installed.published.sha256.clone();
    (installed.store, sha)
}

fn reopen(fixture: &Fixture) -> Store {
    Store::open(&fixture.root, DEFAULT_LOCK_TIMEOUT).unwrap()
}

/// Exact persisted default: selection bytes and the entry link target.
fn observed(fixture: &Fixture) -> (Vec<u8>, Option<PathBuf>) {
    (
        fs::read(fixture.root.join(SELECTION)).unwrap(),
        fs::read_link(&fixture.entry).ok(),
    )
}

fn stored_versions(fixture: &Fixture) -> Vec<String> {
    let mut names: Vec<_> = fs::read_dir(fixture.root.join(VERSIONS))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

fn assert_consistent(store: &Store, current: &str, generation: u64) {
    let status = store.status().unwrap();
    assert!(status.consistent, "{status:?}");
    assert_eq!(status.generation, generation);
    assert_eq!(status.current.as_deref(), Some(current));
    assert_eq!(
        status.entry_state,
        EntryState::Managed {
            sha256: current.to_owned()
        }
    );
    assert_eq!(
        fs::read_link(store.entry()).unwrap(),
        store.version_executable(current)
    );
}

#[test]
fn install_creates_an_immutable_version_and_managed_entry() {
    let fixture = fixture();
    let (store, a) = install_a(&fixture);
    assert_consistent(&store, &a, 1);
    let version = fixture.root.join(VERSIONS).join(&a);
    let mode = |path: &Path| fs::symlink_metadata(path).unwrap().mode() & 0o7777;
    assert_eq!(mode(&version), 0o555);
    assert_eq!(mode(&version.join(EXECUTABLE)), 0o555);
    assert_eq!(mode(&version.join(RECORD)), 0o444);
    assert_eq!(mode(&fixture.root.join(MANIFEST)), 0o444);
    assert_eq!(
        fs::read(version.join(EXECUTABLE)).unwrap(),
        executable(b'a')
    );
    let record = store.verify(&a).unwrap();
    assert_eq!(record.origin, Origin::PinnedRelease);
    assert_eq!(record.package_version, "1.0.0-a");
    assert_eq!(
        Store::locate(&store.version_executable(&a)).as_deref(),
        Some(store.root())
    );
    assert_eq!(Store::locate(&fixture.entry), None);
}

#[test]
fn selection_retains_every_version_and_rollback_restores_the_previous_default() {
    let fixture = fixture();
    let (store, a) = install_a(&fixture);
    let (published, selected) = store
        .publish_and_select(&pinned(&fixture, "1.0.0-b", &executable(b'b')), Some(1))
        .unwrap();
    let b = published.sha256;
    assert!(published.created);
    assert_eq!(
        (selected.generation, selected.previous.as_deref()),
        (2, Some(a.as_str()))
    );
    assert_consistent(&store, &b, 2);

    let rolled_back = store.rollback(None, Some(2)).unwrap();
    assert_eq!(
        (rolled_back.generation, rolled_back.current.as_str()),
        (3, a.as_str())
    );
    assert_consistent(&store, &a, 3);
    // Both versions remain stored and verifiable after the default moves.
    assert_eq!(store.verify(&b).unwrap().package_version, "1.0.0-b");
    assert_eq!(store.verify(&a).unwrap().package_version, "1.0.0-a");

    assert_eq!(store.rollback(Some("1.0.0-b"), None).unwrap().current, b);
    assert_eq!(store.rollback(Some(&a[..12]), None).unwrap().current, a);
    assert!(matches!(
        store.rollback(Some("9.9.9"), None),
        Err(StoreError::UnknownVersion(_))
    ));
    // Selecting the current version is not a new generation.
    let unchanged = store.select(&a, None).unwrap();
    assert!(!unchanged.changed);
    assert_eq!(unchanged.generation, 5);
}

#[test]
fn rollback_without_a_previous_version_is_refused() {
    let fixture = fixture();
    let (store, _) = install_a(&fixture);
    assert!(matches!(
        store.rollback(None, None),
        Err(StoreError::NoPreviousVersion)
    ));
}

#[test]
fn rejected_candidates_leave_the_default_and_versions_unchanged() {
    let fixture = fixture();
    let (store, _) = install_a(&fixture);
    let before = observed(&fixture);
    let versions = stored_versions(&fixture);
    let other_platform = Platform::ALL
        .into_iter()
        .find(|platform| *platform != host())
        .unwrap();

    let mut cases: Vec<(&str, Candidate)> = Vec::new();
    let mut corrupt = pinned(&fixture, "2.0.0-corrupt", &executable(b'c'));
    fs::write(&corrupt.executable, executable(b'x')).unwrap();
    cases.push(("corrupt bytes", corrupt.clone()));
    let mut truncated = pinned(&fixture, "2.0.0-truncated", &executable(b't'));
    fs::write(&truncated.executable, &executable(b't')[..2048]).unwrap();
    cases.push(("incomplete bytes", truncated.clone()));
    let mut wrong_target = pinned(&fixture, "2.0.0-target", &executable(b'w'));
    if let Admission::Pinned { identity, .. } = &mut wrong_target.admission {
        identity.target = other_platform.release_target().as_str().into();
    }
    cases.push(("wrong target", wrong_target));
    let mut unsupported = pinned(&fixture, "2.0.0-protocol", &executable(b'p'));
    if let Admission::Pinned { identity, .. } = &mut unsupported.admission {
        identity.protocol_version = 2;
    }
    cases.push(("unsupported protocol", unsupported));
    let mut substituted_pin = pinned(&fixture, "2.0.0-pin", &executable(b'q'));
    if let Admission::Pinned { sha256, .. } = &mut substituted_pin.admission {
        *sha256 = digest(b"another release");
    }
    cases.push(("pin differs from identity", substituted_pin));
    let mut not_executable = vec![b'#'; 4096];
    not_executable[..9].copy_from_slice(b"#!/bin/sh");
    cases.push(("script", pinned(&fixture, "2.0.0-script", &not_executable)));
    let oversized = fixture.inputs.join("oversized");
    File::create(&oversized)
        .unwrap()
        .set_len(MAX_EXECUTABLE_BYTES + 1)
        .unwrap();
    cases.push((
        "oversized self-install",
        Candidate {
            executable: oversized,
            admission: Admission::SelfInstall {
                package_version: "dev".into(),
            },
        },
    ));
    corrupt.admission = Admission::SelfInstall {
        package_version: "not a version".into(),
    };
    cases.push(("invalid package version", corrupt));
    truncated.executable = fixture.inputs.join("missing");
    cases.push(("missing executable", truncated));

    for (case, candidate) in cases {
        assert!(
            store.publish_and_select(&candidate, None).is_err(),
            "{case}"
        );
        assert!(store.publish(&candidate).is_err(), "{case}");
        assert_eq!(observed(&fixture), before, "{case}");
        assert_eq!(stored_versions(&fixture), versions, "{case}");
    }
}

#[test]
fn identical_republication_is_idempotent_and_substitution_is_refused() {
    let fixture = fixture();
    let (store, a) = install_a(&fixture);
    let again = store
        .publish(&pinned(&fixture, "1.0.0-a", &executable(b'a')))
        .unwrap();
    assert!(!again.created);
    let b = store
        .publish(&pinned(&fixture, "1.0.0-b", &executable(b'b')))
        .unwrap()
        .sha256;

    let path = store.version_executable(&b);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    fs::write(&path, executable(b'z')).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o555)).unwrap();
    let before = observed(&fixture);
    assert!(matches!(
        store.select(&b, None),
        Err(StoreError::CorruptVersion { .. })
    ));
    assert!(matches!(
        store.publish(&pinned(&fixture, "1.0.0-b", &executable(b'b'))),
        Err(StoreError::CorruptVersion { .. })
    ));
    assert_eq!(observed(&fixture), before);
    assert_consistent(&store, &a, 1);
}

#[test]
fn interrupted_publication_is_discarded_by_the_next_operation() {
    let fixture = fixture();
    let (mut store, a) = install_a(&fixture);
    let before = observed(&fixture);
    store.fault = Some(Fault::Staged);
    assert!(matches!(
        store.publish(&pinned(&fixture, "1.0.0-b", &executable(b'b'))),
        Err(StoreError::InjectedFault(Fault::Staged))
    ));
    assert!(
        stored_versions(&fixture)
            .iter()
            .any(|name| name.starts_with(STAGING_PREFIX))
    );
    let store = reopen(&fixture);
    assert_eq!(store.recover().unwrap(), Recovery::Clean);
    assert_eq!(stored_versions(&fixture), vec![a.clone()]);
    assert_eq!(observed(&fixture), before);
}

#[test]
fn interrupted_selection_recovers_to_the_exact_observed_entry() {
    for (fault, completes) in [
        (Fault::IntentWritten, false),
        (Fault::SwapLinkCreated, false),
        (Fault::EntrySwapped, true),
    ] {
        let fixture = fixture();
        let (mut store, a) = install_a(&fixture);
        let b = store
            .publish(&pinned(&fixture, "1.0.0-b", &executable(b'b')))
            .unwrap()
            .sha256;
        store.fault = Some(fault);
        assert!(matches!(
            store.select(&b, Some(1)),
            Err(StoreError::InjectedFault(at)) if at == fault
        ));

        let store = reopen(&fixture);
        let status = store.status().unwrap();
        assert!(!status.consistent, "{fault:?}");
        assert_eq!(status.pending.as_ref().unwrap().to, b);
        let recovered = store.recover().unwrap();
        let swap_links = fs::read_dir(&fixture.bin).unwrap().count();
        // The selected entry and its permanent cross-store coordination lock.
        assert_eq!(swap_links, 2, "{fault:?} left a swap link");
        if completes {
            assert_eq!(
                recovered,
                Recovery::Completed {
                    generation: 2,
                    current: b.clone()
                }
            );
            assert_consistent(&store, &b, 2);
            assert_eq!(store.status().unwrap().previous, Some(a));
        } else {
            assert_eq!(recovered, Recovery::Abandoned { generation: 1 });
            assert_consistent(&store, &a, 1);
            // A retry after recovery selects normally.
            store.select(&b, Some(1)).unwrap();
            assert_consistent(&store, &b, 2);
        }
    }
}

#[test]
fn an_interrupted_selection_is_recovered_before_a_new_one() {
    let fixture = fixture();
    let (mut store, a) = install_a(&fixture);
    let b = store
        .publish(&pinned(&fixture, "1.0.0-b", &executable(b'b')))
        .unwrap()
        .sha256;
    store.fault = Some(Fault::EntrySwapped);
    assert!(store.select(&b, None).is_err());
    let store = reopen(&fixture);
    // The interrupted selection completed first; a stale fence now fails.
    assert!(matches!(
        store.rollback(None, Some(1)),
        Err(StoreError::GenerationMismatch {
            expected: 1,
            actual: 2
        })
    ));
    assert_eq!(store.rollback(None, Some(2)).unwrap().current, a);
}

#[test]
fn an_externally_changed_entry_is_reported_and_refused() {
    let fixture = fixture();
    let (mut store, a) = install_a(&fixture);
    let b = store
        .publish(&pinned(&fixture, "1.0.0-b", &executable(b'b')))
        .unwrap()
        .sha256;
    fs::remove_file(&fixture.entry).unwrap();
    symlink("/bin/sh", &fixture.entry).unwrap();
    let status = store.status().unwrap();
    assert!(!status.consistent);
    assert!(matches!(status.entry_state, EntryState::ForeignLink { .. }));
    assert!(matches!(
        store.select(&b, None),
        Err(StoreError::ExternallyChanged { .. })
    ));
    assert_eq!(fs::read_link(&fixture.entry).unwrap(), Path::new("/bin/sh"));

    // An intent is never completed from the record alone.
    fs::remove_file(&fixture.entry).unwrap();
    symlink(store.version_executable(&a), &fixture.entry).unwrap();
    store.fault = Some(Fault::IntentWritten);
    assert!(matches!(
        store.select(&b, None),
        Err(StoreError::InjectedFault(Fault::IntentWritten))
    ));
    fs::remove_file(&fixture.entry).unwrap();
    symlink("/bin/sh", &fixture.entry).unwrap();
    assert!(matches!(
        reopen(&fixture).recover(),
        Err(StoreError::ExternallyChanged { .. })
    ));
}

#[test]
fn a_stale_generation_fence_is_refused_without_change() {
    let fixture = fixture();
    let (store, a) = install_a(&fixture);
    let b = store
        .publish(&pinned(&fixture, "1.0.0-b", &executable(b'b')))
        .unwrap()
        .sha256;
    let before = observed(&fixture);
    assert!(matches!(
        store.select(&b, Some(0)),
        Err(StoreError::GenerationMismatch {
            expected: 0,
            actual: 1
        })
    ));
    assert_eq!(observed(&fixture), before);
    assert_consistent(&store, &a, 1);
}

#[test]
fn concurrent_fenced_selections_commit_exactly_once() {
    let fixture = fixture();
    let (store, _) = install_a(&fixture);
    let candidates: Vec<String> = (b'b'..=b'f')
        .map(|tag| {
            let version = format!("1.0.0-{}", tag as char);
            store
                .publish(&pinned(&fixture, &version, &executable(tag)))
                .unwrap()
                .sha256
        })
        .collect();
    let barrier = Arc::new(Barrier::new(candidates.len()));
    let threads: Vec<_> = candidates
        .into_iter()
        .map(|sha256| {
            let root = fixture.root.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let store = Store::open(&root, DEFAULT_LOCK_TIMEOUT).unwrap();
                barrier.wait();
                store
                    .select(&sha256, Some(1))
                    .map(|selected| selected.current)
            })
        })
        .collect();
    let results: Vec<_> = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect();
    let winners: Vec<_> = results
        .iter()
        .filter_map(|result| result.as_ref().ok())
        .collect();
    assert_eq!(winners.len(), 1, "{results:?}");
    assert!(
        results
            .iter()
            .filter(|result| result.is_err())
            .all(|result| matches!(
                result,
                Err(StoreError::GenerationMismatch {
                    expected: 1,
                    actual: 2
                })
            ))
    );
    assert_consistent(&store, winners[0], 2);
}

#[test]
fn a_held_lock_times_out_without_change() {
    let fixture = fixture();
    let (store, a) = install_a(&fixture);
    let b = store
        .publish(&pinned(&fixture, "1.0.0-b", &executable(b'b')))
        .unwrap()
        .sha256;
    let held = store.lock(true).unwrap();
    let waiting = Store::open(&fixture.root, Duration::from_millis(100)).unwrap();
    assert!(matches!(
        waiting.select(&b, None),
        Err(StoreError::LockTimeout(_))
    ));
    drop(held);
    assert_consistent(&store, &a, 1);
}

#[test]
fn an_unmanaged_regular_file_entry_is_left_untouched() {
    let fixture = fixture();
    fs::write(&fixture.entry, b"legacy cw").unwrap();
    fs::set_permissions(&fixture.entry, fs::Permissions::from_mode(0o755)).unwrap();
    let before = fs::symlink_metadata(&fixture.entry).unwrap();
    let error = install(
        &fixture.root,
        &fixture.entry,
        &pinned(&fixture, "1.0.0-a", &executable(b'a')),
        DEFAULT_LOCK_TIMEOUT,
    )
    .unwrap_err();
    assert!(
        matches!(
            &error,
            StoreError::UnmanagedEntry {
                kind: "regular file",
                ..
            }
        ),
        "{error}"
    );
    assert!(error.to_string().contains("will not replace or rename"));
    let after = fs::symlink_metadata(&fixture.entry).unwrap();
    assert_eq!(
        (
            before.ino(),
            before.mode(),
            before.len(),
            before.mtime(),
            before.mtime_nsec()
        ),
        (
            after.ino(),
            after.mode(),
            after.len(),
            after.mtime(),
            after.mtime_nsec()
        )
    );
    assert_eq!(fs::read(&fixture.entry).unwrap(), b"legacy cw");
    assert!(!fixture.root.exists());

    fs::remove_file(&fixture.entry).unwrap();
    symlink("/bin/sh", &fixture.entry).unwrap();
    assert!(matches!(
        install(
            &fixture.root,
            &fixture.entry,
            &pinned(&fixture, "1.0.0-a", &executable(b'a')),
            DEFAULT_LOCK_TIMEOUT,
        ),
        Err(StoreError::UnmanagedEntry { .. })
    ));
    assert!(!fixture.root.exists());
}

#[test]
fn a_read_only_entry_directory_is_refused_before_any_write() {
    let fixture = fixture();
    fs::set_permissions(&fixture.bin, fs::Permissions::from_mode(0o555)).unwrap();
    let result = install(
        &fixture.root,
        &fixture.entry,
        &pinned(&fixture, "1.0.0-a", &executable(b'a')),
        DEFAULT_LOCK_TIMEOUT,
    );
    fs::set_permissions(&fixture.bin, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(
        matches!(result, Err(StoreError::NotWritable { .. })),
        "{result:?}"
    );
    assert!(!fixture.root.exists());
    assert!(fs::symlink_metadata(&fixture.entry).is_err());
}

#[test]
fn an_insecure_store_or_a_different_entry_is_refused() {
    let fixture = fixture();
    let (store, _) = install_a(&fixture);
    let other_entry = fixture.bin.join("cw-other");
    assert!(matches!(
        store.require_entry(&other_entry),
        Err(StoreError::EntryMismatch { .. })
    ));
    assert!(matches!(
        install(
            &fixture.root,
            &other_entry,
            &pinned(&fixture, "1.0.0-a", &executable(b'a')),
            DEFAULT_LOCK_TIMEOUT,
        ),
        Err(StoreError::EntryMismatch { .. })
    ));
    fs::set_permissions(&fixture.root, fs::Permissions::from_mode(0o775)).unwrap();
    assert!(matches!(
        Store::open(&fixture.root, DEFAULT_LOCK_TIMEOUT),
        Err(StoreError::Unsafe {
            reason: "writable by group or others",
            ..
        })
    ));
}

#[test]
fn self_install_records_this_build_and_reinstall_adds_a_version() {
    let fixture = fixture();
    let path = fixture.inputs.join("cw");
    fs::write(&path, executable(b's')).unwrap();
    let candidate = Candidate {
        executable: path.clone(),
        admission: Admission::SelfInstall {
            package_version: "dev".into(),
        },
    };
    let installed = install(
        &fixture.root,
        &fixture.entry,
        &candidate,
        DEFAULT_LOCK_TIMEOUT,
    )
    .unwrap();
    let first = installed.published.sha256.clone();
    assert_eq!(installed.published.record.origin, Origin::SelfInstall);
    assert_eq!(installed.published.record.payload, None);

    fs::write(&path, executable(b'u')).unwrap();
    let again = install(
        &fixture.root,
        &fixture.entry,
        &candidate,
        DEFAULT_LOCK_TIMEOUT,
    )
    .unwrap();
    assert!(!again.created_store);
    assert_eq!(again.selected.previous.as_deref(), Some(first.as_str()));
    assert_consistent(&again.store, &again.published.sha256, 2);
    assert!(again.store.verify(&first).is_ok());
}

/// rustix has no mkfifoat on Apple targets; libc's mkfifo is portable.
fn mkfifo(path: &Path) {
    use std::os::unix::ffi::OsStrExt as _;
    let path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    // SAFETY: `path` is a NUL-terminated string that lives past the call.
    let created = unsafe { libc::mkfifo(path.as_ptr(), 0o600) };
    assert_eq!(created, 0);
}

#[test]
fn fifo_and_symlink_candidates_are_refused_without_mutation() {
    for special in ["fifo", "symlink"] {
        let fixture = fixture();
        let (store, _) = install_a(&fixture);
        let candidate = pinned(&fixture, "1.0.0-b", &executable(b'b'));
        let original = candidate.executable.with_extension("original");
        fs::rename(&candidate.executable, &original).unwrap();
        if special == "fifo" {
            mkfifo(&candidate.executable);
        } else {
            symlink(&original, &candidate.executable).unwrap();
        }
        let before = observed(&fixture);
        let versions = stored_versions(&fixture);
        let started = Instant::now();
        assert!(
            store.publish_and_select(&candidate, None).is_err(),
            "{special}"
        );
        assert!(started.elapsed() < Duration::from_secs(1), "{special}");
        assert_eq!(observed(&fixture), before);
        assert_eq!(stored_versions(&fixture), versions);
    }
}

#[test]
fn fifo_state_version_and_lock_files_are_refused_promptly() {
    for selected in [MANIFEST, SELECTION, LOCK, RECORD, EXECUTABLE, "entry-lock"] {
        let fixture = fixture();
        let (store, a) = install_a(&fixture);
        let path = match selected {
            RECORD | EXECUTABLE => fixture.root.join(VERSIONS).join(&a).join(selected),
            "entry-lock" => fixture.bin.join(format!(".cw{ENTRY_LOCK_SUFFIX}")),
            _ => fixture.root.join(selected),
        };
        let parent = path.parent().unwrap();
        let mode = fs::metadata(parent).unwrap().mode() & 0o7777;
        set_mode(parent, 0o700).unwrap();
        fs::remove_file(&path).unwrap();
        mkfifo(&path);
        set_mode(parent, mode).unwrap();
        let started = Instant::now();
        let result = match selected {
            MANIFEST => Store::open(&fixture.root, DEFAULT_LOCK_TIMEOUT).map(|_| ()),
            RECORD | EXECUTABLE => store.verify(&a).map(|_| ()),
            "entry-lock" => store.recover().map(|_| ()),
            _ => store.status().map(|_| ()),
        };
        assert!(result.is_err(), "{selected}: {result:?}");
        assert!(started.elapsed() < Duration::from_secs(1), "{selected}");
        assert_eq!(
            FileType::from_raw_mode(
                rfs::statat(rfs::CWD, &path, AtFlags::SYMLINK_NOFOLLOW)
                    .unwrap()
                    .st_mode
            ),
            FileType::Fifo
        );
        if selected == RECORD {
            assert!(!store.status().unwrap().versions[0].recorded);
        }
    }
}

#[test]
fn inspection_never_creates_a_missing_lock_and_rejects_unsafe_locks() {
    let fixture = fixture();
    let (store, a) = install_a(&fixture);
    let before = observed(&fixture);
    let path = fixture.root.join(LOCK);
    fs::remove_file(&path).unwrap();
    assert!(store.status().is_err());
    assert!(store.verify(&a).is_err());
    assert!(!path.exists());
    assert_eq!(observed(&fixture), before);

    write_new_file(&path, b"", 0o600).unwrap();
    let linked = fixture.root.join("lock-alias");
    fs::hard_link(&path, &linked).unwrap();
    assert!(store.status().is_err());
    fs::remove_file(linked).unwrap();
    set_mode(&path, 0o666).unwrap();
    assert!(store.status().is_err());
    set_mode(&path, 0o600).unwrap();
    set_mode(&fixture.root, 0o555).unwrap();
    assert_consistent(&store, &a, 1);
    assert_eq!(store.verify(&a).unwrap().sha256, a);
    assert_eq!(observed(&fixture), before);
}

#[test]
fn reinstall_and_update_refuse_a_read_only_entry_before_publication() {
    let fixture = fixture();
    let (store, a) = install_a(&fixture);
    let candidate = pinned(&fixture, "1.0.0-b", &executable(b'b'));
    let before = observed(&fixture);
    let versions = stored_versions(&fixture);
    set_mode(&fixture.bin, 0o555).unwrap();
    assert!(matches!(
        install(
            &fixture.root,
            &fixture.entry,
            &candidate,
            DEFAULT_LOCK_TIMEOUT
        ),
        Err(StoreError::NotWritable { .. })
    ));
    assert!(matches!(
        store.publish_and_select(&candidate, None),
        Err(StoreError::NotWritable { .. })
    ));
    assert_eq!(observed(&fixture), before);
    assert_eq!(stored_versions(&fixture), versions);
    assert_consistent(&store, &a, 1);
}

#[test]
fn a_shared_writable_entry_parent_is_refused_before_store_or_lock_creation() {
    for mode in [0o775, 0o777] {
        let fixture = fixture();
        set_mode(&fixture.bin, mode).unwrap();
        let candidate = pinned(&fixture, "1.0.0-a", &executable(b'a'));
        assert!(matches!(
            install(
                &fixture.root,
                &fixture.entry,
                &candidate,
                DEFAULT_LOCK_TIMEOUT
            ),
            Err(StoreError::Unsafe {
                reason: "writable by group or others",
                ..
            })
        ));
        assert!(!fixture.root.exists());
        assert_eq!(fs::read_dir(&fixture.bin).unwrap().count(), 0);
    }
}

#[test]
fn different_stores_share_the_entry_lock_and_only_one_can_select() {
    let fixture = fixture();
    let one = Store::create(&fixture.root, &fixture.entry, DEFAULT_LOCK_TIMEOUT).unwrap();
    let other_root = fixture._dir.path().join("other-store");
    let two = Store::create(&other_root, &fixture.entry, Duration::from_millis(100)).unwrap();
    let a = one
        .publish(&pinned(&fixture, "1.0.0-a", &executable(b'a')))
        .unwrap()
        .sha256;
    let b = two
        .publish(&pinned(&fixture, "1.0.0-b", &executable(b'b')))
        .unwrap()
        .sha256;
    let held = EntryLock::acquire(&fixture.entry, DEFAULT_LOCK_TIMEOUT).unwrap();
    let before = fs::read(other_root.join(SELECTION)).unwrap();
    assert!(matches!(
        two.select(&b, Some(0)),
        Err(StoreError::LockTimeout(_))
    ));
    assert_eq!(fs::read(other_root.join(SELECTION)).unwrap(), before);
    assert!(fs::symlink_metadata(&fixture.entry).is_err());
    drop(held);

    // The race waits as long as a real selection does: on APFS the winner's
    // fsyncs can outlast the short timeout used above.
    let two = Store::open(&other_root, DEFAULT_LOCK_TIMEOUT).unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let threads: Vec<_> = [(one, a), (two, b)]
        .into_iter()
        .map(|(store, digest)| {
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                let result = store.select(&digest, Some(0));
                (store, digest, result)
            })
        })
        .collect();
    let results: Vec<_> = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect();
    assert_eq!(
        results
            .iter()
            .filter(|(_, _, result)| result.is_ok())
            .count(),
        1
    );
    for (store, digest, result) in results {
        match result {
            Ok(_) => assert_consistent(&store, &digest, 1),
            Err(StoreError::ExternallyChanged { .. }) => {
                let status = store.status().unwrap();
                assert_eq!(status.generation, 0);
                assert!(status.current.is_none() && status.pending.is_none());
            }
            other => panic!("unexpected competing-store result: {other:?}"),
        }
        store.verify(&digest).unwrap();
    }
}

fn replace_entry_with_a_regular_file(entry: &Path) {
    if fs::symlink_metadata(entry).is_ok() {
        fs::remove_file(entry).unwrap();
    }
    fs::write(entry, b"outside writer").unwrap();
}

fn replace_entry_with_an_equivalent_link(entry: &Path) {
    let target = fs::read_link(entry).unwrap();
    // Retain the old inode so recreation cannot immediately reuse it.
    fs::hard_link(entry, entry.with_file_name("retained-original-link")).unwrap();
    fs::remove_file(entry).unwrap();
    symlink(target, entry).unwrap();
}

#[test]
fn selection_fences_the_observed_entry_and_preserves_uncertain_intent() {
    for hook in [
        replace_entry_with_a_regular_file as fn(&Path),
        replace_entry_with_an_equivalent_link,
    ] {
        let fixture = fixture();
        let (mut store, a) = install_a(&fixture);
        let b = store
            .publish(&pinned(&fixture, "1.0.0-b", &executable(b'b')))
            .unwrap()
            .sha256;
        store.before_entry_commit = Some(hook);
        assert!(matches!(
            store.select(&b, Some(1)),
            Err(StoreError::ExternallyChanged { .. })
        ));
        let selection = store.read_selection().unwrap();
        assert_eq!(selection.current.as_deref(), Some(a.as_str()));
        assert_eq!(selection.pending.as_ref().unwrap().to, b);
        assert_eq!(selection.generation, 1);
        if fs::symlink_metadata(&fixture.entry).unwrap().is_file() {
            assert_eq!(fs::read(&fixture.entry).unwrap(), b"outside writer");
            let before = observed(&fixture);
            assert!(reopen(&fixture).recover().is_err());
            assert_eq!(observed(&fixture), before);
        } else {
            assert_eq!(
                fs::read_link(&fixture.entry).unwrap(),
                store.version_executable(&a)
            );
        }
        store.verify(&a).unwrap();
        store.verify(&b).unwrap();
    }
}

#[test]
fn first_selection_uses_no_replace_even_after_the_final_entry_check() {
    let fixture = fixture();
    let mut store = Store::create(&fixture.root, &fixture.entry, DEFAULT_LOCK_TIMEOUT).unwrap();
    let a = store
        .publish(&pinned(&fixture, "1.0.0-a", &executable(b'a')))
        .unwrap()
        .sha256;
    store.after_entry_check = Some(replace_entry_with_a_regular_file);
    assert!(
        matches!(store.select(&a, Some(0)), Err(StoreError::Io { source, .. }) if source.kind() == io::ErrorKind::AlreadyExists)
    );
    assert_eq!(fs::read(&fixture.entry).unwrap(), b"outside writer");
    let before = observed(&fixture);
    assert!(reopen(&fixture).recover().is_err());
    assert_eq!(observed(&fixture), before);
    assert!(store.read_selection().unwrap().pending.is_some());
}

#[test]
fn recovery_verifies_observed_bytes_and_keeps_corrupt_or_missing_intent() {
    for fault in [Fault::SwapLinkCreated, Fault::EntrySwapped] {
        for missing in [false, true] {
            let fixture = fixture();
            let (mut store, a) = install_a(&fixture);
            let b = store
                .publish(&pinned(&fixture, "1.0.0-b", &executable(b'b')))
                .unwrap()
                .sha256;
            store.fault = Some(fault);
            assert!(
                matches!(store.select(&b, Some(1)), Err(StoreError::InjectedFault(at)) if at == fault)
            );
            let observed_digest = if fault == Fault::EntrySwapped { &b } else { &a };
            let path = store.version_executable(observed_digest);
            let original = fs::read(&path).unwrap();
            if missing {
                set_mode(path.parent().unwrap(), 0o700).unwrap();
                fs::remove_file(&path).unwrap();
                set_mode(path.parent().unwrap(), 0o555).unwrap();
            } else {
                set_mode(&path, 0o755).unwrap();
                fs::write(&path, executable(b'x')).unwrap();
                set_mode(&path, 0o555).unwrap();
            }
            let before = observed(&fixture);
            let versions = stored_versions(&fixture);
            let swap = store.swap_link(&store.read_selection().unwrap().pending.unwrap().operation);
            let swap_before = fs::read_link(&swap).ok();
            assert!(
                reopen(&fixture).recover().is_err(),
                "{fault:?}, missing={missing}"
            );
            assert_eq!(observed(&fixture), before);
            assert_eq!(stored_versions(&fixture), versions);
            assert_eq!(fs::read_link(&swap).ok(), swap_before);
            assert!(reopen(&fixture).status().unwrap().pending.is_some());

            set_mode(path.parent().unwrap(), 0o700).unwrap();
            if !missing {
                set_mode(&path, 0o755).unwrap();
            }
            fs::write(&path, original).unwrap();
            set_mode(&path, 0o555).unwrap();
            set_mode(path.parent().unwrap(), 0o555).unwrap();
            let recovered = reopen(&fixture);
            recovered.recover().unwrap();
            assert_consistent(
                &recovered,
                observed_digest,
                if fault == Fault::EntrySwapped { 2 } else { 1 },
            );
        }
    }
}

#[test]
fn publication_refuses_the_version_limit_but_reuses_existing_valid_bytes() {
    let fixture = fixture();
    let (store, a) = install_a(&fixture);
    // Occupied digest names consume the bounded inventory even when an owner
    // has populated invalid records; only A is eligible for verified reuse.
    for value in 0..MAX_VERSIONS - 1 {
        create_dir(
            &fixture.root.join(VERSIONS).join(format!("{value:064x}")),
            0o555,
        )
        .unwrap();
    }
    let versions = stored_versions(&fixture);
    assert_eq!(versions.len(), MAX_VERSIONS);
    let before = observed(&fixture);
    let candidate = pinned(&fixture, "1.0.0-b", &executable(b'b'));
    assert!(matches!(
        store.publish_and_select(&candidate, None),
        Err(StoreError::Unsafe {
            reason: "too many stored versions",
            ..
        })
    ));
    let self_b = Candidate {
        executable: candidate.executable,
        admission: Admission::SelfInstall {
            package_version: "dev".into(),
        },
    };
    assert!(matches!(
        store.publish(&self_b),
        Err(StoreError::Unsafe {
            reason: "too many stored versions",
            ..
        })
    ));
    assert_eq!(stored_versions(&fixture), versions);
    assert_eq!(observed(&fixture), before);
    assert!(
        !store
            .publish(&pinned(&fixture, "1.0.0-a", &executable(b'a')))
            .unwrap()
            .created
    );
    let self_a = Candidate {
        executable: store.version_executable(&a),
        admission: Admission::SelfInstall {
            package_version: "dev".into(),
        },
    };
    assert!(!store.publish(&self_a).unwrap().created);
    assert_eq!(stored_versions(&fixture), versions);
    assert_eq!(observed(&fixture), before);
}

#[cfg(target_os = "linux")]
#[test]
fn only_self_install_may_follow_the_running_linux_image_link() {
    let fixture = fixture();
    let (store, _) = install_a(&fixture);
    let candidate = Candidate {
        executable: "/proc/self/exe".into(),
        admission: Admission::SelfInstall {
            package_version: "dev".into(),
        },
    };
    let published = store.publish(&candidate).unwrap();
    assert_eq!(published.record.origin, Origin::SelfInstall);
    assert_eq!(
        published.sha256,
        digest(&fs::read("/proc/self/exe").unwrap())
    );
    store.verify(&published.sha256).unwrap();
    let mut identity = base_identity(host().release_target().as_str());
    identity.package_version = "dev".into();
    identity.sha256 = published.sha256.clone();
    identity.size = published.record.size;
    let pinned = Candidate {
        executable: "/proc/self/exe".into(),
        admission: Admission::Pinned {
            sha256: identity.sha256.clone(),
            identity,
        },
    };
    // Existing-version reuse does not open a source at all. A fresh store
    // proves that pinned candidates cannot use the self-image exception.
    let other = fixture._dir.path().join("other-bin");
    fs::create_dir(&other).unwrap();
    let fresh = Store::create(
        &fixture._dir.path().join("fresh"),
        &other.join("cw"),
        DEFAULT_LOCK_TIMEOUT,
    )
    .unwrap();
    assert!(fresh.publish(&pinned).is_err());
}
