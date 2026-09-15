use super::*;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::os::unix::net::UnixListener;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[derive(Clone, Copy)]
struct Fault {
    point: &'static str,
    leaf: &'static str,
    skip: u32,
}

thread_local! {
    static FAULT: std::cell::Cell<Option<Fault>> = const { std::cell::Cell::new(None) };
}

pub(super) fn inject(point: &str, path: &Path) -> Result<(), PathError> {
    FAULT.with(|slot| {
        if let Some(mut fault) = slot.get() {
            if fault.point == point && path.as_os_str().as_bytes() == fault.leaf.as_bytes() {
                if fault.skip > 0 {
                    fault.skip -= 1;
                    slot.set(Some(fault));
                } else {
                    slot.set(None);
                    return Err(io_at(
                        path,
                        io::Error::other(format!("injected {point} failure")),
                    ));
                }
            }
        }
        Ok(())
    })
}

fn with_fault<T>(
    point: &'static str,
    leaf: &'static str,
    skip: u32,
    operation: impl FnOnce() -> T,
) -> T {
    struct Clear;
    impl Drop for Clear {
        fn drop(&mut self) {
            FAULT.with(|slot| slot.set(None));
        }
    }
    FAULT.with(|slot| {
        assert!(slot.get().is_none());
        slot.set(Some(Fault { point, leaf, skip }));
    });
    let _clear = Clear;
    operation()
}

fn root() -> (tempfile::TempDir, PrivateRoot) {
    let temporary = tempfile::tempdir().unwrap();
    let parent = fs::canonicalize(temporary.path()).unwrap();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
    let root = PrivateRoot::create(&parent.join("root")).unwrap();
    (temporary, root)
}

fn write(root: &PrivateRoot, name: &str, bytes: &[u8], mode: u32) {
    let mut file = root
        .create_regular(Path::new(name), mode, true)
        .unwrap()
        .into_file();
    file.write_all(bytes).unwrap();
    sync_full(&file).unwrap();
}

#[test]
fn raw_relative_aliases_are_rejected_before_path_normalization() {
    let (_temporary, root) = root();
    for invalid in [
        "",
        ".",
        "..",
        "/absolute",
        "a/../b",
        "a/./b",
        "a//b",
        "a/",
        "./a",
        "a\0b",
    ] {
        assert!(
            matches!(
                root.open_regular(Path::new(invalid), false, None, false, None),
                Err(PathError::InvalidRelativePath(_))
            ),
            "{invalid:?}"
        );
    }
    let non_utf8 = PathBuf::from(std::ffi::OsString::from_vec(b"native-\xff".to_vec()));
    validate_relative(&non_utf8).unwrap();
    assert_eq!(single_name(&non_utf8).unwrap().as_bytes(), b"native-\xff");
    // Path validation preserves raw Unix names; the underlying filesystem may
    // reject invalid UTF-8 (the actual APFS test returned EILSEQ). Exercise its
    // supported non-ASCII form without imposing a lossy conversion in the API.
    let native_name = Path::new("native-é");
    root.create_regular(native_name, 0o600, true).unwrap();
    assert!(
        root.open_regular(native_name, false, Some(0), false, Some(0o600))
            .is_ok()
    );
}

#[test]
fn absolute_root_spelling_and_replacement_fail_closed() {
    let (temporary, root) = root();
    let parent = fs::canonicalize(temporary.path()).unwrap();
    for suffix in ["/.", "/", "//", "/../root"] {
        let path = PathBuf::from(format!("{}{suffix}", root.path().display()));
        assert!(matches!(
            PrivateRoot::open(&path),
            Err(PathError::NonCanonicalRoot(_))
        ));
    }
    symlink(root.path(), parent.join("alias")).unwrap();
    assert!(PrivateRoot::open(&parent.join("alias")).is_err());
    fs::rename(root.path(), parent.join("retained-old")).unwrap();
    fs::create_dir(root.path()).unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    assert!(matches!(
        root.create_regular(Path::new("must-not-exist"), 0o600, true),
        Err(PathError::RootIdentityChanged(_))
    ));
    assert!(!root.path().join("must-not-exist").exists());
    assert!(!parent.join("retained-old/must-not-exist").exists());
}

#[test]
fn nested_directory_admission_preserves_requested_mode() {
    let (_temporary, root) = root();
    root.create_dir(Path::new("shared-mode"), 0o755).unwrap();
    root.ensure_dir(Path::new("shared-mode"), 0o755).unwrap();
    assert!(matches!(
        root.open_directory(Path::new("shared-mode"), 0o700),
        Err(PathError::UnsafeDirectory(_))
    ));
    let child = root
        .open_private_directory(Path::new("shared-mode"), 0o755)
        .unwrap();
    write(&child, "file", b"nested", 0o600);
    assert_eq!(
        root.open_regular(
            Path::new("shared-mode/file"),
            false,
            Some(6),
            false,
            Some(0o600)
        )
        .unwrap()
        .identity()
        .size,
        6
    );
}

#[test]
fn intermediate_and_final_symlinks_and_hardlinks_are_rejected() {
    let (_temporary, root) = root();
    let actual = root.create_dir(Path::new("actual"), 0o700).unwrap();
    write(
        &PrivateRoot::open(&actual).unwrap(),
        "file",
        b"inside",
        0o600,
    );
    symlink("actual", root.path().join("alias")).unwrap();
    symlink("actual/file", root.path().join("leaf-alias")).unwrap();
    for path in ["alias/file", "leaf-alias"] {
        assert!(
            root.open_regular(Path::new(path), false, None, false, None)
                .is_err()
        );
    }
    fs::hard_link(actual.join("file"), root.path().join("second")).unwrap();
    assert!(
        root.open_regular(Path::new("actual/file"), false, None, false, None)
            .is_err()
    );
}

#[test]
fn regular_admission_binds_size_mode_type_and_execution() {
    let (_temporary, root) = root();
    write(&root, "file", b"payload", 0o600);
    let admitted = root
        .open_regular(Path::new("file"), false, Some(7), false, Some(0o600))
        .unwrap();
    assert_eq!(admitted.identity().uid, current_uid());
    assert_eq!(admitted.identity().links, 1);
    for (size, executable, mode) in [
        (Some(8), false, None),
        (None, true, None),
        (None, false, Some(0o400)),
    ] {
        assert!(matches!(
            root.open_regular(Path::new("file"), false, size, executable, mode),
            Err(PathError::UnsafeFile(_))
        ));
    }
    fs::set_permissions(root.path().join("file"), fs::Permissions::from_mode(0o700)).unwrap();
    root.open_regular(Path::new("file"), false, Some(7), true, Some(0o700))
        .unwrap();
    fs::set_permissions(root.path().join("file"), fs::Permissions::from_mode(0o622)).unwrap();
    assert!(
        root.open_regular(Path::new("file"), false, None, false, None)
            .is_err()
    );
    root.create_dir(Path::new("directory"), 0o700).unwrap();
    assert!(
        root.open_regular(Path::new("directory"), false, None, false, None)
            .is_err()
    );
    let _socket = UnixListener::bind(root.path().join("socket")).unwrap();
    assert!(
        root.open_regular(Path::new("socket"), false, None, false, None)
            .is_err()
    );
}

#[test]
fn fifo_open_is_bounded_in_an_owned_child() {
    let (_temporary, root) = root();
    let fifo = CString::new(root.path().join("fifo").as_os_str().as_bytes()).unwrap();
    // SAFETY: a new synthetic path below the owned private root, with no device number.
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "darwin::path::tests::fifo_child_open",
            "--ignored",
        ])
        .env("CW_DARWIN_PATH_FIFO_CHILD", root.path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("FIFO admission blocked instead of rejecting the special file");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
#[ignore = "executed by fifo_open_is_bounded_in_an_owned_child with a three-second process deadline"]
fn fifo_child_open() {
    let path =
        std::env::var_os("CW_DARWIN_PATH_FIFO_CHILD").expect("parent-owned fixture path required");
    let root = PrivateRoot::open(Path::new(&path)).unwrap();
    assert!(
        root.open_regular(Path::new("fifo"), false, None, false, None)
            .is_err()
    );
}

#[test]
fn atomic_replace_retains_final_bytes_and_recovers_only_owned_temp() {
    let (temporary, root) = root();
    write(&root, ".state.tmp", b"interrupted", 0o600);
    root.atomic_replace(Path::new("state"), b"first", 0o600)
        .unwrap();
    root.atomic_replace(Path::new("state"), b"second", 0o400)
        .unwrap();
    assert_eq!(fs::read(root.path().join("state")).unwrap(), b"second");
    assert_eq!(
        fs::metadata(root.path().join("state")).unwrap().mode() & 0o777,
        0o400
    );
    let outside = temporary.path().join("outside");
    fs::write(&outside, b"unchanged").unwrap();
    symlink(&outside, root.path().join(".state.tmp")).unwrap();
    assert!(
        root.atomic_replace(Path::new("state"), b"bad", 0o600)
            .is_err()
    );
    assert_eq!(fs::read(&outside).unwrap(), b"unchanged");
    assert_eq!(fs::read(root.path().join("state")).unwrap(), b"second");
}

#[test]
fn atomic_replace_recovers_process_death_after_final_chmod() {
    let (_temporary, root) = root();
    write(&root, "state", b"old", 0o400);
    let stale = root
        .create_regular(Path::new(".state.tmp"), 0o600, true)
        .unwrap();
    // Model the durable namespace left by process death between final chmod
    // and rename, not a returned failure that invokes preparation cleanup.
    stale
        .file()
        .set_permissions(fs::Permissions::from_mode(0o400))
        .unwrap();
    sync_full(stale.file()).unwrap();
    drop(stale);
    root.atomic_replace(Path::new("state"), b"recovered", 0o400)
        .unwrap();
    assert_eq!(fs::read(root.path().join("state")).unwrap(), b"recovered");
    assert!(!root.path().join(".state.tmp").exists());
}

#[test]
fn no_replace_publication_leaves_loser_intact() {
    let (_temporary, root) = root();
    write(&root, "first", b"first", 0o400);
    write(&root, "second", b"second", 0o400);
    assert!(
        root.publish_private_regular_no_replace(Path::new("first"), Path::new("published"), 0o400)
            .unwrap()
    );
    assert!(
        !root
            .publish_private_regular_no_replace(Path::new("second"), Path::new("published"), 0o400)
            .unwrap()
    );
    assert_eq!(fs::read(root.path().join("published")).unwrap(), b"first");
    assert_eq!(fs::read(root.path().join("second")).unwrap(), b"second");
}

#[test]
fn directory_move_is_no_replace_and_remove_requires_empty() {
    let (_temporary, root) = root();
    root.create_dir(Path::new("source"), 0o700).unwrap();
    root.create_dir(Path::new("destination"), 0o700).unwrap();
    let destination = root
        .open_private_directory(Path::new("destination"), 0o700)
        .unwrap();
    root.move_private_directory_to(Path::new("source"), &destination, Path::new("moved"))
        .unwrap();
    root.create_dir(Path::new("second"), 0o700).unwrap();
    assert!(
        root.move_private_directory_to(Path::new("second"), &destination, Path::new("moved"))
            .is_err()
    );
    assert!(root.path().join("second").is_dir());
    assert!(
        root.remove_empty_private_directory(Path::new("destination"))
            .is_err()
    );
    destination
        .remove_empty_private_directory(Path::new("moved"))
        .unwrap();
    root.remove_empty_private_directory(Path::new("destination"))
        .unwrap();
}

#[test]
fn removal_admits_exact_regular_or_socket_without_following_replacement() {
    let (_temporary, root) = root();
    write(&root, "file", b"safe", 0o600);
    assert!(
        root.remove_private_regular(Path::new("file"), 0o400)
            .is_err()
    );
    assert!(
        root.remove_private_regular(Path::new("file"), 0o600)
            .unwrap()
    );
    assert!(
        !root
            .remove_private_regular(Path::new("file"), 0o600)
            .unwrap()
    );
    let path = root.path().join("socket");
    let socket = UnixListener::bind(&path).unwrap();
    let identity = set_socket_private(&path).unwrap();
    assert_eq!(identity, SocketIdentity::capture(&path).unwrap());
    assert!(root.remove_private_socket(Path::new("socket")).unwrap());
    assert!(!root.remove_private_socket(Path::new("socket")).unwrap());
    let _replacement = UnixListener::bind(&path).unwrap();
    set_socket_private(&path).unwrap();
    assert!(matches!(
        identity.revalidate(&path),
        Err(PathError::SocketIdentityChanged(_))
    ));
    drop(socket);
}

#[test]
fn all_mount_identity_fields_participate_in_admission() {
    let (_temporary, root) = root();
    let actual = MountIdentity::read(&root.directory).unwrap();
    for selector in 0..3 {
        let mut changed = actual.clone();
        match selector {
            0 => changed.device ^= 1,
            1 => changed.fsid[0] ^= 1,
            _ => changed.mounted_on.push(b'x'),
        }
        assert_ne!(actual, changed);
    }
}

#[test]
fn actual_nested_apfs_mount_is_rejected() {
    let status = Command::new("/usr/bin/python3")
        .arg("-c")
        .arg(include_str!("mount_fixture.py"))
        .arg(std::env::current_exe().unwrap())
        .stdin(Stdio::null())
        .status()
        .unwrap();
    assert!(
        status.success(),
        "owned mount fixture failed; inspect its retained-path diagnostic"
    );
}

#[test]
#[ignore = "executed by the owned APFS fixture with a twenty-second process deadline"]
fn mounted_volume_child() {
    let path =
        std::env::var_os("CW_DARWIN_PATH_MOUNT_CHILD").expect("owned mount fixture required");
    let root = PrivateRoot::open(Path::new(&path)).unwrap();
    // An absolute private root may itself be a mount root. Its successful ACL,
    // owner and mode admission discriminates those checks from NOXDEV policy.
    let mounted = PrivateRoot::open(&root.path().join("mounted")).unwrap();
    assert_ne!(root.mount, mounted.mount);
    assert_ne!(root.mount.device, mounted.mount.device);
    write(&mounted, "leaf", b"native mount", 0o600);
    assert!(matches!(root.open_directory(Path::new("mounted"), 0o700),
        Err(PathError::MountBoundary(path)) if path == root.path().join("mounted")));
    assert!(
        matches!(root.open_regular(Path::new("mounted/leaf"), false, None, false, None),
        Err(PathError::MountBoundary(path)) if path == root.path().join("mounted"))
    );
    root.create_dir(Path::new("source"), 0o700).unwrap();
    assert!(matches!(
        root.move_private_directory_to(Path::new("source"), &mounted, Path::new("moved")),
        Err(PathError::MountBoundary(_))
    ));
    assert!(root.path().join("source").is_dir());
    root.remove_empty_private_directory(Path::new("source"))
        .unwrap();
}

#[test]
fn failed_atomic_preparation_cleans_only_its_owned_temp_and_preserves_target() {
    for point in ["write", "chmod", "file-sync", "rename"] {
        let (_temporary, root) = root();
        root.atomic_replace(Path::new("state"), b"old", 0o600)
            .unwrap();
        let error = with_fault(point, ".state.tmp", 0, || {
            root.atomic_replace(Path::new("state"), b"new", 0o400)
        })
        .unwrap_err();
        assert!(matches!(error, PathError::Io { .. }), "{point}: {error:?}");
        assert_eq!(fs::read(root.path().join("state")).unwrap(), b"old");
        assert!(!root.path().join(".state.tmp").exists());
        root.atomic_replace(Path::new("state"), b"recovered", 0o400)
            .unwrap();
        assert_eq!(fs::read(root.path().join("state")).unwrap(), b"recovered");
    }
}

#[test]
fn failures_after_publication_retain_effect_and_report_uncertainty() {
    for point in ["after-effect", "parent-sync", "readmission"] {
        let (_temporary, root) = root();
        root.atomic_replace(Path::new("state"), b"old", 0o600)
            .unwrap();
        let error = with_fault(point, "state", 0, || {
            root.atomic_replace(Path::new("state"), b"published", 0o400)
        })
        .unwrap_err();
        assert!(
            matches!(error, PathError::PostEffectUncertain { .. }),
            "{point}: {error:?}"
        );
        assert_eq!(fs::read(root.path().join("state")).unwrap(), b"published");
        assert!(!root.path().join(".state.tmp").exists());
    }
}

#[test]
fn namespace_errors_after_create_remove_and_move_are_not_pre_effect_failures() {
    let (_temporary, root) = root();
    let error = with_fault("after-effect", "directory", 0, || {
        root.create_dir(Path::new("directory"), 0o700)
    })
    .unwrap_err();
    assert!(matches!(error, PathError::PostEffectUncertain { .. }));
    assert!(root.path().join("directory").is_dir());
    let error = with_fault("after-effect", "file", 0, || {
        root.create_regular(Path::new("file"), 0o600, true)
    })
    .unwrap_err();
    assert!(matches!(error, PathError::PostEffectUncertain { .. }));
    assert!(root.path().join("file").is_file());
    let error = with_fault("after-effect", "file", 0, || {
        root.remove_private_regular(Path::new("file"), 0o600)
    })
    .unwrap_err();
    assert!(matches!(error, PathError::PostEffectUncertain { .. }));
    assert!(!root.path().join("file").exists());
    root.create_dir(Path::new("destination"), 0o700).unwrap();
    let destination = root
        .open_private_directory(Path::new("destination"), 0o700)
        .unwrap();
    let error = with_fault("after-effect", "moved", 0, || {
        root.move_private_directory_to(Path::new("directory"), &destination, Path::new("moved"))
    })
    .unwrap_err();
    assert!(matches!(error, PathError::PostEffectUncertain { .. }));
    assert!(!root.path().join("directory").exists());
    assert!(destination.path().join("moved").is_dir());
    // Skip ensure_dir's post-mkdir check to reach create's separate final-open
    // boundary. Even this late failure cannot claim that nothing was created.
    let error = with_fault("after-effect", "new-root", 1, || {
        PrivateRoot::create(&root.path().join("new-root"))
    })
    .unwrap_err();
    assert!(matches!(error, PathError::PostEffectUncertain { .. }));
    assert!(root.path().join("new-root").is_dir());
}

#[test]
fn high_level_root_and_file_acl_admission_rejects_entries() {
    let (_temporary, root) = root();
    write(&root, "file", b"private", 0o600);
    let file = root.path().join("file");
    assert!(
        Command::new("/bin/chmod")
            .args(["+a", "everyone allow readattr"])
            .arg(&file)
            .status()
            .unwrap()
            .success()
    );
    assert!(
        root.open_regular(Path::new("file"), false, None, false, None)
            .is_err()
    );
    assert!(
        Command::new("/bin/chmod")
            .args(["+a", "everyone allow readattr"])
            .arg(root.path())
            .status()
            .unwrap()
            .success()
    );
    assert!(
        root.create_regular(Path::new("blocked"), 0o600, true)
            .is_err()
    );
    assert!(!root.path().join("blocked").exists());
}

#[test]
fn stale_temporary_files_with_aliases_modes_or_acls_are_preserved() {
    for defect in ["hardlink", "mode", "acl"] {
        let (_temporary, root) = root();
        write(&root, "state", b"original", 0o600);
        write(&root, ".state.tmp", b"preserve", 0o600);
        let temporary = root.path().join(".state.tmp");
        match defect {
            "hardlink" => fs::hard_link(&temporary, root.path().join("alias")).unwrap(),
            "mode" => fs::set_permissions(&temporary, fs::Permissions::from_mode(0o644)).unwrap(),
            _ => assert!(
                Command::new("/bin/chmod")
                    .args(["+a", "everyone allow readattr"])
                    .arg(&temporary)
                    .status()
                    .unwrap()
                    .success()
            ),
        }
        let identity = fs::metadata(&temporary).unwrap().ino();
        assert!(
            root.atomic_replace(Path::new("state"), b"bad", 0o600)
                .is_err()
        );
        assert_eq!(fs::metadata(&temporary).unwrap().ino(), identity);
        assert_eq!(fs::read(&temporary).unwrap(), b"preserve");
        assert_eq!(fs::read(root.path().join("state")).unwrap(), b"original");
    }
}

#[test]
fn publication_socket_and_directory_removal_post_effect_failures_preserve_state() {
    let (_temporary, root) = root();
    write(&root, "source", b"published", 0o400);
    let error = with_fault("readmission", "destination", 0, || {
        root.publish_private_regular_no_replace(
            Path::new("source"),
            Path::new("destination"),
            0o400,
        )
    })
    .unwrap_err();
    assert!(matches!(error, PathError::PostEffectUncertain { .. }));
    assert!(!root.path().join("source").exists());
    assert_eq!(
        fs::read(root.path().join("destination")).unwrap(),
        b"published"
    );

    let socket = root.path().join("socket");
    let _listener = UnixListener::bind(&socket).unwrap();
    let error =
        with_fault("after-effect", "socket", 0, || set_socket_private(&socket)).unwrap_err();
    assert!(matches!(error, PathError::PostEffectUncertain { .. }));
    SocketIdentity::capture(&socket).unwrap();
    let error = with_fault("after-effect", "socket", 0, || {
        root.remove_private_socket(Path::new("socket"))
    })
    .unwrap_err();
    assert!(matches!(error, PathError::PostEffectUncertain { .. }));
    assert!(!socket.exists());

    root.create_dir(Path::new("directory"), 0o700).unwrap();
    let error = with_fault("after-effect", "directory", 0, || {
        root.remove_empty_private_directory(Path::new("directory"))
    })
    .unwrap_err();
    assert!(matches!(error, PathError::PostEffectUncertain { .. }));
    assert!(!root.path().join("directory").exists());
}
