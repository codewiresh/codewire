use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};
use std::path::{Path, PathBuf};

use super::*;

/// A private stand-in for `/tmp` (owned by this user, 0700) and a state
/// root, both canonical.
fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let holder = tempfile::tempdir().unwrap();
    let base = std::fs::canonicalize(holder.path()).unwrap();
    let temporary = base.join("tmp");
    let state_root = base.join("state");
    for path in [&temporary, &state_root] {
        std::fs::create_dir(path).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    (holder, temporary, state_root)
}

fn mode(path: &Path) -> u32 {
    std::fs::symlink_metadata(path).unwrap().mode() & 0o7777
}

#[test]
fn root_ids_are_short_stable_and_distinct() {
    let a = root_id(Path::new("/home/a/.codewire/native-v1"));
    assert_eq!(a.len(), ROOT_ID_HEX);
    assert!(a.bytes().all(|byte| byte.is_ascii_hexdigit()));
    assert_eq!(a, root_id(Path::new("/home/a/.codewire/native-v1")));
    assert_ne!(a, root_id(Path::new("/home/a/.codewire/native-v1/engine")));
}

#[test]
fn a_root_gets_a_private_directory_named_by_its_digest() {
    let (_holder, temporary, state_root) = fixture();
    let uid = current_uid();
    let directory = prepare_in(&temporary, &state_root, uid).unwrap();
    let base = temporary.join(format!("cw-{uid}"));
    assert_eq!(directory, base.join(root_id(&state_root)));
    assert_eq!(predicted_in(&temporary, &state_root, uid), directory);
    for path in [&base, &directory] {
        assert_eq!(mode(path), 0o700, "{}", path.display());
    }
    assert_eq!(
        std::fs::read(directory.join(MARKER)).unwrap(),
        state_root.as_os_str().as_bytes()
    );
    // Idempotent, and a later process reads the same marker.
    assert_eq!(prepare_in(&temporary, &state_root, uid).unwrap(), directory);
    assert!(!state_root.join(RECORD).exists());
}

#[test]
fn a_digest_collision_fails_instead_of_sharing() {
    let (_holder, temporary, state_root) = fixture();
    let uid = current_uid();
    let directory = prepare_in(&temporary, &state_root, uid).unwrap();
    std::fs::remove_file(directory.join(MARKER)).unwrap();
    std::fs::write(directory.join(MARKER), b"/another/root").unwrap();
    std::fs::set_permissions(
        directory.join(MARKER),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let error = prepare_in(&temporary, &state_root, uid).unwrap_err();
    assert!(
        matches!(&error, SocketDirError::Collision { other, .. } if other == "/another/root"),
        "{error}"
    );
}

#[test]
fn a_held_default_name_falls_back_to_a_recorded_private_directory() {
    let (_holder, temporary, state_root) = fixture();
    let uid = current_uid();
    let default = temporary.join(format!("cw-{uid}"));
    // Not private: mode 0755. It is never repaired.
    std::fs::create_dir(&default).unwrap();
    std::fs::set_permissions(&default, std::fs::Permissions::from_mode(0o755)).unwrap();
    let directory = prepare_in(&temporary, &state_root, uid).unwrap();
    let base = directory.parent().unwrap().to_owned();
    assert!(valid_fallback(&temporary, &base, uid), "{}", base.display());
    assert_eq!(mode(&base), 0o700);
    assert_eq!(mode(&default), 0o755);
    let record = state_root.join(RECORD);
    assert_eq!(mode(&record), 0o600);
    assert_eq!(
        std::fs::read_to_string(&record).unwrap(),
        format!("{}\n", base.display())
    );
    assert_eq!(predicted_in(&temporary, &state_root, uid), directory);
    // tmpfiles removes the fallback: it is made again under the same name.
    std::fs::remove_dir_all(&base).unwrap();
    assert_eq!(prepare_in(&temporary, &state_root, uid).unwrap(), directory);
    assert_eq!(mode(&base), 0o700);
}

#[test]
fn a_link_under_the_default_name_is_not_followed() {
    let (holder, temporary, state_root) = fixture();
    let uid = current_uid();
    let elsewhere = holder.path().join("elsewhere");
    std::fs::create_dir(&elsewhere).unwrap();
    std::fs::set_permissions(&elsewhere, std::fs::Permissions::from_mode(0o700)).unwrap();
    symlink(&elsewhere, temporary.join(format!("cw-{uid}"))).unwrap();
    let directory = prepare_in(&temporary, &state_root, uid).unwrap();
    assert!(valid_fallback(&temporary, directory.parent().unwrap(), uid));
    assert_eq!(std::fs::read_dir(&elsewhere).unwrap().count(), 0);
}

#[test]
fn a_shared_writable_temporary_directory_is_refused() {
    let (_holder, temporary, state_root) = fixture();
    // Writable by others and not root-owned and sticky.
    std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o777)).unwrap();
    let error = prepare_in(&temporary, &state_root, current_uid()).unwrap_err();
    assert!(
        matches!(&error, SocketDirError::UnsafeTemporary { mode: 0o777, .. }),
        "{error}"
    );
    assert!(error.to_string().contains("sticky"), "{error}");
}

#[test]
fn only_a_temporary_child_with_the_user_prefix_is_a_fallback() {
    let temporary = Path::new("/tmp");
    assert!(valid_fallback(
        temporary,
        Path::new("/tmp/cw-1000.Ab12Cd34"),
        1000
    ));
    for path in [
        "/tmp/cw-1000",
        "/tmp/cw-1001.Ab12Cd34",
        "/tmp/cw-1000.",
        "/tmp/cw-1000.a/b",
        "/var/tmp/cw-1000.Ab12Cd34",
        "/tmp/cw-1000.../x",
    ] {
        assert!(!valid_fallback(temporary, Path::new(path), 1000), "{path}");
    }
}

#[test]
fn subdirectories_are_private_and_a_long_path_is_named() {
    let (_holder, temporary, state_root) = fixture();
    let directory = prepare_in(&temporary, &state_root, current_uid()).unwrap();
    let nested = ensure_subdirectory(&directory, &["v", "0123", "api"]).unwrap();
    assert_eq!(nested, directory.join("v/0123/api"));
    for path in [directory.join("v"), directory.join("v/0123"), nested] {
        assert_eq!(mode(&path), 0o700);
    }
    let fits = PathBuf::from(format!("/{}", "a".repeat(MAXIMUM_SOCKET_PATH_BYTES - 1)));
    check_length(&fits).unwrap();
    let long = PathBuf::from(format!("/{}", "a".repeat(MAXIMUM_SOCKET_PATH_BYTES)));
    let error = check_length(&long).unwrap_err();
    assert!(
        error.to_string().contains(&format!(
            "{} bytes, over the {MAXIMUM_SOCKET_PATH_BYTES}-byte limit",
            MAXIMUM_SOCKET_PATH_BYTES + 1
        )),
        "{error}"
    );
}

#[test]
fn refresh_marks_every_socket_and_directory_as_just_used() {
    let (_holder, temporary, state_root) = fixture();
    let directory = prepare_in(&temporary, &state_root, current_uid()).unwrap();
    let nested = ensure_subdirectory(&directory, &["vms", "id", "api"]).unwrap();
    let socket = nested.join("api.sock");
    let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    let old = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000);
    for path in [&directory, &nested, &socket] {
        rustix::fs::utimensat(
            rustix::fs::CWD,
            path.as_path(),
            &rustix::fs::Timestamps {
                last_access: rustix::fs::Timespec {
                    tv_sec: 1_000_000,
                    tv_nsec: 0,
                },
                last_modification: rustix::fs::Timespec {
                    tv_sec: 1_000_000,
                    tv_nsec: 0,
                },
            },
            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        )
        .unwrap();
        assert_eq!(
            std::fs::symlink_metadata(path).unwrap().modified().unwrap(),
            old
        );
    }
    refresh(&directory);
    for path in [&directory, &nested, &socket] {
        let modified = std::fs::symlink_metadata(path).unwrap().modified().unwrap();
        assert!(
            modified > old + std::time::Duration::from_secs(1_000_000_000),
            "{}",
            path.display()
        );
    }
}

#[test]
fn the_script_helper_predicts_the_same_directory() {
    let (_holder, _temporary, state_root) = fixture();
    let script =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/dev/native_socket_dir.py");
    let output = std::process::Command::new("python3")
        .arg(&script)
        .arg(&state_root)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let printed = String::from_utf8(output.stdout).unwrap();
    assert_eq!(printed.trim_end(), predicted(&state_root).to_str().unwrap());
}
