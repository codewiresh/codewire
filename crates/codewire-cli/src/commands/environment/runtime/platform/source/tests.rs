//! Real ordinary-owner FD/filesystem boundaries. Fixture bytes are inert and
//! deliberately do not establish a full executable/build-record admission.
use super::*;
use std::io::Write as _;
use std::os::unix::fs::{PermissionsExt as _, symlink};

fn fixture() -> (tempfile::TempDir, CwPayloadIdentity) {
    // Ancestry admission refuses symlinks, such as Darwin's /tmp and /var.
    let directory = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let identity = CwPayloadIdentity {
        schema_version: 2,
        protocol_version: 1,
        record_version: 1,
        package_version: "fixture".into(),
        target: "x86_64-unknown-linux-musl".into(),
        source_revision: "a".repeat(40),
        source_tree_sha256: "b".repeat(64),
        rustc: "rustc 1.93.0 fixture".into(),
        sha256: "c".repeat(64),
        size: 128,
    };
    fs::write(directory.path().join("cw"), vec![0; 128]).unwrap();
    fs::write(
        directory.path().join("cw-runtime.json"),
        identity.encode().unwrap(),
    )
    .unwrap();
    (directory, identity)
}

#[test]
fn held_input_is_bounded_lazy_and_preserved_through_eof() {
    let (directory, identity) = fixture();
    let mut held = Candidate::files(directory.path(), &identity.sha256).unwrap();
    assert_eq!(held.count, 0);
    assert_eq!(held.next().unwrap().unwrap().len(), 128);
    assert!(held.next().is_none());
    assert!(directory.path().join("cw").exists());
    assert!(Candidate::open(directory.path(), &identity.sha256).is_err());
}

#[test]
fn replaced_changed_or_linked_inputs_refuse_without_cleanup() {
    for replace in [false, true] {
        let (directory, identity) = fixture();
        let mut held = Candidate::files(directory.path(), &identity.sha256).unwrap();
        let path = directory.path().join("cw");
        if replace {
            fs::rename(&path, directory.path().join("original")).unwrap();
            fs::write(&path, vec![0; 128]).unwrap();
        } else {
            let mut file = OpenOptions::new().write(true).open(&path).unwrap();
            file.write_all(&[1]).unwrap();
        }
        assert!(held.next().unwrap().is_err());
        assert!(path.exists());
    }
    let (directory, identity) = fixture();
    fs::hard_link(directory.path().join("cw"), directory.path().join("linked")).unwrap();
    assert!(Candidate::files(directory.path(), &identity.sha256).is_err());
    assert!(directory.path().join("linked").exists());
}

#[test]
fn fifo_symlink_unsafe_ancestor_and_bad_pin_refuse_before_reading() {
    let (directory, identity) = fixture();
    let path = directory.path().join("cw");
    fs::remove_file(&path).unwrap();
    let name = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    let started = std::time::Instant::now();
    assert!(Candidate::files(directory.path(), &identity.sha256).is_err());
    assert!(started.elapsed() < std::time::Duration::from_secs(1));
    fs::remove_file(&path).unwrap();
    symlink("cw-runtime.json", &path).unwrap();
    assert!(Candidate::files(directory.path(), &identity.sha256).is_err());
    fs::remove_file(&path).unwrap();
    fs::write(&path, vec![0; 128]).unwrap();
    assert!(Candidate::files(directory.path(), &"d".repeat(64)).is_err());
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o777)).unwrap();
    assert!(Candidate::files(directory.path(), &identity.sha256).is_err());
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    assert!(path.exists());
}
