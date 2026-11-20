use super::*;
use std::fs;
use std::os::unix::fs::{PermissionsExt as _, symlink};

fn mode(path: &Path) -> u32 {
    fs::symlink_metadata(path).unwrap().mode() & 0o7777
}

fn euid() -> u32 {
    rustix::process::geteuid().as_raw()
}

#[test]
fn every_refusal_says_only_that_staging_is_unavailable() {
    for refusal in [
        StagingUnavailable::Mount,
        StagingUnavailable::Private,
        StagingUnavailable::Owner,
        StagingUnavailable::Mode,
        StagingUnavailable::Leftovers,
    ] {
        assert_eq!(refusal.to_string(), "cw runtime staging unavailable");
    }
}

#[test]
fn the_mount_is_fixed_unless_the_override_names_another() {
    assert_eq!(
        mount_path(None),
        Path::new("/var/lib/codewire-orchestration/staging")
    );
    assert_eq!(
        mount_path(Some("/srv/staging".into())),
        Path::new("/srv/staging")
    );
}

#[test]
fn startup_makes_an_absent_private_directory_0700_and_the_servers_even_below_setgid_2777() {
    for mount_mode in [0o700, 0o2777] {
        let mount = tempfile::tempdir().unwrap();
        fs::set_permissions(mount.path(), fs::Permissions::from_mode(mount_mode)).unwrap();
        let staging = Staging::open(mount.path()).unwrap();
        let private = mount.path().join("cw-runtime");
        assert_eq!(mode(&private), 0o700);
        assert_eq!(fs::metadata(&private).unwrap().uid(), euid());
        assert_eq!(staging.path(), private);
        // A restart finds it as it was left and opens it again.
        drop(staging);
        Staging::open(mount.path()).unwrap();
        assert_eq!(mode(&private), 0o700);
    }
}

#[test]
fn startup_refuses_a_missing_mount() {
    let parent = tempfile::tempdir().unwrap();
    let absent = parent.path().join("absent");
    assert_eq!(
        Staging::open(&absent).err(),
        Some(StagingUnavailable::Mount)
    );
    assert!(!absent.exists(), "a missing mount is never made");
    let file = parent.path().join("file");
    fs::write(&file, b"not a directory").unwrap();
    assert_eq!(Staging::open(&file).err(), Some(StagingUnavailable::Mount));
}

#[test]
fn startup_refuses_a_symlinked_or_unopenable_private_directory() {
    let mount = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    fs::set_permissions(elsewhere.path(), fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(elsewhere.path().join("kept"), b"outside").unwrap();
    let private = mount.path().join("cw-runtime");
    symlink(elsewhere.path(), &private).unwrap();
    assert_eq!(
        Staging::open(mount.path()).err(),
        Some(StagingUnavailable::Private)
    );
    assert!(
        fs::symlink_metadata(&private)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(fs::read(elsewhere.path().join("kept")).unwrap(), b"outside");

    fs::remove_file(&private).unwrap();
    fs::write(&private, b"a file where the directory goes").unwrap();
    assert_eq!(
        Staging::open(mount.path()).err(),
        Some(StagingUnavailable::Private)
    );
}

#[test]
fn startup_refuses_a_private_directory_another_user_owns() {
    let mount = tempfile::tempdir().unwrap();
    let other = euid().wrapping_add(1);
    // Made now, or found from an earlier run: either way it isn't the server's.
    for _ in 0..2 {
        assert_eq!(
            Staging::open_as(mount.path(), other).err(),
            Some(StagingUnavailable::Owner)
        );
        assert!(mount.path().join("cw-runtime").is_dir());
    }
    Staging::open_as(mount.path(), euid()).unwrap();
}

#[test]
fn startup_refuses_a_private_directory_whose_mode_is_not_exactly_0700() {
    for wrong in [0o750, 0o705, 0o770, 0o777, 0o2700, 0o1700, 0o500] {
        let mount = tempfile::tempdir().unwrap();
        let private = mount.path().join("cw-runtime");
        fs::create_dir(&private).unwrap();
        fs::set_permissions(&private, fs::Permissions::from_mode(wrong)).unwrap();
        assert_eq!(
            Staging::open(mount.path()).err(),
            Some(StagingUnavailable::Mode),
            "mode {wrong:o}"
        );
        assert_eq!(mode(&private), wrong, "a found directory is never repaired");
    }
}

#[test]
fn startup_empties_leftovers_without_following_a_symlink_out() {
    let mount = tempfile::tempdir().unwrap();
    let private = mount.path().join("cw-runtime");
    fs::create_dir(&private).unwrap();
    fs::set_permissions(&private, fs::Permissions::from_mode(0o700)).unwrap();
    let upload = private.join("codewire-cw-runtime-0f2c0d5e-7b0e-4d8a-9a43-5f0c2e1b7d10");
    fs::create_dir(&upload).unwrap();
    fs::set_permissions(&upload, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(upload.join("candidate.cw"), b"an earlier run's upload").unwrap();
    fs::set_permissions(
        upload.join("candidate.cw"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    fs::write(private.join("stray"), b"stray").unwrap();
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("target"), b"outside").unwrap();
    symlink(outside.path(), private.join("to-directory")).unwrap();
    symlink(outside.path().join("target"), private.join("to-file")).unwrap();
    symlink(private.join("missing"), private.join("dangling")).unwrap();

    let staging = Staging::open(mount.path()).unwrap();

    assert_eq!(fs::read_dir(&private).unwrap().count(), 0);
    assert_eq!(fs::read(outside.path().join("target")).unwrap(), b"outside");
    assert_eq!(fs::read_dir(outside.path()).unwrap().count(), 1);
    assert_eq!(mode(&private), 0o700);
    assert_eq!(staging.path(), private);
}

#[test]
fn startup_refuses_leftovers_it_cannot_remove() {
    let mount = tempfile::tempdir().unwrap();
    let private = mount.path().join("cw-runtime");
    fs::create_dir(&private).unwrap();
    fs::set_permissions(&private, fs::Permissions::from_mode(0o700)).unwrap();
    let mut deep = private.clone();
    for level in 0..=MAX_DEPTH + 1 {
        deep = deep.join(format!("level-{level}"));
        fs::create_dir(&deep).unwrap();
    }
    assert_eq!(
        Staging::open(mount.path()).err(),
        Some(StagingUnavailable::Leftovers)
    );
}
