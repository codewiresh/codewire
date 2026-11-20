use std::os::unix::fs::{PermissionsExt as _, symlink};

use super::*;

const BUNDLE: &str = "ca.crt";

fn ca_pem() -> String {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.self_signed(&key).unwrap().pem()
}

fn chmod(path: &Path, mode: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// A mount laid out as the kubelet lays out a ConfigMap volume:
/// `ca.crt -> ..data/ca.crt`, `..data -> ..<timestamp>`, the file 0444.
fn kubelet_mount() -> tempfile::TempDir {
    let mount = tempfile::tempdir().unwrap();
    let versioned = mount.path().join("..2026_11_16_13_00_00.1");
    std::fs::create_dir(&versioned).unwrap();
    std::fs::write(versioned.join(BUNDLE), ca_pem()).unwrap();
    chmod(&versioned.join(BUNDLE), 0o444);
    chmod(&versioned, 0o755);
    symlink("..2026_11_16_13_00_00.1", mount.path().join("..data")).unwrap();
    symlink("..data/ca.crt", mount.path().join(BUNDLE)).unwrap();
    chmod(mount.path(), 0o755);
    mount
}

/// Read `mount` as the platform's own mount: the tests below lay one out in
/// a plain directory, which the real check refuses.
fn read(mount: &Path) -> anyhow::Result<PlatformRoots> {
    extra_roots_from(true, false, mount, BUNDLE, |_| Ok(true))
}

fn open_directory(path: &Path) -> OwnedFd {
    rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .unwrap()
}

#[test]
fn the_kubelets_mount_is_read_and_its_links_followed_inside_it() {
    let mount = kubelet_mount();
    assert_eq!(read(mount.path()).unwrap().len(), 1);
}

#[test]
fn a_measured_workspace_or_a_daemon_outside_broker_mode_reads_no_bundle() {
    let mount = kubelet_mount();
    for (broker, measured) in [(true, true), (false, false)] {
        assert!(
            extra_roots_from(broker, measured, mount.path(), BUNDLE, |_| Ok(true))
                .unwrap()
                .is_empty()
        );
    }
}

/// #5523: with nothing mounted at the path, a valid bundle put there, owned
/// by a user the reader accepts, is not read, and the start goes on.
#[test]
fn a_bundle_planted_in_a_plain_directory_is_ignored() {
    let planted = kubelet_mount();
    assert_eq!(read(planted.path()).unwrap().len(), 1, "a valid bundle");
    assert!(
        derp_extra_roots(true, false, planted.path(), BUNDLE)
            .unwrap()
            .is_empty()
    );
}

/// On a path that is not the platform's mount nothing is inspected further,
/// so what would stop the start on the mount does not stop it here.
#[test]
fn only_the_platforms_mount_is_held_to_the_fatal_checks() {
    let writable = kubelet_mount();
    chmod(writable.path(), 0o777);
    assert!(read(writable.path()).is_err(), "fatal on the mount");
    assert!(
        extra_roots_from(true, false, writable.path(), BUNDLE, |_| Ok(false))
            .unwrap()
            .is_empty()
    );
    let malformed = tempfile::tempdir().unwrap();
    std::fs::write(malformed.path().join(BUNDLE), "not a certificate").unwrap();
    chmod(&malformed.path().join(BUNDLE), 0o444);
    chmod(malformed.path(), 0o755);
    assert!(read(malformed.path()).is_err(), "fatal on the mount");
    assert!(
        extra_roots_from(true, false, malformed.path(), BUNDLE, |_| Ok(false))
            .unwrap()
            .is_empty()
    );
}

#[test]
fn a_mount_root_is_told_from_a_directory_inside_a_filesystem() {
    assert!(is_mount_root(&open_directory(Path::new("/"))).unwrap());
    let plain = tempfile::tempdir().unwrap();
    let plain = open_directory(plain.path());
    assert!(!is_mount_root(&plain).unwrap());
    // The temporary directory is writable, so its filesystem is not
    // read-only either.
    assert!(!is_read_only(&plain).unwrap());
    assert!(!platform_mount(&plain).unwrap());
}

/// The positive side of the real check, on whatever read-only mounts this
/// machine has (`/sys`, in a container; often none on a workstation).
#[test]
fn a_read_only_mount_root_is_the_platforms_kind_of_mount() {
    let mounts = std::fs::read_to_string("/proc/self/mountinfo").unwrap();
    for line in mounts.lines() {
        let mut fields = line.split(' ');
        let (Some(point), Some(options)) = (fields.nth(4), fields.next()) else {
            continue;
        };
        if !options.split(',').any(|option| option == "ro") || point.contains('\\') {
            continue;
        }
        let Ok(directory) = rustix::fs::open(
            point,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) else {
            continue;
        };
        // A mount hidden under a later one opens as the later one.
        if !is_read_only(&directory).unwrap() {
            continue;
        }
        assert!(platform_mount(&directory).unwrap(), "{point}");
    }
}

#[test]
fn no_mount_or_no_bundle_is_no_extra_root() {
    let mount = tempfile::tempdir().unwrap();
    chmod(mount.path(), 0o755);
    assert!(read(&mount.path().join("absent")).unwrap().is_empty());
    assert!(read(mount.path()).unwrap().is_empty());
}

#[test]
fn a_bundle_the_workload_could_write_is_refused() {
    // Group- or world-writable bundle.
    for mode in [0o464, 0o446, 0o666] {
        let mount = tempfile::tempdir().unwrap();
        std::fs::write(mount.path().join(BUNDLE), ca_pem()).unwrap();
        chmod(&mount.path().join(BUNDLE), mode);
        chmod(mount.path(), 0o755);
        assert!(read(mount.path()).is_err(), "{mode:o}");
    }
    // A writable mount directory, whose links could be replaced.
    let mount = kubelet_mount();
    chmod(mount.path(), 0o777);
    assert!(read(mount.path()).is_err());
}

#[test]
fn a_link_that_leaves_the_mount_is_refused() {
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join(BUNDLE), ca_pem()).unwrap();
    chmod(&outside.path().join(BUNDLE), 0o444);
    let mount = tempfile::tempdir().unwrap();
    symlink(outside.path().join(BUNDLE), mount.path().join(BUNDLE)).unwrap();
    chmod(mount.path(), 0o755);
    assert!(read(mount.path()).is_err());
    // The mount path itself must not be a link.
    let real = kubelet_mount();
    let linked = tempfile::tempdir().unwrap();
    symlink(real.path(), linked.path().join("mount")).unwrap();
    assert!(read(&linked.path().join("mount")).is_err());
}

#[test]
fn a_kernel_without_openat2_reads_no_bundle_rather_than_open_it_plainly() {
    assert!(matches!(bundle_or_none(Err(Errno::NOSYS)), Ok(None)));
    // Flags the kernel does not know: containment can't be confirmed.
    assert!(matches!(bundle_or_none(Err(Errno::INVAL)), Ok(None)));
    assert!(matches!(bundle_or_none(Err(Errno::NOENT)), Ok(None)));
    assert!(matches!(bundle_or_none(Err(Errno::XDEV)), Err(Errno::XDEV)));
}
