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

fn read(mount: &Path) -> anyhow::Result<PlatformRoots> {
    derp_extra_roots(true, false, mount, BUNDLE)
}

#[test]
fn the_kubelets_mount_is_read_and_its_links_followed_inside_it() {
    let mount = kubelet_mount();
    assert_eq!(read(mount.path()).unwrap().len(), 1);
}

#[test]
fn a_measured_workspace_or_a_daemon_outside_broker_mode_reads_no_bundle() {
    let mount = kubelet_mount();
    assert!(
        derp_extra_roots(true, true, mount.path(), BUNDLE)
            .unwrap()
            .is_empty()
    );
    assert!(
        derp_extra_roots(false, false, mount.path(), BUNDLE)
            .unwrap()
            .is_empty()
    );
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
