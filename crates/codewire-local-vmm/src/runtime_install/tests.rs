use std::os::unix::fs::{MetadataExt, PermissionsExt};

use super::*;
use crate::artifact::{ArtifactArchitecture, ArtifactSpec};

struct Fixture {
    _dir: tempfile::TempDir,
    source: PathBuf,
    paths: RuntimePaths,
}

fn spec(path: &str, bytes: &[u8]) -> ArtifactSpec {
    ArtifactSpec {
        path: PathBuf::from(path),
        size: bytes.len() as u64,
        sha256: format!("{:x}", Sha256::digest(bytes)),
        architecture: ArtifactArchitecture::host().unwrap(),
    }
}

fn put_blob(source: &Path, bytes: &[u8]) {
    let blobs = source.join("blobs").join("sha256");
    fs::create_dir_all(&blobs).unwrap();
    fs::write(blobs.join(format!("{:x}", Sha256::digest(bytes))), bytes).unwrap();
}

fn blob(bytes: &[u8]) -> BlobRef {
    BlobRef {
        sha256: format!("{:x}", Sha256::digest(bytes)),
        size: bytes.len() as u64,
    }
}

/// A release directory for `files` (helper, kernel, guest root).
fn release(source: &Path, files: [&[u8]; 3]) -> LocalRuntimeDocument {
    release_with(source, files, None)
}

/// A release directory with an optional cw runtime `(lock, pack)`.
fn release_with(
    source: &Path,
    files: [&[u8]; 3],
    cw_runtime: Option<(&[u8], &[u8])>,
) -> LocalRuntimeDocument {
    for bytes in files {
        put_blob(source, bytes);
    }
    let lock = ArtifactLock::for_test(
        spec("vmm", files[0]),
        spec("kernel", files[1]),
        spec("initramfs", files[2]),
    );
    let cw_runtime = cw_runtime.map(|(lock, pack)| {
        put_blob(source, lock);
        put_blob(source, pack);
        CwRuntimeFiles {
            lock: blob(lock),
            pack: blob(pack),
        }
    });
    let document = LocalRuntimeDocument {
        schema: LOCAL_RUNTIME_SCHEMA.into(),
        source_revision: "a".repeat(40),
        release_tag: None,
        targets: BTreeMap::from([(
            host_target(),
            RuntimeTarget {
                lock: serde_json::to_value(&lock).unwrap(),
                cw_runtime,
            },
        )]),
    };
    fs::write(
        source.join(LOCAL_RUNTIME_DOCUMENT),
        serde_json::to_vec(&document).unwrap(),
    )
    .unwrap();
    document
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let source = dir.path().join("release");
    fs::create_dir(&source).unwrap();
    let parent = dir.path().join("local-vmm-v1");
    Fixture {
        source,
        paths: RuntimePaths {
            artifact_root: parent.join("artifacts"),
            artifact_lock: parent.join("artifacts.lock.json"),
        },
        _dir: dir,
    }
}

/// Admission as the supervisor sees it: every pinned file present, exact.
async fn admit_by_digest(lock: ArtifactLock, root: PathBuf) -> Result<(), ArtifactError> {
    let mut specs = lock.executables();
    specs.extend([&lock.kernel, &lock.initramfs]);
    for spec in specs {
        let path = root.join(&spec.path);
        let bytes = fs::read(&path).map_err(|_| ArtifactError::IdentityChanged(path.clone()))?;
        if format!("{:x}", Sha256::digest(&bytes)) != spec.sha256 {
            return Err(ArtifactError::IdentityChanged(path));
        }
    }
    Ok(())
}

async fn run(f: &Fixture, replace: bool) -> Result<InstallOutcome, InstallError> {
    let source = DirectoryBlobSource::new(&f.source);
    let document = source.document()?;
    install_with(&f.paths, &document, &source, replace, admit_by_digest).await
}

fn leftovers(f: &Fixture) -> Vec<String> {
    let mut names: Vec<_> = fs::read_dir(f.paths.artifact_lock.parent().unwrap())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with(".runtime-") && name != ".runtime-install.lock")
        .collect();
    names.sort();
    names
}

#[tokio::test]
async fn installs_exact_files_and_writes_the_lock_last() {
    let f = fixture();
    let document = release(&f.source, [b"vmm-1", b"kernel-1", b"initramfs-1"]);
    let generation = document.host_lock().unwrap().generation().unwrap();
    assert_eq!(
        run(&f, false).await.unwrap(),
        InstallOutcome::Installed {
            generation: generation.clone()
        }
    );
    let mode = |name: &str| {
        fs::metadata(f.paths.artifact_root.join(name))
            .unwrap()
            .mode()
            & 0o777
    };
    assert_eq!(
        (mode("vmm"), mode("kernel"), mode("initramfs")),
        (0o500, 0o400, 0o400)
    );
    assert_eq!(
        fs::read(f.paths.artifact_root.join("kernel")).unwrap(),
        b"kernel-1"
    );
    let lock = ArtifactLock::read(&f.paths.artifact_lock).unwrap();
    assert_eq!(lock, document.host_lock().unwrap());
    let parent = fs::metadata(f.paths.artifact_lock.parent().unwrap()).unwrap();
    assert_eq!(parent.mode() & 0o777, 0o700);
    assert!(leftovers(&f).is_empty(), "{:?}", leftovers(&f));

    // The same runtime again is admitted in place, not fetched.
    fs::remove_dir_all(f.source.join("blobs")).unwrap();
    assert_eq!(
        run(&f, false).await.unwrap(),
        InstallOutcome::AlreadyInstalled { generation }
    );
}

#[tokio::test]
async fn a_damaged_installed_file_is_fetched_again() {
    let f = fixture();
    release(&f.source, [b"vmm-1", b"kernel-1", b"initramfs-1"]);
    run(&f, false).await.unwrap();
    let kernel = f.paths.artifact_root.join("kernel");
    fs::set_permissions(&kernel, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&kernel, b"corrupted").unwrap();
    assert!(matches!(
        run(&f, false).await.unwrap(),
        InstallOutcome::Installed { .. }
    ));
    assert_eq!(fs::read(&kernel).unwrap(), b"kernel-1");
    assert!(leftovers(&f).is_empty());
}

#[tokio::test]
async fn a_different_runtime_is_replaced_only_on_request() {
    let f = fixture();
    release(&f.source, [b"vmm-1", b"kernel-1", b"initramfs-1"]);
    run(&f, false).await.unwrap();
    let newer = release(&f.source, [b"vmm-2", b"kernel-2", b"initramfs-2"]);
    assert!(matches!(
        run(&f, false).await,
        Err(InstallError::DifferentRuntimeInstalled(_))
    ));
    assert_eq!(
        fs::read(f.paths.artifact_root.join("vmm")).unwrap(),
        b"vmm-1"
    );

    run(&f, true).await.unwrap();
    assert_eq!(
        fs::read(f.paths.artifact_root.join("vmm")).unwrap(),
        b"vmm-2"
    );
    assert_eq!(
        ArtifactLock::read(&f.paths.artifact_lock).unwrap(),
        newer.host_lock().unwrap()
    );
    assert!(leftovers(&f).is_empty());
}

#[tokio::test]
async fn a_mismatched_or_missing_blob_installs_nothing() {
    let f = fixture();
    let document = release(&f.source, [b"vmm-1", b"kernel-1", b"initramfs-1"]);
    let initramfs = document.host_lock().unwrap().initramfs.sha256;
    let blob = f.source.join("blobs").join("sha256").join(&initramfs);
    fs::write(&blob, b"initramfs-X").unwrap();
    assert!(matches!(
        run(&f, false).await,
        Err(InstallError::BlobMismatch { sha256 }) if sha256 == initramfs
    ));
    fs::remove_file(&blob).unwrap();
    assert!(matches!(
        run(&f, false).await,
        Err(InstallError::MissingBlob { sha256 }) if sha256 == initramfs
    ));
    assert!(!f.paths.artifact_root.exists() && !f.paths.artifact_lock.exists());
    assert!(leftovers(&f).is_empty());
}

#[tokio::test]
async fn a_failed_admission_keeps_the_previous_runtime() {
    let f = fixture();
    release(&f.source, [b"vmm-1", b"kernel-1", b"initramfs-1"]);
    run(&f, false).await.unwrap();
    let source = DirectoryBlobSource::new(&f.source);
    let newer = release(&f.source, [b"vmm-2", b"kernel-2", b"initramfs-2"]);
    let refused = install_with(
        &f.paths,
        &newer,
        &source,
        true,
        |_, root: PathBuf| async move { Err(ArtifactError::IdentityChanged(root)) },
    )
    .await;
    assert!(matches!(refused, Err(InstallError::Artifact(_))));
    assert_eq!(
        fs::read(f.paths.artifact_root.join("vmm")).unwrap(),
        b"vmm-1"
    );
    assert!(leftovers(&f).is_empty());
}

#[test]
fn documents_name_their_schema_revision_and_host_target() {
    let f = fixture();
    let document = release(&f.source, [b"v", b"k", b"i"]);
    let parse = |value: serde_json::Value| {
        LocalRuntimeDocument::parse(&serde_json::to_vec(&value).unwrap())
    };
    let mut value = serde_json::to_value(&document).unwrap();
    assert!(parse(value.clone()).is_ok());
    value["schema"] = "codewire.cw.local-runtime/v2".into();
    assert!(matches!(
        parse(value.clone()),
        Err(InstallError::Document(_))
    ));
    value["schema"] = LOCAL_RUNTIME_SCHEMA.into();
    value["source_revision"] = "main".into();
    assert!(matches!(
        parse(value.clone()),
        Err(InstallError::Document(_))
    ));
    value["source_revision"] = "b".repeat(40).into();
    value["surprise"] = true.into();
    assert!(matches!(parse(value), Err(InstallError::Document(_))));

    let mut other = document.clone();
    let target = other.targets.remove(&host_target()).unwrap();
    other.targets = BTreeMap::from([("plan9-mips".into(), target)]);
    assert!(matches!(
        other.host_lock(),
        Err(InstallError::UnknownTarget(_))
    ));
}

#[tokio::test]
async fn a_shared_runtime_directory_is_refused() {
    let f = fixture();
    release(&f.source, [b"v", b"k", b"i"]);
    let parent = f.paths.artifact_lock.parent().unwrap();
    fs::create_dir(parent).unwrap();
    fs::set_permissions(parent, fs::Permissions::from_mode(0o777)).unwrap();
    assert!(matches!(
        run(&f, false).await,
        Err(InstallError::UnsafeDirectory { .. })
    ));
}

#[tokio::test]
async fn the_cw_runtime_installs_beside_the_lock_and_follows_the_release() {
    let f = fixture();
    let parent = f.paths.artifact_lock.parent().unwrap().to_path_buf();
    release_with(&f.source, [b"v", b"k", b"i"], Some((b"lock-1", b"pack-1")));
    run(&f, false).await.unwrap();
    assert_eq!(fs::read(parent.join(CW_RUNTIME_LOCK)).unwrap(), b"lock-1");
    assert_eq!(fs::read(parent.join(CW_RUNTIME_PACK)).unwrap(), b"pack-1");
    let mode = fs::metadata(parent.join(CW_RUNTIME_PACK)).unwrap().mode() & 0o777;
    assert_eq!(mode, 0o400);
    assert!(matches!(
        run(&f, false).await.unwrap(),
        InstallOutcome::AlreadyInstalled { .. }
    ));

    // A damaged pack under the same lock is fetched again without --replace.
    fs::set_permissions(
        parent.join(CW_RUNTIME_PACK),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    fs::write(parent.join(CW_RUNTIME_PACK), b"damaged").unwrap();
    assert!(matches!(
        run(&f, false).await.unwrap(),
        InstallOutcome::Installed { .. }
    ));
    assert_eq!(fs::read(parent.join(CW_RUNTIME_PACK)).unwrap(), b"pack-1");

    // Another cw runtime, or none, replaces the installed one only on request.
    release_with(&f.source, [b"v", b"k", b"i"], Some((b"lock-2", b"pack-2")));
    assert!(matches!(
        run(&f, false).await,
        Err(InstallError::DifferentRuntimeInstalled(path)) if path == parent.join(CW_RUNTIME_LOCK)
    ));
    run(&f, true).await.unwrap();
    assert_eq!(fs::read(parent.join(CW_RUNTIME_LOCK)).unwrap(), b"lock-2");
    release(&f.source, [b"v", b"k", b"i"]);
    assert!(run(&f, false).await.is_err());
    run(&f, true).await.unwrap();
    assert!(!parent.join(CW_RUNTIME_LOCK).exists() && !parent.join(CW_RUNTIME_PACK).exists());
    let partials: Vec<_> = fs::read_dir(&parent)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.ends_with(".partial"))
        .collect();
    assert!(partials.is_empty(), "{partials:?}");
}
