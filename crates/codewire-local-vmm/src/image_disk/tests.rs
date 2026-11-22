use super::*;

const MANIFEST: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const OTHER_MANIFEST: &str = "2222222222222222222222222222222222222222222222222222222222222222";

fn store() -> (tempfile::TempDir, ImageDiskStore) {
    let engine = tempfile::tempdir().unwrap();
    fs::set_permissions(engine.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let root = PrivateRoot::open(engine.path()).unwrap();
    let store = ImageDiskStore::create(&root).unwrap();
    (engine, store)
}

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(5)
}

#[test]
fn the_id_names_the_image_and_architecture_and_nothing_else() {
    let id = image_disk_id("amd64", MANIFEST).unwrap();
    assert!(digest(&id));
    assert_eq!(image_disk_id("amd64", MANIFEST).unwrap(), id);
    assert_ne!(image_disk_id("arm64", MANIFEST).unwrap(), id);
    assert_ne!(image_disk_id("amd64", OTHER_MANIFEST).unwrap(), id);
    assert!(image_disk_id("riscv64", MANIFEST).is_err());
    assert!(image_disk_id("amd64", "sha256:1111").is_err());
}

#[test]
fn build_ids_are_random_128_bit_hex() {
    let first = new_build_id();
    assert!(valid_build_id(&first));
    assert_ne!(new_build_id(), first);
    assert!(!valid_build_id("ABCDEF0123456789abcdef0123456789"));
    assert!(!valid_build_id(&first[..31]));
    let bytes = build_id_bytes(&first).unwrap();
    assert_eq!(hex(&bytes), first);
    assert_eq!(build_id_bytes("ab"), None);
}

#[test]
fn the_lock_is_exclusive_per_image() {
    let (_engine, store) = store();
    let id = image_disk_id("amd64", MANIFEST).unwrap();
    let other = image_disk_id("amd64", OTHER_MANIFEST).unwrap();
    let held = store.lock(&id, deadline()).unwrap();
    assert!(store.try_lock(&id).unwrap().is_none());
    assert!(store.try_lock(&other).unwrap().is_some());
    assert!(matches!(
        store.lock(&id, Instant::now()),
        Err(ImageDiskError::LockTimeout(_))
    ));
    drop(held);
    assert!(store.try_lock(&id).unwrap().is_some());
}

#[cfg(target_os = "linux")]
#[test]
fn a_promoted_disk_is_sealed_and_admitted_only_for_its_build() {
    let (_engine, store) = store();
    let id = image_disk_id("amd64", MANIFEST).unwrap();
    let lock = store.lock(&id, deadline()).unwrap();
    assert!(store.open(&lock).unwrap_err().is_not_found());

    let staged = store.stage(&lock, "amd64", MANIFEST).unwrap();
    let build_id = staged.record.build_id.clone();
    // Nothing is visible until promotion.
    assert!(store.open(&lock).unwrap_err().is_not_found());
    let sealed = store.promote(&lock, staged).unwrap();
    assert_eq!(sealed.record.build_id, build_id);
    let metadata = fs::metadata(&sealed.path).unwrap();
    assert_eq!(metadata.permissions().mode() & 0o777, 0o400);
    assert_eq!(metadata.len(), IMAGE_DISK_BYTES);
    drop(lock);

    let admitted = store.admit_attachment(&id, &build_id).unwrap();
    assert_eq!(admitted, sealed);
    store.revalidate(&admitted).unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn a_rebuilt_disk_is_refused_under_a_generation_made_on_the_old_build() {
    let (_engine, store) = store();
    let id = image_disk_id("amd64", MANIFEST).unwrap();
    let lock = store.lock(&id, deadline()).unwrap();
    let old = store
        .promote(&lock, store.stage(&lock, "amd64", MANIFEST).unwrap())
        .unwrap();
    let rebuilt = store
        .promote(&lock, store.stage(&lock, "amd64", MANIFEST).unwrap())
        .unwrap();
    drop(lock);
    assert_ne!(rebuilt.record.build_id, old.record.build_id);

    let refused = store
        .admit_attachment(&id, &old.record.build_id)
        .unwrap_err();
    assert!(matches!(refused, ImageDiskError::BuildMismatch { .. }));
    let message = refused.to_string();
    assert!(message.contains("was rebuilt"), "{message}");
    assert!(message.contains("/state are kept"), "{message}");
    assert!(matches!(
        store.revalidate(&old),
        Err(ImageDiskError::BuildMismatch { .. })
    ));
    store
        .admit_attachment(&id, &rebuilt.record.build_id)
        .unwrap();
}

/// cw-security's condition 1 on #4646: promotion seals the inode the store
/// created. A disk swapped in at the staged path after the build, even with
/// the builder's clean exit, promotes nothing and leaves the store empty.
#[cfg(target_os = "linux")]
#[test]
fn a_disk_swapped_in_after_the_build_is_never_promoted() {
    let (_engine, store) = store();
    let id = image_disk_id("amd64", MANIFEST).unwrap();
    let lock = store.lock(&id, deadline()).unwrap();
    let staged = store.stage(&lock, "amd64", MANIFEST).unwrap();
    let impostor = staged.path.with_file_name("impostor.raw");
    let file = File::create(&impostor).unwrap();
    file.set_len(IMAGE_DISK_BYTES).unwrap();
    fs::set_permissions(&impostor, fs::Permissions::from_mode(0o600)).unwrap();
    drop(file);
    fs::rename(&impostor, &staged.path).unwrap();
    assert!(matches!(
        store.promote(&lock, staged),
        Err(ImageDiskError::DiskChanged(_))
    ));
    assert!(store.open(&lock).unwrap_err().is_not_found());
    assert_eq!(fs::read_dir(store.staging.path()).unwrap().count(), 0);
}

#[cfg(target_os = "linux")]
#[test]
fn an_unpromoted_build_leaves_nothing_and_the_next_build_starts_clean() {
    let (_engine, store) = store();
    let id = image_disk_id("amd64", MANIFEST).unwrap();
    let lock = store.lock(&id, deadline()).unwrap();
    let staged = store.stage(&lock, "amd64", MANIFEST).unwrap();
    let path = staged.path.clone();
    // A builder that failed, crashed or never said complete: no promotion.
    drop(staged);
    assert!(fs::symlink_metadata(&path).is_err());
    assert!(store.open(&lock).unwrap_err().is_not_found());

    // A staging left by a killed process is removed under the next lock.
    let abandoned = store.stage(&lock, "amd64", MANIFEST).unwrap();
    let abandoned_path = abandoned.path.clone();
    std::mem::forget(abandoned);
    let next = store.stage(&lock, "amd64", MANIFEST).unwrap();
    assert!(fs::symlink_metadata(&abandoned_path).is_err());
    store.promote(&lock, next).unwrap();
    assert_eq!(fs::read_dir(store.staging.path()).unwrap().count(), 0);
}

#[cfg(target_os = "linux")]
#[test]
fn a_staged_disk_belongs_to_its_locked_image() {
    let (_engine, store) = store();
    let id = image_disk_id("amd64", MANIFEST).unwrap();
    let lock = store.lock(&id, deadline()).unwrap();
    assert!(matches!(
        store.stage(&lock, "amd64", OTHER_MANIFEST),
        Err(ImageDiskError::InvalidRecord(_))
    ));
    let other_lock = store
        .lock(&image_disk_id("amd64", OTHER_MANIFEST).unwrap(), deadline())
        .unwrap();
    let staged = store.stage(&lock, "amd64", MANIFEST).unwrap();
    assert!(matches!(
        store.promote(&other_lock, staged),
        Err(ImageDiskError::InvalidRecord(_))
    ));
}

#[cfg(target_os = "linux")]
#[test]
fn collection_removes_only_unnamed_disks_and_skips_a_locked_one() {
    let (_engine, store) = store();
    let kept = image_disk_id("amd64", MANIFEST).unwrap();
    let unnamed = image_disk_id("amd64", OTHER_MANIFEST).unwrap();
    let in_use = image_disk_id("arm64", MANIFEST).unwrap();
    for (id, architecture, manifest) in [
        (&kept, "amd64", MANIFEST),
        (&unnamed, "amd64", OTHER_MANIFEST),
        (&in_use, "arm64", MANIFEST),
    ] {
        let lock = store.lock(id, deadline()).unwrap();
        store
            .promote(&lock, store.stage(&lock, architecture, manifest).unwrap())
            .unwrap();
    }
    // A create that resolved `in_use` and has not recorded it holds the lock.
    let create = store.lock(&in_use, deadline()).unwrap();
    let removed = store
        .collect_unreferenced(|id| id == kept.as_str())
        .unwrap();
    assert_eq!(removed, vec![unnamed.clone()]);
    assert!(store.open(&create).is_ok());
    drop(create);
    assert!(
        store
            .admit_attachment(&unnamed, &new_build_id())
            .unwrap_err()
            .is_not_found()
    );
    let lock = store.lock(&kept, deadline()).unwrap();
    assert!(store.open(&lock).is_ok());
}

#[cfg(target_os = "linux")]
#[test]
fn a_tampered_record_or_disk_is_refused() {
    let (_engine, store) = store();
    let id = image_disk_id("amd64", MANIFEST).unwrap();
    let lock = store.lock(&id, deadline()).unwrap();
    let sealed = store
        .promote(&lock, store.stage(&lock, "amd64", MANIFEST).unwrap())
        .unwrap();
    drop(lock);
    fs::set_permissions(&sealed.path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(matches!(
        store.admit_attachment(&id, &sealed.record.build_id),
        Err(ImageDiskError::DiskChanged(_))
    ));
    fs::set_permissions(&sealed.path, fs::Permissions::from_mode(0o400)).unwrap();
    let record_path = sealed.path.with_file_name(RECORD_NAME);
    let mut record = sealed.record.clone();
    record.manifest_sha256 = OTHER_MANIFEST.to_owned();
    fs::write(&record_path, serde_json::to_vec(&record).unwrap()).unwrap();
    assert!(matches!(
        store.admit_attachment(&id, &sealed.record.build_id),
        Err(ImageDiskError::InvalidRecord(_))
    ));
}

/// #5602: a published disk is admitted from a directory the runner does not
/// own, by its record and build id, at the size its record names.
#[test]
fn a_published_disk_is_admitted_only_as_its_record_names_it() {
    let directory = tempfile::tempdir().unwrap();
    let id = image_disk_id("amd64", MANIFEST).unwrap();
    let build = new_build_id();
    let record = |disk_bytes: u64| ImageDiskRecord {
        schema_version: 1,
        image_disk_id: id.clone(),
        build_id: build.clone(),
        format_version: IMAGE_DISK_FORMAT_VERSION,
        architecture: "amd64".to_owned(),
        manifest_sha256: MANIFEST.to_owned(),
        disk_bytes,
    };
    let write_record = |disk_bytes: u64| {
        fs::write(
            directory.path().join(RECORD_NAME),
            serde_json::to_vec(&record(disk_bytes)).unwrap(),
        )
        .unwrap();
    };
    write_record(8192);
    fs::write(directory.path().join(DISK_NAME), vec![0_u8; 8192]).unwrap();
    let attachment = ImageDiskAttachment::Published {
        directory: directory.path().to_owned(),
        image_disk_id: id.clone(),
        build_id: build.clone(),
    };
    assert!(attachment.is_valid());
    let admitted = admit_published(directory.path(), &id, &build).unwrap();
    assert_eq!(admitted.path, directory.path().join(DISK_NAME));
    assert_eq!(admitted.record.disk_bytes, 8192);

    // Another build, or another image, is refused.
    assert!(matches!(
        admit_published(directory.path(), &id, &new_build_id()),
        Err(ImageDiskError::BuildMismatch { .. })
    ));
    let other = image_disk_id("amd64", OTHER_MANIFEST).unwrap();
    assert!(matches!(
        admit_published(directory.path(), &other, &build),
        Err(ImageDiskError::InvalidRecord(_))
    ));
    // A disk that is not the record's size, or a size that is not whole
    // blocks, is refused.
    fs::write(directory.path().join(DISK_NAME), vec![0_u8; 4096]).unwrap();
    assert!(matches!(
        admit_published(directory.path(), &id, &build),
        Err(ImageDiskError::DiskChanged(_))
    ));
    write_record(4095);
    assert!(matches!(
        admit_published(directory.path(), &id, &build),
        Err(ImageDiskError::InvalidRecord(_))
    ));
    // A link in place of the disk is never followed.
    write_record(4096);
    let target = tempfile::NamedTempFile::new().unwrap();
    fs::write(target.path(), vec![0_u8; 4096]).unwrap();
    fs::remove_file(directory.path().join(DISK_NAME)).unwrap();
    std::os::unix::fs::symlink(target.path(), directory.path().join(DISK_NAME)).unwrap();
    assert!(admit_published(directory.path(), &id, &build).is_err());
    // A relative directory is not an attachment.
    assert!(
        !ImageDiskAttachment::Published {
            directory: "image".into(),
            image_disk_id: id,
            build_id: build,
        }
        .is_valid()
    );
}
