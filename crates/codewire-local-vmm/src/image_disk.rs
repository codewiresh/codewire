//! Image disks (#4646): one read-only ext4 disk per image, shared by every
//! local VM of that image.
//!
//! The host derives everything here: the image disk id, the store path, the
//! random build id and the promotion. It formats an empty disk and never
//! mounts or parses one; a builder guest with no network, identity or
//! workload unpacks the image's layers onto it, and the host promotes it only
//! after that guest reported completion and exited.
//!
//! ```text
//! engine/image-disks/
//!   locks/<id>.lock       one flock per image
//!   staging/<id>-<uuid>/  a disk being built
//!   disks/<id>/           image.raw (0400) and record.json
//! ```
//!
//! A create, restore or fork holds the image's lock from resolving its disk
//! until a record names it, and collection takes the same lock and asks
//! again whether anything names the disk, so a disk is never removed between
//! "it exists" and "a VM record names it".

use std::ffi::OsStr;
use std::fs::{self, File};
use std::io;
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use codewire_vmm_guest_probe::image_disk::BuildId;
use codewire_vmm_guest_probe::{SetupArchitecture, Sha256Value};
use rand::RngCore as _;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::host::path::{FileIdentity, PathError, PrivateRoot};

pub use codewire_vmm_guest_probe::image_disk::IMAGE_DISK_FORMAT_VERSION;
/// Sparse, as the root disk is; the builder writes only what the image holds.
pub const IMAGE_DISK_BYTES: u64 = 32 * 1024 * 1024 * 1024;
const DISK_NAME: &str = "image.raw";
const RECORD_NAME: &str = "record.json";
const MAXIMUM_RECORD_BYTES: usize = 4096;
const LOCK_POLL: Duration = Duration::from_millis(50);

#[derive(Debug, thiserror::Error)]
pub enum ImageDiskError {
    #[error(transparent)]
    Path(#[from] PathError),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("not a sha256 digest: {0}")]
    InvalidDigest(String),
    #[error("unsupported architecture: {0}")]
    InvalidArchitecture(String),
    #[error("timed out waiting for the image disk lock of {0}")]
    LockTimeout(String),
    #[error("the image disk store record for {0} is invalid")]
    InvalidRecord(String),
    #[error("no image disk {0}")]
    NotFound(String),
    #[error(
        "image disk {image_disk_id} was rebuilt: this VM's root was made on build {expected}, the \
         disk on this host is build {found}; re-create the VM's root, its files under /state are kept"
    )]
    BuildMismatch {
        image_disk_id: String,
        expected: String,
        found: String,
    },
    #[error("image disk {0} changed on disk after it was sealed")]
    DiskChanged(String),
    #[error("mkfs.ext4 is unavailable")]
    MkfsUnavailable,
    #[error("mkfs.ext4 failed")]
    MkfsFailed,
}

impl ImageDiskError {
    pub fn is_not_found(&self) -> bool {
        matches!(self, Self::NotFound(_))
    }
}

/// The image disk id, as lowercase hex: the guest probe's
/// [`codewire_vmm_guest_probe::image_disk::image_disk_id`], so the host and
/// the guest can never disagree on it. It leaves out the project and the
/// runtime, because neither changes what the layers unpack to.
pub fn image_disk_id(architecture: &str, manifest_sha256: &str) -> Result<String, ImageDiskError> {
    let architecture = match architecture {
        "amd64" => SetupArchitecture::Amd64,
        "arm64" => SetupArchitecture::Arm64,
        _ => return Err(ImageDiskError::InvalidArchitecture(architecture.to_owned())),
    };
    let manifest = Sha256Value::parse_hex(manifest_sha256)
        .map_err(|_| ImageDiskError::InvalidDigest(manifest_sha256.to_owned()))?;
    Ok(codewire_vmm_guest_probe::image_disk::image_disk_id(manifest, architecture).to_string())
}

/// The bytes the setup pack header carries for a hex build id.
pub fn build_id_bytes(build_id: &str) -> Option<BuildId> {
    if !valid_build_id(build_id) {
        return None;
    }
    let mut bytes = [0_u8; 16];
    for (index, pair) in build_id.as_bytes().chunks(2).enumerate() {
        let text = std::str::from_utf8(pair).ok()?;
        bytes[index] = u8::from_str_radix(text, 16).ok()?;
    }
    Some(bytes)
}

/// A fresh random build id: 128 bits, as 32 lowercase hex digits. A rebuilt
/// disk for the same image is a different disk by construction.
pub fn new_build_id() -> String {
    let mut bytes = [0_u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex(&bytes)
}

pub fn valid_build_id(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// The image disk a VM's root generation sits on: which disk and which
/// build of it. The runner admits it itself; a request names a disk in the
/// runner's own store, or a published one in a directory it does not own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImageDiskAttachment {
    /// A disk the local store built and sealed.
    Stored {
        image_disk_id: String,
        build_id: String,
    },
    /// A disk published as an image, which the `standard` Pod mounts
    /// read-only from its image volume (#5602): `image.raw`, `record.json`
    /// and the image's `config.json` in one directory.
    Published {
        directory: PathBuf,
        image_disk_id: String,
        build_id: String,
    },
}

impl ImageDiskAttachment {
    pub fn image_disk_id(&self) -> &str {
        match self {
            Self::Stored { image_disk_id, .. } | Self::Published { image_disk_id, .. } => {
                image_disk_id
            }
        }
    }

    pub fn build_id(&self) -> &str {
        match self {
            Self::Stored { build_id, .. } | Self::Published { build_id, .. } => build_id,
        }
    }

    pub fn is_valid(&self) -> bool {
        let named = digest(self.image_disk_id()) && valid_build_id(self.build_id());
        match self {
            Self::Stored { .. } => named,
            Self::Published { directory, .. } => named && directory.is_absolute(),
        }
    }

    /// The boundary check before any attachment: the disk this names, by id
    /// and build id, must be the disk that is there.
    pub fn admit(&self, engine_root: &PrivateRoot) -> Result<AdmittedImageDisk, ImageDiskError> {
        match self {
            Self::Stored {
                image_disk_id,
                build_id,
            } => ImageDiskStore::create(engine_root)?.admit_attachment(image_disk_id, build_id),
            Self::Published {
                directory,
                image_disk_id,
                build_id,
            } => admit_published(directory, image_disk_id, build_id),
        }
    }

    /// Checks that an admitted disk is still the same file.
    pub fn revalidate(
        &self,
        engine_root: &PrivateRoot,
        admitted: &AdmittedImageDisk,
    ) -> Result<(), ImageDiskError> {
        if self.admit(engine_root)?.identity != admitted.identity {
            return Err(ImageDiskError::DiskChanged(
                admitted.record.image_disk_id.clone(),
            ));
        }
        Ok(())
    }
}

/// Admits a published image disk. The disk's integrity rests on the
/// digest-pinned, read-only image volume that holds it; its marker, which the
/// guest checks, is a consistency check, not authentication. The path it
/// returns is opened again by Cloud Hypervisor, which is sound only on that
/// read-only volume: before this admits a disk in a writable directory, pass
/// the VMM the descriptor or re-check the identity after it opens the file.
///
/// Its directory is read-only and not the
/// runner's, so the files are opened without following a link and checked
/// by type and size; the record binds the build as a stored disk's does. A
/// published disk is sized to its content (a node writes a sparse file out
/// in full), so its size is any whole number of blocks up to a stored one's.
pub fn admit_published(
    directory: &Path,
    image_disk_id: &str,
    build_id: &str,
) -> Result<AdmittedImageDisk, ImageDiskError> {
    if !digest(image_disk_id) {
        return Err(ImageDiskError::InvalidDigest(image_disk_id.to_owned()));
    }
    let invalid = || ImageDiskError::InvalidRecord(image_disk_id.to_owned());
    if !valid_build_id(build_id) || !directory.is_absolute() {
        return Err(invalid());
    }
    let record_file = open_published(&directory.join(RECORD_NAME))?;
    if record_file.metadata()?.len() > MAXIMUM_RECORD_BYTES as u64 {
        return Err(invalid());
    }
    let record: ImageDiskRecord = serde_json::from_reader(record_file).map_err(|_| invalid())?;
    record.validate_published(image_disk_id)?;
    if record.build_id != build_id {
        return Err(ImageDiskError::BuildMismatch {
            image_disk_id: image_disk_id.to_owned(),
            expected: build_id.to_owned(),
            found: record.build_id,
        });
    }
    let disk = open_published(&directory.join(DISK_NAME))?;
    let metadata = disk.metadata()?;
    if metadata.len() != record.disk_bytes {
        return Err(ImageDiskError::DiskChanged(image_disk_id.to_owned()));
    }
    Ok(AdmittedImageDisk {
        path: directory.join(DISK_NAME),
        identity: FileIdentity::from_metadata(&metadata),
        record,
    })
}

fn open_published(path: &Path) -> Result<File, ImageDiskError> {
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    if !file.metadata()?.file_type().is_file() {
        return Err(ImageDiskError::NotFound(path.display().to_string()));
    }
    Ok(file)
}

/// The store's record of one sealed image disk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageDiskRecord {
    pub schema_version: u32,
    pub image_disk_id: String,
    pub build_id: String,
    pub format_version: u32,
    pub architecture: String,
    pub manifest_sha256: String,
    pub disk_bytes: u64,
}

impl ImageDiskRecord {
    fn validate(&self, image_disk_id: &str) -> Result<(), ImageDiskError> {
        if self.disk_bytes != IMAGE_DISK_BYTES {
            return Err(ImageDiskError::InvalidRecord(image_disk_id.to_owned()));
        }
        self.validate_published(image_disk_id)
    }

    fn validate_published(&self, image_disk_id: &str) -> Result<(), ImageDiskError> {
        let invalid = || ImageDiskError::InvalidRecord(image_disk_id.to_owned());
        if self.schema_version != 1
            || self.format_version != IMAGE_DISK_FORMAT_VERSION
            || self.image_disk_id != image_disk_id
            || !valid_build_id(&self.build_id)
            || self.disk_bytes == 0
            || self.disk_bytes > IMAGE_DISK_BYTES
            || !self.disk_bytes.is_multiple_of(4096)
        {
            return Err(invalid());
        }
        if self::image_disk_id(&self.architecture, &self.manifest_sha256).map_err(|_| invalid())?
            != image_disk_id
        {
            return Err(invalid());
        }
        Ok(())
    }
}

/// A sealed image disk, admitted for one attachment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmittedImageDisk {
    pub record: ImageDiskRecord,
    pub path: PathBuf,
    pub identity: FileIdentity,
}

/// Holds one image's lock. Dropping it releases the lock.
#[derive(Debug)]
pub struct ImageDiskLock {
    image_disk_id: String,
    _file: File,
}

impl ImageDiskLock {
    pub fn image_disk_id(&self) -> &str {
        &self.image_disk_id
    }
}

/// An empty, formatted disk in staging, waiting for its builder guest.
/// Dropped without [`ImageDiskStore::promote`], it is removed.
#[derive(Debug)]
pub struct StagedImageDisk<'a> {
    store: &'a ImageDiskStore,
    name: String,
    pub record: ImageDiskRecord,
    pub path: PathBuf,
    /// The device and inode the store created. Promotion seals only this
    /// file, never whatever the path names by then.
    staged: (u64, u64),
}

impl StagedImageDisk<'_> {
    /// Its directory's name under `staging/`.
    pub fn name(&self) -> &str {
        &self.name
    }
}

impl Drop for StagedImageDisk<'_> {
    fn drop(&mut self) {
        if !self.name.is_empty() {
            let _ = self.store.remove_staged(&self.name);
        }
    }
}

#[derive(Debug)]
pub struct ImageDiskStore {
    locks: PrivateRoot,
    staging: PrivateRoot,
    disks: PrivateRoot,
}

impl ImageDiskStore {
    pub fn create(engine_root: &PrivateRoot) -> Result<Self, ImageDiskError> {
        let store = PrivateRoot::open(&engine_root.ensure_dir(Path::new("image-disks"), 0o700)?)?;
        let directory = |name: &str| -> Result<PrivateRoot, ImageDiskError> {
            Ok(PrivateRoot::open(
                &store.ensure_dir(Path::new(name), 0o700)?,
            )?)
        };
        Ok(Self {
            locks: directory("locks")?,
            staging: directory("staging")?,
            disks: directory("disks")?,
        })
    }

    /// Waits until `deadline` for the image's lock.
    pub fn lock(
        &self,
        image_disk_id: &str,
        deadline: Instant,
    ) -> Result<ImageDiskLock, ImageDiskError> {
        loop {
            if let Some(lock) = self.try_lock(image_disk_id)? {
                return Ok(lock);
            }
            if Instant::now() >= deadline {
                return Err(ImageDiskError::LockTimeout(image_disk_id.to_owned()));
            }
            std::thread::sleep(LOCK_POLL);
        }
    }

    /// The image's lock, or None while someone else holds it.
    pub fn try_lock(&self, image_disk_id: &str) -> Result<Option<ImageDiskLock>, ImageDiskError> {
        if !digest(image_disk_id) {
            return Err(ImageDiskError::InvalidDigest(image_disk_id.to_owned()));
        }
        let name = PathBuf::from(format!("{image_disk_id}.lock"));
        let opened = match self.locks.create_regular(&name, 0o600, true) {
            Ok(opened) => opened,
            Err(error) if already_exists(&error) => {
                self.locks
                    .open_regular(&name, true, Some(0), false, Some(0o600))?
            }
            Err(error) => return Err(error.into()),
        };
        let file = opened.into_file();
        // SAFETY: flock on a descriptor this function owns.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::WouldBlock {
                return Ok(None);
            }
            return Err(error.into());
        }
        Ok(Some(ImageDiskLock {
            image_disk_id: image_disk_id.to_owned(),
            _file: file,
        }))
    }

    /// The sealed disk for the locked image, if one exists.
    pub fn open(&self, lock: &ImageDiskLock) -> Result<AdmittedImageDisk, ImageDiskError> {
        self.open_unlocked(lock.image_disk_id())
    }

    /// The boundary check before any attachment (condition 1 on #4242): the
    /// disk a VM's root generation names, by id and build id, must be the
    /// disk the store holds. A rebuilt disk is refused with the reason.
    pub fn admit_attachment(
        &self,
        image_disk_id: &str,
        build_id: &str,
    ) -> Result<AdmittedImageDisk, ImageDiskError> {
        if !valid_build_id(build_id) {
            return Err(ImageDiskError::InvalidRecord(image_disk_id.to_owned()));
        }
        let admitted = self.open_unlocked(image_disk_id)?;
        if admitted.record.build_id != build_id {
            return Err(ImageDiskError::BuildMismatch {
                image_disk_id: image_disk_id.to_owned(),
                expected: build_id.to_owned(),
                found: admitted.record.build_id,
            });
        }
        Ok(admitted)
    }

    /// Checks that an admitted disk is still the same sealed file.
    pub fn revalidate(&self, admitted: &AdmittedImageDisk) -> Result<(), ImageDiskError> {
        let current =
            self.admit_attachment(&admitted.record.image_disk_id, &admitted.record.build_id)?;
        if current.identity != admitted.identity {
            return Err(ImageDiskError::DiskChanged(
                admitted.record.image_disk_id.clone(),
            ));
        }
        Ok(())
    }

    /// Formats an empty disk in staging for the locked image, with a new
    /// build id. Any abandoned staging of the same image is removed first:
    /// holding the lock proves no builder still writes it.
    pub fn stage(
        &self,
        lock: &ImageDiskLock,
        architecture: &str,
        manifest_sha256: &str,
    ) -> Result<StagedImageDisk<'_>, ImageDiskError> {
        let image_disk_id = lock.image_disk_id();
        if self::image_disk_id(architecture, manifest_sha256)? != image_disk_id {
            return Err(ImageDiskError::InvalidRecord(image_disk_id.to_owned()));
        }
        self.remove_abandoned(image_disk_id)?;
        let name = format!("{image_disk_id}-{}", Uuid::new_v4().simple());
        let directory = PrivateRoot::open(&self.staging.create_dir(Path::new(&name), 0o700)?)?;
        let disk = directory
            .create_regular(Path::new(DISK_NAME), 0o600, true)?
            .into_file();
        let created = disk.metadata()?;
        let staged = StagedImageDisk {
            store: self,
            name,
            record: ImageDiskRecord {
                schema_version: 1,
                image_disk_id: image_disk_id.to_owned(),
                build_id: new_build_id(),
                format_version: IMAGE_DISK_FORMAT_VERSION,
                architecture: architecture.to_owned(),
                manifest_sha256: manifest_sha256.to_owned(),
                disk_bytes: IMAGE_DISK_BYTES,
            },
            path: directory.path().join(DISK_NAME),
            staged: (created.dev(), created.ino()),
        };
        disk.set_len(IMAGE_DISK_BYTES)?;
        disk.sync_all()?;
        drop(disk);
        format_empty_ext4(&staged.path)?;
        let formatted = directory
            .open_regular(
                Path::new(DISK_NAME),
                false,
                Some(IMAGE_DISK_BYTES),
                false,
                Some(0o600),
            )?
            .into_file();
        let metadata = formatted.metadata()?;
        if (metadata.dev(), metadata.ino()) != staged.staged {
            return Err(ImageDiskError::DiskChanged(
                staged.record.image_disk_id.clone(),
            ));
        }
        formatted.sync_all()?;
        Ok(staged)
    }

    /// The disk of a staging directory, by the name the supervisor gave a
    /// builder process. The name must be one [`Self::stage`] makes.
    pub fn staged_disk_path(&self, name: &str) -> Result<PathBuf, ImageDiskError> {
        let valid = name.split_once('-').is_some_and(|(id, build)| {
            digest(id)
                && build.len() == 32
                && build
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        });
        if !valid {
            return Err(ImageDiskError::InvalidDigest(name.to_owned()));
        }
        let directory = PrivateRoot::open(&self.staging.path().join(name))?;
        Ok(directory.path().join(DISK_NAME))
    }

    /// Seals a staged disk after its builder reported completion and exited:
    /// syncs it, makes it 0400, writes the record and publishes the
    /// directory in one rename.
    pub fn promote(
        &self,
        lock: &ImageDiskLock,
        mut staged: StagedImageDisk<'_>,
    ) -> Result<AdmittedImageDisk, ImageDiskError> {
        let image_disk_id = lock.image_disk_id();
        if staged.record.image_disk_id != image_disk_id {
            return Err(ImageDiskError::InvalidRecord(image_disk_id.to_owned()));
        }
        let directory = PrivateRoot::open(&self.staging.path().join(&staged.name))?;
        let disk = directory
            .open_regular(
                Path::new(DISK_NAME),
                false,
                Some(IMAGE_DISK_BYTES),
                false,
                Some(0o600),
            )?
            .into_file();
        // Seal the inode the store created, not whatever the path names now.
        let metadata = disk.metadata()?;
        if (metadata.dev(), metadata.ino()) != staged.staged {
            return Err(ImageDiskError::DiskChanged(image_disk_id.to_owned()));
        }
        disk.set_permissions(fs::Permissions::from_mode(0o400))?;
        disk.sync_all()?;
        drop(disk);
        let bytes = serde_json::to_vec(&staged.record)
            .map_err(|_| ImageDiskError::InvalidRecord(image_disk_id.to_owned()))?;
        let record = directory.create_regular(Path::new(RECORD_NAME), 0o600, true)?;
        let mut file = record.into_file();
        io::Write::write_all(&mut file, &bytes)?;
        file.sync_all()?;
        drop(file);
        // A sealed disk from an earlier build is replaced only by a caller
        // that found it unusable under this lock; remove it before publishing.
        if fs::symlink_metadata(self.disks.path().join(image_disk_id)).is_ok() {
            self.remove_sealed(image_disk_id)?;
        }
        self.staging.move_private_directory_to(
            Path::new(&staged.name),
            &self.disks,
            Path::new(image_disk_id),
        )?;
        staged.name.clear();
        let admitted = self.open_unlocked(image_disk_id)?;
        if (admitted.identity.device, admitted.identity.inode) != staged.staged {
            self.remove_sealed(image_disk_id)?;
            return Err(ImageDiskError::DiskChanged(image_disk_id.to_owned()));
        }
        Ok(admitted)
    }

    /// Removes every sealed disk that nothing names, each under its own
    /// lock. `retained` is asked under the lock, so a create that resolved a
    /// disk and has not yet recorded it still holds the lock and is skipped.
    /// Returns the ids removed.
    pub fn collect_unreferenced(
        &self,
        retained: impl Fn(&str) -> bool,
    ) -> Result<Vec<String>, ImageDiskError> {
        let mut removed = Vec::new();
        for entry in fs::read_dir(self.disks.path())? {
            let name = entry?.file_name();
            let Some(image_disk_id) = name.to_str().filter(|name| digest(name)) else {
                continue;
            };
            let Some(_lock) = self.try_lock(image_disk_id)? else {
                continue;
            };
            if retained(image_disk_id) {
                continue;
            }
            self.remove_sealed(image_disk_id)?;
            removed.push(image_disk_id.to_owned());
        }
        Ok(removed)
    }

    fn open_unlocked(&self, image_disk_id: &str) -> Result<AdmittedImageDisk, ImageDiskError> {
        if !digest(image_disk_id) {
            return Err(ImageDiskError::InvalidDigest(image_disk_id.to_owned()));
        }
        let directory = match PrivateRoot::open(&self.disks.path().join(image_disk_id)) {
            Ok(directory) => directory,
            Err(_) if fs::symlink_metadata(self.disks.path().join(image_disk_id)).is_err() => {
                return Err(ImageDiskError::NotFound(image_disk_id.to_owned()));
            }
            Err(error) => return Err(error.into()),
        };
        let record_file = directory
            .open_regular(Path::new(RECORD_NAME), false, None, false, Some(0o600))?
            .into_file();
        if record_file.metadata()?.len() > MAXIMUM_RECORD_BYTES as u64 {
            return Err(ImageDiskError::InvalidRecord(image_disk_id.to_owned()));
        }
        let record: ImageDiskRecord = serde_json::from_reader(record_file)
            .map_err(|_| ImageDiskError::InvalidRecord(image_disk_id.to_owned()))?;
        record.validate(image_disk_id)?;
        let opened = match directory.open_regular(
            Path::new(DISK_NAME),
            false,
            Some(record.disk_bytes),
            false,
            Some(0o400),
        ) {
            Ok(opened) => opened,
            Err(_) if fs::symlink_metadata(directory.path().join(DISK_NAME)).is_err() => {
                return Err(ImageDiskError::NotFound(image_disk_id.to_owned()));
            }
            Err(_) => return Err(ImageDiskError::DiskChanged(image_disk_id.to_owned())),
        };
        Ok(AdmittedImageDisk {
            path: directory.path().join(DISK_NAME),
            identity: opened.identity().clone(),
            record,
        })
    }

    fn remove_sealed(&self, image_disk_id: &str) -> Result<(), ImageDiskError> {
        let directory = PrivateRoot::open(&self.disks.path().join(image_disk_id))?;
        remove_present(&directory, DISK_NAME)?;
        remove_present(&directory, RECORD_NAME)?;
        self.disks
            .remove_empty_private_directory(Path::new(image_disk_id))?;
        Ok(())
    }

    fn remove_staged(&self, name: &str) -> Result<(), ImageDiskError> {
        let directory = PrivateRoot::open(&self.staging.path().join(name))?;
        remove_present(&directory, DISK_NAME)?;
        remove_present(&directory, RECORD_NAME)?;
        self.staging
            .remove_empty_private_directory(Path::new(name))?;
        Ok(())
    }

    fn remove_abandoned(&self, image_disk_id: &str) -> Result<(), ImageDiskError> {
        let prefix = format!("{image_disk_id}-");
        for entry in fs::read_dir(self.staging.path())? {
            let name = entry?.file_name();
            if let Some(name) = name.to_str().filter(|name| name.starts_with(&prefix)) {
                self.remove_staged(name)?;
            }
        }
        Ok(())
    }
}

fn remove_present(directory: &PrivateRoot, name: &str) -> Result<(), ImageDiskError> {
    if let Ok(metadata) = fs::symlink_metadata(directory.path().join(name)) {
        directory.remove_private_regular(Path::new(name), metadata.mode() & 0o777)?;
    }
    Ok(())
}

/// An empty ext4 without a journal: the builder writes it once and every VM
/// mounts it `ro,noload`.
fn format_empty_ext4(disk: &Path) -> Result<(), ImageDiskError> {
    let mkfs = crate::host::e2fsprogs("mkfs.ext4").ok_or(ImageDiskError::MkfsUnavailable)?;
    #[cfg(target_os = "macos")]
    let config = crate::host::mke2fs_config().ok_or(ImageDiskError::MkfsUnavailable)?;
    let mut command = Command::new(mkfs);
    crate::sweep_before_exec(&mut command);
    command.args(crate::host::EXT4_FORMAT).args([
        OsStr::new("-q"),
        OsStr::new("-F"),
        OsStr::new("-m"),
        OsStr::new("0"),
        OsStr::new("-O"),
        OsStr::new("^has_journal"),
        OsStr::new("-L"),
        OsStr::new("CWIMAGE"),
    ]);
    command.arg(disk).env_clear().env("LC_ALL", "C");
    #[cfg(target_os = "macos")]
    command.env("MKE2FS_CONFIG", config);
    let status = command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|_| ImageDiskError::MkfsUnavailable)?;
    if !status.success() {
        return Err(ImageDiskError::MkfsFailed);
    }
    Ok(())
}

fn already_exists(error: &PathError) -> bool {
    match error {
        #[cfg(target_os = "linux")]
        PathError::Openat2 { source, .. } => *source == rustix::io::Errno::EXIST,
        #[cfg(target_os = "macos")]
        PathError::Io { source, .. } => source.kind() == io::ErrorKind::AlreadyExists,
        _ => false,
    }
}

fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests;
