//! Private, immutable cw assets and catalog disks, independent of boot assets.
//!
//! Only verified fixed-format payloads enter the filesystem seed. No image
//! archive is extracted or executed. The supervisor serializes publication;
//! the catalog manifest is the commit point after the sealed disk is durable.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use codewire_vmm_guest_probe::cw_runtime::{
    CW_RUNTIME_MAX_CATALOG, CW_RUNTIME_MAX_PACK, CW_RUNTIME_MAX_VERSIONS, CwRuntimeCatalog,
    CwRuntimeProvenance, decode_runtime_pack,
};
pub use codewire_vmm_guest_probe::cw_runtime_live::{RuntimeSelection, SelectionOutcome};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::linux::path::{FileIdentity, PathError, PrivateRoot};

const MAXIMUM_LOCK_BYTES: usize = 16 * 1024;
const MAXIMUM_MANIFEST_BYTES: usize = CW_RUNTIME_MAX_CATALOG + MAXIMUM_LOCK_BYTES;
pub const MAXIMUM_RUNTIME_DISK_BYTES: u64 = 5 * 1024 * 1024 * 1024;
const DISK_ALIGNMENT: u64 = 16 * 1024 * 1024;
const MINIMUM_DISK_BYTES: u64 = 64 * 1024 * 1024;
const TOOL_TIMEOUT: Duration = Duration::from_secs(120);
const PREPARATION_TIMEOUT: Duration = Duration::from_secs(180);
const PUBLICATION_ACQUISITION_TIMEOUT: Duration = Duration::from_secs(5);
const TOOL_OUTPUT_LIMIT: u64 = 128 * 1024;
const MAXIMUM_STORE_OBJECTS: usize = 1024;

/// Validation-only evidence for a Linux runtime journal row. This interface
/// returns no journal contents and cannot open a store, path or process.
/// The private transaction owner validates the typed intent and exact receipt.
pub struct CwRuntimeJournalEvidence<'a> {
    pub kind: &'a str,
    pub operation_id: Uuid,
    pub environment_id: Uuid,
    pub phase: &'a str,
    pub payload: &'a [u8],
    pub result: Option<&'a [u8]>,
    pub error_code: Option<&'a str>,
}

impl CwRuntimeJournalEvidence<'_> {
    // Match the owning journal's JSON byte bound, including JSON escaping.
    pub const MAXIMUM_JSON_BYTES: usize = 2 * 1024 * 1024;

    pub fn validate(&self) -> bool {
        self.validate_owned()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CwRuntimeFileSpec {
    pub path: PathBuf,
    pub size: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CwRuntimeAssetLock {
    pub schema_version: u32,
    pub image_index_sha256: String,
    pub pack: CwRuntimeFileSpec,
}

#[derive(Debug)]
pub struct AdmittedCwRuntimeAsset {
    pub provenance: CwRuntimeProvenance,
    pub pack_sha256: String,
    bytes: Vec<u8>,
    payload_offset: usize,
}

impl AdmittedCwRuntimeAsset {
    pub fn read_source(lock_path: &Path) -> Result<Self, CwRuntimeError> {
        let parent = lock_path.parent().ok_or(CwRuntimeError::InvalidAsset)?;
        let root = PrivateRoot::open(parent)?;
        let name = lock_path.file_name().ok_or(CwRuntimeError::InvalidAsset)?;
        let lock_bytes = read_bounded(&root, Path::new(name), MAXIMUM_LOCK_BYTES, None)?;
        let lock: CwRuntimeAssetLock =
            serde_json::from_slice(&lock_bytes).map_err(|_| CwRuntimeError::InvalidAsset)?;
        if lock.schema_version != 1
            || !digest(&lock.image_index_sha256)
            || lock.pack.path != Path::new("runtime.pack")
            || !(24..=CW_RUNTIME_MAX_PACK as u64).contains(&lock.pack.size)
            || !digest(&lock.pack.sha256)
        {
            return Err(CwRuntimeError::InvalidAsset);
        }
        let bytes = read_bounded(
            &root,
            &lock.pack.path,
            CW_RUNTIME_MAX_PACK,
            Some(lock.pack.size),
        )?;
        if sha(&bytes) != lock.pack.sha256 {
            return Err(CwRuntimeError::InvalidAsset);
        }
        let asset = Self::decode(bytes)?;
        if asset.provenance.image_index_sha256 != lock.image_index_sha256 {
            return Err(CwRuntimeError::InvalidAsset);
        }
        Ok(asset)
    }

    fn decode(bytes: Vec<u8>) -> Result<Self, CwRuntimeError> {
        let (provenance, payload) =
            decode_runtime_pack(&bytes).map_err(CwRuntimeError::InvalidCatalog)?;
        let payload_offset = bytes.len() - payload.len();
        Ok(Self {
            provenance,
            pack_sha256: sha(&bytes),
            bytes,
            payload_offset,
        })
    }

    fn payload(&self) -> &[u8] {
        &self.bytes[self.payload_offset..]
    }

    pub(crate) fn pack(&self) -> &[u8] {
        &self.bytes
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CwRuntimeCatalogManifest {
    pub schema_version: u32,
    pub catalog: CwRuntimeCatalog,
    pub disk: CwRuntimeFileSpec,
}

impl CwRuntimeCatalogManifest {
    pub fn generation(&self) -> Result<String, CwRuntimeError> {
        self.catalog
            .validate()
            .map_err(CwRuntimeError::InvalidCatalog)?;
        Ok(sha(&self
            .catalog
            .encode()
            .map_err(CwRuntimeError::InvalidCatalog)?))
    }

    fn validate(&self, generation: &str) -> Result<(), CwRuntimeError> {
        if self.schema_version != 1
            || !digest(generation)
            || self.generation()? != generation
            || self.disk.path != Path::new("runtime.raw")
            || !(MINIMUM_DISK_BYTES..=MAXIMUM_RUNTIME_DISK_BYTES).contains(&self.disk.size)
            || !self.disk.size.is_multiple_of(DISK_ALIGNMENT)
            || !digest(&self.disk.sha256)
        {
            return Err(CwRuntimeError::InvalidManifest);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmittedCwRuntimeDisk {
    pub generation: String,
    pub path: PathBuf,
    pub identity: FileIdentity,
    pub manifest: CwRuntimeCatalogManifest,
}

impl AdmittedCwRuntimeDisk {
    /// Validate saved metadata without using its path as filesystem authority.
    pub fn validate_metadata(&self) -> Result<(), CwRuntimeError> {
        self.manifest.validate(&self.generation)?;
        if !self.path.is_absolute()
            || self.path.file_name() != Some(std::ffi::OsStr::new("runtime.raw"))
            || self.path.parent().and_then(Path::file_name)
                != Some(std::ffi::OsStr::new(&self.generation))
            || self.identity.size != self.manifest.disk.size
            || self.identity.mode != 0o100400
            || self.identity.links != 1
        {
            return Err(CwRuntimeError::InvalidManifest);
        }
        Ok(())
    }

    pub fn revalidate(&self) -> Result<(), CwRuntimeError> {
        self.validate_metadata()?;
        let root = PrivateRoot::open(self.path.parent().ok_or(CwRuntimeError::InvalidManifest)?)?;
        let name = self
            .path
            .file_name()
            .ok_or(CwRuntimeError::InvalidManifest)?;
        let opened = root.open_regular(
            Path::new(name),
            false,
            Some(self.manifest.disk.size),
            false,
            Some(0o400),
        )?;
        if opened.identity() != &self.identity
            || hash_file(
                opened.into_file(),
                self.manifest.disk.size,
                Instant::now() + PREPARATION_TIMEOUT,
            )? != self.manifest.disk.sha256
        {
            return Err(CwRuntimeError::DiskChanged);
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct CwRuntimeStore {
    root: PrivateRoot,
    assets: PrivateRoot,
    catalogs: PrivateRoot,
    staging: PrivateRoot,
}

impl CwRuntimeStore {
    pub fn create(engine_root: &PrivateRoot) -> Result<Self, CwRuntimeError> {
        let store = PrivateRoot::open(&engine_root.ensure_dir(Path::new("cw-runtimes"), 0o700)?)?;
        let directory = |name: &str| -> Result<PrivateRoot, CwRuntimeError> {
            Ok(PrivateRoot::open(
                &store.ensure_dir(Path::new(name), 0o700)?,
            )?)
        };
        Ok(Self {
            assets: directory("assets")?,
            catalogs: directory("catalogs")?,
            staging: directory("staging")?,
            root: store,
        })
    }

    pub fn admit_source(&self, source: &Path) -> Result<AdmittedCwRuntimeAsset, CwRuntimeError> {
        self.admit_source_inner(source, None)
    }

    pub(crate) fn admit_source_pinned(
        &self,
        source: &Path,
        image: &str,
        payload: &str,
    ) -> Result<AdmittedCwRuntimeAsset, CwRuntimeError> {
        if !digest(image) || !digest(payload) {
            return Err(CwRuntimeError::InvalidAsset);
        }
        self.admit_source_inner(source, Some((image, payload)))
    }

    fn admit_source_inner(
        &self,
        source: &Path,
        expected: Option<(&str, &str)>,
    ) -> Result<AdmittedCwRuntimeAsset, CwRuntimeError> {
        let deadline = Instant::now() + PREPARATION_TIMEOUT;
        let _publication = self.acquire_publication_until(deadline)?;
        self.recover_abandoned(deadline)?;
        let asset = AdmittedCwRuntimeAsset::read_source(source)?;
        if expected.is_some_and(|(image, payload)| {
            asset.provenance.image_index_sha256 != image
                || asset.provenance.payload.sha256 != payload
        }) {
            return Err(CwRuntimeError::AssetCollision);
        }
        let name = format!("{}.pack", asset.provenance.payload.sha256);
        let mut count = 0;
        let mut present = false;
        for entry in fs::read_dir(self.assets.path())? {
            check_deadline(deadline)?;
            count += 1;
            present |= entry?.file_name() == name.as_str();
        }
        if !present && count >= MAXIMUM_STORE_OBJECTS {
            return Err(CwRuntimeError::RetentionLimit);
        }
        check_deadline(deadline)?;
        if !present {
            publish_exact(&self.assets, Path::new(&name), &asset.bytes)?;
        }
        let stored = self.read_asset(&asset.provenance.payload.sha256)?;
        if stored.pack_sha256 != asset.pack_sha256 || stored.provenance != asset.provenance {
            return Err(CwRuntimeError::AssetCollision);
        }
        Ok(stored)
    }

    pub(crate) fn read_asset(
        &self,
        payload: &str,
    ) -> Result<AdmittedCwRuntimeAsset, CwRuntimeError> {
        if !digest(payload) {
            return Err(CwRuntimeError::InvalidAsset);
        }
        let bytes = read_bounded(
            &self.assets,
            Path::new(&format!("{payload}.pack")),
            CW_RUNTIME_MAX_PACK,
            None,
        )?;
        let asset = AdmittedCwRuntimeAsset::decode(bytes)?;
        if asset.provenance.payload.sha256 != payload {
            return Err(CwRuntimeError::InvalidAsset);
        }
        Ok(asset)
    }

    /// Admission and catalog construction occur before a lifecycle disruption.
    /// Every retained pin is mandatory; a missing asset is never regenerated.
    pub fn prepare_catalog(
        &self,
        active: &CwRuntimeProvenance,
        retained: &BTreeMap<String, CwRuntimeProvenance>,
    ) -> Result<AdmittedCwRuntimeDisk, CwRuntimeError> {
        let deadline = Instant::now() + PREPARATION_TIMEOUT;
        let publication = self.acquire_publication_until(deadline)?;
        self.recover_abandoned(deadline)?;
        let mut members = retained.clone();
        if members
            .get(&active.payload.sha256)
            .is_some_and(|old| old != active)
        {
            return Err(CwRuntimeError::AssetCollision);
        }
        members.insert(active.payload.sha256.clone(), active.clone());
        if members.len() > CW_RUNTIME_MAX_VERSIONS {
            return Err(CwRuntimeError::RetentionLimit);
        }
        let runtimes = members
            .iter()
            .map(|(payload, expected)| {
                check_deadline(deadline)?;
                let asset = self.read_asset(payload)?;
                if &asset.provenance != expected {
                    return Err(CwRuntimeError::AssetCollision);
                }
                Ok(asset.provenance)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let catalog = CwRuntimeCatalog {
            schema_version: 1,
            active_sha256: active.payload.sha256.clone(),
            runtimes,
        };
        let catalog_bytes = catalog.encode().map_err(CwRuntimeError::InvalidCatalog)?;
        let generation = sha(&catalog_bytes);
        match self.open_catalog_until(&generation, deadline) {
            Ok(disk) => return Ok(disk),
            Err(error) if error.is_not_found() => {}
            Err(error) => return Err(error),
        }
        for (count, entry) in fs::read_dir(self.catalogs.path())?.enumerate() {
            check_deadline(deadline)?;
            if count + 1 >= MAXIMUM_STORE_OBJECTS {
                return Err(CwRuntimeError::RetentionLimit);
            }
            let name = entry?.file_name();
            if !name.to_str().is_some_and(digest) {
                return Err(CwRuntimeError::InvalidManifest);
            }
            PrivateRoot::open(&self.catalogs.path().join(name))?;
        }
        let temporary_name = format!("catalog-{}", Uuid::new_v4());
        let temporary =
            PrivateRoot::open(&self.staging.create_dir(Path::new(&temporary_name), 0o700)?)?;
        let mut cleanup = CatalogStagingCleanup {
            root: &self.staging,
            name: temporary_name.clone(),
            members: members.keys().cloned().collect(),
        };
        let seed = PrivateRoot::open(&temporary.create_dir(Path::new("seed"), 0o700)?)?;
        write_private(&seed, Path::new("catalog.json"), &catalog_bytes)?;
        let mut total = 0_u64;
        for (payload, expected) in &members {
            check_deadline(deadline)?;
            let asset = self.read_asset(payload)?;
            if &asset.provenance != expected {
                return Err(CwRuntimeError::AssetCollision);
            }
            total = total
                .checked_add(asset.provenance.payload.size)
                .ok_or(CwRuntimeError::RetentionLimit)?;
            let directory = PrivateRoot::open(&seed.create_dir(Path::new(payload), 0o700)?)?;
            write_private(&directory, Path::new("cw"), asset.payload())?;
            let provenance =
                serde_json::to_vec(&asset.provenance).map_err(|_| CwRuntimeError::InvalidAsset)?;
            write_private(&directory, Path::new("provenance.json"), &provenance)?;
        }
        let disk_bytes =
            (total + total / 10 + MINIMUM_DISK_BYTES).div_ceil(DISK_ALIGNMENT) * DISK_ALIGNMENT;
        if disk_bytes > MAXIMUM_RUNTIME_DISK_BYTES {
            return Err(CwRuntimeError::RetentionLimit);
        }
        let disk_name = Path::new("runtime.raw");
        let disk_path = temporary.path().join(disk_name);
        let disk = temporary
            .create_regular(disk_name, 0o600, true)?
            .into_file();
        disk.set_len(disk_bytes)?;
        disk.sync_all()?;
        drop(disk);
        format_runtime_disk(
            &temporary,
            &seed,
            &disk_path,
            &catalog,
            &publication,
            deadline,
        )?;
        let file = temporary
            .open_regular(disk_name, false, Some(disk_bytes), false, Some(0o600))?
            .into_file();
        file.sync_all()?;
        let disk_sha256 = hash_file(file, disk_bytes, deadline)?;
        fs::set_permissions(&disk_path, fs::Permissions::from_mode(0o400))?;
        File::open(&disk_path)?.sync_all()?;
        let manifest = CwRuntimeCatalogManifest {
            schema_version: 1,
            catalog,
            disk: CwRuntimeFileSpec {
                path: disk_name.to_owned(),
                size: disk_bytes,
                sha256: disk_sha256,
            },
        };
        manifest.validate(&generation)?;
        let bytes = serde_json::to_vec(&manifest).map_err(|_| CwRuntimeError::InvalidManifest)?;
        write_private(&temporary, Path::new("manifest.json"), &bytes)?;
        cleanup.cleanup_seed()?;
        // Publish the complete directory atomically. A crash cannot leave a
        // visible catalog with a missing disk or an orphan disk blocking retry.
        self.staging.move_private_directory_to(
            Path::new(&temporary_name),
            &self.catalogs,
            Path::new(&generation),
        )?;
        cleanup.name.clear();
        let admitted = self.open_catalog_until(&generation, deadline)?;
        if admitted.manifest != manifest {
            return Err(CwRuntimeError::AssetCollision);
        }
        Ok(admitted)
    }

    pub fn open_catalog(&self, generation: &str) -> Result<AdmittedCwRuntimeDisk, CwRuntimeError> {
        self.open_catalog_until(generation, Instant::now() + PREPARATION_TIMEOUT)
    }

    /// Reopen only the path derived from this authoritative private store.
    /// Persisted paths never authorize a filesystem read or a replacement.
    pub fn revalidate_attachment(
        &self,
        attachment: &AdmittedCwRuntimeDisk,
    ) -> Result<AdmittedCwRuntimeDisk, CwRuntimeError> {
        attachment.validate_metadata()?;
        let path = self
            .catalogs
            .path()
            .join(&attachment.generation)
            .join("runtime.raw");
        if attachment.path != path {
            return Err(CwRuntimeError::InvalidManifest);
        }
        let admitted = self.open_catalog(&attachment.generation)?;
        if &admitted != attachment {
            return Err(CwRuntimeError::DiskChanged);
        }
        Ok(admitted)
    }

    fn open_catalog_until(
        &self,
        generation: &str,
        deadline: Instant,
    ) -> Result<AdmittedCwRuntimeDisk, CwRuntimeError> {
        check_deadline(deadline)?;
        if !digest(generation) {
            return Err(CwRuntimeError::InvalidManifest);
        }
        let directory = PrivateRoot::open(&self.catalogs.path().join(generation))?;
        let mut names = BTreeSet::new();
        for entry in fs::read_dir(directory.path())? {
            check_deadline(deadline)?;
            let name = entry?.file_name();
            if names.len() == 2 || !matches!(name.to_str(), Some("manifest.json" | "runtime.raw")) {
                return Err(CwRuntimeError::InvalidManifest);
            }
            names.insert(name);
        }
        if names
            != BTreeSet::from([
                std::ffi::OsString::from("manifest.json"),
                std::ffi::OsString::from("runtime.raw"),
            ])
        {
            return Err(CwRuntimeError::InvalidManifest);
        }
        let bytes = read_bounded(
            &directory,
            Path::new("manifest.json"),
            MAXIMUM_MANIFEST_BYTES,
            None,
        )?;
        let manifest: CwRuntimeCatalogManifest =
            serde_json::from_slice(&bytes).map_err(|_| CwRuntimeError::InvalidManifest)?;
        manifest.validate(generation)?;
        let opened = directory.open_regular(
            &manifest.disk.path,
            false,
            Some(manifest.disk.size),
            false,
            Some(0o400),
        )?;
        let identity = opened.identity().clone();
        if hash_file(opened.into_file(), manifest.disk.size, deadline)? != manifest.disk.sha256 {
            return Err(CwRuntimeError::DiskChanged);
        }
        Ok(AdmittedCwRuntimeDisk {
            generation: generation.to_owned(),
            path: directory.path().join(&manifest.disk.path),
            identity,
            manifest,
        })
    }

    fn publication_guard(&self) -> Result<PublicationGuard, CwRuntimeError> {
        use std::os::fd::AsRawFd as _;
        let name = Path::new("publication.lock");
        let opened = match self.root.create_regular(name, 0o600, true) {
            Ok(opened) => opened,
            Err(PathError::Openat2 {
                source: rustix::io::Errno::EXIST,
                ..
            }) => self
                .root
                .open_regular(name, true, Some(0), false, Some(0o600))?,
            Err(error) => return Err(error.into()),
        };
        let file = opened.into_file();
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::WouldBlock {
                return Err(CwRuntimeError::PublicationBusy);
            }
            return Err(error.into());
        }
        Ok(PublicationGuard(file))
    }

    fn acquire_publication_until(
        &self,
        deadline: Instant,
    ) -> Result<PublicationGuard, CwRuntimeError> {
        let deadline = deadline.min(Instant::now() + PUBLICATION_ACQUISITION_TIMEOUT);
        loop {
            match self.publication_guard() {
                // An unrelated concurrent fork can briefly retain a CLOEXEC
                // lock reference until exec. Bound acquisition, without ever
                // releasing an old formatter's reference or recovering early.
                Err(CwRuntimeError::PublicationBusy) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                result => return result,
            }
        }
    }

    /// Called only while holding the exclusive publication lock. Validate the
    /// entire abandoned namespace before deleting its typed temporary objects.
    /// Published catalog directories and payloads are never recovery targets.
    fn recover_abandoned(&self, deadline: Instant) -> Result<(), CwRuntimeError> {
        let mut ingest = Vec::new();
        for (count, entry) in fs::read_dir(self.assets.path())?.enumerate() {
            check_deadline(deadline)?;
            if count >= MAXIMUM_STORE_OBJECTS {
                return Err(CwRuntimeError::RetentionLimit);
            }
            let entry = entry?;
            let name = entry.file_name();
            let text = name.to_str().ok_or(CwRuntimeError::InvalidAsset)?;
            if text.strip_suffix(".pack").is_some_and(digest) {
                inspect_private_file(
                    &self.assets,
                    Path::new(&name),
                    0o400,
                    CW_RUNTIME_MAX_PACK as u64,
                )?;
            } else if text.strip_prefix(".ingest-").is_some_and(canonical_uuid) {
                inspect_private_file(
                    &self.assets,
                    Path::new(&name),
                    0o400,
                    CW_RUNTIME_MAX_PACK as u64,
                )?;
                ingest.push(PathBuf::from(name));
            } else {
                return Err(CwRuntimeError::InvalidAsset);
            }
        }
        let mut abandoned = Vec::new();
        for (count, entry) in fs::read_dir(self.staging.path())?.enumerate() {
            check_deadline(deadline)?;
            if count >= MAXIMUM_STORE_OBJECTS {
                return Err(CwRuntimeError::RetentionLimit);
            }
            let name = entry?.file_name();
            let text = name.to_str().ok_or(CwRuntimeError::InvalidManifest)?;
            if !text.strip_prefix("catalog-").is_some_and(canonical_uuid) {
                return Err(CwRuntimeError::InvalidManifest);
            }
            let directory = PrivateRoot::open(&self.staging.path().join(&name))?;
            let mut members = BTreeSet::new();
            let mut logs = Vec::new();
            for (count, entry) in fs::read_dir(directory.path())?.enumerate() {
                check_deadline(deadline)?;
                if count >= 5 {
                    return Err(CwRuntimeError::InvalidManifest);
                }
                let name = entry?.file_name();
                let text = name.to_str().ok_or(CwRuntimeError::InvalidManifest)?;
                match text {
                    "runtime.raw" => {
                        let metadata = fs::symlink_metadata(directory.path().join(&name))?;
                        let mode = metadata.mode() & 0o7777;
                        if !matches!(mode, 0o400 | 0o600) {
                            return Err(CwRuntimeError::InvalidManifest);
                        }
                        inspect_private_file(
                            &directory,
                            Path::new(&name),
                            mode,
                            MAXIMUM_RUNTIME_DISK_BYTES,
                        )?;
                    }
                    "manifest.json" | "metadata.commands" => {
                        inspect_private_file(
                            &directory,
                            Path::new(&name),
                            0o400,
                            MAXIMUM_MANIFEST_BYTES as u64,
                        )?;
                    }
                    "seed" => {
                        let seed = PrivateRoot::open(&directory.path().join("seed"))?;
                        for (count, entry) in fs::read_dir(seed.path())?.enumerate() {
                            check_deadline(deadline)?;
                            if count > CW_RUNTIME_MAX_VERSIONS {
                                return Err(CwRuntimeError::RetentionLimit);
                            }
                            let name = entry?.file_name();
                            let text = name.to_str().ok_or(CwRuntimeError::InvalidManifest)?;
                            if text == "catalog.json" {
                                inspect_private_file(
                                    &seed,
                                    Path::new(&name),
                                    0o400,
                                    CW_RUNTIME_MAX_CATALOG as u64,
                                )?;
                            } else if digest(text) {
                                let child = PrivateRoot::open(&seed.path().join(&name))?;
                                for (count, entry) in fs::read_dir(child.path())?.enumerate() {
                                    if count >= 2 {
                                        return Err(CwRuntimeError::InvalidManifest);
                                    }
                                    let name = entry?.file_name();
                                    let maximum = match name.to_str() { Some("cw") => codewire_vmm_guest_probe::cw_runtime::CW_RUNTIME_MAX_BYTES,
                                        Some("provenance.json") => codewire_vmm_guest_probe::cw_runtime::CW_RUNTIME_MAX_PROVENANCE,
                                        _ => return Err(CwRuntimeError::InvalidManifest) };
                                    inspect_private_file(
                                        &child,
                                        Path::new(&name),
                                        0o400,
                                        maximum as u64,
                                    )?;
                                }
                                members.insert(text.to_owned());
                            } else {
                                return Err(CwRuntimeError::InvalidManifest);
                            }
                        }
                    }
                    _ if text
                        .strip_prefix("tool-")
                        .and_then(|text| text.strip_suffix(".log"))
                        .is_some_and(canonical_uuid) =>
                    {
                        inspect_private_file(
                            &directory,
                            Path::new(&name),
                            0o600,
                            // Output can overshoot the live capture limit before
                            // the producer stops the leaf tool. Recovery reads
                            // no log contents, so a typed owned log is removable
                            // regardless of its length.
                            u64::MAX,
                        )?;
                        logs.push(PathBuf::from(name));
                    }
                    _ => return Err(CwRuntimeError::InvalidManifest),
                }
            }
            abandoned.push((text.to_owned(), members, logs));
        }
        for (name, members, logs) in abandoned {
            let directory = PrivateRoot::open(&self.staging.path().join(&name))?;
            for log in logs {
                directory.remove_private_regular(&log, 0o600)?;
            }
            let mut cleanup = CatalogStagingCleanup {
                root: &self.staging,
                name,
                members,
            };
            cleanup.cleanup()?;
        }
        for path in ingest {
            self.assets.remove_private_regular(&path, 0o400)?;
        }
        Ok(())
    }
}

struct PublicationGuard(File);
// Closing the final reference releases flock. Explicit LOCK_UN would also
// release an orphan leaf tool's reference to this same open file description.

fn canonical_uuid(value: &str) -> bool {
    Uuid::parse_str(value).is_ok_and(|uuid| !uuid.is_nil() && uuid.to_string() == value)
}

fn inspect_private_file(
    root: &PrivateRoot,
    name: &Path,
    mode: u32,
    maximum: u64,
) -> Result<(), CwRuntimeError> {
    let opened = root.open_regular(name, false, None, false, Some(mode))?;
    if opened.identity().size > maximum {
        return Err(CwRuntimeError::InvalidAsset);
    }
    Ok(())
}

fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn read_bounded(
    root: &PrivateRoot,
    path: &Path,
    limit: usize,
    size: Option<u64>,
) -> Result<Vec<u8>, CwRuntimeError> {
    let opened = root.open_regular(path, false, size, false, None)?;
    if opened.identity().size == 0 || opened.identity().size > limit as u64 {
        return Err(CwRuntimeError::InvalidAsset);
    }
    let expected = opened.identity().size;
    let mut file = opened.into_file();
    let before = file.metadata()?;
    let mut bytes = Vec::with_capacity(expected as usize);
    (&mut file).take(limit as u64 + 1).read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    if bytes.len() as u64 != expected
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
    {
        return Err(CwRuntimeError::InvalidAsset);
    }
    Ok(bytes)
}

fn check_deadline(deadline: Instant) -> Result<(), CwRuntimeError> {
    if Instant::now() >= deadline {
        Err(CwRuntimeError::ToolFailed)
    } else {
        Ok(())
    }
}

fn hash_file(
    mut file: File,
    expected_size: u64,
    deadline: Instant,
) -> Result<String, CwRuntimeError> {
    let before = file.metadata()?;
    if expected_size > MAXIMUM_RUNTIME_DISK_BYTES || before.len() != expected_size {
        return Err(CwRuntimeError::DiskChanged);
    }
    let mut digest = Sha256::new();
    let mut bytes = [0_u8; 64 * 1024];
    let mut total = 0_u64;
    loop {
        check_deadline(deadline)?;
        let remaining = (expected_size + 1 - total).min(bytes.len() as u64) as usize;
        let count = file.read(&mut bytes[..remaining])?;
        if count == 0 {
            break;
        }
        total += count as u64;
        if total > expected_size {
            return Err(CwRuntimeError::DiskChanged);
        }
        digest.update(&bytes[..count]);
    }
    let after = file.metadata()?;
    if total != expected_size
        || FileIdentity::from_metadata(&before) != FileIdentity::from_metadata(&after)
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
    {
        return Err(CwRuntimeError::DiskChanged);
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn write_private(root: &PrivateRoot, path: &Path, bytes: &[u8]) -> Result<(), CwRuntimeError> {
    let mut file = root.create_regular(path, 0o400, true)?.into_file();
    let mut cleanup = PrivateFileCleanup {
        root,
        path: Some(path.to_owned()),
        permissions: 0o400,
    };
    file.write_all(bytes)?;
    file.sync_all()?;
    cleanup.path = None;
    Ok(())
}

fn publish_exact(root: &PrivateRoot, name: &Path, bytes: &[u8]) -> Result<(), CwRuntimeError> {
    let temporary = PathBuf::from(format!(".ingest-{}", Uuid::new_v4()));
    write_private(root, &temporary, bytes)?;
    let mut cleanup = PrivateFileCleanup {
        root,
        path: Some(temporary.clone()),
        permissions: 0o400,
    };
    let result = root.publish_private_regular_no_replace(&temporary, name, 0o400);
    match result {
        Ok(true) => {
            cleanup.path = None;
            Ok(())
        }
        Ok(false) => {
            root.remove_private_regular(&temporary, 0o400)?;
            let found = read_bounded(root, name, bytes.len(), Some(bytes.len() as u64))?;
            if found == bytes {
                Ok(())
            } else {
                Err(CwRuntimeError::AssetCollision)
            }
        }
        Err(error) => {
            let _ = root.remove_private_regular(&temporary, 0o400);
            Err(error.into())
        }
    }
}

fn format_runtime_disk(
    temporary: &PrivateRoot,
    seed: &PrivateRoot,
    disk: &Path,
    catalog: &CwRuntimeCatalog,
    publication: &PublicationGuard,
    deadline: Instant,
) -> Result<(), CwRuntimeError> {
    run_tool(
        temporary,
        publication,
        "/usr/sbin/mkfs.ext4",
        &[
            "-q".into(),
            "-F".into(),
            "-m".into(),
            "0".into(),
            "-N".into(),
            "4096".into(),
            "-O".into(),
            "^has_journal".into(),
            "-E".into(),
            "lazy_itable_init=0".into(),
            "-L".into(),
            "CWRUNTIME".into(),
            "-d".into(),
            seed.path().as_os_str().to_owned(),
            disk.as_os_str().to_owned(),
        ],
        deadline,
    )?;
    let mut commands = String::from("rmdir /lost+found\n");
    let mut entries = vec![
        ("/".to_owned(), 0o40555_u32, None),
        (
            "/catalog.json".to_owned(),
            0o100444,
            Some(
                catalog
                    .encode()
                    .map_err(CwRuntimeError::InvalidCatalog)?
                    .len() as u64,
            ),
        ),
    ];
    for runtime in &catalog.runtimes {
        let root = format!("/{}", runtime.payload.sha256);
        entries.extend([
            (root.clone(), 0o40555, None),
            (format!("{root}/cw"), 0o100555, Some(runtime.payload.size)),
            (
                format!("{root}/provenance.json"),
                0o100444,
                Some(
                    serde_json::to_vec(runtime)
                        .map_err(|_| CwRuntimeError::InvalidAsset)?
                        .len() as u64,
                ),
            ),
        ]);
    }
    for (path, mode, _) in &entries {
        commands.push_str(&format!("set_inode_field {path} uid 0\nset_inode_field {path} gid 0\nset_inode_field {path} mode 0{mode:o}\n"));
    }
    write_private(
        temporary,
        Path::new("metadata.commands"),
        commands.as_bytes(),
    )?;
    run_tool(
        temporary,
        publication,
        "/usr/sbin/debugfs",
        &[
            "-w".into(),
            "-f".into(),
            temporary.path().join("metadata.commands").into_os_string(),
            disk.as_os_str().to_owned(),
        ],
        deadline,
    )?;
    // debugfs can report a command error while exiting zero. Inspect the
    // resulting inode fields rather than interpreting exit status as proof.
    for (path, mode, size) in entries {
        let output = run_tool(
            temporary,
            publication,
            "/usr/sbin/debugfs",
            &[
                "-R".into(),
                format!("stat {path}").into(),
                disk.as_os_str().to_owned(),
            ],
            deadline,
        )?;
        validate_inode_report(&output, mode, size)?;
    }
    Ok(())
}

fn validate_inode_report(
    output: &[u8],
    mode: u32,
    size: Option<u64>,
) -> Result<(), CwRuntimeError> {
    let text = std::str::from_utf8(output).map_err(|_| CwRuntimeError::ToolFailed)?;
    let words = text.split_whitespace().collect::<Vec<_>>();
    let value = |label: &str| {
        words
            .iter()
            .position(|word| *word == label)
            .and_then(|position| words.get(position + 1))
            .copied()
    };
    let expected_type = if size.is_some() {
        "regular"
    } else {
        "directory"
    };
    if value("Type:") != Some(expected_type)
        || value("User:") != Some("0")
        || value("Group:") != Some("0")
        || value("Mode:").and_then(|value| u32::from_str_radix(value, 8).ok())
            != Some(mode & 0o7777)
        || size.is_some_and(|size| {
            value("Size:").and_then(|value| value.parse::<u64>().ok()) != Some(size)
        })
        || size.is_some() && value("Links:") != Some("1")
    {
        return Err(CwRuntimeError::ToolFailed);
    }
    Ok(())
}

fn run_tool(
    temporary: &PrivateRoot,
    publication: &PublicationGuard,
    tool: &str,
    arguments: &[std::ffi::OsString],
    operation_deadline: Instant,
) -> Result<Vec<u8>, CwRuntimeError> {
    check_deadline(operation_deadline)?;
    let output_name = PathBuf::from(format!("tool-{}.log", Uuid::new_v4()));
    let output = temporary
        .create_regular(&output_name, 0o600, true)?
        .into_file();
    let _cleanup = PrivateFileCleanup {
        root: temporary,
        path: Some(output_name.clone()),
        permissions: 0o600,
    };
    let mut command = Command::new(tool);
    command
        .args(arguments)
        .env_clear()
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(output.try_clone()?)
        .stderr(output);
    inherit_publication_custody(&mut command, publication)?;
    let child = command.spawn()?;
    drop(command);
    let mut child = OwnedToolChild(child);
    let deadline = operation_deadline.min(Instant::now() + TOOL_TIMEOUT);
    let status = loop {
        if let Some(status) = child.0.try_wait()? {
            break status;
        }
        let metadata = fs::metadata(temporary.path().join(&output_name))?;
        if metadata.len() > TOOL_OUTPUT_LIMIT || Instant::now() >= deadline {
            let _ = child.0.kill();
            let _ = child.0.wait();
            let _ = temporary.remove_private_regular(&output_name, 0o600);
            return Err(CwRuntimeError::ToolFailed);
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let read_output = || -> Result<Vec<u8>, CwRuntimeError> {
        let opened = temporary.open_regular(&output_name, false, None, false, Some(0o600))?;
        if opened.identity().size > TOOL_OUTPUT_LIMIT {
            return Err(CwRuntimeError::ToolFailed);
        }
        let mut bytes = Vec::new();
        opened
            .into_file()
            .take(TOOL_OUTPUT_LIMIT + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > TOOL_OUTPUT_LIMIT {
            return Err(CwRuntimeError::ToolFailed);
        }
        Ok(bytes)
    };
    let bytes = read_output();
    temporary.remove_private_regular(&output_name, 0o600)?;
    let bytes = bytes?;
    if !status.success() {
        return Err(CwRuntimeError::ToolFailed);
    }
    Ok(bytes)
}

fn inherit_publication_custody(
    command: &mut Command,
    publication: &PublicationGuard,
) -> Result<(), io::Error> {
    use std::os::fd::{AsRawFd as _, FromRawFd as _};
    use std::os::unix::process::CommandExt as _;
    let parent = unsafe { libc::getpid() };
    // Stdio is rewritten before pre_exec. Pin a distinct descriptor above it,
    // even if the caller began with stdin/stdout/stderr closed.
    let lock_fd = unsafe { libc::fcntl(publication.0.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
    if lock_fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let lock = unsafe { File::from_raw_fd(lock_fd) };
    // These trusted tools are leaf children. Retain the same locked open file
    // description until leaf exit, including the parent-death signal window.
    // Acquiring the publication lock therefore proves the prior writer exited.
    unsafe {
        command.pre_exec(move || {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::getppid() != parent {
                return Err(io::Error::from(io::ErrorKind::Interrupted));
            }
            if libc::fcntl(lock.as_raw_fd(), libc::F_SETFD, 0) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    Ok(())
}

struct OwnedToolChild(std::process::Child);
impl Drop for OwnedToolChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct PrivateFileCleanup<'a> {
    root: &'a PrivateRoot,
    path: Option<PathBuf>,
    permissions: u32,
}
impl Drop for PrivateFileCleanup<'_> {
    fn drop(&mut self) {
        if let Some(path) = &self.path {
            let _ = self.root.remove_private_regular(path, self.permissions);
        }
    }
}

struct CatalogStagingCleanup<'a> {
    root: &'a PrivateRoot,
    name: String,
    members: BTreeSet<String>,
}
impl CatalogStagingCleanup<'_> {
    fn cleanup_seed(&self) -> Result<(), CwRuntimeError> {
        if self.name.is_empty() {
            return Ok(());
        }
        let directory = PrivateRoot::open(&self.root.path().join(&self.name))?;
        if let Ok(seed) = PrivateRoot::open(&directory.path().join("seed")) {
            for member in &self.members {
                if let Ok(child) = PrivateRoot::open(&seed.path().join(member)) {
                    for name in ["cw", "provenance.json"] {
                        child.remove_private_regular(Path::new(name), 0o400)?;
                    }
                    seed.remove_empty_private_directory(Path::new(member))?;
                }
            }
            seed.remove_private_regular(Path::new("catalog.json"), 0o400)?;
            directory.remove_empty_private_directory(Path::new("seed"))?;
        }
        if fs::symlink_metadata(directory.path().join("metadata.commands")).is_ok() {
            directory.remove_private_regular(Path::new("metadata.commands"), 0o400)?;
        }
        Ok(())
    }
    fn cleanup(&mut self) -> Result<(), CwRuntimeError> {
        if self.name.is_empty() {
            return Ok(());
        }
        self.cleanup_seed()?;
        let directory = PrivateRoot::open(&self.root.path().join(&self.name))?;
        for name in ["runtime.raw", "manifest.json"] {
            let path = directory.path().join(name);
            if let Ok(metadata) = fs::symlink_metadata(path) {
                directory.remove_private_regular(Path::new(name), metadata.mode() & 0o777)?;
            }
        }
        self.root
            .remove_empty_private_directory(Path::new(&self.name))?;
        self.name.clear();
        Ok(())
    }
}
impl Drop for CatalogStagingCleanup<'_> {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CwRuntimeError {
    #[error("another cw runtime publication is active")]
    PublicationBusy,
    #[error("cw runtime asset is invalid or unavailable")]
    InvalidAsset,
    #[error("cw runtime catalog is invalid: {0}")]
    InvalidCatalog(&'static str),
    #[error("cw runtime catalog manifest is invalid")]
    InvalidManifest,
    #[error("cw runtime payload or catalog collides with retained identity")]
    AssetCollision,
    #[error("cw runtime update cannot retain every referenced version within its bound")]
    RetentionLimit,
    #[error("retained cw runtime disk identity changed")]
    DiskChanged,
    #[error("cw runtime disk production or inode verification failed")]
    ToolFailed,
    #[error(transparent)]
    Path(#[from] PathError),
    #[error(transparent)]
    Io(#[from] io::Error),
}

impl CwRuntimeError {
    fn is_not_found(&self) -> bool {
        matches!(self, Self::Io(error) if error.kind() == io::ErrorKind::NotFound)
            || matches!(self, Self::Path(PathError::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound)
            || matches!(
                self,
                Self::Path(PathError::Openat2 {
                    source: rustix::io::Errno::NOENT,
                    ..
                })
            )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use codewire_vmm_guest_probe::cw_runtime::{CwImageDescriptor, CwImagePayload};

    fn fixture_asset(root: &Path, marker: u8) -> (PathBuf, Vec<u8>) {
        fs::create_dir(root).unwrap();
        fs::set_permissions(root, fs::Permissions::from_mode(0o700)).unwrap();
        let mut cw = vec![0_u8; 136];
        cw[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        cw[16..18].copy_from_slice(&2_u16.to_le_bytes());
        cw[18..20].copy_from_slice(&62_u16.to_le_bytes());
        cw[32..40].copy_from_slice(&64_u64.to_le_bytes());
        cw[54..56].copy_from_slice(&56_u16.to_le_bytes());
        cw[56..58].copy_from_slice(&1_u16.to_le_bytes());
        cw[64..68].copy_from_slice(&1_u32.to_le_bytes());
        cw[135] = marker;
        let descriptor = CwImageDescriptor {
            sha256: "a".repeat(64),
            size: 10240,
        };
        let provenance = CwRuntimeProvenance {
            schema_version: 1,
            image_index_sha256: "b".repeat(64),
            image_manifest: descriptor.clone(),
            image_config: descriptor.clone(),
            image_layer: descriptor,
            layer_diff_id: "a".repeat(64),
            payload: CwImagePayload {
                schema_version: 2,
                protocol_version: 1,
                record_version: 1,
                package_version: "0.1.0".into(),
                target: "x86_64-unknown-linux-musl".into(),
                source_revision: format!("{marker:040x}"),
                source_tree_sha256: "c".repeat(64),
                rustc: "rustc 1.93.0 (synthetic fixture)".into(),
                sha256: sha(&cw),
                size: cw.len() as u64,
            },
        };
        let provenance = serde_json::to_vec(&provenance).unwrap();
        let mut pack = b"CWRPACK1".to_vec();
        pack.extend_from_slice(&(provenance.len() as u64).to_le_bytes());
        pack.extend_from_slice(&(cw.len() as u64).to_le_bytes());
        pack.extend_from_slice(&provenance);
        pack.extend_from_slice(&cw);
        let lock = CwRuntimeAssetLock {
            schema_version: 1,
            image_index_sha256: "b".repeat(64),
            pack: CwRuntimeFileSpec {
                path: "runtime.pack".into(),
                size: pack.len() as u64,
                sha256: sha(&pack),
            },
        };
        let root = PrivateRoot::open(root).unwrap();
        write_private(&root, Path::new("runtime.pack"), &pack).unwrap();
        write_private(
            &root,
            Path::new("cw-runtime.lock.json"),
            &serde_json::to_vec(&lock).unwrap(),
        )
        .unwrap();
        (root.path().join("cw-runtime.lock.json"), cw)
    }

    #[test]
    fn live_runtime_source_pins_refuse_before_asset_publication() {
        let task = tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let (path, _) = fixture_asset(&task.path().join("source"), 1);
        let source = AdmittedCwRuntimeAsset::read_source(&path).unwrap();
        let engine = PrivateRoot::create(&task.path().join("engine")).unwrap();
        let store = CwRuntimeStore::create(&engine).unwrap();
        for (image, payload) in [
            ("f".repeat(64), source.provenance.payload.sha256.clone()),
            (source.provenance.image_index_sha256.clone(), "f".repeat(64)),
            ("B".repeat(64), source.provenance.payload.sha256.clone()),
        ] {
            assert!(store.admit_source_pinned(&path, &image, &payload).is_err());
            assert_eq!(fs::read_dir(store.assets.path()).unwrap().count(), 0);
            assert_eq!(fs::read_dir(store.catalogs.path()).unwrap().count(), 0);
        }
        let admitted = store
            .admit_source_pinned(
                &path,
                &source.provenance.image_index_sha256,
                &source.provenance.payload.sha256,
            )
            .unwrap();
        assert_eq!(admitted.provenance, source.provenance);
        assert_eq!(
            store
                .read_asset(&admitted.provenance.payload.sha256)
                .unwrap()
                .pack(),
            source.pack()
        );
        assert_eq!(fs::read_dir(store.assets.path()).unwrap().count(), 1);
        assert_eq!(fs::read_dir(store.catalogs.path()).unwrap().count(), 0);
    }

    fn replace_lock(path: &Path, change: impl FnOnce(&mut CwRuntimeAssetLock)) {
        let mut lock: CwRuntimeAssetLock =
            serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        change(&mut lock);
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(path, serde_json::to_vec(&lock).unwrap()).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o400)).unwrap();
    }

    #[test]
    fn source_admission_checks_external_pack_and_image_pins() {
        let task = tempfile::tempdir().unwrap();
        let (path, _) = fixture_asset(&task.path().join("source"), 1);
        let asset = AdmittedCwRuntimeAsset::read_source(&path).unwrap();
        replace_lock(&path, |lock| lock.image_index_sha256 = "d".repeat(64));
        assert!(AdmittedCwRuntimeAsset::read_source(&path).is_err());
        replace_lock(&path, |lock| {
            lock.image_index_sha256 = asset.provenance.image_index_sha256.clone();
            lock.pack.sha256 = "e".repeat(64);
        });
        assert!(AdmittedCwRuntimeAsset::read_source(&path).is_err());
        replace_lock(&path, |lock| {
            lock.pack.sha256 = asset.pack_sha256.clone();
            lock.pack.path = task.path().join("source/runtime.pack");
        });
        assert!(AdmittedCwRuntimeAsset::read_source(&path).is_err());
    }

    #[test]
    fn catalog_rejects_conflicting_retained_provenance_and_overflow_before_formatting() {
        let task = tempfile::tempdir().unwrap();
        fs::set_permissions(task.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let engine = PrivateRoot::create(&task.path().join("engine")).unwrap();
        let store = CwRuntimeStore::create(&engine).unwrap();
        let (path, _) = fixture_asset(&task.path().join("source"), 1);
        let active = store.admit_source(&path).unwrap().provenance;
        let mut conflicting = active.clone();
        conflicting.payload.source_revision = "f".repeat(40);
        assert!(matches!(
            store.prepare_catalog(
                &active,
                &BTreeMap::from([(active.payload.sha256.clone(), conflicting)])
            ),
            Err(CwRuntimeError::AssetCollision)
        ));
        let members = (0..=CW_RUNTIME_MAX_VERSIONS)
            .map(|number| (format!("{number:064x}"), active.clone()))
            .collect();
        assert!(matches!(
            store.prepare_catalog(&active, &members),
            Err(CwRuntimeError::RetentionLimit)
        ));
        assert_eq!(fs::read_dir(store.catalogs.path()).unwrap().count(), 0);
        assert_eq!(fs::read_dir(store.staging.path()).unwrap().count(), 0);
    }

    #[test]
    fn real_catalog_disk_has_root_metadata_and_preserves_the_old_immutable_generation() {
        let task = tempfile::tempdir().unwrap();
        fs::set_permissions(task.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let engine = PrivateRoot::create(&task.path().join("engine")).unwrap();
        let store = CwRuntimeStore::create(&engine).unwrap();
        let (old_path, old_cw) = fixture_asset(&task.path().join("old"), 1);
        let old = store.admit_source(&old_path).unwrap().provenance;
        let disk = store.prepare_catalog(&old, &BTreeMap::new()).unwrap();
        disk.revalidate().unwrap();
        let saved: AdmittedCwRuntimeDisk =
            serde_json::from_slice(&serde_json::to_vec(&disk).unwrap()).unwrap();
        assert_eq!(store.revalidate_attachment(&saved).unwrap(), disk);
        let mut foreign = saved.clone();
        foreign.path = task
            .path()
            .join("foreign")
            .join(&saved.generation)
            .join("runtime.raw");
        assert!(foreign.validate_metadata().is_ok());
        assert!(matches!(
            store.revalidate_attachment(&foreign),
            Err(CwRuntimeError::InvalidManifest)
        ));
        let mut changed = saved;
        changed.manifest.disk.sha256 = "d".repeat(64);
        assert!(matches!(
            store.revalidate_attachment(&changed),
            Err(CwRuntimeError::DiskChanged)
        ));
        assert_eq!(disk, store.prepare_catalog(&old, &BTreeMap::new()).unwrap());
        let (current_path, _) = fixture_asset(&task.path().join("current"), 2);
        let current = store.admit_source(&current_path).unwrap().provenance;
        let next = store
            .prepare_catalog(
                &current,
                &BTreeMap::from([(old.payload.sha256.clone(), old.clone())]),
            )
            .unwrap();
        assert_ne!(next.generation, disk.generation);
        assert_eq!(next.manifest.catalog.active().unwrap(), &current);
        assert_eq!(
            next.manifest.catalog.runtime(&old.payload.sha256).unwrap(),
            &old
        );
        disk.revalidate().unwrap();
        // Independently inspect actual ext4 bytes, not the host seed's UID.
        let read = Command::new("/usr/sbin/debugfs")
            .args(["-R", &format!("cat /{}/cw", old.payload.sha256)])
            .arg(&next.path)
            .env_clear()
            .env("LC_ALL", "C")
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(read.status.success());
        assert_eq!(read.stdout, old_cw);
        assert_eq!(fs::read_dir(store.staging.path()).unwrap().count(), 0);
        fs::write(next.path.parent().unwrap().join("unexpected"), b"extra").unwrap();
        assert!(matches!(
            store.open_catalog(&next.generation),
            Err(CwRuntimeError::InvalidManifest)
        ));
    }

    #[test]
    fn inode_report_rejects_copied_workload_ownership_and_links() {
        let report = "Inode: 12 Type: regular Mode: 0555 User: 0 Group: 0 Size: 136 Links: 1";
        validate_inode_report(report.as_bytes(), 0o100555, Some(136)).unwrap();
        for changed in [
            report.replace("User: 0", "User: 1000"),
            report.replace("Group: 0", "Group: 1000"),
            report.replace("Links: 1", "Links: 2"),
            report.replace("0555", "0755"),
            report.replace("136", "137"),
            "File not found by ext2_lookup".into(),
        ] {
            assert!(validate_inode_report(changed.as_bytes(), 0o100555, Some(136)).is_err());
        }
    }

    #[test]
    fn failed_tool_spawn_and_deadline_leave_no_log_or_live_child() {
        let task = tempfile::tempdir().unwrap();
        fs::set_permissions(task.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let engine = PrivateRoot::create(&task.path().join("engine")).unwrap();
        let store = CwRuntimeStore::create(&engine).unwrap();
        let publication = store.publication_guard().unwrap();
        let root = PrivateRoot::create(&task.path().join("tools")).unwrap();
        assert!(
            run_tool(
                &root,
                &publication,
                "/missing-codewire-filesystem-tool",
                &[],
                Instant::now() + Duration::from_secs(1)
            )
            .is_err()
        );
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
        assert!(
            run_tool(
                &root,
                &publication,
                "/usr/bin/sleep",
                &["30".into()],
                Instant::now() + Duration::from_millis(50)
            )
            .is_err()
        );
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
        let file = root
            .create_regular(Path::new("hash"), 0o400, true)
            .unwrap()
            .into_file();
        assert!(hash_file(file, 0, Instant::now()).is_err());
    }

    #[test]
    fn publication_lock_and_typed_recovery_preserve_committed_assets() {
        let task = tempfile::tempdir().unwrap();
        fs::set_permissions(task.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let engine = PrivateRoot::create(&task.path().join("engine")).unwrap();
        let store = CwRuntimeStore::create(&engine).unwrap();
        let first = store.publication_guard().unwrap();
        assert!(matches!(
            store.publication_guard(),
            Err(CwRuntimeError::PublicationBusy)
        ));
        drop(first);
        let name = format!("catalog-{}", Uuid::new_v4());
        let directory =
            PrivateRoot::open(&store.staging.create_dir(Path::new(&name), 0o700).unwrap()).unwrap();
        write_private(&directory, Path::new("runtime.raw"), b"partial").unwrap();
        let log = format!("tool-{}.log", Uuid::new_v4());
        directory
            .create_regular(Path::new(&log), 0o600, true)
            .unwrap()
            .into_file()
            .set_len(TOOL_OUTPUT_LIMIT + 4096)
            .unwrap();
        let ingest = format!(".ingest-{}", Uuid::new_v4());
        write_private(&store.assets, Path::new(&ingest), b"partial").unwrap();
        let _publication = store.publication_guard().unwrap();
        store
            .recover_abandoned(Instant::now() + Duration::from_secs(1))
            .unwrap();
        assert_eq!(fs::read_dir(store.staging.path()).unwrap().count(), 0);
        assert_eq!(fs::read_dir(store.assets.path()).unwrap().count(), 0);
        let published = format!("{}.pack", "a".repeat(64));
        write_private(&store.assets, Path::new(&published), b"retained").unwrap();
        write_private(&store.assets, Path::new(&ingest), b"partial").unwrap();
        write_private(&store.assets, Path::new("foreign"), b"unrelated").unwrap();
        assert!(
            store
                .recover_abandoned(Instant::now() + Duration::from_secs(1))
                .is_err()
        );
        assert!(store.assets.path().join(&ingest).is_file());
        assert_eq!(
            fs::read(store.assets.path().join(&published)).unwrap(),
            b"retained"
        );
    }

    #[test]
    fn leaf_tool_holds_publication_lock_until_exit() {
        let task = tempfile::tempdir().unwrap();
        fs::set_permissions(task.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let engine = PrivateRoot::create(&task.path().join("engine")).unwrap();
        let store = CwRuntimeStore::create(&engine).unwrap();
        let publication = store.publication_guard().unwrap();
        let mut command = Command::new("/usr/bin/sleep");
        command
            .arg("30")
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        inherit_publication_custody(&mut command, &publication).unwrap();
        let mut child = OwnedToolChild(command.spawn().unwrap());
        drop(command);
        drop(publication);
        assert!(matches!(
            store.publication_guard(),
            Err(CwRuntimeError::PublicationBusy)
        ));
        assert!(matches!(
            store.acquire_publication_until(Instant::now() + Duration::from_millis(30)),
            Err(CwRuntimeError::PublicationBusy)
        ));
        child.0.kill().unwrap();
        child.0.wait().unwrap();
        store
            .acquire_publication_until(Instant::now() + Duration::from_secs(1))
            .unwrap();
    }

    #[test]
    fn full_asset_store_can_reuse_but_cannot_publish_another_asset() {
        let task = tempfile::tempdir().unwrap();
        fs::set_permissions(task.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let engine = PrivateRoot::create(&task.path().join("engine")).unwrap();
        let store = CwRuntimeStore::create(&engine).unwrap();
        let (old_path, _) = fixture_asset(&task.path().join("old"), 1);
        let old = store.admit_source(&old_path).unwrap();
        for index in 1..MAXIMUM_STORE_OBJECTS {
            let path = store.assets.path().join(format!("{index:064x}.pack"));
            fs::write(&path, b"retained").unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o400)).unwrap();
        }
        assert_eq!(
            store.admit_source(&old_path).unwrap().provenance,
            old.provenance
        );
        let (new_path, _) = fixture_asset(&task.path().join("new"), 2);
        assert!(matches!(
            store.admit_source(&new_path),
            Err(CwRuntimeError::RetentionLimit)
        ));
        assert_eq!(
            fs::read_dir(store.assets.path()).unwrap().count(),
            MAXIMUM_STORE_OBJECTS
        );
    }

    // A separate process lets the test kill a producer without forking the
    // threaded Rust harness or killing another test's thread.
    #[test]
    #[ignore = "invoked only by killed_producer_stops_leaf_before_recovery"]
    fn publication_lock_child_fixture() {
        let task = std::env::var_os("CODEWIRE_RUNTIME_TEST_ROOT").unwrap();
        let task = PathBuf::from(task);
        let engine = PrivateRoot::create(&task.join("engine")).unwrap();
        let store = CwRuntimeStore::create(&engine).unwrap();
        let publication = store.publication_guard().unwrap();
        let publication = if std::env::var_os("CODEWIRE_RUNTIME_TEST_CLOSED_STDIO").is_some() {
            use std::os::fd::{AsRawFd as _, FromRawFd as _};
            assert!(publication.0.as_raw_fd() > 2);
            assert_eq!(unsafe { libc::dup2(publication.0.as_raw_fd(), 0) }, 0);
            unsafe {
                libc::close(1);
                libc::close(2);
            }
            let stdin_lock = PublicationGuard(unsafe { File::from_raw_fd(0) });
            drop(publication);
            stdin_lock
        } else {
            publication
        };
        let name = format!("catalog-{}", Uuid::new_v4());
        let directory =
            PrivateRoot::open(&store.staging.create_dir(Path::new(&name), 0o700).unwrap()).unwrap();
        let _ = run_tool(
            &directory,
            &publication,
            "/usr/bin/python3",
            &[
                "-c".into(),
                "import os,sys,time\nexpected=os.stat(sys.argv[2])\nheld=False\nfor value in os.listdir('/proc/self/fd'):\n if int(value)<=2:continue\n try:actual=os.fstat(int(value))\n except OSError:continue\n held|=(actual.st_dev,actual.st_ino)==(expected.st_dev,expected.st_ino)\nassert held\nopen(sys.argv[1],'x').write(str(os.getpid()))\ntime.sleep(30)"
                    .into(),
                task.join("leaf.pid").into_os_string(),
                store.root.path().join("publication.lock").into_os_string(),
            ],
            Instant::now() + Duration::from_secs(60),
        );
    }

    #[test]
    fn killed_producer_stops_leaf_before_recovery() {
        assert_killed_producer_cleanup(false);
    }

    #[test]
    fn killed_producer_with_closed_stdio_stops_leaf_before_recovery() {
        assert_killed_producer_cleanup(true);
    }

    fn assert_killed_producer_cleanup(closed_stdio: bool) {
        let task = tempfile::tempdir().unwrap();
        fs::set_permissions(task.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "cw_runtime::tests::publication_lock_child_fixture",
                "--ignored",
            ])
            .env_clear()
            .env("CODEWIRE_RUNTIME_TEST_ROOT", task.path())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if closed_stdio {
            command.env("CODEWIRE_RUNTIME_TEST_CLOSED_STDIO", "1");
        }
        let mut producer = OwnedToolChild(command.spawn().unwrap());
        let deadline = Instant::now() + Duration::from_secs(5);
        let leaf = loop {
            if let Ok(value) = fs::read_to_string(task.path().join("leaf.pid"))
                && let Ok(pid) = value.parse::<u32>()
            {
                break pid;
            }
            assert!(Instant::now() < deadline, "leaf fixture did not start");
            assert!(producer.0.try_wait().unwrap().is_none());
            std::thread::sleep(Duration::from_millis(10));
        };
        let engine = PrivateRoot::open(&task.path().join("engine")).unwrap();
        let store = CwRuntimeStore::create(&engine).unwrap();
        assert!(matches!(
            store.publication_guard(),
            Err(CwRuntimeError::PublicationBusy)
        ));
        producer.0.kill().unwrap();
        producer.0.wait().unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let publication = loop {
            match store.publication_guard() {
                Ok(publication) => break publication,
                Err(CwRuntimeError::PublicationBusy) => {
                    assert!(Instant::now() < deadline, "orphan tool still holds lock");
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("unexpected publication failure: {error}"),
            }
        };
        // A zombie has exited and cannot write. No process signal is needed:
        // producer-death custody must already have stopped the exact leaf.
        if let Ok(stat) = fs::read_to_string(format!("/proc/{leaf}/stat")) {
            let (_, fields) = stat.rsplit_once(") ").unwrap();
            assert_eq!(fields.split_whitespace().next(), Some("Z"));
        }
        store.recover_abandoned(deadline).unwrap();
        assert_eq!(fs::read_dir(store.staging.path()).unwrap().count(), 0);
        drop(publication);
    }
}
