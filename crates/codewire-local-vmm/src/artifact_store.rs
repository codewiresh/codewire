//! Owner-private, generation-addressed runtime artifact storage.
//!
//! Artifact blobs are published by content digest before a canonical lock
//! manifest is published as the generation commit point. A crash can therefore
//! leave only unreferenced blobs or bounded ingest files; it can never expose a
//! partially committed runtime generation.

use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::artifact::{AdmittedArtifact, AdmittedArtifacts, ArtifactLock, ArtifactSpec};
use crate::linux::path::{PathError, PrivateRoot};

const STORE_DIRECTORY: &str = "runtime-artifacts";
const BLOBS_DIRECTORY: &str = "blobs";
const GENERATIONS_DIRECTORY: &str = "generations";
const MAXIMUM_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAXIMUM_STORE_OBJECTS: usize = 4096;

#[derive(Debug)]
pub(crate) struct RuntimeArtifactStore {
    blobs: PrivateRoot,
    generations: PrivateRoot,
}

impl RuntimeArtifactStore {
    pub(crate) fn create(engine_root: &PrivateRoot) -> Result<Self, RuntimeArtifactStoreError> {
        let store_path = engine_root.ensure_dir(Path::new(STORE_DIRECTORY), 0o700)?;
        let store = PrivateRoot::open(&store_path)?;
        let blobs_path = store.ensure_dir(Path::new(BLOBS_DIRECTORY), 0o700)?;
        let generations_path = store.ensure_dir(Path::new(GENERATIONS_DIRECTORY), 0o700)?;
        Ok(Self {
            blobs: PrivateRoot::open(&blobs_path)?,
            generations: PrivateRoot::open(&generations_path)?,
        })
    }

    pub(crate) async fn admit_source(
        &self,
        artifact_lock_path: &Path,
        artifact_root: &Path,
    ) -> Result<String, RuntimeArtifactStoreError> {
        self.cleanup_stale_ingest()?;
        let lock = ArtifactLock::read(artifact_lock_path)?;
        let generation = lock.generation()?;
        match self.read_generation(&generation) {
            Ok(stored) => {
                if stored != lock {
                    return Err(RuntimeArtifactStoreError::GenerationCollision(generation));
                }
                let _ = self.open_generation(&generation).await?;
                return Ok(generation);
            }
            Err(error) if error.is_not_found() => {}
            Err(error) => return Err(error),
        }

        let admitted = lock.admit(artifact_root).await?;
        self.publish_blob(
            &admitted.cloud_hypervisor,
            &lock.cloud_hypervisor.artifact,
            true,
        )?;
        self.publish_blob(&admitted.kernel, &lock.kernel, false)?;
        self.publish_blob(&admitted.initramfs, &lock.initramfs, false)?;
        self.publish_generation(&generation, &lock)?;

        let stored = self.read_generation(&generation)?;
        if stored != lock {
            return Err(RuntimeArtifactStoreError::GenerationCollision(generation));
        }
        let _ = self.open_generation(&generation).await?;
        Ok(generation)
    }

    pub(crate) async fn open_generation(
        &self,
        generation: &str,
    ) -> Result<AdmittedArtifacts, RuntimeArtifactStoreError> {
        let lock = self.read_generation(generation)?;
        self.admit_cached(&lock).await
    }

    async fn admit_cached(
        &self,
        lock: &ArtifactLock,
    ) -> Result<AdmittedArtifacts, RuntimeArtifactStoreError> {
        let mut cached = lock.clone();
        cached.cloud_hypervisor.artifact.path =
            blob_name(&cached.cloud_hypervisor.artifact, true).into();
        cached.kernel.path = blob_name(&cached.kernel, false).into();
        cached.initramfs.path = blob_name(&cached.initramfs, false).into();
        cached
            .admit(self.blobs.path())
            .await
            .map_err(RuntimeArtifactStoreError::from)
    }

    fn publish_blob(
        &self,
        artifact: &AdmittedArtifact,
        spec: &ArtifactSpec,
        executable: bool,
    ) -> Result<(), RuntimeArtifactStoreError> {
        let permissions = if executable { 0o500 } else { 0o400 };
        let destination = blob_name(spec, executable);
        let temporary = format!(
            ".ingest-{}-{}",
            if executable { "x" } else { "r" },
            Uuid::new_v4()
        );
        let temporary_path = self.blobs.path().join(&temporary);
        let opened = self
            .blobs
            .create_regular(Path::new(&temporary), permissions, true)?;
        let copied = copy_exact_blob(artifact, opened.into_file(), &temporary_path, spec);
        if let Err(error) = copied {
            let _ = self
                .blobs
                .remove_private_regular(Path::new(&temporary), permissions);
            return Err(error);
        }
        match self.blobs.publish_private_regular_no_replace(
            Path::new(&temporary),
            Path::new(&destination),
            permissions,
        ) {
            Ok(true) => Ok(()),
            Ok(false) => {
                self.blobs
                    .remove_private_regular(Path::new(&temporary), permissions)?;
                self.verify_blob(spec, executable)
            }
            Err(error) => {
                let _ = self
                    .blobs
                    .remove_private_regular(Path::new(&temporary), permissions);
                Err(error.into())
            }
        }
    }

    fn verify_blob(
        &self,
        spec: &ArtifactSpec,
        executable: bool,
    ) -> Result<(), RuntimeArtifactStoreError> {
        let name = blob_name(spec, executable);
        let path = self.blobs.path().join(&name);
        let opened = self.blobs.open_regular(
            Path::new(&name),
            false,
            Some(spec.size),
            executable,
            Some(if executable { 0o500 } else { 0o400 }),
        )?;
        let mut file = opened.into_file();
        let mut digest = Sha256::new();
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let read = file
                .read(&mut buffer)
                .map_err(|source| RuntimeArtifactStoreError::Io {
                    path: path.clone(),
                    source,
                })?;
            if read == 0 {
                break;
            }
            digest.update(&buffer[..read]);
        }
        if format!("{:x}", digest.finalize()) != spec.sha256 {
            return Err(RuntimeArtifactStoreError::BlobMismatch(path));
        }
        Ok(())
    }

    fn publish_generation(
        &self,
        generation: &str,
        lock: &ArtifactLock,
    ) -> Result<(), RuntimeArtifactStoreError> {
        validate_generation(generation)?;
        if lock.generation()? != generation {
            return Err(RuntimeArtifactStoreError::InvalidManifest(
                generation.to_owned(),
            ));
        }
        let bytes = lock.canonical_json()?;
        if bytes.is_empty() || bytes.len() as u64 > MAXIMUM_MANIFEST_BYTES {
            return Err(RuntimeArtifactStoreError::InvalidManifest(
                generation.to_owned(),
            ));
        }
        let temporary = format!(".ingest-{}", Uuid::new_v4());
        let temporary_path = self.generations.path().join(&temporary);
        let opened = self
            .generations
            .create_regular(Path::new(&temporary), 0o400, true)?;
        let write_result = (|| {
            let mut file = opened.into_file();
            file.write_all(&bytes)
                .map_err(|source| RuntimeArtifactStoreError::Io {
                    path: temporary_path.clone(),
                    source,
                })?;
            file.sync_all()
                .map_err(|source| RuntimeArtifactStoreError::Io {
                    path: temporary_path.clone(),
                    source,
                })
        })();
        if let Err(error) = write_result {
            let _ = self
                .generations
                .remove_private_regular(Path::new(&temporary), 0o400);
            return Err(error);
        }
        let destination = generation_manifest_name(generation);
        match self.generations.publish_private_regular_no_replace(
            Path::new(&temporary),
            Path::new(&destination),
            0o400,
        ) {
            Ok(true) => Ok(()),
            Ok(false) => {
                self.generations
                    .remove_private_regular(Path::new(&temporary), 0o400)?;
                Ok(())
            }
            Err(error) => {
                let _ = self
                    .generations
                    .remove_private_regular(Path::new(&temporary), 0o400);
                Err(error.into())
            }
        }
    }

    fn read_generation(&self, generation: &str) -> Result<ArtifactLock, RuntimeArtifactStoreError> {
        validate_generation(generation)?;
        let name = generation_manifest_name(generation);
        let opened =
            self.generations
                .open_regular(Path::new(&name), false, None, false, Some(0o400))?;
        if opened.identity().size == 0 || opened.identity().size > MAXIMUM_MANIFEST_BYTES {
            return Err(RuntimeArtifactStoreError::InvalidManifest(
                generation.to_owned(),
            ));
        }
        let expected_size = opened.identity().size;
        let mut bytes = Vec::with_capacity(expected_size as usize);
        opened
            .into_file()
            .take(MAXIMUM_MANIFEST_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|source| RuntimeArtifactStoreError::Io {
                path: self.generations.path().join(&name),
                source,
            })?;
        let lock: ArtifactLock = serde_json::from_slice(&bytes).map_err(|source| {
            RuntimeArtifactStoreError::DecodeManifest {
                path: self.generations.path().join(&name),
                source,
            }
        })?;
        if bytes.len() as u64 != expected_size
            || lock.canonical_json()? != bytes
            || lock.generation()? != generation
        {
            return Err(RuntimeArtifactStoreError::InvalidManifest(
                generation.to_owned(),
            ));
        }
        Ok(lock)
    }

    fn cleanup_stale_ingest(&self) -> Result<(), RuntimeArtifactStoreError> {
        let blob_ingest = inventory_blobs(&self.blobs)?;
        let generation_ingest = inventory_generations(&self.generations)?;
        for (name, permissions) in blob_ingest {
            self.blobs
                .remove_private_regular(Path::new(&name), permissions)?;
        }
        for name in generation_ingest {
            self.generations
                .remove_private_regular(Path::new(&name), 0o400)?;
        }
        Ok(())
    }
}

fn copy_exact_blob(
    artifact: &AdmittedArtifact,
    mut destination: fs::File,
    destination_path: &Path,
    spec: &ArtifactSpec,
) -> Result<(), RuntimeArtifactStoreError> {
    let mut source = artifact.open_exact()?;
    let mut digest = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = source
            .read(&mut buffer)
            .map_err(|source| RuntimeArtifactStoreError::Io {
                path: artifact.path().to_owned(),
                source,
            })?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or(RuntimeArtifactStoreError::BlobMismatch(
                destination_path.to_owned(),
            ))?;
        if total > spec.size {
            return Err(RuntimeArtifactStoreError::BlobMismatch(
                destination_path.to_owned(),
            ));
        }
        digest.update(&buffer[..read]);
        destination
            .write_all(&buffer[..read])
            .map_err(|source| RuntimeArtifactStoreError::Io {
                path: destination_path.to_owned(),
                source,
            })?;
    }
    if total != spec.size || format!("{:x}", digest.finalize()) != spec.sha256 {
        return Err(RuntimeArtifactStoreError::BlobMismatch(
            destination_path.to_owned(),
        ));
    }
    destination
        .sync_all()
        .map_err(|source| RuntimeArtifactStoreError::Io {
            path: destination_path.to_owned(),
            source,
        })
}

fn inventory_blobs(root: &PrivateRoot) -> Result<Vec<(String, u32)>, RuntimeArtifactStoreError> {
    let mut ingest = Vec::new();
    let mut count = 0_usize;
    for entry in fs::read_dir(root.path()).map_err(|source| RuntimeArtifactStoreError::Io {
        path: root.path().to_owned(),
        source,
    })? {
        let entry = entry.map_err(|source| RuntimeArtifactStoreError::Io {
            path: root.path().to_owned(),
            source,
        })?;
        count += 1;
        if count > MAXIMUM_STORE_OBJECTS {
            return Err(RuntimeArtifactStoreError::ObjectLimit);
        }
        let path = entry.path();
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| RuntimeArtifactStoreError::UnexpectedObject(path.clone()))?;
        let (permissions, temporary) = if valid_blob_name(&name, 'x') {
            (0o500, false)
        } else if valid_blob_name(&name, 'r') {
            (0o400, false)
        } else if valid_ingest_name(&name, ".ingest-x-") {
            (0o500, true)
        } else if valid_ingest_name(&name, ".ingest-r-") {
            (0o400, true)
        } else {
            return Err(RuntimeArtifactStoreError::UnexpectedObject(path));
        };
        root.open_regular(Path::new(&name), false, None, false, Some(permissions))?;
        if temporary {
            ingest.push((name, permissions));
        }
    }
    Ok(ingest)
}

fn inventory_generations(root: &PrivateRoot) -> Result<Vec<String>, RuntimeArtifactStoreError> {
    let mut ingest = Vec::new();
    let mut count = 0_usize;
    for entry in fs::read_dir(root.path()).map_err(|source| RuntimeArtifactStoreError::Io {
        path: root.path().to_owned(),
        source,
    })? {
        let entry = entry.map_err(|source| RuntimeArtifactStoreError::Io {
            path: root.path().to_owned(),
            source,
        })?;
        count += 1;
        if count > MAXIMUM_STORE_OBJECTS {
            return Err(RuntimeArtifactStoreError::ObjectLimit);
        }
        let path = entry.path();
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| RuntimeArtifactStoreError::UnexpectedObject(path.clone()))?;
        let temporary = if valid_generation_manifest_name(&name) {
            false
        } else if valid_ingest_name(&name, ".ingest-") {
            true
        } else {
            return Err(RuntimeArtifactStoreError::UnexpectedObject(path));
        };
        let opened = root.open_regular(Path::new(&name), false, None, false, Some(0o400))?;
        if !temporary
            && (opened.identity().size == 0 || opened.identity().size > MAXIMUM_MANIFEST_BYTES)
        {
            return Err(RuntimeArtifactStoreError::UnexpectedObject(path));
        }
        if temporary {
            ingest.push(name);
        }
    }
    Ok(ingest)
}

fn blob_name(spec: &ArtifactSpec, executable: bool) -> String {
    format!("{}-{}", if executable { 'x' } else { 'r' }, spec.sha256)
}

fn generation_manifest_name(generation: &str) -> String {
    format!("{generation}.json")
}

fn validate_generation(generation: &str) -> Result<(), RuntimeArtifactStoreError> {
    if valid_digest(generation) {
        Ok(())
    } else {
        Err(RuntimeArtifactStoreError::InvalidGeneration)
    }
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_blob_name(name: &str, prefix: char) -> bool {
    name.strip_prefix(&format!("{prefix}-"))
        .is_some_and(valid_digest)
}

fn valid_generation_manifest_name(name: &str) -> bool {
    name.strip_suffix(".json").is_some_and(valid_digest)
}

fn valid_ingest_name(name: &str, prefix: &str) -> bool {
    name.strip_prefix(prefix)
        .and_then(|value| Uuid::parse_str(value).ok().map(|uuid| (value, uuid)))
        .is_some_and(|(value, uuid)| uuid.to_string() == value)
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum RuntimeArtifactStoreError {
    #[error(transparent)]
    Artifact(#[from] crate::artifact::ArtifactError),
    #[error(transparent)]
    Path(#[from] PathError),
    #[error("runtime artifact generation identity is invalid")]
    InvalidGeneration,
    #[error("runtime artifact generation manifest is invalid: {0}")]
    InvalidManifest(String),
    #[error("decode runtime artifact generation manifest {path}: {source}")]
    DecodeManifest {
        path: PathBuf,
        source: serde_json::Error,
    },
    #[error("runtime artifact generation hash collision: {0}")]
    GenerationCollision(String),
    #[error("runtime artifact blob differs from its admitted source: {0}")]
    BlobMismatch(PathBuf),
    #[error("runtime artifact store contains an unexpected object: {0}")]
    UnexpectedObject(PathBuf),
    #[error("runtime artifact store object limit exceeded")]
    ObjectLimit,
    #[error("runtime artifact store I/O failed for {path}: {source}")]
    Io { path: PathBuf, source: io::Error },
}

impl RuntimeArtifactStoreError {
    fn is_not_found(&self) -> bool {
        match self {
            Self::Path(PathError::Openat2 { source, .. }) => *source == rustix::io::Errno::NOENT,
            Self::Path(PathError::Io { source, .. }) | Self::Io { source, .. } => {
                source.kind() == io::ErrorKind::NotFound
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use crate::artifact::{
        ARTIFACT_LOCK_SCHEMA_VERSION, ArtifactArchitecture, ExecutableArtifactSpec,
    };

    use super::*;

    fn private_root() -> (tempfile::TempDir, PrivateRoot) {
        let parent = tempfile::tempdir().unwrap();
        fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let root = PrivateRoot::open(parent.path()).unwrap();
        (parent, root)
    }

    fn spec(path: &str, bytes: &[u8]) -> ArtifactSpec {
        ArtifactSpec {
            path: path.into(),
            size: bytes.len() as u64,
            sha256: format!("{:x}", Sha256::digest(bytes)),
            architecture: ArtifactArchitecture::host().unwrap(),
        }
    }

    fn lock() -> ArtifactLock {
        ArtifactLock {
            schema_version: ARTIFACT_LOCK_SCHEMA_VERSION,
            cloud_hypervisor: ExecutableArtifactSpec {
                artifact: spec("bin/cloud-hypervisor", b"cloud-hypervisor"),
                version: crate::artifact::CLOUD_HYPERVISOR_RELEASE.to_owned(),
            },
            kernel: spec("boot/kernel", b"kernel"),
            initramfs: spec("boot/initramfs", b"initramfs"),
        }
    }

    fn admitted(path: &Path, bytes: &[u8], executable: bool) -> AdmittedArtifact {
        fs::write(path, bytes).unwrap();
        fs::set_permissions(
            path,
            fs::Permissions::from_mode(if executable { 0o500 } else { 0o400 }),
        )
        .unwrap();
        crate::artifact::admit_test_artifact(path, executable).unwrap()
    }

    #[test]
    fn manifest_is_the_atomic_generation_commit_point() {
        let (parent, engine) = private_root();
        let store = RuntimeArtifactStore::create(&engine).unwrap();
        let lock = lock();
        let generation = lock.generation().unwrap();
        let source = parent.path().join("source");
        fs::create_dir(&source).unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(0o700)).unwrap();
        let cloud_hypervisor = admitted(&source.join("ch"), b"cloud-hypervisor", true);
        let kernel = admitted(&source.join("kernel"), b"kernel", false);
        let initramfs = admitted(&source.join("initramfs"), b"initramfs", false);

        store
            .publish_blob(&cloud_hypervisor, &lock.cloud_hypervisor.artifact, true)
            .unwrap();
        store.publish_blob(&kernel, &lock.kernel, false).unwrap();
        store
            .publish_blob(&initramfs, &lock.initramfs, false)
            .unwrap();
        assert!(
            store
                .read_generation(&generation)
                .unwrap_err()
                .is_not_found()
        );

        store.publish_generation(&generation, &lock).unwrap();
        assert_eq!(store.read_generation(&generation).unwrap(), lock);
        assert!(
            store
                .generations
                .path()
                .join(generation_manifest_name(&generation))
                .is_file()
        );
    }

    #[test]
    fn blob_publication_is_digest_bound_and_idempotent() {
        let (parent, engine) = private_root();
        let store = RuntimeArtifactStore::create(&engine).unwrap();
        let bytes = b"immutable-runtime-artifact";
        let artifact = admitted(&parent.path().join("source"), bytes, false);
        let spec = spec("source", bytes);

        store.publish_blob(&artifact, &spec, false).unwrap();
        store.publish_blob(&artifact, &spec, false).unwrap();

        let name = blob_name(&spec, false);
        let opened = store
            .blobs
            .open_regular(
                Path::new(&name),
                false,
                Some(bytes.len() as u64),
                false,
                Some(0o400),
            )
            .unwrap();
        let mut actual = Vec::new();
        opened.into_file().read_to_end(&mut actual).unwrap();
        assert_eq!(actual, bytes);
        assert_eq!(fs::read_dir(store.blobs.path()).unwrap().count(), 1);
    }

    #[test]
    fn blob_publication_rejects_a_corrupt_existing_digest_name() {
        let (parent, engine) = private_root();
        let store = RuntimeArtifactStore::create(&engine).unwrap();
        let expected = b"immutable-runtime-artifact";
        let artifact = admitted(&parent.path().join("source"), expected, false);
        let spec = spec("source", expected);
        let destination = store.blobs.path().join(blob_name(&spec, false));
        fs::write(&destination, b"corrupt-runtime-artifact!!").unwrap();
        fs::set_permissions(&destination, fs::Permissions::from_mode(0o400)).unwrap();

        assert!(matches!(
            store.publish_blob(&artifact, &spec, false),
            Err(RuntimeArtifactStoreError::BlobMismatch(path)) if path == destination
        ));
        assert_eq!(
            fs::read(&destination).unwrap(),
            b"corrupt-runtime-artifact!!"
        );
        assert_eq!(fs::read_dir(store.blobs.path()).unwrap().count(), 1);
    }

    #[test]
    fn cleanup_validates_the_whole_namespace_before_removing_ingest() {
        let (_parent, engine) = private_root();
        let store = RuntimeArtifactStore::create(&engine).unwrap();
        let temporary = format!(".ingest-r-{}", Uuid::new_v4());
        store
            .blobs
            .create_regular(Path::new(&temporary), 0o400, true)
            .unwrap();
        store
            .blobs
            .create_regular(Path::new("unknown"), 0o400, true)
            .unwrap();

        assert!(matches!(
            store.cleanup_stale_ingest(),
            Err(RuntimeArtifactStoreError::UnexpectedObject(_))
        ));
        assert!(store.blobs.path().join(&temporary).is_file());

        store
            .blobs
            .remove_private_regular(Path::new("unknown"), 0o400)
            .unwrap();
        store.cleanup_stale_ingest().unwrap();
        assert!(!store.blobs.path().join(temporary).exists());
    }

    #[test]
    fn manifest_relocation_and_noncanonical_bytes_fail_closed() {
        let (_parent, engine) = private_root();
        let store = RuntimeArtifactStore::create(&engine).unwrap();
        let lock = lock();
        let generation = lock.generation().unwrap();
        let wrong_generation = "f".repeat(64);
        let wrong_manifest = store
            .generations
            .create_regular(
                Path::new(&generation_manifest_name(&wrong_generation)),
                0o400,
                true,
            )
            .unwrap();
        let mut wrong_manifest = wrong_manifest.into_file();
        wrong_manifest
            .write_all(&lock.canonical_json().unwrap())
            .unwrap();
        wrong_manifest.sync_all().unwrap();
        assert!(matches!(
            store.read_generation(&wrong_generation),
            Err(RuntimeArtifactStoreError::InvalidManifest(value)) if value == wrong_generation
        ));

        let manifest = store
            .generations
            .path()
            .join(generation_manifest_name(&generation));
        fs::write(&manifest, serde_json::to_string_pretty(&lock).unwrap()).unwrap();
        fs::set_permissions(&manifest, fs::Permissions::from_mode(0o400)).unwrap();
        assert!(matches!(
            store.read_generation(&generation),
            Err(RuntimeArtifactStoreError::InvalidManifest(value)) if value == generation
        ));
    }
}
