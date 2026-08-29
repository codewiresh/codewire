//! Owner-private, generation-addressed runtime artifact storage.
//!
//! Artifact blobs are published by content digest before a canonical lock
//! manifest is published as the generation commit point. A crash can therefore
//! leave only unreferenced blobs or bounded ingest files; it can never expose a
//! partially committed runtime generation.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::artifact::{AdmittedArtifact, AdmittedArtifacts, ArtifactLock, ArtifactSpec};
use crate::linux::path::{PathError, PrivateRoot, current_uid};

const STORE_DIRECTORY: &str = "runtime-artifacts";
const BLOBS_DIRECTORY: &str = "blobs";
const GENERATIONS_DIRECTORY: &str = "generations";
const MAXIMUM_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAXIMUM_STORE_OBJECTS: usize = 4096;

#[derive(Debug)]
pub(crate) struct RuntimeArtifactStore {
    store: PrivateRoot,
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
            store,
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

    /// Removes only generation manifests absent from the complete durable
    /// supervisor reachability set, then removes blobs no retained manifest
    /// references. The supervisor singleton serializes this with admission and
    /// runner replacement. Every namespace object and every retained blob is
    /// admitted before the first unlink, so an unsafe object leaves the store
    /// unchanged for diagnosis.
    pub(crate) fn collect_unreferenced(
        &self,
        retained: &BTreeSet<String>,
    ) -> Result<RuntimeArtifactCollection, RuntimeArtifactStoreError> {
        for generation in retained {
            validate_generation(generation)?;
        }
        self.validate_store_namespace()?;
        let generation_objects = inventory_generations(&self.generations)?;
        let blob_objects = inventory_blobs(&self.blobs)?;

        let mut manifests = BTreeMap::new();
        for object in generation_objects.iter().filter(|object| !object.temporary) {
            let generation = object
                .generation
                .as_deref()
                .ok_or_else(|| RuntimeArtifactStoreError::UnexpectedObject(object.path.clone()))?;
            let lock = self.read_generation(generation)?;
            if manifests.insert(generation.to_owned(), lock).is_some() {
                return Err(RuntimeArtifactStoreError::GenerationCollision(
                    generation.to_owned(),
                ));
            }
        }

        let mut retained_blobs = BTreeMap::new();
        for generation in retained {
            let lock = manifests
                .get(generation)
                .ok_or_else(|| RuntimeArtifactStoreError::MissingGeneration(generation.clone()))?;
            retain_blob(&mut retained_blobs, &lock.cloud_hypervisor.artifact, true)?;
            retain_blob(&mut retained_blobs, &lock.kernel, false)?;
            retain_blob(&mut retained_blobs, &lock.initramfs, false)?;
        }
        for blob in retained_blobs.values() {
            self.verify_blob(&blob.spec, blob.executable)?;
        }

        let mut removed_generations = Vec::new();
        let mut removed_blobs = Vec::new();
        let mut removed_temporary_objects = 0_usize;
        let mut reclaimed_bytes = 0_u64;

        // Manifests are the generation commit points. Remove unreachable
        // manifests first so a crash can leave only harmless extra blobs,
        // never a committed generation whose blob was already collected.
        for object in generation_objects.into_iter().filter(|object| {
            object.temporary
                || object
                    .generation
                    .as_ref()
                    .is_some_and(|generation| !retained.contains(generation))
        }) {
            if !self
                .generations
                .remove_private_regular(Path::new(&object.name), object.permissions)?
            {
                return Err(RuntimeArtifactStoreError::UnexpectedObject(object.path));
            }
            reclaimed_bytes = reclaimed_bytes.saturating_add(object.size);
            if let Some(generation) = object.generation {
                removed_generations.push(generation);
            } else {
                removed_temporary_objects += 1;
            }
        }

        for object in blob_objects
            .into_iter()
            .filter(|object| object.temporary || !retained_blobs.contains_key(&object.name))
        {
            if !self
                .blobs
                .remove_private_regular(Path::new(&object.name), object.permissions)?
            {
                return Err(RuntimeArtifactStoreError::UnexpectedObject(object.path));
            }
            reclaimed_bytes = reclaimed_bytes.saturating_add(object.size);
            if object.temporary {
                removed_temporary_objects += 1;
            } else {
                removed_blobs.push(object.name);
            }
        }
        removed_generations.sort();
        removed_blobs.sort();
        Ok(RuntimeArtifactCollection {
            removed_generations,
            removed_blobs,
            removed_temporary_objects,
            reclaimed_bytes,
        })
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
        self.publish_generation_with(generation, lock, write_generation_manifest)
    }

    fn publish_generation_with<W>(
        &self,
        generation: &str,
        lock: &ArtifactLock,
        write_manifest: W,
    ) -> Result<(), RuntimeArtifactStoreError>
    where
        W: FnOnce(fs::File, &Path, &[u8]) -> Result<(), RuntimeArtifactStoreError>,
    {
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
        let write_result = write_manifest(opened.into_file(), &temporary_path, &bytes);
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
        if bytes.len() as u64 != expected_size {
            return Err(RuntimeArtifactStoreError::InvalidManifest(
                generation.to_owned(),
            ));
        }
        decode_generation_manifest(generation, &self.generations.path().join(&name), &bytes)
    }

    fn cleanup_stale_ingest(&self) -> Result<(), RuntimeArtifactStoreError> {
        self.validate_store_namespace()?;
        let blob_ingest = inventory_blobs(&self.blobs)?;
        let generation_ingest = inventory_generations(&self.generations)?;
        for object in blob_ingest.into_iter().filter(|object| object.temporary) {
            self.blobs
                .remove_private_regular(Path::new(&object.name), object.permissions)?;
        }
        for object in generation_ingest
            .into_iter()
            .filter(|object| object.temporary)
        {
            self.generations
                .remove_private_regular(Path::new(&object.name), object.permissions)?;
        }
        Ok(())
    }

    fn validate_store_namespace(&self) -> Result<(), RuntimeArtifactStoreError> {
        let mut expected =
            BTreeSet::from([BLOBS_DIRECTORY.to_owned(), GENERATIONS_DIRECTORY.to_owned()]);
        for entry in
            fs::read_dir(self.store.path()).map_err(|source| RuntimeArtifactStoreError::Io {
                path: self.store.path().to_owned(),
                source,
            })?
        {
            let entry = entry.map_err(|source| RuntimeArtifactStoreError::Io {
                path: self.store.path().to_owned(),
                source,
            })?;
            let path = entry.path();
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| RuntimeArtifactStoreError::UnexpectedObject(path.clone()))?;
            if !expected.remove(&name) {
                return Err(RuntimeArtifactStoreError::UnexpectedObject(path));
            }
        }
        if !expected.is_empty() {
            return Err(RuntimeArtifactStoreError::UnexpectedObject(
                self.store.path().to_owned(),
            ));
        }
        Ok(())
    }
}

fn write_generation_manifest(
    mut file: fs::File,
    path: &Path,
    bytes: &[u8],
) -> Result<(), RuntimeArtifactStoreError> {
    file.write_all(bytes)
        .map_err(|source| RuntimeArtifactStoreError::Io {
            path: path.to_owned(),
            source,
        })?;
    file.sync_all()
        .map_err(|source| RuntimeArtifactStoreError::Io {
            path: path.to_owned(),
            source,
        })
}

fn decode_generation_manifest(
    generation: &str,
    path: &Path,
    bytes: &[u8],
) -> Result<ArtifactLock, RuntimeArtifactStoreError> {
    validate_generation(generation)?;
    if bytes.is_empty() || bytes.len() as u64 > MAXIMUM_MANIFEST_BYTES {
        return Err(RuntimeArtifactStoreError::InvalidManifest(
            generation.to_owned(),
        ));
    }
    let lock: ArtifactLock = serde_json::from_slice(bytes).map_err(|source| {
        RuntimeArtifactStoreError::DecodeManifest {
            path: path.to_owned(),
            source,
        }
    })?;
    if lock.canonical_json()? != bytes || lock.generation()? != generation {
        return Err(RuntimeArtifactStoreError::InvalidManifest(
            generation.to_owned(),
        ));
    }
    let _ = lock.validate_metadata()?;
    Ok(lock)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RuntimeArtifactCollection {
    pub(crate) removed_generations: Vec<String>,
    pub(crate) removed_blobs: Vec<String>,
    pub(crate) removed_temporary_objects: usize,
    pub(crate) reclaimed_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RuntimeArtifactDiagnostic {
    pub(crate) kind: &'static str,
    pub(crate) path: PathBuf,
    pub(crate) reason: &'static str,
    pub(crate) reclaimable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DiagnosticRetainedBlob {
    size: u64,
    executable: bool,
}

/// Inspects the runtime-artifact namespace without creating, adopting,
/// repairing, moving, or deleting any object. Reclaimability is asserted only
/// when every retained manifest needed to derive blob reachability is valid.
pub(crate) fn runtime_artifact_diagnostics(
    engine_root: &Path,
    retained: &BTreeSet<String>,
) -> Vec<RuntimeArtifactDiagnostic> {
    let store_path = engine_root.join(STORE_DIRECTORY);
    let generations_path = store_path.join(GENERATIONS_DIRECTORY);
    let blobs_path = store_path.join(BLOBS_DIRECTORY);
    let mut diagnostics = Vec::new();

    let store_metadata = match fs::symlink_metadata(&store_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            record_unavailable_generations(
                retained,
                &generations_path,
                "recorded_runtime_artifact_generation_missing",
                &mut diagnostics,
            );
            return diagnostics;
        }
        Err(_) => {
            diagnostics.push(runtime_artifact_diagnostic(
                "runtime_artifact_store",
                store_path,
                "unreadable_runtime_artifact_store",
                false,
            ));
            record_unavailable_generations(
                retained,
                &generations_path,
                "recorded_runtime_artifact_generation_unverifiable",
                &mut diagnostics,
            );
            return diagnostics;
        }
    };
    if !private_store_directory(&store_metadata) || PrivateRoot::open(&store_path).is_err() {
        diagnostics.push(runtime_artifact_diagnostic(
            "runtime_artifact_store",
            store_path,
            "unsafe_runtime_artifact_store",
            false,
        ));
        record_unavailable_generations(
            retained,
            &generations_path,
            "recorded_runtime_artifact_generation_unverifiable",
            &mut diagnostics,
        );
        return diagnostics;
    }

    match fs::read_dir(&store_path) {
        Ok(entries) => {
            for (index, entry) in entries.enumerate() {
                if index == MAXIMUM_STORE_OBJECTS {
                    diagnostics.push(runtime_artifact_diagnostic(
                        "runtime_artifact_store",
                        store_path.clone(),
                        "runtime_artifact_object_bound_exceeded",
                        false,
                    ));
                    break;
                }
                let Ok(entry) = entry else {
                    diagnostics.push(runtime_artifact_diagnostic(
                        "runtime_artifact_store",
                        store_path.clone(),
                        "unreadable_runtime_artifact_store",
                        false,
                    ));
                    break;
                };
                if !matches!(
                    entry.file_name().to_str(),
                    Some(BLOBS_DIRECTORY | GENERATIONS_DIRECTORY)
                ) {
                    diagnostics.push(runtime_artifact_diagnostic(
                        "runtime_artifact_store",
                        entry.path(),
                        "unexpected_runtime_artifact_object",
                        false,
                    ));
                }
            }
        }
        Err(_) => diagnostics.push(runtime_artifact_diagnostic(
            "runtime_artifact_store",
            store_path,
            "unreadable_runtime_artifact_store",
            false,
        )),
    }

    let (expected_blobs, retained_reachability_complete) =
        diagnose_generations(&generations_path, retained, &mut diagnostics);
    diagnose_blobs(
        &blobs_path,
        &expected_blobs,
        retained_reachability_complete,
        &mut diagnostics,
    );
    diagnostics.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then_with(|| left.kind.cmp(right.kind))
    });
    diagnostics
}

fn diagnose_generations(
    path: &Path,
    retained: &BTreeSet<String>,
    diagnostics: &mut Vec<RuntimeArtifactDiagnostic>,
) -> (BTreeMap<String, DiagnosticRetainedBlob>, bool) {
    let mut expected_blobs = BTreeMap::new();
    let mut found = BTreeSet::new();
    let mut valid_retained = BTreeSet::new();
    let mut retained_conflict = false;
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            diagnostics.push(runtime_artifact_diagnostic(
                "runtime_artifact_store",
                path.to_owned(),
                "runtime_artifact_directory_missing",
                false,
            ));
            record_unavailable_generations(
                retained,
                path,
                "recorded_runtime_artifact_generation_missing",
                diagnostics,
            );
            return (expected_blobs, retained.is_empty());
        }
        Err(_) => {
            diagnostics.push(runtime_artifact_diagnostic(
                "runtime_artifact_store",
                path.to_owned(),
                "unreadable_runtime_artifact_directory",
                false,
            ));
            record_unavailable_generations(
                retained,
                path,
                "recorded_runtime_artifact_generation_unverifiable",
                diagnostics,
            );
            return (expected_blobs, retained.is_empty());
        }
    };
    if !private_store_directory(&metadata) {
        diagnostics.push(runtime_artifact_diagnostic(
            "runtime_artifact_store",
            path.to_owned(),
            "unsafe_runtime_artifact_directory",
            false,
        ));
        record_unavailable_generations(
            retained,
            path,
            "recorded_runtime_artifact_generation_unverifiable",
            diagnostics,
        );
        return (expected_blobs, retained.is_empty());
    }
    let generations = match PrivateRoot::open(path) {
        Ok(generations) => generations,
        Err(_) => {
            diagnostics.push(runtime_artifact_diagnostic(
                "runtime_artifact_store",
                path.to_owned(),
                "unsafe_runtime_artifact_directory",
                false,
            ));
            record_unavailable_generations(
                retained,
                path,
                "recorded_runtime_artifact_generation_unverifiable",
                diagnostics,
            );
            return (expected_blobs, retained.is_empty());
        }
    };
    let entries = match fs::read_dir(path) {
        Ok(entries) => entries,
        Err(_) => {
            diagnostics.push(runtime_artifact_diagnostic(
                "runtime_artifact_store",
                path.to_owned(),
                "unreadable_runtime_artifact_directory",
                false,
            ));
            record_unavailable_generations(
                retained,
                path,
                "recorded_runtime_artifact_generation_unverifiable",
                diagnostics,
            );
            return (expected_blobs, retained.is_empty());
        }
    };
    let mut scan_complete = true;
    for (index, entry) in entries.enumerate() {
        if index == MAXIMUM_STORE_OBJECTS {
            diagnostics.push(runtime_artifact_diagnostic(
                "runtime_artifact_store",
                path.to_owned(),
                "runtime_artifact_object_bound_exceeded",
                false,
            ));
            scan_complete = false;
            break;
        }
        let Ok(entry) = entry else {
            diagnostics.push(runtime_artifact_diagnostic(
                "runtime_artifact_store",
                path.to_owned(),
                "unreadable_runtime_artifact_directory",
                false,
            ));
            scan_complete = false;
            break;
        };
        let object_path = entry.path();
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            diagnostics.push(runtime_artifact_diagnostic(
                "runtime_artifact_generation",
                object_path,
                "unknown_runtime_artifact_object",
                false,
            ));
            continue;
        };
        if valid_ingest_name(&name, ".ingest-") {
            let reclaimable = generations
                .open_regular(Path::new(&name), false, None, false, Some(0o400))
                .is_ok();
            diagnostics.push(runtime_artifact_diagnostic(
                "runtime_artifact_ingest",
                object_path,
                if reclaimable {
                    "interrupted_runtime_artifact_ingest"
                } else {
                    "unsafe_runtime_artifact_ingest"
                },
                reclaimable,
            ));
            continue;
        }
        let Some(generation) = generation_from_manifest_name(&name).map(str::to_owned) else {
            diagnostics.push(runtime_artifact_diagnostic(
                "runtime_artifact_generation",
                object_path,
                "unknown_runtime_artifact_object",
                false,
            ));
            continue;
        };
        found.insert(generation.clone());
        let referenced = retained.contains(&generation);
        let opened =
            match generations.open_regular(Path::new(&name), false, None, false, Some(0o400)) {
                Ok(opened) => opened,
                Err(_) => {
                    diagnostics.push(runtime_artifact_diagnostic(
                        "runtime_artifact_generation",
                        object_path,
                        if referenced {
                            "unsafe_referenced_runtime_artifact_generation"
                        } else {
                            "unsafe_unreferenced_runtime_artifact_generation"
                        },
                        false,
                    ));
                    continue;
                }
            };
        let expected_size = opened.identity().size;
        if expected_size == 0 || expected_size > MAXIMUM_MANIFEST_BYTES {
            diagnostics.push(runtime_artifact_diagnostic(
                "runtime_artifact_generation",
                object_path,
                if referenced {
                    "invalid_referenced_runtime_artifact_generation"
                } else {
                    "invalid_unreferenced_runtime_artifact_generation"
                },
                false,
            ));
            continue;
        }
        let mut bytes = Vec::with_capacity(expected_size as usize);
        let read = opened
            .into_file()
            .take(MAXIMUM_MANIFEST_BYTES + 1)
            .read_to_end(&mut bytes);
        let lock = read.ok().and_then(|_| {
            (bytes.len() as u64 == expected_size)
                .then(|| decode_generation_manifest(&generation, &object_path, &bytes))
                .and_then(Result::ok)
        });
        let Some(lock) = lock else {
            diagnostics.push(runtime_artifact_diagnostic(
                "runtime_artifact_generation",
                object_path,
                if referenced {
                    "invalid_referenced_runtime_artifact_generation"
                } else {
                    "invalid_unreferenced_runtime_artifact_generation"
                },
                false,
            ));
            continue;
        };
        if referenced {
            valid_retained.insert(generation);
            if retain_diagnostic_blobs(&mut expected_blobs, &lock).is_err() {
                retained_conflict = true;
                diagnostics.push(runtime_artifact_diagnostic(
                    "runtime_artifact_generation",
                    object_path,
                    "conflicting_referenced_runtime_artifact_generation",
                    false,
                ));
            }
        } else {
            diagnostics.push(runtime_artifact_diagnostic(
                "runtime_artifact_generation",
                object_path,
                "unreferenced_runtime_artifact_generation",
                true,
            ));
        }
    }

    for generation in retained
        .iter()
        .filter(|generation| !found.contains(*generation))
    {
        diagnostics.push(runtime_artifact_diagnostic(
            "runtime_artifact_generation",
            path.join(generation_manifest_name(generation)),
            if scan_complete {
                "recorded_runtime_artifact_generation_missing"
            } else {
                "recorded_runtime_artifact_generation_unverifiable"
            },
            false,
        ));
    }
    (
        expected_blobs,
        !retained_conflict && valid_retained.len() == retained.len(),
    )
}

fn diagnose_blobs(
    path: &Path,
    expected: &BTreeMap<String, DiagnosticRetainedBlob>,
    retained_reachability_complete: bool,
    diagnostics: &mut Vec<RuntimeArtifactDiagnostic>,
) {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            diagnostics.push(runtime_artifact_diagnostic(
                "runtime_artifact_store",
                path.to_owned(),
                "runtime_artifact_directory_missing",
                false,
            ));
            record_unavailable_blobs(
                expected,
                path,
                "recorded_runtime_artifact_blob_missing",
                diagnostics,
            );
            return;
        }
        Err(_) => {
            diagnostics.push(runtime_artifact_diagnostic(
                "runtime_artifact_store",
                path.to_owned(),
                "unreadable_runtime_artifact_directory",
                false,
            ));
            record_unavailable_blobs(
                expected,
                path,
                "recorded_runtime_artifact_blob_unverifiable",
                diagnostics,
            );
            return;
        }
    };
    if !private_store_directory(&metadata) {
        diagnostics.push(runtime_artifact_diagnostic(
            "runtime_artifact_store",
            path.to_owned(),
            "unsafe_runtime_artifact_directory",
            false,
        ));
        record_unavailable_blobs(
            expected,
            path,
            "recorded_runtime_artifact_blob_unverifiable",
            diagnostics,
        );
        return;
    }
    let blobs = match PrivateRoot::open(path) {
        Ok(blobs) => blobs,
        Err(_) => {
            diagnostics.push(runtime_artifact_diagnostic(
                "runtime_artifact_store",
                path.to_owned(),
                "unsafe_runtime_artifact_directory",
                false,
            ));
            record_unavailable_blobs(
                expected,
                path,
                "recorded_runtime_artifact_blob_unverifiable",
                diagnostics,
            );
            return;
        }
    };
    let entries = match fs::read_dir(path) {
        Ok(entries) => entries,
        Err(_) => {
            diagnostics.push(runtime_artifact_diagnostic(
                "runtime_artifact_store",
                path.to_owned(),
                "unreadable_runtime_artifact_directory",
                false,
            ));
            record_unavailable_blobs(
                expected,
                path,
                "recorded_runtime_artifact_blob_unverifiable",
                diagnostics,
            );
            return;
        }
    };
    let mut found = BTreeSet::new();
    let mut scan_complete = true;
    for (index, entry) in entries.enumerate() {
        if index == MAXIMUM_STORE_OBJECTS {
            diagnostics.push(runtime_artifact_diagnostic(
                "runtime_artifact_store",
                path.to_owned(),
                "runtime_artifact_object_bound_exceeded",
                false,
            ));
            scan_complete = false;
            break;
        }
        let Ok(entry) = entry else {
            diagnostics.push(runtime_artifact_diagnostic(
                "runtime_artifact_store",
                path.to_owned(),
                "unreadable_runtime_artifact_directory",
                false,
            ));
            scan_complete = false;
            break;
        };
        let object_path = entry.path();
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            diagnostics.push(runtime_artifact_diagnostic(
                "runtime_artifact_blob",
                object_path,
                "unknown_runtime_artifact_object",
                false,
            ));
            continue;
        };
        let blob_shape = if valid_blob_name(&name, 'x') {
            Some((true, 0o500, name.strip_prefix("x-").unwrap()))
        } else if valid_blob_name(&name, 'r') {
            Some((false, 0o400, name.strip_prefix("r-").unwrap()))
        } else {
            None
        };
        if let Some((executable, permissions, digest)) = blob_shape {
            found.insert(name.clone());
            let expected_blob = expected.get(&name);
            let opened = match blobs.open_regular(
                Path::new(&name),
                false,
                None,
                executable,
                Some(permissions),
            ) {
                Ok(opened) => opened,
                Err(_) => {
                    diagnostics.push(runtime_artifact_diagnostic(
                        "runtime_artifact_blob",
                        object_path,
                        if expected_blob.is_some() {
                            "unsafe_referenced_runtime_artifact_blob"
                        } else if retained_reachability_complete {
                            "unsafe_unreferenced_runtime_artifact_blob"
                        } else {
                            "unsafe_runtime_artifact_blob_reachability_unknown"
                        },
                        false,
                    ));
                    continue;
                }
            };
            if let Some(expected_blob) = expected_blob {
                if expected_blob.executable != executable
                    || opened.identity().size != expected_blob.size
                {
                    diagnostics.push(runtime_artifact_diagnostic(
                        "runtime_artifact_blob",
                        object_path,
                        "corrupt_referenced_runtime_artifact_blob",
                        false,
                    ));
                    continue;
                }
                let digest_matches =
                    sha256_reader(opened.into_file()).is_ok_and(|actual| actual == digest);
                if !digest_matches {
                    diagnostics.push(runtime_artifact_diagnostic(
                        "runtime_artifact_blob",
                        object_path,
                        "corrupt_referenced_runtime_artifact_blob",
                        false,
                    ));
                }
            } else if retained_reachability_complete {
                diagnostics.push(runtime_artifact_diagnostic(
                    "runtime_artifact_blob",
                    object_path,
                    "unreferenced_runtime_artifact_blob",
                    true,
                ));
            } else {
                diagnostics.push(runtime_artifact_diagnostic(
                    "runtime_artifact_blob",
                    object_path,
                    "runtime_artifact_blob_reachability_unknown",
                    false,
                ));
            }
            continue;
        }
        let ingest_permissions = if valid_ingest_name(&name, ".ingest-x-") {
            Some((true, 0o500))
        } else if valid_ingest_name(&name, ".ingest-r-") {
            Some((false, 0o400))
        } else {
            None
        };
        if let Some((executable, permissions)) = ingest_permissions {
            let reclaimable = blobs
                .open_regular(Path::new(&name), false, None, executable, Some(permissions))
                .is_ok();
            diagnostics.push(runtime_artifact_diagnostic(
                "runtime_artifact_ingest",
                object_path,
                if reclaimable {
                    "interrupted_runtime_artifact_ingest"
                } else {
                    "unsafe_runtime_artifact_ingest"
                },
                reclaimable,
            ));
        } else {
            diagnostics.push(runtime_artifact_diagnostic(
                "runtime_artifact_blob",
                object_path,
                "unknown_runtime_artifact_object",
                false,
            ));
        }
    }
    for name in expected.keys().filter(|name| !found.contains(*name)) {
        diagnostics.push(runtime_artifact_diagnostic(
            "runtime_artifact_blob",
            path.join(name),
            if scan_complete {
                "recorded_runtime_artifact_blob_missing"
            } else {
                "recorded_runtime_artifact_blob_unverifiable"
            },
            false,
        ));
    }
}

fn retain_diagnostic_blobs(
    retained: &mut BTreeMap<String, DiagnosticRetainedBlob>,
    lock: &ArtifactLock,
) -> Result<(), ()> {
    let mut next = retained.clone();
    for (spec, executable) in [
        (&lock.cloud_hypervisor.artifact, true),
        (&lock.kernel, false),
        (&lock.initramfs, false),
    ] {
        let name = blob_name(spec, executable);
        let candidate = DiagnosticRetainedBlob {
            size: spec.size,
            executable,
        };
        if next
            .get(&name)
            .is_some_and(|existing| existing != &candidate)
        {
            return Err(());
        }
        next.insert(name, candidate);
    }
    *retained = next;
    Ok(())
}

fn record_unavailable_generations(
    retained: &BTreeSet<String>,
    generations: &Path,
    reason: &'static str,
    diagnostics: &mut Vec<RuntimeArtifactDiagnostic>,
) {
    for generation in retained {
        diagnostics.push(runtime_artifact_diagnostic(
            "runtime_artifact_generation",
            generations.join(generation_manifest_name(generation)),
            reason,
            false,
        ));
    }
}

fn record_unavailable_blobs(
    expected: &BTreeMap<String, DiagnosticRetainedBlob>,
    blobs: &Path,
    reason: &'static str,
    diagnostics: &mut Vec<RuntimeArtifactDiagnostic>,
) {
    for name in expected.keys() {
        diagnostics.push(runtime_artifact_diagnostic(
            "runtime_artifact_blob",
            blobs.join(name),
            reason,
            false,
        ));
    }
}

fn runtime_artifact_diagnostic(
    kind: &'static str,
    path: PathBuf,
    reason: &'static str,
    reclaimable: bool,
) -> RuntimeArtifactDiagnostic {
    RuntimeArtifactDiagnostic {
        kind,
        path,
        reason,
        reclaimable,
    }
}

fn private_store_directory(metadata: &fs::Metadata) -> bool {
    metadata.is_dir() && metadata.uid() == current_uid() && metadata.mode() & 0o777 == 0o700
}

fn sha256_reader(mut file: fs::File) -> Result<String, io::Error> {
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

#[derive(Debug, Clone)]
struct RetainedBlob {
    spec: ArtifactSpec,
    executable: bool,
}

fn retain_blob(
    retained: &mut BTreeMap<String, RetainedBlob>,
    spec: &ArtifactSpec,
    executable: bool,
) -> Result<(), RuntimeArtifactStoreError> {
    let name = blob_name(spec, executable);
    if let Some(existing) = retained.get(&name) {
        if existing.spec.size != spec.size
            || existing.spec.sha256 != spec.sha256
            || existing.spec.architecture != spec.architecture
            || existing.executable != executable
        {
            return Err(RuntimeArtifactStoreError::BlobReferenceCollision(name));
        }
        return Ok(());
    }
    retained.insert(
        name,
        RetainedBlob {
            spec: spec.clone(),
            executable,
        },
    );
    Ok(())
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

#[derive(Debug)]
struct StoreObject {
    name: String,
    path: PathBuf,
    size: u64,
    permissions: u32,
    temporary: bool,
    generation: Option<String>,
}

fn inventory_blobs(root: &PrivateRoot) -> Result<Vec<StoreObject>, RuntimeArtifactStoreError> {
    let mut objects = Vec::new();
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
        let opened = root.open_regular(
            Path::new(&name),
            false,
            None,
            executable_from_blob_name(&name),
            Some(permissions),
        )?;
        objects.push(StoreObject {
            name,
            path,
            size: opened.identity().size,
            permissions,
            temporary,
            generation: None,
        });
    }
    Ok(objects)
}

fn inventory_generations(
    root: &PrivateRoot,
) -> Result<Vec<StoreObject>, RuntimeArtifactStoreError> {
    let mut objects = Vec::new();
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
        let (generation, temporary) = if let Some(generation) = generation_from_manifest_name(&name)
        {
            (Some(generation.to_owned()), false)
        } else if valid_ingest_name(&name, ".ingest-") {
            (None, true)
        } else {
            return Err(RuntimeArtifactStoreError::UnexpectedObject(path));
        };
        let opened = root.open_regular(Path::new(&name), false, None, false, Some(0o400))?;
        if !temporary
            && (opened.identity().size == 0 || opened.identity().size > MAXIMUM_MANIFEST_BYTES)
        {
            return Err(RuntimeArtifactStoreError::UnexpectedObject(path));
        }
        objects.push(StoreObject {
            name,
            path,
            size: opened.identity().size,
            permissions: 0o400,
            temporary,
            generation,
        });
    }
    Ok(objects)
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

fn generation_from_manifest_name(name: &str) -> Option<&str> {
    name.strip_suffix(".json")
        .filter(|value| valid_digest(value))
}

fn executable_from_blob_name(name: &str) -> bool {
    valid_blob_name(name, 'x') || valid_ingest_name(name, ".ingest-x-")
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
    #[error("retained runtime artifact generation is missing: {0}")]
    MissingGeneration(String),
    #[error("runtime artifact blob has conflicting retained metadata: {0}")]
    BlobReferenceCollision(String),
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
    use std::sync::{Arc, Barrier};

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

    fn lock_with_kernel(kernel: &[u8]) -> ArtifactLock {
        let mut lock = lock();
        lock.kernel = spec("boot/kernel", kernel);
        lock
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

    fn publish_test_generation(
        store: &RuntimeArtifactStore,
        parent: &Path,
        lock: &ArtifactLock,
        kernel: &[u8],
    ) -> String {
        let source = parent.join(Uuid::new_v4().to_string());
        fs::create_dir(&source).unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(0o700)).unwrap();
        let cloud_hypervisor = admitted(&source.join("ch"), b"cloud-hypervisor", true);
        let kernel = admitted(&source.join("kernel"), kernel, false);
        let initramfs = admitted(&source.join("initramfs"), b"initramfs", false);
        store
            .publish_blob(&cloud_hypervisor, &lock.cloud_hypervisor.artifact, true)
            .unwrap();
        store.publish_blob(&kernel, &lock.kernel, false).unwrap();
        store
            .publish_blob(&initramfs, &lock.initramfs, false)
            .unwrap();
        let generation = lock.generation().unwrap();
        store.publish_generation(&generation, lock).unwrap();
        generation
    }

    fn assert_generation_intact(store: &RuntimeArtifactStore, lock: &ArtifactLock) {
        let generation = lock.generation().unwrap();
        assert_eq!(store.read_generation(&generation).unwrap(), *lock);
        for (spec, executable) in [
            (&lock.cloud_hypervisor.artifact, true),
            (&lock.kernel, false),
            (&lock.initramfs, false),
        ] {
            store.verify_blob(spec, executable).unwrap();
        }
    }

    fn directory_names(path: &Path) -> BTreeSet<String> {
        fs::read_dir(path)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect()
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
    fn admitted_source_tampering_never_publishes_or_disturbs_the_prior_generation() {
        let (parent, engine) = private_root();
        let store = RuntimeArtifactStore::create(&engine).unwrap();
        let retained_lock = lock_with_kernel(b"retained-kernel");
        publish_test_generation(&store, parent.path(), &retained_lock, b"retained-kernel");
        let before = directory_names(store.blobs.path());
        let expected = b"candidate-kernel";
        let tampered = b"tampered--kernel";
        assert_eq!(expected.len(), tampered.len());
        let source = parent.path().join("candidate-kernel");
        let artifact = admitted(&source, expected, false);
        let spec = spec("candidate-kernel", expected);
        fs::set_permissions(&source, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&source, tampered).unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(0o400)).unwrap();

        assert!(matches!(
            store.publish_blob(&artifact, &spec, false),
            Err(RuntimeArtifactStoreError::BlobMismatch(path))
                if path.parent() == Some(store.blobs.path())
                    && path.file_name().is_some_and(|name| name.to_string_lossy().starts_with(".ingest-r-"))
        ));
        assert_eq!(directory_names(store.blobs.path()), before);
        assert!(!store.blobs.path().join(blob_name(&spec, false)).exists());
        assert_eq!(fs::read(source).unwrap(), tampered);
        assert_generation_intact(&store, &retained_lock);
    }

    #[test]
    fn concurrent_identical_publishers_converge_without_partial_objects() {
        let (parent, engine) = private_root();
        let source = parent.path().join("source");
        fs::create_dir(&source).unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(0o700)).unwrap();
        let lock = lock();
        let cloud_hypervisor = admitted(&source.join("ch"), b"cloud-hypervisor", true);
        let kernel = admitted(&source.join("kernel"), b"kernel", false);
        let initramfs = admitted(&source.join("initramfs"), b"initramfs", false);
        let generation = lock.generation().unwrap();
        let engine_path = engine.path().to_owned();
        let barrier = Arc::new(Barrier::new(2));

        std::thread::scope(|scope| {
            for _ in 0..2 {
                let engine_path = engine_path.clone();
                let barrier = Arc::clone(&barrier);
                let lock = lock.clone();
                let generation = generation.clone();
                let cloud_hypervisor = cloud_hypervisor.clone();
                let kernel = kernel.clone();
                let initramfs = initramfs.clone();
                scope.spawn(move || {
                    let engine = PrivateRoot::open(&engine_path).unwrap();
                    let store = RuntimeArtifactStore::create(&engine).unwrap();
                    barrier.wait();
                    store
                        .publish_blob(&cloud_hypervisor, &lock.cloud_hypervisor.artifact, true)
                        .unwrap();
                    store.publish_blob(&kernel, &lock.kernel, false).unwrap();
                    store
                        .publish_blob(&initramfs, &lock.initramfs, false)
                        .unwrap();
                    store.publish_generation(&generation, &lock).unwrap();
                });
            }
        });

        let store = RuntimeArtifactStore::create(&engine).unwrap();
        assert_generation_intact(&store, &lock);
        assert_eq!(directory_names(store.blobs.path()).len(), 3);
        assert_eq!(
            directory_names(store.generations.path()),
            BTreeSet::from([generation_manifest_name(&generation)])
        );
    }

    #[test]
    fn partial_manifest_enospc_and_crash_residue_keep_the_prior_generation_bootable() {
        let (parent, engine) = private_root();
        let store = RuntimeArtifactStore::create(&engine).unwrap();
        let retained_lock = lock_with_kernel(b"retained-kernel");
        let retained =
            publish_test_generation(&store, parent.path(), &retained_lock, b"retained-kernel");
        let candidate_lock = lock_with_kernel(b"candidate-kernel");
        let candidate_source = parent.path().join("candidate");
        fs::create_dir(&candidate_source).unwrap();
        fs::set_permissions(&candidate_source, fs::Permissions::from_mode(0o700)).unwrap();
        let cloud_hypervisor = admitted(&candidate_source.join("ch"), b"cloud-hypervisor", true);
        let kernel = admitted(&candidate_source.join("kernel"), b"candidate-kernel", false);
        let initramfs = admitted(&candidate_source.join("initramfs"), b"initramfs", false);
        store
            .publish_blob(
                &cloud_hypervisor,
                &candidate_lock.cloud_hypervisor.artifact,
                true,
            )
            .unwrap();
        store
            .publish_blob(&kernel, &candidate_lock.kernel, false)
            .unwrap();
        store
            .publish_blob(&initramfs, &candidate_lock.initramfs, false)
            .unwrap();
        let candidate = candidate_lock.generation().unwrap();

        assert!(matches!(
            store.publish_generation_with(
                &candidate,
                &candidate_lock,
                |mut file, path, _bytes| {
                    file.write_all(b"partial-manifest").unwrap();
                    Err(RuntimeArtifactStoreError::Io {
                        path: path.to_owned(),
                        source: io::Error::from_raw_os_error(libc::ENOSPC),
                    })
                },
            ),
            Err(RuntimeArtifactStoreError::Io { source, .. })
                if source.raw_os_error() == Some(libc::ENOSPC)
        ));
        assert!(
            !store
                .generations
                .path()
                .join(generation_manifest_name(&candidate))
                .exists()
        );
        assert!(
            directory_names(store.generations.path())
                .iter()
                .all(|name| !name.starts_with(".ingest-"))
        );

        let interrupted = format!(".ingest-{}", Uuid::new_v4());
        let mut partial = store
            .generations
            .create_regular(Path::new(&interrupted), 0o400, true)
            .unwrap()
            .into_file();
        partial.write_all(b"crash-residue").unwrap();
        partial.sync_all().unwrap();
        drop(partial);

        let collected = store
            .collect_unreferenced(&BTreeSet::from([retained]))
            .unwrap();
        assert_eq!(collected.removed_generations, Vec::<String>::new());
        assert_eq!(
            collected.removed_blobs,
            vec![blob_name(&candidate_lock.kernel, false)]
        );
        assert_eq!(collected.removed_temporary_objects, 1);
        assert_generation_intact(&store, &retained_lock);

        publish_test_generation(&store, parent.path(), &candidate_lock, b"candidate-kernel");
        assert_generation_intact(&store, &candidate_lock);
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

    #[test]
    fn collection_retains_exact_generations_and_shared_blobs() {
        let (parent, engine) = private_root();
        let store = RuntimeArtifactStore::create(&engine).unwrap();
        let retained_lock = lock_with_kernel(b"current-kernel");
        let retained =
            publish_test_generation(&store, parent.path(), &retained_lock, b"current-kernel");
        let stale_lock = lock_with_kernel(b"stale-kernel");
        let stale = publish_test_generation(&store, parent.path(), &stale_lock, b"stale-kernel");
        let blob_ingest = format!(".ingest-r-{}", Uuid::new_v4());
        let generation_ingest = format!(".ingest-{}", Uuid::new_v4());
        store
            .blobs
            .create_regular(Path::new(&blob_ingest), 0o400, true)
            .unwrap();
        store
            .generations
            .create_regular(Path::new(&generation_ingest), 0o400, true)
            .unwrap();

        let collected = store
            .collect_unreferenced(&BTreeSet::from([retained.clone()]))
            .unwrap();

        assert_eq!(collected.removed_generations, vec![stale.clone()]);
        assert_eq!(
            collected.removed_blobs,
            vec![blob_name(&stale_lock.kernel, false)]
        );
        assert_eq!(collected.removed_temporary_objects, 2);
        assert!(collected.reclaimed_bytes > 0);
        assert!(
            store
                .generations
                .path()
                .join(generation_manifest_name(&retained))
                .is_file()
        );
        assert!(
            !store
                .generations
                .path()
                .join(generation_manifest_name(&stale))
                .exists()
        );
        for (spec, executable) in [
            (&retained_lock.cloud_hypervisor.artifact, true),
            (&retained_lock.kernel, false),
            (&retained_lock.initramfs, false),
        ] {
            assert!(
                store
                    .blobs
                    .path()
                    .join(blob_name(spec, executable))
                    .is_file()
            );
        }
        assert!(
            !store
                .blobs
                .path()
                .join(blob_name(&stale_lock.kernel, false))
                .exists()
        );
    }

    #[test]
    fn collection_validates_the_whole_namespace_before_unlink() {
        let (parent, engine) = private_root();
        let store = RuntimeArtifactStore::create(&engine).unwrap();
        let stale_lock = lock_with_kernel(b"stale-kernel");
        let stale = publish_test_generation(&store, parent.path(), &stale_lock, b"stale-kernel");
        let unknown = store.blobs.path().join("unknown");
        fs::write(&unknown, b"leave me").unwrap();
        fs::set_permissions(&unknown, fs::Permissions::from_mode(0o400)).unwrap();

        assert!(matches!(
            store.collect_unreferenced(&BTreeSet::new()),
            Err(RuntimeArtifactStoreError::UnexpectedObject(path)) if path == unknown
        ));
        assert!(
            store
                .generations
                .path()
                .join(generation_manifest_name(&stale))
                .is_file()
        );
        assert!(
            store
                .blobs
                .path()
                .join(blob_name(&stale_lock.kernel, false))
                .is_file()
        );
    }

    #[test]
    fn missing_or_corrupt_retained_generation_fails_before_collection() {
        let (parent, engine) = private_root();
        let store = RuntimeArtifactStore::create(&engine).unwrap();
        let retained_lock = lock_with_kernel(b"current-kernel");
        let retained =
            publish_test_generation(&store, parent.path(), &retained_lock, b"current-kernel");
        let stale_lock = lock_with_kernel(b"stale-kernel");
        let stale = publish_test_generation(&store, parent.path(), &stale_lock, b"stale-kernel");

        let missing = "f".repeat(64);
        assert!(matches!(
            store.collect_unreferenced(&BTreeSet::from([missing.clone()])),
            Err(RuntimeArtifactStoreError::MissingGeneration(value)) if value == missing
        ));
        assert!(
            store
                .generations
                .path()
                .join(generation_manifest_name(&stale))
                .is_file()
        );

        let retained_kernel = store
            .blobs
            .path()
            .join(blob_name(&retained_lock.kernel, false));
        fs::set_permissions(&retained_kernel, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&retained_kernel, b"broken-kernel!").unwrap();
        fs::set_permissions(&retained_kernel, fs::Permissions::from_mode(0o400)).unwrap();
        assert!(matches!(
            store.collect_unreferenced(&BTreeSet::from([retained])),
            Err(RuntimeArtifactStoreError::BlobMismatch(path)) if path == retained_kernel
        ));
        assert!(
            store
                .generations
                .path()
                .join(generation_manifest_name(&stale))
                .is_file()
        );
    }

    #[test]
    fn diagnostics_report_only_unreferenced_artifacts_and_interrupted_ingests() {
        let (parent, engine) = private_root();
        let store = RuntimeArtifactStore::create(&engine).unwrap();
        let retained_lock = lock_with_kernel(b"current-kernel");
        let retained =
            publish_test_generation(&store, parent.path(), &retained_lock, b"current-kernel");
        let stale_lock = lock_with_kernel(b"stale-kernel");
        let stale = publish_test_generation(&store, parent.path(), &stale_lock, b"stale-kernel");
        let blob_ingest = format!(".ingest-r-{}", Uuid::new_v4());
        let generation_ingest = format!(".ingest-{}", Uuid::new_v4());
        store
            .blobs
            .create_regular(Path::new(&blob_ingest), 0o400, true)
            .unwrap();
        store
            .generations
            .create_regular(Path::new(&generation_ingest), 0o400, true)
            .unwrap();

        let diagnostics =
            runtime_artifact_diagnostics(engine.path(), &BTreeSet::from([retained.clone()]));

        let retained_manifest = store
            .generations
            .path()
            .join(generation_manifest_name(&retained));
        assert!(
            !diagnostics
                .iter()
                .any(|diagnostic| diagnostic.path == retained_manifest)
        );
        for (spec, executable) in [
            (&retained_lock.cloud_hypervisor.artifact, true),
            (&retained_lock.kernel, false),
            (&retained_lock.initramfs, false),
        ] {
            let path = store.blobs.path().join(blob_name(spec, executable));
            assert!(!diagnostics.iter().any(|diagnostic| diagnostic.path == path));
        }
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.path
                == store
                    .generations
                    .path()
                    .join(generation_manifest_name(&stale))
                && diagnostic.reason == "unreferenced_runtime_artifact_generation"
                && diagnostic.reclaimable
        }));
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.path
                == store
                    .blobs
                    .path()
                    .join(blob_name(&stale_lock.kernel, false))
                && diagnostic.reason == "unreferenced_runtime_artifact_blob"
                && diagnostic.reclaimable
        }));
        for path in [
            store.blobs.path().join(&blob_ingest),
            store.generations.path().join(&generation_ingest),
        ] {
            assert!(diagnostics.iter().any(|diagnostic| {
                diagnostic.path == path
                    && diagnostic.reason == "interrupted_runtime_artifact_ingest"
                    && diagnostic.reclaimable
            }));
            assert!(path.exists());
        }
    }

    #[test]
    fn diagnostics_never_claim_blob_reachability_when_a_retained_manifest_is_missing() {
        let (parent, engine) = private_root();
        let store = RuntimeArtifactStore::create(&engine).unwrap();
        let stale_lock = lock_with_kernel(b"uncommitted-kernel");
        let stale =
            publish_test_generation(&store, parent.path(), &stale_lock, b"uncommitted-kernel");
        let missing = "f".repeat(64);

        let diagnostics =
            runtime_artifact_diagnostics(engine.path(), &BTreeSet::from([missing.clone()]));

        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.path
                == store
                    .generations
                    .path()
                    .join(generation_manifest_name(&missing))
                && diagnostic.reason == "recorded_runtime_artifact_generation_missing"
                && !diagnostic.reclaimable
        }));
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.path
                == store
                    .blobs
                    .path()
                    .join(blob_name(&stale_lock.kernel, false))
                && diagnostic.reason == "runtime_artifact_blob_reachability_unknown"
                && !diagnostic.reclaimable
        }));
        assert!(
            store
                .generations
                .path()
                .join(generation_manifest_name(&stale))
                .is_file()
        );
    }

    #[test]
    fn diagnostics_report_a_corrupt_referenced_blob_without_mutation() {
        let (parent, engine) = private_root();
        let store = RuntimeArtifactStore::create(&engine).unwrap();
        let retained_lock = lock_with_kernel(b"current-kernel");
        let retained =
            publish_test_generation(&store, parent.path(), &retained_lock, b"current-kernel");
        let kernel = store
            .blobs
            .path()
            .join(blob_name(&retained_lock.kernel, false));
        fs::set_permissions(&kernel, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&kernel, b"broken-kernel").unwrap();
        fs::set_permissions(&kernel, fs::Permissions::from_mode(0o400)).unwrap();

        let diagnostics = runtime_artifact_diagnostics(engine.path(), &BTreeSet::from([retained]));

        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.path == kernel
                && diagnostic.reason == "corrupt_referenced_runtime_artifact_blob"
                && !diagnostic.reclaimable
        }));
        assert_eq!(fs::read(kernel).unwrap(), b"broken-kernel");
    }

    #[test]
    fn diagnostics_classify_unsafe_and_unknown_objects_without_mutation() {
        let (parent, engine) = private_root();
        let store = RuntimeArtifactStore::create(&engine).unwrap();
        let retained_lock = lock_with_kernel(b"current-kernel");
        let retained =
            publish_test_generation(&store, parent.path(), &retained_lock, b"current-kernel");
        let manifest = store
            .generations
            .path()
            .join(generation_manifest_name(&retained));
        fs::set_permissions(&manifest, fs::Permissions::from_mode(0o600)).unwrap();
        let unsafe_ingest = format!(".ingest-r-{}", Uuid::new_v4());
        let unsafe_ingest_path = store.blobs.path().join(&unsafe_ingest);
        fs::write(&unsafe_ingest_path, b"partial").unwrap();
        fs::set_permissions(&unsafe_ingest_path, fs::Permissions::from_mode(0o600)).unwrap();
        let unknown = store.store.path().join("unknown");
        fs::write(&unknown, b"unknown").unwrap();
        let mut invalid_lock = lock();
        invalid_lock.schema_version += 1;
        let invalid_generation = invalid_lock.generation().unwrap();
        let invalid_manifest = store
            .generations
            .path()
            .join(generation_manifest_name(&invalid_generation));
        fs::write(&invalid_manifest, invalid_lock.canonical_json().unwrap()).unwrap();
        fs::set_permissions(&invalid_manifest, fs::Permissions::from_mode(0o400)).unwrap();

        let diagnostics = runtime_artifact_diagnostics(engine.path(), &BTreeSet::from([retained]));

        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.path == manifest
                && diagnostic.reason == "unsafe_referenced_runtime_artifact_generation"
                && !diagnostic.reclaimable
        }));
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.path == unsafe_ingest_path
                && diagnostic.reason == "unsafe_runtime_artifact_ingest"
                && !diagnostic.reclaimable
        }));
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.path == unknown
                && diagnostic.reason == "unexpected_runtime_artifact_object"
                && !diagnostic.reclaimable
        }));
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.path == invalid_manifest
                && diagnostic.reason == "invalid_unreferenced_runtime_artifact_generation"
                && !diagnostic.reclaimable
        }));
        assert!(manifest.exists());
        assert!(unsafe_ingest_path.exists());
        assert!(unknown.exists());
        assert!(invalid_manifest.exists());
    }
}
