use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, Read as _};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use bytes::Bytes;
use futures::{Stream, StreamExt as _};
use sha2::{Digest as _, Sha256};
use tokio::io::AsyncWriteExt as _;
use uuid::Uuid;

use super::Sha256Digest;
use crate::linux::path::{PathError, PrivateRoot};

const CONTENT_DIRECTORY: &str = "content";
const BLOBS_DIRECTORY: &str = "blobs";
const MAXIMUM_BLOB_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const MAXIMUM_CONTENT_OBJECTS: usize = 65_536;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobAdmission {
    pub digest: Sha256Digest,
    pub size: u64,
    pub cached: bool,
}

#[derive(Debug)]
pub struct ContentStore {
    content: PrivateRoot,
    blobs: PrivateRoot,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ContentCollection {
    pub(crate) removed_blobs: Vec<Sha256Digest>,
    pub(crate) removed_temporary_objects: usize,
    pub(crate) reclaimed_bytes: u64,
}

impl ContentStore {
    pub fn create(runtime_root: &PrivateRoot) -> Result<Self, ContentStoreError> {
        let content_path = runtime_root.ensure_dir(Path::new(CONTENT_DIRECTORY), 0o700)?;
        let content = PrivateRoot::open(&content_path)?;
        let blobs_path = content.ensure_dir(Path::new(BLOBS_DIRECTORY), 0o700)?;
        Ok(Self {
            content,
            blobs: PrivateRoot::open(&blobs_path)?,
        })
    }

    pub async fn admit_bytes(
        &self,
        digest: &Sha256Digest,
        bytes: Bytes,
    ) -> Result<BlobAdmission, ContentStoreError> {
        let size = u64::try_from(bytes.len()).map_err(|_| ContentStoreError::BlobTooLarge)?;
        self.admit_stream(
            digest,
            size,
            futures::stream::once(async move { Ok::<_, std::convert::Infallible>(bytes) }),
        )
        .await
    }

    pub fn contains_verified(
        &self,
        digest: &Sha256Digest,
        expected_size: u64,
    ) -> Result<bool, ContentStoreError> {
        self.verify_existing(digest, expected_size)
    }

    pub async fn admit_stream<S, E>(
        &self,
        digest: &Sha256Digest,
        expected_size: u64,
        stream: S,
    ) -> Result<BlobAdmission, ContentStoreError>
    where
        S: Stream<Item = Result<Bytes, E>>,
    {
        if expected_size > MAXIMUM_BLOB_BYTES {
            return Err(ContentStoreError::BlobTooLarge);
        }
        if self.verify_existing(digest, expected_size)? {
            return Ok(BlobAdmission {
                digest: digest.clone(),
                size: expected_size,
                cached: true,
            });
        }

        let temporary = format!(".ingest-{}", Uuid::new_v4());
        let opened = self
            .blobs
            .create_regular(Path::new(&temporary), 0o600, true)?;
        let mut cleanup = TemporaryBlob::new(self.blobs.path(), &temporary);
        let mut file = tokio::fs::File::from_std(opened.into_file());
        let mut hasher = Sha256::new();
        let mut written = 0_u64;
        futures::pin_mut!(stream);
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| ContentStoreError::Stream)?;
            let chunk_len =
                u64::try_from(chunk.len()).map_err(|_| ContentStoreError::BlobTooLarge)?;
            written = written
                .checked_add(chunk_len)
                .ok_or(ContentStoreError::BlobTooLarge)?;
            if written > expected_size {
                return Err(ContentStoreError::SizeMismatch {
                    expected: expected_size,
                    actual: written,
                });
            }
            hasher.update(&chunk);
            file.write_all(&chunk)
                .await
                .map_err(ContentStoreError::Io)?;
        }
        if written != expected_size {
            return Err(ContentStoreError::SizeMismatch {
                expected: expected_size,
                actual: written,
            });
        }
        let actual = format!("sha256:{:x}", hasher.finalize());
        if actual != digest.as_str() {
            return Err(ContentStoreError::DigestMismatch);
        }
        file.sync_all().await.map_err(ContentStoreError::Io)?;
        let file = file.into_std().await;
        file.set_permissions(fs::Permissions::from_mode(0o400))
            .map_err(ContentStoreError::Io)?;
        file.sync_all().map_err(ContentStoreError::Io)?;
        drop(file);
        cleanup.permissions = 0o400;

        let published = self.blobs.publish_private_regular_no_replace(
            Path::new(&temporary),
            Path::new(digest.hex()),
            0o400,
        )?;
        if published {
            cleanup.disarm();
        } else if !self.verify_existing(digest, expected_size)? {
            return Err(ContentStoreError::ExistingBlobInvalid);
        }
        Ok(BlobAdmission {
            digest: digest.clone(),
            size: expected_size,
            cached: !published,
        })
    }

    pub fn open_blob(
        &self,
        digest: &Sha256Digest,
        expected_size: u64,
    ) -> Result<File, ContentStoreError> {
        if !self.verify_existing(digest, expected_size)? {
            return Err(ContentStoreError::BlobMissing);
        }
        Ok(self
            .blobs
            .open_regular(
                Path::new(digest.hex()),
                false,
                Some(expected_size),
                false,
                Some(0o400),
            )?
            .into_file())
    }

    pub fn read_blob(
        &self,
        digest: &Sha256Digest,
        expected_size: u64,
        maximum_size: u64,
    ) -> Result<Vec<u8>, ContentStoreError> {
        if expected_size > maximum_size {
            return Err(ContentStoreError::BlobTooLarge);
        }
        let mut file = self.open_blob(digest, expected_size)?;
        let capacity =
            usize::try_from(expected_size).map_err(|_| ContentStoreError::BlobTooLarge)?;
        let mut bytes = Vec::with_capacity(capacity);
        file.read_to_end(&mut bytes)
            .map_err(ContentStoreError::Io)?;
        Ok(bytes)
    }

    /// Collects only published blobs absent from the complete durable
    /// supervisor reachability map, plus abandoned bounded ingest files.
    ///
    /// The supervisor singleton serializes this with resolution. Every object
    /// is admitted before the first unlink so an unknown name, type, mode, or
    /// hardlink leaves the full CAS unchanged for diagnosis.
    pub(crate) fn collect_unreferenced(
        &self,
        retained: &BTreeMap<Sha256Digest, u64>,
    ) -> Result<ContentCollection, ContentStoreError> {
        if retained.values().any(|size| *size > MAXIMUM_BLOB_BYTES) {
            return Err(ContentStoreError::BlobTooLarge);
        }
        for entry in fs::read_dir(self.content.path()).map_err(ContentStoreError::Io)? {
            let entry = entry.map_err(ContentStoreError::Io)?;
            if entry.file_name() != BLOBS_DIRECTORY {
                return Err(ContentStoreError::UnexpectedObject(entry.path()));
            }
        }

        let mut objects = Vec::new();
        for entry in fs::read_dir(self.blobs.path()).map_err(ContentStoreError::Io)? {
            let entry = entry.map_err(ContentStoreError::Io)?;
            if objects.len() == MAXIMUM_CONTENT_OBJECTS {
                return Err(ContentStoreError::ObjectLimit);
            }
            let path = entry.path();
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| ContentStoreError::UnexpectedObject(path.clone()))?;
            if let Some(digest) = digest_from_blob_name(&name) {
                let expected_size = retained.get(&digest).copied();
                let opened = self.blobs.open_regular(
                    Path::new(&name),
                    false,
                    expected_size,
                    false,
                    Some(0o400),
                )?;
                if opened.identity().size > MAXIMUM_BLOB_BYTES {
                    return Err(ContentStoreError::BlobTooLarge);
                }
                objects.push(ContentObject {
                    name,
                    size: opened.identity().size,
                    permissions: 0o400,
                    digest: Some(digest),
                    retained: expected_size.is_some(),
                });
                continue;
            }
            if valid_temporary_blob_name(&name) {
                let (size, permissions) = self.admit_temporary_blob(&name)?;
                objects.push(ContentObject {
                    name,
                    size,
                    permissions,
                    digest: None,
                    retained: false,
                });
                continue;
            }
            return Err(ContentStoreError::UnexpectedObject(path));
        }

        let mut removed_blobs = Vec::new();
        let mut removed_temporary_objects = 0_usize;
        let mut reclaimed_bytes = 0_u64;
        for object in objects.into_iter().filter(|object| !object.retained) {
            if !self
                .blobs
                .remove_private_regular(Path::new(&object.name), object.permissions)?
            {
                return Err(ContentStoreError::UnexpectedObject(
                    self.blobs.path().join(&object.name),
                ));
            }
            reclaimed_bytes = reclaimed_bytes.saturating_add(object.size);
            match object.digest {
                Some(digest) => removed_blobs.push(digest),
                None => removed_temporary_objects += 1,
            }
        }
        removed_blobs.sort();
        Ok(ContentCollection {
            removed_blobs,
            removed_temporary_objects,
            reclaimed_bytes,
        })
    }

    fn admit_temporary_blob(&self, name: &str) -> Result<(u64, u32), ContentStoreError> {
        for permissions in [0o600, 0o400] {
            match self
                .blobs
                .open_regular(Path::new(name), false, None, false, Some(permissions))
            {
                Ok(opened) => {
                    if opened.identity().size > MAXIMUM_BLOB_BYTES {
                        return Err(ContentStoreError::BlobTooLarge);
                    }
                    return Ok((opened.identity().size, permissions));
                }
                Err(PathError::UnsafeFile(_)) => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err(ContentStoreError::UnexpectedObject(
            self.blobs.path().join(name),
        ))
    }

    fn verify_existing(
        &self,
        digest: &Sha256Digest,
        expected_size: u64,
    ) -> Result<bool, ContentStoreError> {
        let opened = match self.blobs.open_regular(
            Path::new(digest.hex()),
            false,
            Some(expected_size),
            false,
            Some(0o400),
        ) {
            Ok(opened) => opened,
            Err(error) if path_error_is_not_found(&error) => return Ok(false),
            Err(PathError::UnsafeFile(_)) => return Err(ContentStoreError::ExistingBlobInvalid),
            Err(error) => return Err(error.into()),
        };
        let mut file = opened.into_file();
        let mut hasher = Sha256::new();
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let read = file.read(&mut buffer).map_err(ContentStoreError::Io)?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
        let actual = format!("sha256:{:x}", hasher.finalize());
        if actual != digest.as_str() {
            return Err(ContentStoreError::ExistingBlobInvalid);
        }
        Ok(true)
    }
}

#[derive(Debug)]
struct ContentObject {
    name: String,
    size: u64,
    permissions: u32,
    digest: Option<Sha256Digest>,
    retained: bool,
}

fn digest_from_blob_name(name: &str) -> Option<Sha256Digest> {
    (name.len() == 64)
        .then(|| Sha256Digest::parse(&format!("sha256:{name}")).ok())
        .flatten()
}

fn valid_temporary_blob_name(name: &str) -> bool {
    name.strip_prefix(".ingest-")
        .and_then(|value| Uuid::parse_str(value).ok().map(|uuid| (value, uuid)))
        .is_some_and(|(value, uuid)| value == uuid.to_string())
}

struct TemporaryBlob {
    root: PathBuf,
    name: String,
    permissions: u32,
    active: bool,
}

impl TemporaryBlob {
    fn new(root: &Path, name: &str) -> Self {
        Self {
            root: root.to_owned(),
            name: name.to_owned(),
            permissions: 0o600,
            active: true,
        }
    }

    fn disarm(&mut self) {
        self.active = false;
    }
}

impl Drop for TemporaryBlob {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        if let Ok(root) = PrivateRoot::open(&self.root) {
            let _ = root.remove_private_regular(Path::new(&self.name), self.permissions);
        }
    }
}

fn path_error_is_not_found(error: &PathError) -> bool {
    match error {
        PathError::Openat2 { source, .. } => *source == rustix::io::Errno::NOENT,
        PathError::Io { source, .. } => source.kind() == io::ErrorKind::NotFound,
        _ => false,
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ContentStoreError {
    #[error("OCI blob exceeds the local content bound")]
    BlobTooLarge,
    #[error("OCI blob stream failed")]
    Stream,
    #[error("OCI blob size mismatch: expected {expected}, received {actual}")]
    SizeMismatch { expected: u64, actual: u64 },
    #[error("OCI blob digest mismatch")]
    DigestMismatch,
    #[error("existing OCI CAS blob is invalid")]
    ExistingBlobInvalid,
    #[error("OCI CAS blob is missing")]
    BlobMissing,
    #[error("OCI CAS contains too many objects")]
    ObjectLimit,
    #[error("OCI CAS contains an unknown or unsafe object: {0}")]
    UnexpectedObject(PathBuf),
    #[error("OCI CAS filesystem I/O failed: {0}")]
    Io(io::Error),
    #[error(transparent)]
    Path(#[from] PathError),
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};

    use super::*;

    fn store() -> (tempfile::TempDir, ContentStore) {
        let parent = tempfile::tempdir().unwrap();
        let root_path = parent.path().join("runtime");
        fs::create_dir(&root_path).unwrap();
        fs::set_permissions(&root_path, fs::Permissions::from_mode(0o700)).unwrap();
        let root = PrivateRoot::open(&root_path).unwrap();
        let store = ContentStore::create(&root).unwrap();
        (parent, store)
    }

    fn digest(bytes: &[u8]) -> Sha256Digest {
        Sha256Digest::parse(&format!("sha256:{:x}", Sha256::digest(bytes))).unwrap()
    }

    #[tokio::test]
    async fn blob_admission_is_atomic_digest_bound_and_cacheable() {
        let (_parent, store) = store();
        let bytes = Bytes::from_static(b"verified-content");
        let digest = digest(&bytes);
        let first = store.admit_bytes(&digest, bytes.clone()).await.unwrap();
        assert!(!first.cached);
        let second = store.admit_bytes(&digest, bytes.clone()).await.unwrap();
        assert!(second.cached);
        assert_eq!(
            store.read_blob(&digest, bytes.len() as u64, 1024).unwrap(),
            bytes
        );
        let metadata = fs::symlink_metadata(store.blobs.path().join(digest.hex())).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o400);
        assert_eq!(metadata.nlink(), 1);
    }

    #[tokio::test]
    async fn mismatch_never_publishes_or_leaves_a_temporary_blob() {
        let (_parent, store) = store();
        let expected = digest(b"expected");
        assert!(matches!(
            store
                .admit_bytes(&expected, Bytes::from_static(b"hostile"))
                .await,
            Err(ContentStoreError::DigestMismatch)
        ));
        assert!(fs::read_dir(store.blobs.path()).unwrap().next().is_none());
    }

    #[tokio::test]
    async fn existing_symlink_or_hardlink_fails_closed() {
        let (parent, store) = store();
        let bytes = b"content";
        let digest = digest(bytes);
        let outside = parent.path().join("outside");
        fs::write(&outside, bytes).unwrap();
        symlink(&outside, store.blobs.path().join(digest.hex())).unwrap();
        assert!(matches!(
            store
                .admit_bytes(&digest, Bytes::copy_from_slice(bytes))
                .await,
            Err(ContentStoreError::Path(_)) | Err(ContentStoreError::ExistingBlobInvalid)
        ));
        fs::remove_file(store.blobs.path().join(digest.hex())).unwrap();
        fs::write(store.blobs.path().join(digest.hex()), bytes).unwrap();
        fs::set_permissions(
            store.blobs.path().join(digest.hex()),
            fs::Permissions::from_mode(0o400),
        )
        .unwrap();
        fs::hard_link(
            store.blobs.path().join(digest.hex()),
            store.blobs.path().join("second-link"),
        )
        .unwrap();
        assert!(matches!(
            store
                .admit_bytes(&digest, Bytes::copy_from_slice(bytes))
                .await,
            Err(ContentStoreError::ExistingBlobInvalid)
        ));
    }

    #[tokio::test]
    async fn collection_retains_reachable_blobs_and_removes_stale_ingest() {
        let (_parent, store) = store();
        let retained_bytes = Bytes::from_static(b"retained");
        let retained_digest = digest(&retained_bytes);
        store
            .admit_bytes(&retained_digest, retained_bytes.clone())
            .await
            .unwrap();
        let stale_bytes = Bytes::from_static(b"stale");
        let stale_digest = digest(&stale_bytes);
        store
            .admit_bytes(&stale_digest, stale_bytes.clone())
            .await
            .unwrap();
        let temporary = format!(".ingest-{}", Uuid::new_v4());
        fs::write(store.blobs.path().join(&temporary), b"partial").unwrap();
        fs::set_permissions(
            store.blobs.path().join(&temporary),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();

        let collected = store
            .collect_unreferenced(&BTreeMap::from([(
                retained_digest.clone(),
                retained_bytes.len() as u64,
            )]))
            .unwrap();

        assert_eq!(collected.removed_blobs, vec![stale_digest.clone()]);
        assert_eq!(collected.removed_temporary_objects, 1);
        assert_eq!(
            collected.reclaimed_bytes,
            stale_bytes.len() as u64 + b"partial".len() as u64
        );
        assert!(
            store
                .contains_verified(&retained_digest, retained_bytes.len() as u64)
                .unwrap()
        );
        assert!(
            !store
                .contains_verified(&stale_digest, stale_bytes.len() as u64)
                .unwrap()
        );
        assert!(!store.blobs.path().join(temporary).exists());
    }

    #[tokio::test]
    async fn collection_rejects_unknown_objects_before_unlink() {
        let (_parent, store) = store();
        let stale_bytes = Bytes::from_static(b"stale");
        let stale_digest = digest(&stale_bytes);
        store
            .admit_bytes(&stale_digest, stale_bytes.clone())
            .await
            .unwrap();
        let unknown = store.blobs.path().join("unknown");
        fs::write(&unknown, b"leave me").unwrap();
        fs::set_permissions(&unknown, fs::Permissions::from_mode(0o400)).unwrap();

        assert!(matches!(
            store.collect_unreferenced(&BTreeMap::new()),
            Err(ContentStoreError::UnexpectedObject(path)) if path == unknown
        ));
        assert!(
            store
                .contains_verified(&stale_digest, stale_bytes.len() as u64)
                .unwrap()
        );

        fs::remove_file(&unknown).unwrap();
        let parent_unknown = store.content.path().join("unknown");
        fs::write(&parent_unknown, b"leave me").unwrap();
        fs::set_permissions(&parent_unknown, fs::Permissions::from_mode(0o400)).unwrap();
        assert!(matches!(
            store.collect_unreferenced(&BTreeMap::new()),
            Err(ContentStoreError::UnexpectedObject(path)) if path == parent_unknown
        ));
        assert!(store.blobs.path().join(stale_digest.hex()).is_file());
    }

    #[tokio::test]
    async fn collection_never_retains_a_descriptor_with_the_wrong_size() {
        let (_parent, store) = store();
        let bytes = Bytes::from_static(b"retained");
        let digest = digest(&bytes);
        store.admit_bytes(&digest, bytes.clone()).await.unwrap();

        assert!(matches!(
            store
                .collect_unreferenced(&BTreeMap::from([(digest.clone(), bytes.len() as u64 + 1,)])),
            Err(ContentStoreError::Path(PathError::UnsafeFile(_)))
        ));
        assert!(store.blobs.path().join(digest.hex()).is_file());
    }
}
