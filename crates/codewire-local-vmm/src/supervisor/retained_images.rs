//! The newest pulled image of each repository, kept as a content-collection
//! root after its last environment is removed (#4262).
//!
//! Without it, removing the last local VM that used an image let collection
//! take the image's layers, and the next create pulled the whole image again
//! (about 1.9 GB for the workspace image). The record keeps at most
//! [`MAXIMUM_RETAINED_REPOSITORIES`] repositories, most recently used first: a
//! pull of a repository replaces its older image, and one more repository
//! drops the one used longest ago. It lives in one `supervisor_metadata` row,
//! which an older supervisor of this schema ignores. `cw prune --local`
//! (`PruneImages`) forgets it and collects.
//!
//! The per-name download cache (#2952) is unchanged: it keeps a failed
//! create's partial pull for its retry, which this record never sees.

use super::*;
use crate::control::v1::local_image_cache_service_server::LocalImageCacheService;

/// How many repositories keep their newest image once no environment uses
/// it. Two keeps the workspace image and one other across a `cw` update.
pub(crate) const MAXIMUM_RETAINED_REPOSITORIES: usize = 2;
/// The record's bound in the store; two images' blob lists are far smaller.
const MAXIMUM_RECORD_BYTES: usize = 256 * 1024;
/// An image with more blobs than this is not recorded.
const MAXIMUM_BLOBS_PER_IMAGE: usize = 512;
const MAXIMUM_REPOSITORY_BYTES: usize = 512;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum RetainedImagesError {
    #[error("the retained image record is larger than {MAXIMUM_RECORD_BYTES} bytes")]
    TooLarge,
    #[error("the retained image record is not valid")]
    Invalid,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RetainedImages {
    /// Most recently used first, one per repository.
    images: Vec<RetainedImage>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RetainedImage {
    /// `registry/repository`, without a tag or digest.
    repository: String,
    blobs: BTreeMap<Sha256Digest, u64>,
}

impl RetainedImages {
    pub(crate) fn decode(encoded: &str) -> Result<Self, RetainedImagesError> {
        if encoded.len() > MAXIMUM_RECORD_BYTES {
            return Err(RetainedImagesError::TooLarge);
        }
        let record: Self =
            serde_json::from_str(encoded).map_err(|_| RetainedImagesError::Invalid)?;
        let mut repositories = BTreeSet::new();
        let valid = record.images.len() <= MAXIMUM_RETAINED_REPOSITORIES
            && record.images.iter().all(|image| {
                valid_repository(&image.repository)
                    && !image.blobs.is_empty()
                    && image.blobs.len() <= MAXIMUM_BLOBS_PER_IMAGE
                    && repositories.insert(image.repository.as_str())
            });
        if valid {
            Ok(record)
        } else {
            Err(RetainedImagesError::Invalid)
        }
    }

    pub(crate) fn encode(&self) -> Result<String, RetainedImagesError> {
        let encoded = serde_json::to_string(self).map_err(|_| RetainedImagesError::Invalid)?;
        if encoded.len() > MAXIMUM_RECORD_BYTES {
            return Err(RetainedImagesError::TooLarge);
        }
        Ok(encoded)
    }

    /// Record `repository`'s newest image as the most recently used,
    /// replacing its older one and dropping the repository used longest ago
    /// beyond the bound. `false`, and nothing changes, for an image this
    /// record does not keep.
    fn record(&mut self, repository: String, blobs: BTreeMap<Sha256Digest, u64>) -> bool {
        if !valid_repository(&repository)
            || blobs.is_empty()
            || blobs.len() > MAXIMUM_BLOBS_PER_IMAGE
        {
            return false;
        }
        self.images.retain(|image| image.repository != repository);
        self.images.insert(0, RetainedImage { repository, blobs });
        self.images.truncate(MAXIMUM_RETAINED_REPOSITORIES);
        true
    }

    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.images.is_empty()
    }

    /// Add every recorded blob to what a collection keeps.
    pub(crate) fn retain(&self, content: &mut BTreeMap<Sha256Digest, u64>) {
        for (digest, size) in self.images.iter().flat_map(|image| &image.blobs) {
            content.entry(digest.clone()).or_insert(*size);
        }
    }

    /// Each image with its size, and how much of it nothing else keeps
    /// (`others`: what a collection keeps without this record).
    fn summaries(&self, others: &BTreeMap<Sha256Digest, u64>) -> Vec<v1::RetainedImage> {
        self.images
            .iter()
            .map(|image| v1::RetainedImage {
                repository: image.repository.clone(),
                bytes: image
                    .blobs
                    .values()
                    .fold(0_u64, |total, size| total.saturating_add(*size)),
                reclaimable_bytes: image
                    .blobs
                    .iter()
                    .filter(|(digest, _)| !others.contains_key(*digest))
                    .fold(0_u64, |total, (_, size)| total.saturating_add(*size)),
            })
            .collect()
    }
}

fn valid_repository(repository: &str) -> bool {
    !repository.is_empty()
        && repository.len() <= MAXIMUM_REPOSITORY_BYTES
        && !repository.contains(['@', ':', ' '])
        && repository.contains('/')
}

/// The repository an image is retained under: its registry and repository
/// path, so a newer tag or digest of it replaces the older image.
pub(crate) fn repository_key(reference: &RegistryReference) -> String {
    format!("{}/{}", reference.registry(), reference.repository())
}

/// The record this store holds. One this supervisor cannot read is logged
/// and treated as empty, not fatal: it only keeps a cache, and the next pull
/// writes a valid one.
pub(crate) fn load(
    store: &SupervisorStore,
    log: Option<&DiagnosticLog>,
) -> Result<RetainedImages, SupervisorError> {
    let Some(encoded) = store.retained_images()? else {
        return Ok(RetainedImages::default());
    };
    Ok(RetainedImages::decode(&encoded).unwrap_or_else(|_| {
        diagnostic_log::record(log, "retained_images_dropped", &[]);
        RetainedImages::default()
    }))
}

impl SupervisorCore {
    /// Keep `reference`'s newest image, `blobs`, after its last environment
    /// is removed. An image the record does not keep, or a record too large
    /// to store, leaves the record as it was.
    pub(super) fn record_retained_image(
        &mut self,
        reference: &RegistryReference,
        blobs: BTreeMap<Sha256Digest, u64>,
    ) -> Result<(), SupervisorError> {
        let mut next = self.retained_images.clone();
        if !next.record(repository_key(reference), blobs) {
            return Ok(());
        }
        let Ok(encoded) = next.encode() else {
            diagnostic_log::record(self.log.as_deref(), "retained_images_too_large", &[]);
            return Ok(());
        };
        self.store.put_retained_images(Some(&encoded))?;
        self.retained_images = next;
        Ok(())
    }

    /// The images the record keeps and what pruning them would free.
    fn retained_images_report(&self) -> Result<v1::PruneImagesResponse, SupervisorError> {
        let others = self.collection_retained_without_images()?.content;
        let images = self.retained_images.summaries(&others);
        let reclaimable_bytes = images.iter().fold(0_u64, |total, image| {
            total.saturating_add(image.reclaimable_bytes)
        });
        Ok(v1::PruneImagesResponse {
            images,
            reclaimable_bytes,
            collection_pending: false,
        })
    }

    /// Forget the record, and every name's download cache that no
    /// environment or pending create still needs, so a collection frees them.
    fn forget_retained_images(&mut self) -> Result<(), SupervisorError> {
        self.store.put_retained_images(None)?;
        self.retained_images = RetainedImages::default();
        self.retain_needed_download_caches()
    }
}

#[tonic::async_trait]
impl LocalImageCacheService for SupervisorRpc {
    async fn prune_images(
        &self,
        request: Request<v1::PruneImagesRequest>,
    ) -> Result<Response<v1::PruneImagesResponse>, Status> {
        let dry_run = request.into_inner().dry_run;
        let mut report = {
            let mut core = self.supervisor.core();
            let report = core.retained_images_report().map_err(Status::from)?;
            if !dry_run {
                core.forget_retained_images().map_err(Status::from)?;
            }
            report
        };
        if !dry_run {
            // Forgetting is durable, as a delete is: a collection that waits
            // for writers or fails is left to the collector, and said so.
            let collected = self.supervisor.collect_if_idle().await;
            if collected.is_err() {
                diagnostic_log::record(
                    self.supervisor.log.as_deref(),
                    "content_collection_failed",
                    &[],
                );
            }
            report.collection_pending = !matches!(collected, Ok(true));
        }
        Ok(Response::new(report))
    }
}

#[cfg(test)]
mod tests;
