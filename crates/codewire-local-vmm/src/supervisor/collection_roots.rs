//! What content collection keeps (#2978): the content every environment,
//! pending create and disk snapshot references, each name's latest pull
//! (#2952) and the retained images (#4262). The filesystem walk that removes
//! the rest is in the supervisor.

use super::*;

impl SupervisorCore {
    /// Cache `name`'s newest pull. Besides it, only names that hold an
    /// environment or await a create keep theirs: a failed create's layers
    /// stay for its retry until another name pulls, so the cache never
    /// outgrows the environments (#2978).
    pub(super) fn cache_download(
        &mut self,
        name: &str,
        verified: BTreeMap<Sha256Digest, u64>,
    ) -> Result<(), SupervisorError> {
        self.retain_needed_download_caches()?;
        self.download_cache.insert(name.to_owned(), verified);
        Ok(())
    }

    /// Keep only the download caches of names that hold an environment or
    /// await a create, so the cache never outgrows them (#2952).
    pub(super) fn retain_needed_download_caches(&mut self) -> Result<(), SupervisorError> {
        let pending = self.store.pending_operations()?;
        let environments = &self.state.environments;
        self.download_cache.retain(|cached, _| {
            environments.contains_key(cached)
                || pending.iter().any(|operation| {
                    operation.kind == OperationKind::Create
                        && operation_name(operation) == Some(cached.as_str())
                })
        });
        Ok(())
    }

    /// Record a registry pull: `name`'s download cache, whether or not it
    /// resolved, and on success its image as the repository's retained one.
    pub(super) fn record_pull(
        &mut self,
        name: &str,
        reference: &RegistryReference,
        verified: BTreeMap<Sha256Digest, u64>,
        resolved: Result<ResolvedImage, RegistryResolverError>,
    ) -> Result<ResolvedImage, SupervisorError> {
        self.cache_download(name, verified.clone())?;
        let resolved = resolved?;
        self.record_retained_image(reference, verified)?;
        Ok(resolved)
    }

    /// What a collection keeps, read from memory and the journal only; the
    /// filesystem walk runs afterwards with no lock held (#2978).
    pub(super) fn collection_retained(&self) -> Result<CollectionRetained, SupervisorError> {
        let mut retained = self.collection_retained_without_images()?;
        self.retained_images.retain(&mut retained.content);
        Ok(retained)
    }

    /// [`Self::collection_retained`] without the retained images (#4262).
    pub(super) fn collection_retained_without_images(
        &self,
    ) -> Result<CollectionRetained, SupervisorError> {
        let mut content = referenced_content_blobs(&self.state)?;
        #[cfg(all(target_os = "linux", feature = "synthetic-oci-input-smoke"))]
        if let Some(image) = self.synthetic_workspace_image_pin()? {
            retain_image_content(&mut content, &image)?;
        }
        for operation in self.store.pending_operations()? {
            if operation.kind != OperationKind::Create {
                continue;
            }
            let (_, workspace_plan) = create_request_from_operation(&operation)?;
            retain_workspace_plan_content(&mut content, &workspace_plan)?;
        }
        for (digest, size) in self.download_cache.values().flatten() {
            content.entry(digest.clone()).or_insert(*size);
        }
        let mut artifacts = referenced_artifact_generations(&self.state)?;
        // Local disk snapshots are retention roots (#3046).
        snapshots::retain(&self.config, &mut content, &mut artifacts)?;
        Ok(CollectionRetained { content, artifacts })
    }
}
