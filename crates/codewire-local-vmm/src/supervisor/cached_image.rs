//! Where a create's workspace image comes from: a pinned synthetic image, the
//! content store for a digest already cached (#4968), or the registry.

use super::*;

/// How many operations' cached-image notes the supervisor keeps for their
/// watchers: far more than run at once.
const CACHED_IMAGE_NOTES: usize = 64;

impl Supervisor {
    pub(super) async fn resolve_workspace_image(
        &self,
        name: &str,
        reference: &RegistryReference,
        content: &ContentStore,
        pinned: Option<ResolvedImage>,
    ) -> Result<ResolvedImage, SupervisorError> {
        if let Some(image) = pinned {
            if image.source_reference != reference.original() {
                return Err(SupervisorError::InvalidState);
            }
            image.verify_cached(content)?;
            return Ok(image);
        }
        let size = self.core().recorded_size(reference)?;
        let architecture = crate::oci::OciArchitecture::native().ok();
        let cached = size.zip(architecture).and_then(|(size, architecture)| {
            crate::oci::cached_digest_image(reference, size, architecture, content)
        });
        if let Some(image) = cached {
            let mut core = self.core();
            // Held for this name, as a pull's downloads are, until the
            // create records the image or another name pulls.
            core.cache_download(name, image_blobs(&image))?;
            core.note_cached_image(name)?;
            diagnostic_log::record(self.log.as_deref(), "workspace_image_cached", &[]);
            return Ok(image);
        }
        let resolver = RegistryResolver::new(content)?;
        let resolved = resolver.resolve_anonymous(reference).await;
        self.core()
            .record_pull(name, reference, resolver.verified_blobs(), resolved)
    }
}

impl SupervisorCore {
    /// The size the supervisor recorded for the document a digest reference
    /// names: from an environment, a pending create, a name's latest pull or
    /// a retained image. A tag has none, since it can move.
    fn recorded_size(&self, reference: &RegistryReference) -> Result<Option<u64>, SupervisorError> {
        let Some(digest) = reference.digest() else {
            return Ok(None);
        };
        Ok(self.collection_retained()?.content.get(digest).copied())
    }

    /// Note that `name`'s operation took its image from the content store.
    /// Staging holds the name's writer, so the one pending operation that
    /// stages an image for it is the one resolving now.
    fn note_cached_image(&mut self, name: &str) -> Result<(), SupervisorError> {
        let staging = self
            .store
            .pending_operations()?
            .into_iter()
            .filter(|operation| {
                matches!(
                    operation.kind,
                    OperationKind::Create | OperationKind::Start | OperationKind::UpdateWorkspace
                ) && operation_name(operation) == Some(name)
            });
        for operation in staging {
            self.note_cached_operation(operation.operation_id);
        }
        Ok(())
    }

    fn note_cached_operation(&mut self, operation_id: Uuid) {
        if self.cached_image_operations.len() == CACHED_IMAGE_NOTES {
            self.cached_image_operations.pop_front();
        }
        self.cached_image_operations.push_back(operation_id);
    }
}

/// `operation` as its watchers see it, saying whether its image came from the
/// content store.
pub(super) fn noted(supervisor: &Supervisor, mut operation: v1::Operation) -> v1::Operation {
    operation.workspace_image_cached = Uuid::parse_str(&operation.operation_id)
        .is_ok_and(|id| supervisor.core().cached_image_operations.contains(&id));
    operation
}

/// Every blob `image` names, with its size.
fn image_blobs(image: &ResolvedImage) -> BTreeMap<Sha256Digest, u64> {
    [&image.source, &image.manifest, &image.config]
        .into_iter()
        .chain(image.layers.iter().map(|layer| &layer.descriptor))
        .map(|descriptor| (descriptor.digest.clone(), descriptor.size))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::super::tests::{
        begin_and_advance_test_operation, project_environment, test_supervisor,
        test_supervisor_core,
    };
    use super::*;
    use crate::supervisor_metadata::oci::{OCI_CONFIG, OCI_LAYER_GZIP, OCI_MANIFEST};

    fn digest(bytes: &[u8]) -> Sha256Digest {
        Sha256Digest::parse(&format!("sha256:{:x}", Sha256::digest(bytes))).unwrap()
    }

    /// A single-platform image for this host, its blobs admitted to `content`,
    /// returning its manifest's digest and every blob with its size.
    async fn stored_image(content: &ContentStore) -> (Sha256Digest, BTreeMap<Sha256Digest, u64>) {
        let layer = b"a layer an earlier create downloaded".to_vec();
        let config = serde_json::to_vec(&serde_json::json!({
            "architecture": crate::oci::OciArchitecture::native().unwrap().as_str(),
            "os": "linux",
            "rootfs": {"type": "layers", "diff_ids": [digest(b"unpacked").as_str()]},
        }))
        .unwrap();
        let manifest = serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 2,
            "mediaType": OCI_MANIFEST,
            "config": {"mediaType": OCI_CONFIG, "digest": digest(&config).as_str(), "size": config.len()},
            "layers": [{"mediaType": OCI_LAYER_GZIP, "digest": digest(&layer).as_str(), "size": layer.len()}],
        }))
        .unwrap();
        let mut blobs = BTreeMap::new();
        for bytes in [&manifest, &config, &layer] {
            content
                .admit_bytes(&digest(bytes), bytes::Bytes::from(bytes.clone()))
                .await
                .unwrap();
            blobs.insert(digest(bytes), bytes.len() as u64);
        }
        (digest(&manifest), blobs)
    }

    /// A digest whose content the store holds, and whose size an earlier
    /// pull recorded, is resolved with no registry round trip, held for its
    /// name and noted for the operation staging it (#4968).
    /// `registry.invalid` never answers, so a registry request would fail.
    #[tokio::test]
    async fn a_cached_digest_is_resolved_without_the_registry() {
        let (_parent, core) = test_supervisor_core(project_environment());
        let environment_id = core.environment("dev").unwrap().id;
        let staging = begin_and_advance_test_operation(
            &core.store,
            environment_id,
            OperationKind::Start,
            &serde_json::json!({"name": "dev"}),
            0,
        );
        let supervisor = test_supervisor(core);
        let engine = PrivateRoot::open(&supervisor.config.engine_root()).unwrap();
        let content = ContentStore::create(&engine).unwrap();
        let (manifest, blobs) = stored_image(&content).await;
        supervisor.core().download_cache = BTreeMap::from([("earlier".to_owned(), blobs.clone())]);
        let reference =
            RegistryReference::parse(&format!("registry.invalid/test/workspace@{manifest}"))
                .unwrap();

        let image = supervisor
            .resolve_workspace_image("dev", &reference, &content, None)
            .await
            .unwrap();
        assert_eq!(image.source.digest, manifest);
        assert_eq!(image.source_reference, reference.original());
        assert_eq!(supervisor.core().download_cache.get("dev"), Some(&blobs));
        let watched = |id: Uuid| {
            noted(
                &supervisor,
                v1::Operation {
                    operation_id: id.to_string(),
                    ..Default::default()
                },
            )
            .workspace_image_cached
        };
        assert!(watched(staging.operation_id));
        assert!(!watched(Uuid::new_v4()));
        // A tag of the same repository has no recorded size: it can move.
        let tag = RegistryReference::parse("registry.invalid/test/workspace:latest").unwrap();
        assert_eq!(supervisor.core().recorded_size(&tag).unwrap(), None);
    }

    /// The notes stay bounded: the oldest goes first.
    #[test]
    fn the_cached_image_notes_keep_the_newest() {
        let (_parent, mut core) = test_supervisor_core(project_environment());
        let first = Uuid::new_v4();
        core.note_cached_operation(first);
        for _ in 0..CACHED_IMAGE_NOTES {
            core.note_cached_operation(Uuid::new_v4());
        }
        assert_eq!(core.cached_image_operations.len(), CACHED_IMAGE_NOTES);
        assert!(!core.cached_image_operations.contains(&first));
    }
}
