use super::super::tests::{project_environment, test_supervisor_core, test_supervisor_service};
use super::*;

fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::parse(&format!("sha256:{:x}", Sha256::digest(bytes))).unwrap()
}

fn blobs(names: &[&str]) -> BTreeMap<Sha256Digest, u64> {
    names
        .iter()
        .map(|name| (digest(name.as_bytes()), 10))
        .collect()
}

fn repositories(record: &RetainedImages) -> Vec<&str> {
    record
        .images
        .iter()
        .map(|image| image.repository.as_str())
        .collect()
}

#[test]
fn a_repository_keeps_only_its_newest_image_and_two_repositories_at_most() {
    let mut record = RetainedImages::default();
    assert!(record.record("ghcr.io/acme/workspace".to_owned(), blobs(&["v1"])));
    assert!(record.record("ghcr.io/acme/tools".to_owned(), blobs(&["tools"])));
    // A newer image of a repository replaces its older one and is now the
    // most recently used.
    assert!(record.record("ghcr.io/acme/workspace".to_owned(), blobs(&["v2"])));
    assert_eq!(
        repositories(&record),
        ["ghcr.io/acme/workspace", "ghcr.io/acme/tools"]
    );
    assert_eq!(record.images[0].blobs, blobs(&["v2"]));
    // A third repository drops the one used longest ago.
    assert!(record.record("ghcr.io/acme/other".to_owned(), blobs(&["other"])));
    assert_eq!(
        repositories(&record),
        ["ghcr.io/acme/other", "ghcr.io/acme/workspace"]
    );
}

#[test]
fn an_image_the_record_cannot_keep_leaves_it_unchanged() {
    let mut record = RetainedImages::default();
    assert!(record.record("ghcr.io/acme/workspace".to_owned(), blobs(&["v1"])));
    let before = record.clone();
    assert!(!record.record("ghcr.io/acme/empty".to_owned(), BTreeMap::new()));
    assert!(!record.record("no-registry".to_owned(), blobs(&["x"])));
    let too_many = (0..=MAXIMUM_BLOBS_PER_IMAGE)
        .map(|index| (digest(index.to_string().as_bytes()), 1))
        .collect();
    assert!(!record.record("ghcr.io/acme/huge".to_owned(), too_many));
    assert_eq!(record, before);
}

#[test]
fn the_record_round_trips_and_decoding_refuses_what_it_never_writes() {
    let mut record = RetainedImages::default();
    record.record(
        "ghcr.io/acme/workspace".to_owned(),
        blobs(&["v1", "v1-config"]),
    );
    let encoded = record.encode().unwrap();
    assert_eq!(RetainedImages::decode(&encoded).unwrap(), record);

    let image = |repository: &str| {
        format!(
            "{{\"repository\":\"{repository}\",\"blobs\":{{\"{}\":1}}}}",
            digest(repository.as_bytes()).as_str()
        )
    };
    for invalid in [
        "not json".to_owned(),
        "{\"images\":[],\"extra\":1}".to_owned(),
        format!(
            "{{\"images\":[{},{},{}]}}",
            image("r/a"),
            image("r/b"),
            image("r/c")
        ),
        format!("{{\"images\":[{},{}]}}", image("r/a"), image("r/a")),
        "{\"images\":[{\"repository\":\"r/a\",\"blobs\":{}}]}".to_owned(),
        "{\"images\":[{\"repository\":\"r/a\",\"blobs\":{\"sha256:00\":1}}]}".to_owned(),
        "{\"images\":[{\"repository\":\"r/a:latest\",\"blobs\":{}}]}".to_owned(),
    ] {
        assert_eq!(
            RetainedImages::decode(&invalid),
            Err(RetainedImagesError::Invalid),
            "{invalid}"
        );
    }
    assert_eq!(
        RetainedImages::decode(&" ".repeat(MAXIMUM_RECORD_BYTES + 1)),
        Err(RetainedImagesError::TooLarge)
    );
}

#[test]
fn a_tag_or_digest_names_the_same_repository() {
    let tagged = RegistryReference::parse("ghcr.io/acme/workspace:v0.4.15").unwrap();
    let pinned = RegistryReference::parse(&format!(
        "ghcr.io/acme/workspace@{}",
        digest(b"manifest").as_str()
    ))
    .unwrap();
    assert_eq!(repository_key(&tagged), "ghcr.io/acme/workspace");
    assert_eq!(repository_key(&pinned), repository_key(&tagged));
}

#[tokio::test]
async fn a_recorded_image_reloads_and_an_unreadable_record_is_dropped() {
    let (_parent, mut core) = test_supervisor_core(project_environment());
    let reference = RegistryReference::parse("ghcr.io/acme/workspace:v1").unwrap();
    core.record_retained_image(&reference, blobs(&["v1"]))
        .unwrap();
    assert_eq!(load(&core.store, None).unwrap(), core.retained_images);
    assert!(!core.retained_images.is_empty());

    core.store
        .put_retained_images(Some("written by a newer cw"))
        .unwrap();
    assert_eq!(load(&core.store, None).unwrap(), RetainedImages::default());
}

#[tokio::test]
async fn collection_keeps_a_retained_image_after_its_last_environment() {
    let (_parent, mut core) = test_supervisor_core(project_environment());
    let engine = PrivateRoot::open(&core.config.engine_root()).unwrap();
    let content = ContentStore::create(&engine).unwrap();
    let layer: &'static [u8] = b"a workspace image layer";
    let layer_digest = digest(layer);
    content
        .admit_bytes(&layer_digest, bytes::Bytes::from_static(layer))
        .await
        .unwrap();
    let reference = RegistryReference::parse("ghcr.io/acme/workspace:v1").unwrap();
    let size = u64::try_from(layer.len()).unwrap();
    core.record_retained_image(&reference, BTreeMap::from([(layer_digest.clone(), size)]))
        .unwrap();

    // No environment references the layer, and no download cache holds it.
    core.download_cache.clear();
    core.collect_content_now().unwrap();
    assert!(content.contains_verified(&layer_digest, size).unwrap());
}

#[tokio::test]
async fn prune_reports_then_frees_what_only_the_record_kept() {
    let (_parent, mut core) = test_supervisor_core(project_environment());
    let engine = PrivateRoot::open(&core.config.engine_root()).unwrap();
    let content = ContentStore::create(&engine).unwrap();
    let layer: &'static [u8] = b"a layer only the record keeps";
    let layer_digest = digest(layer);
    content
        .admit_bytes(&layer_digest, bytes::Bytes::from_static(layer))
        .await
        .unwrap();
    let size = u64::try_from(layer.len()).unwrap();
    let reference = RegistryReference::parse("ghcr.io/acme/workspace:v1").unwrap();
    core.record_retained_image(&reference, BTreeMap::from([(layer_digest.clone(), size)]))
        .unwrap();
    let service = test_supervisor_service(core);

    let report = service
        .prune_images(Request::new(v1::PruneImagesRequest { dry_run: true }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(report.reclaimable_bytes, size);
    assert_eq!(report.images.len(), 1);
    assert_eq!(report.images[0].repository, "ghcr.io/acme/workspace");
    assert_eq!(report.images[0].bytes, size);
    assert!(content.contains_verified(&layer_digest, size).unwrap());
    assert!(!service.supervisor.core().retained_images.is_empty());

    let pruned = service
        .prune_images(Request::new(v1::PruneImagesRequest { dry_run: false }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(pruned.reclaimable_bytes, size);
    assert!(service.supervisor.core().retained_images.is_empty());
    assert_eq!(
        service.supervisor.core().store.retained_images().unwrap(),
        None
    );
    // This harness stages no runtime artifacts, so the full collection fails
    // and is reported pending; the content half then frees the layer.
    assert!(pruned.collection_pending);
    service.supervisor.core().collect_content_now().unwrap();
    assert!(!content.contains_verified(&layer_digest, size).unwrap());
}
