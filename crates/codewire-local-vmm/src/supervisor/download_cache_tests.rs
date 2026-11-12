use super::tests::{project_environment, test_supervisor_core, test_supervisor_service};
use super::*;

fn cached_layer() -> (Sha256Digest, &'static [u8]) {
    let bytes: &'static [u8] = b"a layer the failed create downloaded";
    let digest = Sha256Digest::parse(&format!("sha256:{:x}", Sha256::digest(bytes))).unwrap();
    (digest, bytes)
}

#[tokio::test]
async fn a_failed_creates_rollback_delete_keeps_the_download_cache() {
    // Left in `error` and never provisioned, as a failed create leaves it;
    // its rollback is a delete that runs every cleanup effect.
    let mut failed = project_environment();
    failed.state = StoredEnvironmentState::Error;
    failed.generation = 0;
    let (_parent, core) = test_supervisor_core(failed);
    let core = super::tests::test_supervisor(core);
    let engine = PrivateRoot::open(&core.config.engine_root()).unwrap();
    let content = ContentStore::create(&engine).unwrap();
    let (layer, bytes) = cached_layer();
    content
        .admit_bytes(&layer, bytes::Bytes::from_static(bytes))
        .await
        .unwrap();
    core.core().download_cache = BTreeMap::from([(
        "dev".to_owned(),
        BTreeMap::from([(layer.clone(), bytes.len() as u64)]),
    )]);

    core.core().begin_rollback_of_failed_creates().unwrap();
    core.drain_pending(true).await.unwrap();
    assert!(matches!(
        core.environment("dev"),
        Err(SupervisorError::NotFound(_))
    ));
    assert_eq!(core.core().download_cache.len(), 1);
    assert!(
        content
            .contains_verified(&layer, bytes.len() as u64)
            .unwrap()
    );
}

#[tokio::test]
async fn a_requested_delete_frees_only_its_own_download_cache() {
    let (_parent, mut core) = test_supervisor_core(project_environment());
    let environment_id = core.environment("dev").unwrap().id;
    let (layer, bytes) = cached_layer();
    // Another name's failed create keeps its retry cache (#2978).
    core.download_cache = BTreeMap::from([
        (
            "dev".to_owned(),
            BTreeMap::from([(layer.clone(), bytes.len() as u64)]),
        ),
        (
            "other".to_owned(),
            BTreeMap::from([(layer.clone(), bytes.len() as u64)]),
        ),
    ]);
    let service = test_supervisor_service(core);

    service
        .delete_environment(Request::new(v1::EnvironmentSelector {
            name: "dev".to_owned(),
            request_id: Uuid::new_v4().to_string(),
            environment_id: environment_id.to_string(),
        }))
        .await
        .unwrap();
    assert_eq!(
        service
            .supervisor
            .core()
            .download_cache
            .keys()
            .collect::<Vec<_>>(),
        ["other"]
    );
}

#[tokio::test]
async fn collection_keeps_the_latest_pull_until_a_delete_frees_it() {
    let (_parent, mut core) = test_supervisor_core(project_environment());
    let engine = PrivateRoot::open(&core.config.engine_root()).unwrap();
    let content = ContentStore::create(&engine).unwrap();
    let admit = |bytes: &'static [u8]| {
        let digest = Sha256Digest::parse(&format!("sha256:{:x}", Sha256::digest(bytes))).unwrap();
        (digest, bytes)
    };
    let (layer, layer_bytes) = admit(b"a layer the failed create downloaded");
    let (bundle, bundle_bytes) = admit(b"a repository bundle no environment owns");
    for (digest, bytes) in [(&layer, layer_bytes), (&bundle, bundle_bytes)] {
        content
            .admit_bytes(digest, bytes::Bytes::from_static(bytes))
            .await
            .unwrap();
    }
    core.download_cache = BTreeMap::from([(
        "dev".to_owned(),
        BTreeMap::from([(layer.clone(), layer_bytes.len() as u64)]),
    )]);

    // A failed create's retry finds its layer; nothing else unreferenced
    // is kept.
    core.collect_content_now().unwrap();
    assert!(
        content
            .contains_verified(&layer, layer_bytes.len() as u64)
            .unwrap()
    );
    assert!(
        !content
            .contains_verified(&bundle, bundle_bytes.len() as u64)
            .unwrap()
    );

    // A delete clears the cache before it collects.
    core.download_cache.clear();
    core.collect_content_now().unwrap();
    assert!(
        !content
            .contains_verified(&layer, layer_bytes.len() as u64)
            .unwrap()
    );
}
