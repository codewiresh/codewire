//! SSH enrollments whose caller goes away during the write (#5413).

use super::*;

/// An SSH enrollment whose caller goes away during its write is undone: its
/// cancellation is seen at publication (#5413). No credential, no material.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_ssh_enrollment_whose_caller_goes_during_its_write_is_undone() {
    let temp = tempfile::tempdir().unwrap();
    let config = runtime_config(&temp);
    let store = TestProtectedStore::default();
    let put_block = store.block_puts();
    let (shutdown, server, probe) =
        start_server_with_ssh_probe(config.clone(), store.clone()).await;
    let mut enrolling = connect_when_ready(&config).await;
    let mut request = tokio::spawn(async move {
        enrolling
            .generate_ssh_credential("abandoned-ssh".into(), None)
            .await
    });
    store.wait_for_put(&mut request).await;
    request.abort();
    assert!(request.await.unwrap_err().is_cancelled());
    wait_on_ssh(&probe, "the caller gone", |probe| probe.abandoned() == 1).await;
    drop(put_block);
    wait_on_ssh(&probe, "the enrollment ended", |probe| {
        probe.admitted() == 0
    })
    .await;

    let mut observer = connect_when_ready(&config).await;
    assert!(observer.list_credentials().await.unwrap().is_empty());
    assert!(store.values().is_empty());
    shutdown.send(()).unwrap();
    server.await.unwrap().unwrap();
}

/// Of two enrollments at once, the abandoned one is undone; the other publishes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_abandoned_ssh_enrollment_is_undone_beside_one_that_publishes() {
    let temp = tempfile::tempdir().unwrap();
    let config = runtime_config(&temp);
    let store = TestProtectedStore::default();
    let put_block = store.block_puts();
    let (shutdown, server, probe) =
        start_server_with_ssh_probe(config.clone(), store.clone()).await;
    let mut first_client = connect_when_ready(&config).await;
    let mut first = tokio::spawn(async move {
        first_client
            .generate_ssh_credential("published-first".into(), None)
            .await
    });
    store.wait_for_put(&mut first).await;
    let mut cancelled_client = connect_when_ready(&config).await;
    let cancelled = tokio::spawn(async move {
        cancelled_client
            .generate_ssh_credential("cancelled-before-publication".into(), None)
            .await
    });
    wait_for_ssh_admission(&probe, 2).await;
    cancelled.abort();
    assert!(cancelled.await.unwrap_err().is_cancelled());
    wait_on_ssh(&probe, "the caller gone", |probe| probe.abandoned() == 1).await;
    drop(put_block);
    first.await.unwrap().unwrap();
    wait_on_ssh(&probe, "both enrollments ended", |probe| {
        probe.admitted() == 0
    })
    .await;

    let mut observer = connect_when_ready(&config).await;
    let credentials = observer.list_credentials().await.unwrap();
    assert_eq!(credentials.len(), 1);
    assert_eq!(credentials[0].metadata.display_name, "published-first");
    assert_eq!(store.values().len(), 1);
    shutdown.send(()).unwrap();
    server.await.unwrap().unwrap();
}
