//! The store recheck and the store's own refusal of a deleted network
//! (#3542).

use super::*;

/// The store, not the registry, refuses a deleted network: once the
/// registry no longer remembers the delete (a shared registry's `x.`
/// record lasts 15 minutes), a new coordinate setup is still refused
/// (#3542).
#[tokio::test]
async fn a_deleted_network_is_refused_by_the_store_after_the_registry_forgets_it() {
    let store = Arc::new(MemoryStore::new());
    store
        .network_create_with_owner(
            "network-test",
            "org-test",
            "local-owner:org-test",
            chrono::Utc::now(),
        )
        .await
        .unwrap();
    let state = crate::server::AppState::new(config(), store.clone());
    let (address, server) = serve(crate::server::router_from_state(state.clone())).await;
    let mut dial = client(address, "cw_test").coordinate().await.unwrap();
    dial.send(request(hello(MeshCoordinateRole::Dial)))
        .await
        .unwrap();
    assert!(matches!(
        response(&mut dial).await.msg,
        Some(mesh_coordinator_service_coordinate_response::Msg::DerpMap(
            _
        ))
    ));

    store
        .network_delete_by_owner("network-test", "org-test", "local-owner:org-test")
        .await
        .unwrap();
    state
        .mesh_coordinate
        .revoke_network("network-test")
        .await
        .unwrap();
    state.mesh_coordinate.registry().retired_networks.clear();

    let mut late = client(address, "cw_test").coordinate().await.unwrap();
    late.send(request(hello(MeshCoordinateRole::Dial)))
        .await
        .unwrap();
    let refused = late
        .message::<MeshCoordinatorServiceCoordinateResponse>()
        .await;
    assert!(
        refused.is_err(),
        "a deleted network opened a session: {refused:?}"
    );
    server.abort();
}

/// The store recheck ends a session whose node, or for a dial session
/// whose network, the store no longer has, and keeps the others (#3542).
#[tokio::test]
async fn the_store_recheck_ends_sessions_the_store_no_longer_has() {
    let store = Arc::new(MemoryStore::new());
    store
        .network_create_with_owner(
            "network-test",
            "org-test",
            "local-owner:org-test",
            chrono::Utc::now(),
        )
        .await
        .unwrap();
    let state = crate::server::AppState::new(config(), store.clone());
    let unregistered = AuthorizedPeer {
        peer_id: stable_peer_id("network-test", "peer", "gone"),
        network_id: "network-test".to_owned(),
        node_name: Some("gone".to_owned()),
        role: MeshCoordinateRole::Peer,
        environment: None,
    };
    let dial = AuthorizedPeer {
        peer_id: Uuid::new_v4(),
        network_id: "network-test".to_owned(),
        node_name: None,
        role: MeshCoordinateRole::Dial,
        environment: None,
    };
    let (tx, _gone_rx) = mpsc::channel(4);
    let (_, gone) = register(&state.mesh_coordinate, &unregistered, tx).unwrap();
    let (tx, _dial_rx) = mpsc::channel(4);
    let (_, dialing) = register(&state.mesh_coordinate, &dial, tx).unwrap();

    recheck_store(&state).await;
    tokio::time::timeout(Duration::from_secs(1), gone.notified())
        .await
        .expect("a session for a node the store lacks ended");
    assert_eq!(state.mesh_coordinate.local_sessions().len(), 1);

    store
        .network_delete_by_owner("network-test", "org-test", "local-owner:org-test")
        .await
        .unwrap();
    recheck_store(&state).await;
    tokio::time::timeout(Duration::from_secs(1), dialing.notified())
        .await
        .expect("a dial session in a deleted network ended");
    assert!(state.mesh_coordinate.local_sessions().is_empty());
}
