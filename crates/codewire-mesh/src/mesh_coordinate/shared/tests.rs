use super::*;

#[test]
fn keys_hash_the_network_and_round_trip() {
    let peer = Uuid::new_v4();
    let key = peer_key("free text / network", peer);
    let net = net_key("free text / network");
    assert_eq!(net.len(), 32);
    assert_eq!(key, format!("p.{net}.{}", peer.simple()));
    let record = PeerRecord {
        session_id: Uuid::new_v4(),
        replica_id: Uuid::new_v4(),
        network_id: "free text / network".to_owned(),
        node: None,
        last_heard: Utc::now(),
        draining: false,
        age_ms: 0,
    };
    let value = serde_json::to_vec(&record).unwrap();
    let Some(Change::Peer {
        peer_id,
        revision,
        record: Some(read),
        expired: false,
        ..
    }) = change(&key, Operation::Put, &value, 7, Utc::now())
    else {
        panic!("a peer record");
    };
    assert_eq!((peer_id, revision), (peer, 7));
    assert_eq!(read.session_id, record.session_id);
}

#[test]
fn a_delete_and_an_expiry_are_told_apart() {
    let key = peer_key("n", Uuid::new_v4());
    assert!(matches!(
        change(&key, Operation::Delete, b"", 3, Utc::now()),
        Some(Change::Peer {
            record: None,
            expired: false,
            ..
        })
    ));
    assert!(matches!(
        change(&key, Operation::Purge, b"", 3, Utc::now()),
        Some(Change::Peer {
            record: None,
            expired: true,
            ..
        })
    ));
}

#[test]
fn unknown_keys_and_values_are_skipped() {
    let peer = Uuid::new_v4();
    for key in [
        "q.abc".to_owned(),
        format!("p.{}", net_key("n")),
        format!("{}.extra", peer_key("n", peer)),
        format!("p.{}.not-a-uuid", net_key("n")),
    ] {
        assert!(
            change(&key, Operation::Put, b"{}", 1, Utc::now()).is_none(),
            "{key}"
        );
    }
    assert!(
        change(
            &peer_key("n", peer),
            Operation::Put,
            b"not json",
            1,
            Utc::now()
        )
        .is_none()
    );
    assert!(matches!(
        change(&retired_key("n"), Operation::Put, b"", 1, Utc::now()),
        Some(Change::Retired { live: true, .. })
    ));
}

/// NATS unreachable at startup: Mesh serves its own sessions, admits only its
/// own keys, refuses a change it can't share, and stays ready (#3542).
#[tokio::test]
async fn without_nats_at_startup_mesh_serves_its_own_sessions_and_stays_ready() {
    use codewire_proto::codewire::internal::v1::MeshCoordinateRole;
    use tower::ServiceExt as _;

    let mut state = crate::mesh_coordinate::MeshCoordinateState::new();
    // Nothing listens on the discard port.
    let sharing =
        state.share_in_background(crate::config::NatsConfig::for_test("nats://127.0.0.1:9"));
    let peer = crate::mesh_coordinate::AuthorizedPeer {
        peer_id: crate::mesh_coordinate::stable_peer_id("network-test", "peer", "one"),
        network_id: "network-test".to_owned(),
        node_name: Some("one".to_owned()),
        role: MeshCoordinateRole::Peer,
        environment: None,
    };
    let (tx, _events) = mpsc::channel(4);
    let (session_id, _close) = crate::mesh_coordinate::register(&state, &peer, tx).unwrap();
    let node = codewire_tailnet::node::Node {
        id: peer.peer_id,
        as_of: "2026-11-13T12:00:00Z".parse().unwrap(),
        key: codewire_tailnet::node::NodePublic::from_raw([0x44; 32]),
        disco_key: codewire_tailnet::node::DiscoPublic::from_raw([0x45; 32]),
        preferred_derp: 1,
        derp_latency: None,
        endpoints: Vec::new(),
        addresses: vec![codewire_tailnet::node::prefix_from_uuid(&peer.peer_id)],
    };
    crate::mesh_coordinate::update_node(&state, peer.peer_id, session_id, node.clone());

    assert!(state.is_shared());
    assert!(state.shared.get().is_none(), "NATS was reached");
    assert!(state.knows_key(&node.key), "its own session is served");
    assert!(matches!(
        state.revoke_node("network-test", "one").await,
        Err(CoordinationError::NotConnected)
    ));

    let config =
        crate::config::Config::from_sources(["--base-url=http://mesh.test"], |_| None).unwrap();
    let mut app_state =
        crate::server::AppState::new(config, Arc::new(crate::store::MemoryStore::new()));
    app_state.mesh_coordinate = state;
    let ready = |app_state: crate::server::AppState| async move {
        let response = crate::server::router_from_state(app_state)
            .oneshot(
                axum::http::Request::get("/readyz")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), 64)
            .await
            .unwrap();
        (status, body)
    };
    let (status, body) = ready(app_state.clone()).await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert_eq!(&body[..], b"ok");
    app_state.draining.store(true, Ordering::Release);
    let (status, _) = ready(app_state).await;
    assert_eq!(status, axum::http::StatusCode::SERVICE_UNAVAILABLE);
    sharing.abort();
}

/// Two replicas sharing one bucket of a real NATS server (CI's `run_nats`).
mod nats_tests {
    use std::time::Duration;

    use codewire_proto::codewire::internal::v1::MeshCoordinateRole;
    use codewire_tailnet::node::{DiscoPublic, NodePublic, prefix_from_uuid};
    use tokio::sync::Notify;

    use crate::mesh_coordinate::shared::*;
    use crate::mesh_coordinate::{
        AuthorizedPeer, CoordinateEvent, MeshCoordinateState, add_tunnel, deregister, register,
        stable_peer_id, update_node,
    };

    /// A hang guard, never a proof: every wait below ends on its condition.
    const WAIT: Duration = Duration::from_secs(30);

    struct Replicas {
        a: MeshCoordinateState,
        b: MeshCoordinateState,
        js: async_nats::jetstream::Context,
        kv: kv::Store,
        tasks: Vec<tokio::task::JoinHandle<()>>,
    }

    impl Drop for Replicas {
        fn drop(&mut self) {
            for task in &self.tasks {
                task.abort();
            }
        }
    }

    async fn replicas() -> Replicas {
        replicas_with(Timing::default(), Timing::default()).await
    }

    /// Two replicas, each with its own bounds.
    async fn replicas_with(a_timing: Timing, b_timing: Timing) -> Replicas {
        let url = std::env::var("NATS_URL").expect("set NATS_URL to a JetStream-enabled NATS");
        let js = async_nats::jetstream::new(async_nats::connect(url).await.unwrap());
        let mut config = bucket_config(1);
        config.bucket = format!("mesh-sessions-test-{}", Uuid::new_v4().simple());
        let kv = js.create_key_value(config).await.unwrap();
        let a = MeshCoordinateState::new();
        let b = MeshCoordinateState::new();
        let mut tasks = Shared::attach(&a, kv.clone(), a_timing);
        tasks.extend(Shared::attach(&b, kv.clone(), b_timing));
        let replicas = Replicas {
            a,
            b,
            js,
            kv,
            tasks,
        };
        for state in [&replicas.a, &replicas.b] {
            eventually(|| {
                state
                    .shared
                    .get()
                    .is_some_and(|shared| shared.view_current())
            })
            .await;
        }
        replicas
    }

    async fn eventually(condition: impl Fn() -> bool) {
        tokio::time::timeout(WAIT, async {
            while !condition() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("the condition held in time");
    }

    /// Every change `state` queued before now has been written, or refused.
    async fn flushed(state: &MeshCoordinateState) {
        let (done, finished) = tokio::sync::oneshot::channel();
        state.shared.get().unwrap().send(Dirty::Flush(done));
        tokio::time::timeout(WAIT, finished)
            .await
            .expect("the writer flushed in time")
            .expect("the writer answered");
    }

    /// `state`'s watch has delivered everything written before now: its own
    /// next heartbeat, written after it, came back through the watch.
    async fn caught_up(state: &MeshCoordinateState) {
        let shared = state.shared.get().unwrap();
        let seen = shared.live_heartbeats.load(Ordering::Acquire);
        shared.beat_now.notify_one();
        eventually(|| shared.live_heartbeats.load(Ordering::Acquire) > seen).await;
    }

    /// Both replicas have written what they queued and seen what was written,
    /// so nothing more follows from what happened before.
    async fn settled(r: &Replicas) {
        flushed(&r.a).await;
        flushed(&r.b).await;
        caught_up(&r.a).await;
        caught_up(&r.b).await;
    }

    struct Session {
        peer: AuthorizedPeer,
        session_id: Uuid,
        close: Arc<Notify>,
        events: mpsc::Receiver<CoordinateEvent>,
    }

    fn member(network_id: &str, name: &str) -> AuthorizedPeer {
        AuthorizedPeer {
            peer_id: stable_peer_id(network_id, "peer", name),
            network_id: network_id.to_owned(),
            node_name: Some(name.to_owned()),
            role: MeshCoordinateRole::Peer,
            environment: None,
        }
    }

    fn open(state: &MeshCoordinateState, peer: &AuthorizedPeer) -> Session {
        let (tx, events) = mpsc::channel(64);
        let (session_id, close) = register(state, peer, tx).expect("registered");
        Session {
            peer: peer.clone(),
            session_id,
            close,
            events,
        }
    }

    fn node(peer: &AuthorizedPeer, key: u8) -> Node {
        Node {
            id: peer.peer_id,
            as_of: "2026-11-13T12:00:00Z".parse().unwrap(),
            key: NodePublic::from_raw([key; 32]),
            disco_key: DiscoPublic::from_raw([key.wrapping_add(1); 32]),
            preferred_derp: 1,
            derp_latency: None,
            endpoints: Vec::new(),
            addresses: vec![prefix_from_uuid(&peer.peer_id)],
        }
    }

    fn send_node(state: &MeshCoordinateState, session: &Session, key: u8) -> Node {
        let node = node(&session.peer, key);
        update_node(
            state,
            session.peer.peer_id,
            session.session_id,
            node.clone(),
        );
        node
    }

    /// The next event matching `wanted`, skipping others.
    async fn next(
        session: &mut Session,
        wanted: impl Fn(&CoordinateEvent) -> bool,
    ) -> CoordinateEvent {
        tokio::time::timeout(WAIT, async {
            loop {
                let event = session.events.recv().await.expect("the session is open");
                if wanted(&event) {
                    return event;
                }
            }
        })
        .await
        .expect("the event arrived in time")
    }

    fn update_with(key: u8) -> impl Fn(&CoordinateEvent) -> bool {
        move |event| {
            matches!(event, CoordinateEvent::Update(nodes)
                if nodes.iter().any(|node| node.key == NodePublic::from_raw([key; 32])))
        }
    }

    fn written(state: &MeshCoordinateState, session: &Session) -> bool {
        state
            .registry()
            .peers
            .get(&session.peer.peer_id)
            .is_some_and(|peer| peer.session_id == session.session_id && peer.revision.is_some())
    }

    async fn closed(session: &Session) {
        tokio::time::timeout(WAIT, session.close.notified())
            .await
            .expect("the session ended in time");
    }

    #[tokio::test]
    #[ignore = "requires NATS_URL pointing at a JetStream-enabled NATS server"]
    async fn members_on_two_replicas_reach_each_other() {
        let r = replicas().await;
        let network = format!("net-{}", Uuid::new_v4());
        let mut one = open(&r.a, &member(&network, "one"));
        let mut two = open(&r.b, &member(&network, "two"));
        send_node(&r.a, &one, 0x11);
        send_node(&r.b, &two, 0x33);
        eventually(|| r.a.registry().remote.peers.contains_key(&two.peer.peer_id)).await;
        add_tunnel(
            &r.a,
            one.peer.peer_id,
            two.peer.peer_id,
            MeshCoordinateRole::Peer,
        )
        .unwrap();
        next(&mut one, update_with(0x33)).await;
        next(&mut two, update_with(0x11)).await;
        // A new node from either end reaches the other across replicas.
        send_node(&r.b, &two, 0x55);
        next(&mut one, update_with(0x55)).await;
        // And a session that ends is removed for its partner.
        deregister(&r.b, two.peer.peer_id, two.session_id);
        let removed = two.peer.peer_id;
        next(
            &mut one,
            move |event| matches!(event, CoordinateEvent::Remove(id) if *id == removed),
        )
        .await;
    }

    /// #5642 across replicas: B on one replica subscribes to A on the other.
    /// A's session ends (a Sandbox stopped), B is told, and A's next session
    /// with a new key reaches B without B subscribing again.
    #[tokio::test]
    #[ignore = "requires NATS_URL pointing at a JetStream-enabled NATS server"]
    async fn a_target_that_ends_and_returns_on_another_replica_reaches_its_subscriber() {
        let r = replicas().await;
        let network = format!("net-{}", Uuid::new_v4());
        let target = member(&network, "target");
        let mut subscriber = open(&r.a, &member(&network, "subscriber"));
        let first = open(&r.b, &target);
        send_node(&r.a, &subscriber, 0x11);
        send_node(&r.b, &first, 0x33);
        eventually(|| r.a.registry().remote.peers.contains_key(&target.peer_id)).await;
        add_tunnel(
            &r.a,
            subscriber.peer.peer_id,
            target.peer_id,
            MeshCoordinateRole::Peer,
        )
        .unwrap();
        next(&mut subscriber, update_with(0x33)).await;

        deregister(&r.b, target.peer_id, first.session_id);
        let gone = target.peer_id;
        next(
            &mut subscriber,
            move |event| matches!(event, CoordinateEvent::Remove(id) if *id == gone),
        )
        .await;

        let second = open(&r.b, &target);
        send_node(&r.b, &second, 0x77);
        next(&mut subscriber, update_with(0x77)).await;
    }

    #[tokio::test]
    #[ignore = "requires NATS_URL pointing at a JetStream-enabled NATS server"]
    async fn a_node_holds_one_session_across_replicas_and_partners_see_it_move() {
        let r = replicas().await;
        let network = format!("net-{}", Uuid::new_v4());
        let mut partner = open(&r.a, &member(&network, "partner"));
        let moving = member(&network, "moving");
        let old = open(&r.a, &moving);
        send_node(&r.a, &partner, 0x11);
        send_node(&r.a, &old, 0x33);
        add_tunnel(
            &r.a,
            partner.peer.peer_id,
            moving.peer_id,
            MeshCoordinateRole::Peer,
        )
        .unwrap();
        next(&mut partner, update_with(0x33)).await;
        eventually(|| written(&r.a, &old)).await;

        // The node reconnects through the other replica.
        let new = open(&r.b, &moving);
        send_node(&r.b, &new, 0x55);
        closed(&old).await;
        let event = next(&mut partner, |event| {
            matches!(event, CoordinateEvent::Remove(_)) || update_with(0x55)(event)
        })
        .await;
        assert!(
            matches!(event, CoordinateEvent::Update(_)),
            "moved, not removed"
        );
        assert!(!r.a.registry().peers.contains_key(&moving.peer_id));
    }

    #[tokio::test]
    #[ignore = "requires NATS_URL pointing at a JetStream-enabled NATS server"]
    async fn derp_admits_a_key_of_the_other_replica_only_while_its_session_lives() {
        let r = replicas().await;
        let network = format!("net-{}", Uuid::new_v4());
        let session = open(&r.a, &member(&network, "one"));
        let key = send_node(&r.a, &session, 0x77).key;
        eventually(|| r.b.knows_key(&key)).await;
        deregister(&r.a, session.peer.peer_id, session.session_id);
        eventually(|| !r.b.knows_key(&key)).await;
        assert!(!r.a.knows_key(&key));
    }

    #[tokio::test]
    #[ignore = "requires NATS_URL pointing at a JetStream-enabled NATS server"]
    async fn a_node_revoked_on_one_replica_ends_on_the_other_and_stays_ended() {
        let r = replicas().await;
        let network = format!("net-{}", Uuid::new_v4());
        let mut partner = open(&r.a, &member(&network, "partner"));
        let revoked = member(&network, "revoked");
        let session = open(&r.a, &revoked);
        send_node(&r.a, &partner, 0x11);
        let key = send_node(&r.a, &session, 0x33).key;
        add_tunnel(
            &r.a,
            partner.peer.peer_id,
            revoked.peer_id,
            MeshCoordinateRole::Peer,
        )
        .unwrap();
        eventually(|| written(&r.a, &session) && r.b.knows_key(&key)).await;

        r.b.revoke_node(&network, "revoked").await.unwrap();
        closed(&session).await;
        let id = revoked.peer_id;
        next(
            &mut partner,
            move |event| matches!(event, CoordinateEvent::Remove(gone) if *gone == id),
        )
        .await;
        eventually(|| !r.a.knows_key(&key) && !r.b.knows_key(&key)).await;
        // The ended session's replica wrote nothing back.
        flushed(&r.a).await;
        let entry =
            r.kv.entry(peer_key(&network, revoked.peer_id))
                .await
                .unwrap();
        assert!(entry.is_none_or(|entry| entry.operation != Operation::Put));
    }

    #[tokio::test]
    #[ignore = "requires NATS_URL pointing at a JetStream-enabled NATS server"]
    async fn a_network_deleted_on_one_replica_ends_and_refuses_sessions_on_the_other() {
        let r = replicas().await;
        let network = format!("net-{}", Uuid::new_v4());
        let session = open(&r.a, &member(&network, "one"));
        send_node(&r.a, &session, 0x11);
        eventually(|| written(&r.a, &session)).await;

        r.b.revoke_network(&network).await.unwrap();
        closed(&session).await;
        eventually(|| r.a.registry().remote.retired.contains(&net_key(&network))).await;
        let (tx, _events) = mpsc::channel(4);
        assert!(register(&r.a, &member(&network, "late"), tx).is_none());
    }

    #[tokio::test]
    #[ignore = "requires NATS_URL pointing at a JetStream-enabled NATS server"]
    async fn a_stopping_replica_leaves_its_records_for_the_next_session() {
        let r = replicas().await;
        let network = format!("net-{}", Uuid::new_v4());
        let mut partner = open(&r.b, &member(&network, "partner"));
        let moving = member(&network, "moving");
        let old = open(&r.a, &moving);
        send_node(&r.b, &partner, 0x11);
        let key = send_node(&r.a, &old, 0x33).key;
        add_tunnel(
            &r.b,
            partner.peer.peer_id,
            moving.peer_id,
            MeshCoordinateRole::Peer,
        )
        .unwrap();
        next(&mut partner, update_with(0x33)).await;

        r.a.drain().await;
        closed(&old).await;
        // The record stays, draining: the partner keeps the node, but the key
        // is admitted for nothing new.
        eventually(|| {
            r.b.registry()
                .remote
                .peers
                .get(&moving.peer_id)
                .is_some_and(|peer| peer.draining)
        })
        .await;
        assert!(!r.b.knows_key(&key));
        let new = open(&r.b, &moving);
        send_node(&r.b, &new, 0x55);
        let event = next(&mut partner, |event| {
            matches!(event, CoordinateEvent::Remove(_)) || update_with(0x55)(event)
        })
        .await;
        assert!(
            matches!(event, CoordinateEvent::Update(_)),
            "moved, not removed"
        );
    }

    fn fast(record_max_age: Duration, draining_grace: Duration) -> Timing {
        Timing {
            refresh: Duration::from_millis(200),
            record_max_age,
            draining_grace,
        }
    }

    fn removed(id: Uuid) -> impl Fn(&CoordinateEvent) -> bool {
        move |event| matches!(event, CoordinateEvent::Remove(gone) if *gone == id)
    }

    #[tokio::test]
    #[ignore = "requires NATS_URL pointing at a JetStream-enabled NATS server"]
    async fn a_draining_record_reaches_nobody_new_and_goes_after_its_grace() {
        let r = replicas_with(
            Timing::default(),
            fast(RECORD_MAX_AGE, Duration::from_secs(5)),
        )
        .await;
        let network = format!("net-{}", Uuid::new_v4());
        let mut partner = open(&r.b, &member(&network, "partner"));
        let stopping = member(&network, "stopping");
        let old = open(&r.a, &stopping);
        send_node(&r.b, &partner, 0x11);
        let key = send_node(&r.a, &old, 0x33).key;
        add_tunnel(
            &r.b,
            partner.peer.peer_id,
            stopping.peer_id,
            MeshCoordinateRole::Peer,
        )
        .unwrap();
        next(&mut partner, update_with(0x33)).await;

        r.a.drain().await;
        closed(&old).await;
        let draining = || {
            r.b.registry()
                .remote
                .peers
                .get(&stopping.peer_id)
                .is_some_and(|peer| peer.draining)
        };
        eventually(draining).await;
        assert!(!r.b.knows_key(&key));
        // A new subscriber is never sent the draining node.
        let mut late = open(&r.b, &member(&network, "late"));
        add_tunnel(
            &r.b,
            late.peer.peer_id,
            stopping.peer_id,
            MeshCoordinateRole::Peer,
        )
        .unwrap();
        // Whatever the late subscriber could be sent has arrived by now.
        caught_up(&r.b).await;
        while let Ok(event) = late.events.try_recv() {
            assert!(
                !update_with(0x33)(&event),
                "a draining node reached a new subscriber"
            );
        }
        // The node never comes back: its existing partner loses it.
        next(&mut partner, removed(stopping.peer_id)).await;
        assert!(!draining());
    }

    #[tokio::test]
    #[ignore = "requires NATS_URL pointing at a JetStream-enabled NATS server"]
    async fn a_revocation_ends_a_draining_record_at_once() {
        // The grace is 30 s; the event must arrive well within it.
        let r = replicas().await;
        let network = format!("net-{}", Uuid::new_v4());
        let mut partner = open(&r.b, &member(&network, "partner"));
        let stopping = member(&network, "stopping");
        let old = open(&r.a, &stopping);
        send_node(&r.b, &partner, 0x11);
        send_node(&r.a, &old, 0x33);
        add_tunnel(
            &r.b,
            partner.peer.peer_id,
            stopping.peer_id,
            MeshCoordinateRole::Peer,
        )
        .unwrap();
        next(&mut partner, update_with(0x33)).await;
        eventually(|| written(&r.a, &old)).await;
        r.a.drain().await;
        eventually(|| {
            r.b.registry()
                .remote
                .peers
                .get(&stopping.peer_id)
                .is_some_and(|peer| peer.draining)
        })
        .await;

        r.b.revoke_node(&network, "stopping").await.unwrap();
        next(&mut partner, removed(stopping.peer_id)).await;
    }

    #[tokio::test]
    #[ignore = "requires NATS_URL pointing at a JetStream-enabled NATS server"]
    async fn a_record_not_rewritten_in_time_admits_nothing() {
        // The other replica rewrites only every 15 s; this one trusts a
        // record for 8 s of its server-set time.
        let r = replicas_with(
            Timing::default(),
            fast(Duration::from_secs(8), DRAINING_GRACE),
        )
        .await;
        let network = format!("net-{}", Uuid::new_v4());
        let mut partner = open(&r.b, &member(&network, "partner"));
        let quiet = member(&network, "quiet");
        let session = open(&r.a, &quiet);
        send_node(&r.b, &partner, 0x11);
        let key = send_node(&r.a, &session, 0x33).key;
        add_tunnel(
            &r.b,
            partner.peer.peer_id,
            quiet.peer_id,
            MeshCoordinateRole::Peer,
        )
        .unwrap();
        next(&mut partner, update_with(0x33)).await;
        assert!(r.b.knows_key(&key));
        eventually(|| !r.b.knows_key(&key)).await;
        next(&mut partner, removed(quiet.peer_id)).await;
    }

    #[tokio::test]
    #[ignore = "requires NATS_URL pointing at a JetStream-enabled NATS server"]
    async fn a_session_its_replica_cannot_share_ends() {
        let r = replicas_with(
            fast(Duration::from_secs(5), DRAINING_GRACE),
            Timing::default(),
        )
        .await;
        let network = format!("net-{}", Uuid::new_v4());
        let session = open(&r.a, &member(&network, "one"));
        send_node(&r.a, &session, 0x11);
        eventually(|| written(&r.a, &session)).await;
        // The bucket goes away: no write lands, so no revocation could be seen.
        r.js.delete_key_value(r.kv.name.as_str()).await.unwrap();
        tokio::time::timeout(WAIT, session.close.notified())
            .await
            .expect("the unshared session ended");
    }

    /// Blocker 1 of the #4580 review: a refresh racing the drain never skips
    /// the draining mark.
    #[tokio::test]
    #[ignore = "requires NATS_URL pointing at a JetStream-enabled NATS server"]
    async fn a_drain_marks_records_even_when_a_refresh_races_it() {
        for _ in 0..5 {
            let racing = Timing {
                refresh: Duration::from_millis(1),
                ..Timing::default()
            };
            let r = replicas_with(racing, Timing::default()).await;
            let network = format!("net-{}", Uuid::new_v4());
            let stopping = member(&network, "stopping");
            let session = open(&r.a, &stopping);
            send_node(&r.a, &session, 0x33);
            eventually(|| written(&r.a, &session)).await;
            r.a.drain().await;
            eventually(|| {
                r.b.registry()
                    .remote
                    .peers
                    .get(&stopping.peer_id)
                    .is_some_and(|peer| peer.draining)
            })
            .await;
        }
    }

    /// Blocker 2: a writer stuck on NATS doesn't delay failing closed.
    #[tokio::test]
    #[ignore = "requires NATS_URL pointing at a JetStream-enabled NATS server"]
    async fn a_hung_writer_still_ends_unshared_sessions_on_time() {
        let r = replicas_with(
            fast(Duration::from_secs(5), DRAINING_GRACE),
            Timing::default(),
        )
        .await;
        let network = format!("net-{}", Uuid::new_v4());
        let session = open(&r.a, &member(&network, "one"));
        send_node(&r.a, &session, 0x11);
        eventually(|| written(&r.a, &session)).await;
        let (_release, hold) = tokio::sync::oneshot::channel();
        r.a.shared.get().unwrap().send(Dirty::Hold(hold));
        tokio::time::timeout(WAIT, session.close.notified())
            .await
            .expect("the session ended while its writer hung");
    }

    /// Blocker 3: a watch that stops delivering without failing stops
    /// admitting the other replica's keys.
    #[tokio::test]
    #[ignore = "requires NATS_URL pointing at a JetStream-enabled NATS server"]
    async fn a_stalled_watch_admits_no_remote_key() {
        let r = replicas_with(Timing::default(), fast(RECORD_MAX_AGE, DRAINING_GRACE)).await;
        let network = format!("net-{}", Uuid::new_v4());
        let session = open(&r.a, &member(&network, "one"));
        let key = send_node(&r.a, &session, 0x77).key;
        eventually(|| r.b.knows_key(&key)).await;
        r.b.shared
            .get()
            .unwrap()
            .watch_paused
            .store(true, Ordering::Release);
        eventually(|| !r.b.knows_key(&key)).await;
    }

    /// Blocker A of the #4580 re-review: NATS reached long after startup
    /// ends none of the sessions served meanwhile.
    #[tokio::test]
    #[ignore = "requires NATS_URL pointing at a JetStream-enabled NATS server"]
    async fn a_late_connect_ends_no_session_served_meanwhile() {
        let url = std::env::var("NATS_URL").expect("set NATS_URL to a JetStream-enabled NATS");
        let js = async_nats::jetstream::new(async_nats::connect(url).await.unwrap());
        let mut config = bucket_config(1);
        config.bucket = format!("mesh-sessions-test-{}", Uuid::new_v4().simple());
        let kv = js.create_key_value(config).await.unwrap();
        let state = MeshCoordinateState::new();
        let network = format!("net-{}", Uuid::new_v4());
        let session = open(&state, &member(&network, "early"));
        send_node(&state, &session, 0x11);
        // Longer than the record bound before NATS is reached.
        tokio::time::sleep(Duration::from_secs(6)).await;
        let tasks = Shared::attach(&state, kv, fast(Duration::from_secs(5), DRAINING_GRACE));
        eventually(|| written(&state, &session)).await;
        // The guard looks for unshared sessions before each heartbeat: two
        // more live heartbeats mean it has looked since the first write.
        let shared = state.shared.get().unwrap();
        let seen = shared.live_heartbeats.load(Ordering::Acquire);
        eventually(|| shared.live_heartbeats.load(Ordering::Acquire) >= seen + 2).await;
        let alive = written(&state, &session);
        for task in tasks {
            task.abort();
        }
        assert!(alive, "a session served before NATS was reached ended");
    }

    /// Blocker B: a session whose first write is delayed never overwrites the
    /// newer session its node opened through another replica.
    #[tokio::test]
    #[ignore = "requires NATS_URL pointing at a JetStream-enabled NATS server"]
    async fn a_delayed_first_write_never_overwrites_the_newer_session() {
        // With the older replica's watch paused only its writer's create
        // guards the newer session; with it live, its watch does too.
        for watch_paused in [true, false] {
            let r = replicas().await;
            let network = format!("net-{}", Uuid::new_v4());
            let moving = member(&network, "moving");
            let a = r.a.shared.get().unwrap();
            a.watch_paused.store(watch_paused, Ordering::Release);
            // The older replica's writer is stuck before the old session's
            // first write.
            let (release, hold) = tokio::sync::oneshot::channel();
            a.send(Dirty::Hold(hold));
            let old = open(&r.a, &moving);
            send_node(&r.a, &old, 0x33);
            tokio::time::sleep(Duration::from_millis(20)).await;
            // The node reconnects through the other replica, which writes
            // first.
            let new = open(&r.b, &moving);
            send_node(&r.b, &new, 0x55);
            eventually(|| written(&r.b, &new)).await;
            let _ = release.send(());
            closed(&old).await;
            // The newer session lives on, and the record is still its own.
            // The older replica's watch may be paused, so only its writer is
            // waited for; the newer one's watch sees any overwrite.
            flushed(&r.a).await;
            flushed(&r.b).await;
            caught_up(&r.b).await;
            assert!(
                written(&r.b, &new),
                "the newer session was ended (watch paused: {watch_paused})"
            );
            let entry =
                r.kv.entry(peer_key(&network, moving.peer_id))
                    .await
                    .unwrap()
                    .unwrap();
            let record: PeerRecord = serde_json::from_slice(&entry.value).unwrap();
            assert_eq!(
                record.session_id, new.session_id,
                "watch paused: {watch_paused}"
            );
        }
    }

    /// Skew 1 of the #4580 review: a crashed replica whose clock ran 60 s fast
    /// left its record; the node's reconnect through another replica wins
    /// at once, not after the record expires.
    #[tokio::test]
    #[ignore = "requires NATS_URL pointing at a JetStream-enabled NATS server"]
    async fn a_crashed_fast_replicas_record_never_beats_a_reconnect() {
        let r = replicas().await;
        let network = format!("net-{}", Uuid::new_v4());
        let moving = member(&network, "moving");
        let fast = Utc::now() + chrono::Duration::seconds(60);
        let forged = PeerRecord {
            session_id: Uuid::new_v4(),
            replica_id: Uuid::new_v4(),
            network_id: network.clone(),
            node: None,
            last_heard: fast,
            draining: false,
            age_ms: 0,
        };
        r.kv.put(
            peer_key(&network, moving.peer_id),
            serde_json::to_vec(&forged).unwrap().into(),
        )
        .await
        .unwrap();
        caught_up(&r.b).await;
        let new = open(&r.b, &moving);
        send_node(&r.b, &new, 0x55);
        eventually(|| written(&r.b, &new)).await;
        settled(&r).await;
        assert!(
            written(&r.b, &new),
            "the reconnect lost to the crashed record"
        );
        let entry =
            r.kv.entry(peer_key(&network, moving.peer_id))
                .await
                .unwrap()
                .unwrap();
        let record: PeerRecord = serde_json::from_slice(&entry.value).unwrap();
        assert_eq!(record.session_id, new.session_id);
    }

    /// Skew 2: an older session still open on one replica loses to the
    /// node's live reconnect through another, whatever the first's clock.
    #[tokio::test]
    #[ignore = "requires NATS_URL pointing at a JetStream-enabled NATS server"]
    async fn a_half_open_older_session_loses_to_the_live_reconnect() {
        let r = replicas().await;
        let network = format!("net-{}", Uuid::new_v4());
        let moving = member(&network, "moving");
        let old = open(&r.a, &moving);
        send_node(&r.a, &old, 0x33);
        eventually(|| written(&r.a, &old)).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        let new = open(&r.b, &moving);
        send_node(&r.b, &new, 0x55);
        closed(&old).await;
        settled(&r).await;
        assert!(written(&r.b, &new), "the live reconnect was ended");
        let entry =
            r.kv.entry(peer_key(&network, moving.peer_id))
                .await
                .unwrap()
                .unwrap();
        let record: PeerRecord = serde_json::from_slice(&entry.value).unwrap();
        assert_eq!(record.session_id, new.session_id);
    }

    /// Skew 3: on one replica the later session wins by the monotonic clock,
    /// so a wall-clock step back can't make a reconnect lose to its own
    /// older record.
    #[tokio::test]
    #[ignore = "requires NATS_URL pointing at a JetStream-enabled NATS server"]
    async fn a_reconnect_on_the_same_replica_replaces_its_older_record() {
        let r = replicas().await;
        let network = format!("net-{}", Uuid::new_v4());
        let node = member(&network, "node");
        let old = open(&r.a, &node);
        send_node(&r.a, &old, 0x33);
        eventually(|| written(&r.a, &old)).await;
        let new = open(&r.a, &node);
        send_node(&r.a, &new, 0x55);
        closed(&old).await;
        eventually(|| written(&r.a, &new)).await;
        let entry =
            r.kv.entry(peer_key(&network, node.peer_id))
                .await
                .unwrap()
                .unwrap();
        let record: PeerRecord = serde_json::from_slice(&entry.value).unwrap();
        assert_eq!(record.session_id, new.session_id);
    }

    async fn record_of(r: &Replicas, network: &str, peer_id: Uuid) -> PeerRecord {
        let entry =
            r.kv.entry(peer_key(network, peer_id))
                .await
                .unwrap()
                .unwrap();
        serde_json::from_slice(&entry.value).unwrap()
    }

    /// #5515's review: the sharing gauge reads the current view, not the first
    /// attach. A replica whose watch stalls after it attached (every change
    /// dropped, its own heartbeats included, as when its connection drops)
    /// reads unshared within a few refreshes, and shared again once the watch
    /// delivers its heartbeat.
    #[tokio::test]
    #[ignore = "requires NATS_URL pointing at a JetStream-enabled NATS server"]
    async fn a_replica_whose_watch_stalls_after_attaching_stops_reading_shared() {
        let r = replicas_with(fast(RECORD_MAX_AGE, DRAINING_GRACE), Timing::default()).await;
        assert!(sharing_now(&r.a), "attached and current");
        let a = r.a.shared.get().unwrap();
        a.watch_paused.store(true, Ordering::Release);
        eventually(|| !sharing_now(&r.a)).await;
        a.watch_paused.store(false, Ordering::Release);
        eventually(|| sharing_now(&r.a)).await;
    }

    /// The #4580 re-review's blocker: a restarted watch replays this
    /// replica's last heartbeat, stamped up to a refresh ago. The server-time
    /// estimate must not go back with it, or a reconnect soon after an older
    /// session would be placed before it and lose.
    #[tokio::test]
    #[ignore = "requires NATS_URL pointing at a JetStream-enabled NATS server"]
    async fn a_watch_restart_never_places_a_reconnect_too_early() {
        let r = replicas().await;
        let network = format!("net-{}", Uuid::new_v4());
        let moving = member(&network, "moving");
        // B's heartbeat is now several seconds old.
        tokio::time::sleep(Duration::from_secs(6)).await;
        let b = r.b.shared.get().unwrap();
        // Only the replay filter guards the estimate here: no heartbeat
        // follows the snapshot to correct it.
        b.no_beat_after_snapshot.store(true, Ordering::Release);
        b.restart_watch.store(true, Ordering::Release);
        let old = open(&r.a, &moving);
        send_node(&r.a, &old, 0x33);
        eventually(|| written(&r.a, &old)).await;
        // The restart replays B's heartbeat; wait until its view is back.
        eventually(|| b.replayed_heartbeats.load(Ordering::Acquire) > 0).await;
        eventually(|| b.view_current()).await;
        let new = open(&r.b, &moving);
        send_node(&r.b, &new, 0x55);
        closed(&old).await;
        settled(&r).await;
        assert!(
            written(&r.b, &new),
            "the reconnect was placed before the older session"
        );
        assert_eq!(
            record_of(&r, &network, moving.peer_id).await.session_id,
            new.session_id
        );
    }

    /// A server-time estimate lagging by less than the gap between two
    /// registrations keeps their order.
    #[tokio::test]
    #[ignore = "requires NATS_URL pointing at a JetStream-enabled NATS server"]
    async fn a_lagging_server_clock_within_the_gap_keeps_the_order() {
        let r = replicas().await;
        let network = format!("net-{}", Uuid::new_v4());
        let moving = member(&network, "moving");
        *r.b.shared.get().unwrap().clock_offset.lock().unwrap() = chrono::Duration::seconds(-1);
        let old = open(&r.a, &moving);
        send_node(&r.a, &old, 0x33);
        eventually(|| written(&r.a, &old)).await;
        tokio::time::sleep(Duration::from_secs(2)).await;
        let new = open(&r.b, &moving);
        send_node(&r.b, &new, 0x55);
        closed(&old).await;
        settled(&r).await;
        assert!(written(&r.b, &new));
        assert_eq!(
            record_of(&r, &network, moving.peer_id).await.session_id,
            new.session_id
        );
    }

    /// A server clock stepped forward and then back (or a new leader behind)
    /// is followed at the next heartbeat, so an older unwritten session is
    /// not placed late and never overwrites the node's live reconnect.
    #[tokio::test]
    #[ignore = "requires NATS_URL pointing at a JetStream-enabled NATS server"]
    async fn a_server_clock_stepped_forward_then_back_keeps_the_order() {
        let r = replicas_with(Timing::default(), fast(RECORD_MAX_AGE, DRAINING_GRACE)).await;
        let network = format!("net-{}", Uuid::new_v4());
        let moving = member(&network, "moving");
        let b = r.b.shared.get().unwrap();
        // A reading 60 s ahead, as from a server clock stepped forward.
        let ahead = b.server_now().unwrap() + chrono::Duration::seconds(60);
        b.heard_self(ahead);
        // The clock steps back: B's next live heartbeats bring it back.
        eventually(|| {
            b.server_now()
                .is_some_and(|now| now < ahead - chrono::Duration::seconds(30))
        })
        .await;
        // An older session on B whose first write is held back.
        let (release, hold) = tokio::sync::oneshot::channel();
        b.send(Dirty::Hold(hold));
        let old = open(&r.b, &moving);
        send_node(&r.b, &old, 0x33);
        tokio::time::sleep(Duration::from_millis(50)).await;
        // The node reconnects through A, which writes first.
        let new = open(&r.a, &moving);
        send_node(&r.a, &new, 0x55);
        eventually(|| written(&r.a, &new)).await;
        let _ = release.send(());
        closed(&old).await;
        settled(&r).await;
        assert!(written(&r.a, &new), "the live reconnect was overwritten");
        assert_eq!(
            record_of(&r, &network, moving.peer_id).await.session_id,
            new.session_id
        );
    }

    /// With no server time read yet, neither the watcher nor the writer
    /// decides: the unwritten session is neither ended nor written, until a
    /// heartbeat gives a time and the later registration wins.
    #[tokio::test]
    #[ignore = "requires NATS_URL pointing at a JetStream-enabled NATS server"]
    async fn without_a_server_time_the_order_waits_for_one() {
        let r = replicas_with(Timing::default(), fast(RECORD_MAX_AGE, DRAINING_GRACE)).await;
        let network = format!("net-{}", Uuid::new_v4());
        let moving = member(&network, "moving");
        let b = r.b.shared.get().unwrap();
        b.ignore_heartbeats.store(true, Ordering::Release);
        *b.server_clock.lock().unwrap() = None;
        let old = open(&r.a, &moving);
        send_node(&r.a, &old, 0x33);
        eventually(|| written(&r.a, &old)).await;
        let new = open(&r.b, &moving);
        send_node(&r.b, &new, 0x55);
        // B's writer has tried the new session, and its watch has seen all
        // there is; its heartbeats come back but give no server time.
        flushed(&r.b).await;
        caught_up(&r.b).await;
        assert!(
            r.b.registry().peers.contains_key(&moving.peer_id),
            "ended without a server time"
        );
        assert!(!written(&r.b, &new), "written without a server time");
        b.ignore_heartbeats.store(false, Ordering::Release);
        eventually(|| written(&r.b, &new)).await;
        closed(&old).await;
        assert_eq!(
            record_of(&r, &network, moving.peer_id).await.session_id,
            new.session_id
        );
    }
}
