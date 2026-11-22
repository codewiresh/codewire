use super::*;
use codewire_tailnet::node::{DiscoPublic, NodePublic, prefix_from_uuid};
use tokio::task::JoinHandle;

struct ChannelSource {
    rx: mpsc::UnboundedReceiver<SessionInput>,
}

impl SessionSource for ChannelSource {
    async fn next(&mut self) -> Option<SessionInput> {
        self.rx.recv().await
    }
}

struct ChannelSink {
    tx: mpsc::UnboundedSender<SessionOutput>,
}

impl SessionSink for ChannelSink {
    async fn send(&mut self, output: SessionOutput) -> bool {
        self.tx.send(output).is_ok()
    }
}

/// The user every test client signs in as, unless a test names another.
const USER: &str = "user-1";

fn spawn_session(
    peers: Arc<PeerRegistry>,
    peer_id: Uuid,
    sidecar_id: Option<Uuid>,
    kind: PeerKind,
) -> (
    mpsc::UnboundedSender<SessionInput>,
    mpsc::UnboundedReceiver<SessionOutput>,
    JoinHandle<()>,
) {
    let principal = match kind {
        PeerKind::Client => Principal::User(USER.into()),
        PeerKind::Sidecar => Principal::Environment(peer_id),
    };
    spawn_session_as(peers, peer_id, sidecar_id, kind, principal)
}

fn spawn_session_as(
    peers: Arc<PeerRegistry>,
    peer_id: Uuid,
    sidecar_id: Option<Uuid>,
    kind: PeerKind,
    principal: Principal,
) -> (
    mpsc::UnboundedSender<SessionInput>,
    mpsc::UnboundedReceiver<SessionOutput>,
    JoinHandle<()>,
) {
    let context = SessionContext {
        peers,
        coordination: None,
        derp_map: crate::test_derp_map(),
        revocations: crate::test_revocations(),
    };
    spawn_on(context, peer_id, sidecar_id, kind, principal)
}

fn spawn_on(
    context: SessionContext,
    peer_id: Uuid,
    sidecar_id: Option<Uuid>,
    kind: PeerKind,
    principal: Principal,
) -> (
    mpsc::UnboundedSender<SessionInput>,
    mpsc::UnboundedReceiver<SessionOutput>,
    JoinHandle<()>,
) {
    let (input_tx, input_rx) = mpsc::unbounded_channel();
    let (output_tx, output_rx) = mpsc::unbounded_channel();
    let proof = matches!(kind, PeerKind::Sidecar).then(|| PeerProof {
        generation: 1,
        expires_at: unix_now() + 600,
    });
    let task = tokio::spawn(run_peer_session(
        ChannelSource { rx: input_rx },
        ChannelSink { tx: output_tx },
        context,
        SessionPeer {
            peer_id,
            principal,
            sidecar_id,
            kind,
            transport: Transport::Connect,
            proof,
        },
        Some(test_checks(Some(1), Duration::from_secs(3600))),
        None,
        None,
    ));
    (input_tx, output_rx, task)
}

use std::sync::atomic::{AtomicI64, Ordering};

const SECRET: &str = "session-secret";

/// Peer checks over a current generation the test can move (0 = gone).
struct MovableVerifier {
    generation: AtomicI64,
}

impl PeerVerifier for MovableVerifier {
    fn verify<'a>(
        &'a self,
        env_id: Uuid,
        token: &'a str,
    ) -> crate::peer::BoxFuture<'a, Result<PeerProof, ProofError>> {
        Box::pin(async move {
            let claims = codewire_server_core::peer_token::validate(SECRET, token, unix_now())
                .map_err(|_| ProofError::Refused)?;
            let current = match self.generation.load(Ordering::SeqCst) {
                0 => None,
                generation => Some(generation),
            };
            crate::peer::check_claims(&claims, env_id, current)
        })
    }

    fn is_current<'a>(
        &'a self,
        _env_id: Uuid,
        generation: i64,
    ) -> crate::peer::BoxFuture<'a, Result<bool, ProofError>> {
        Box::pin(async move { Ok(self.generation.load(Ordering::SeqCst) == generation) })
    }
}

fn test_checks(generation: Option<i64>, recheck: Duration) -> PeerChecks {
    movable_checks(
        Arc::new(MovableVerifier {
            generation: AtomicI64::new(generation.unwrap_or_default()),
        }),
        recheck,
    )
}

fn movable_checks(verifier: Arc<MovableVerifier>, recheck: Duration) -> PeerChecks {
    PeerChecks { verifier, recheck }
}

fn token(env_id: Uuid, generation: i64, expires_at: i64) -> String {
    codewire_server_core::peer_token::issue(SECRET, &env_id.to_string(), generation, expires_at)
        .unwrap()
}

fn spawn_peer(
    peers: Arc<PeerRegistry>,
    env_id: Uuid,
    proof: PeerProof,
    checks: PeerChecks,
) -> (
    mpsc::UnboundedSender<SessionInput>,
    mpsc::UnboundedReceiver<SessionOutput>,
    JoinHandle<()>,
) {
    let (input_tx, input_rx) = mpsc::unbounded_channel();
    let (output_tx, output_rx) = mpsc::unbounded_channel();
    let task = tokio::spawn(run_peer_session(
        ChannelSource { rx: input_rx },
        ChannelSink { tx: output_tx },
        SessionContext {
            peers,
            coordination: None,
            derp_map: crate::test_derp_map(),
            revocations: crate::test_revocations(),
        },
        SessionPeer {
            peer_id: env_id,
            principal: Principal::Environment(env_id),
            sidecar_id: None,
            kind: PeerKind::Sidecar,
            transport: Transport::Connect,
            proof: Some(proof),
        },
        Some(checks),
        None,
        None,
    ));
    (input_tx, output_rx, task)
}

async fn ends(task: JoinHandle<()>) {
    tokio::time::timeout(std::time::Duration::from_secs(5), task)
        .await
        .expect("session did not end")
        .expect("session task panicked");
}

/// A session first sends the DERP map the coordinator built at startup.
#[tokio::test]
async fn a_session_first_sends_the_coordinators_derp_map() {
    let (_input, mut output, task) = spawn_session(
        Arc::new(PeerRegistry::default()),
        Uuid::new_v4(),
        None,
        PeerKind::Sidecar,
    );
    let SessionOutput::DerpMap(map) = next_output(&mut output).await else {
        panic!("the first output was not the DERP map");
    };
    assert_eq!(map, crate::test_derp_map().to_json());
    assert_eq!(
        map["Regions"]["1"]["Nodes"][0]["HostName"],
        "derp.example.invalid"
    );
    task.abort();
}

#[tokio::test]
async fn a_lapsed_proof_ends_the_session() {
    let env_id = Uuid::new_v4();
    let peers = Arc::new(PeerRegistry::default());
    let lapsed = PeerProof {
        generation: 1,
        expires_at: unix_now() - crate::peer::PEER_RECHECK_INTERVAL.as_secs() as i64 * 10,
    };
    let (_input, mut output, task) = spawn_peer(
        peers.clone(),
        env_id,
        lapsed,
        test_checks(Some(1), Duration::from_millis(20)),
    );
    assert!(matches!(
        next_output(&mut output).await,
        SessionOutput::DerpMap(_)
    ));
    ends(task).await;
    // Its entry is gone, so the next peer registers freely.
    assert!(peers.register(env_id, Some((1, unix_now()))).is_some());
}

#[tokio::test]
async fn a_generation_change_revokes_the_session() {
    let env_id = Uuid::new_v4();
    let verifier = Arc::new(MovableVerifier {
        generation: AtomicI64::new(1),
    });
    let (_input, mut output, task) = spawn_peer(
        Arc::new(PeerRegistry::default()),
        env_id,
        PeerProof {
            generation: 1,
            expires_at: unix_now() + 600,
        },
        movable_checks(verifier.clone(), Duration::from_millis(20)),
    );
    assert!(matches!(
        next_output(&mut output).await,
        SessionOutput::DerpMap(_)
    ));
    verifier.generation.store(2, Ordering::SeqCst);
    ends(task).await;
}

#[tokio::test]
async fn only_a_newer_proof_replaces_a_session_and_the_old_one_never_tears_it_down() {
    let env_id = Uuid::new_v4();
    let client_id = Uuid::new_v4();
    let peers = Arc::new(PeerRegistry::default());
    let now = unix_now();
    let checks = || test_checks(Some(1), Duration::from_secs(3600));

    let (first_tx, mut first_out, first_task) = spawn_peer(
        peers.clone(),
        env_id,
        PeerProof {
            generation: 1,
            expires_at: now + 600,
        },
        checks(),
    );
    assert!(matches!(
        next_output(&mut first_out).await,
        SessionOutput::DerpMap(_)
    ));

    // An older or equal proof (a stolen token) is refused outright.
    for expires_at in [now + 300, now + 600] {
        let (_tx, mut out, task) = spawn_peer(
            peers.clone(),
            env_id,
            PeerProof {
                generation: 1,
                expires_at,
            },
            checks(),
        );
        ends(task).await;
        assert!(out.try_recv().is_err(), "a refused session sends nothing");
    }

    // An in-band proof raises the holder's rank, so a token that would
    // have outranked the connect-time proof no longer does.
    first_tx
        .send(SessionInput::Proof(token(env_id, 1, now + 590)))
        .unwrap();
    first_tx
        .send(SessionInput::Proof(token(env_id, 1, now + 650)))
        .unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    let (_tx, _out, refused) = spawn_peer(
        peers.clone(),
        env_id,
        PeerProof {
            generation: 1,
            expires_at: now + 620,
        },
        checks(),
    );
    ends(refused).await;

    // A newer proof replaces the holder, which then ends without removing
    // its replacement.
    let (second_tx, mut second_out, second_task) = spawn_peer(
        peers.clone(),
        env_id,
        PeerProof {
            generation: 1,
            expires_at: now + 700,
        },
        checks(),
    );
    assert!(matches!(
        next_output(&mut second_out).await,
        SessionOutput::DerpMap(_)
    ));
    ends(first_task).await;
    drop(first_tx);

    let (client_tx, mut client_out, client_task) =
        spawn_session(peers.clone(), client_id, Some(env_id), PeerKind::Client);
    assert!(matches!(
        next_output(&mut client_out).await,
        SessionOutput::DerpMap(_)
    ));
    second_tx
        .send(SessionInput::Node(sample_node(env_id, 4)))
        .unwrap();
    let nodes = expect_peer_update(next_output(&mut client_out).await);
    assert_eq!(nodes[0].id, env_id, "the replacement is still registered");

    drop(client_tx);
    drop(second_tx);
    ends(client_task).await;
    ends(second_task).await;
}

#[tokio::test]
async fn a_bad_proof_ends_the_session() {
    let env_id = Uuid::new_v4();
    for bad in [
        token(env_id, 2, unix_now() + 600),
        token(Uuid::new_v4(), 1, unix_now() + 600),
        "not-a-token".to_owned(),
    ] {
        let (input, mut output, task) = spawn_peer(
            Arc::new(PeerRegistry::default()),
            env_id,
            PeerProof {
                generation: 1,
                expires_at: unix_now() + 600,
            },
            test_checks(Some(1), Duration::from_secs(3600)),
        );
        assert!(matches!(
            next_output(&mut output).await,
            SessionOutput::DerpMap(_)
        ));
        input.send(SessionInput::Proof(bad)).unwrap();
        ends(task).await;
    }
}

#[tokio::test]
async fn an_environment_peer_without_proof_never_registers() {
    let env_id = Uuid::new_v4();
    let peers = Arc::new(PeerRegistry::default());
    let (_input_tx, input_rx) = mpsc::unbounded_channel();
    let (output_tx, mut output_rx) = mpsc::unbounded_channel();
    run_peer_session(
        ChannelSource { rx: input_rx },
        ChannelSink { tx: output_tx },
        SessionContext {
            peers: peers.clone(),
            coordination: None,
            derp_map: crate::test_derp_map(),
            revocations: crate::test_revocations(),
        },
        SessionPeer {
            peer_id: env_id,
            principal: Principal::Environment(env_id),
            sidecar_id: None,
            kind: PeerKind::Sidecar,
            transport: Transport::Connect,
            proof: None,
        },
        Some(test_checks(Some(1), Duration::from_secs(3600))),
        None,
        None,
    )
    .await;
    assert!(output_rx.try_recv().is_err());
    assert!(peers.register(env_id, Some((1, 0))).is_some());
}

async fn next_output(rx: &mut mpsc::UnboundedReceiver<SessionOutput>) -> SessionOutput {
    tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
        .await
        .expect("session output timed out")
        .expect("session output closed")
}

fn sample_node(id: Uuid, derp: i32) -> Node {
    Node {
        id,
        as_of: "2026-07-11T12:00:00Z".parse().unwrap(),
        key: node_key(id),
        disco_key: disco_key(id),
        preferred_derp: derp,
        derp_latency: None,
        endpoints: vec![],
        addresses: vec![prefix_from_uuid(&id)],
    }
}

/// Each peer's own node key, since keys are bound to who announced them.
fn node_key(id: Uuid) -> NodePublic {
    let mut raw = [0_u8; 32];
    raw[..16].copy_from_slice(id.as_bytes());
    raw[16..].copy_from_slice(id.as_bytes());
    NodePublic::from_raw(raw)
}

/// Each node's own disco key: a key is bound to its announcer (#5962).
fn disco_key(id: Uuid) -> DiscoPublic {
    let mut raw = [0x5a_u8; 32];
    raw[16..].copy_from_slice(id.as_bytes());
    DiscoPublic::from_raw(raw)
}

fn expect_peer_update(output: SessionOutput) -> Vec<Node> {
    match output {
        SessionOutput::Peer(PeerEvent::Update(nodes)) => nodes,
        other => panic!("expected peer update, got {other:?}"),
    }
}

#[tokio::test]
async fn core_sends_derp_first_accumulates_peers_and_removes_on_teardown() {
    let peers = Arc::new(PeerRegistry::default());
    let sidecar_id = Uuid::parse_str("12345678-1234-5678-1234-567812345678").unwrap();
    let client_one_id = Uuid::parse_str("00112233-4455-6677-8899-aabbccddeeff").unwrap();
    let client_two_id = Uuid::parse_str("ffeeddcc-bbaa-9988-7766-554433221100").unwrap();

    let (sidecar_tx, mut sidecar_out, sidecar_task) =
        spawn_session(peers.clone(), sidecar_id, None, PeerKind::Sidecar);
    let (client_one_tx, mut client_one_out, client_one_task) = spawn_session(
        peers.clone(),
        client_one_id,
        Some(sidecar_id),
        PeerKind::Client,
    );
    let (client_two_tx, mut client_two_out, client_two_task) =
        spawn_session(peers, client_two_id, Some(sidecar_id), PeerKind::Client);

    for output in [
        next_output(&mut sidecar_out).await,
        next_output(&mut client_one_out).await,
        next_output(&mut client_two_out).await,
    ] {
        assert!(matches!(output, SessionOutput::DerpMap(_)));
    }

    sidecar_tx
        .send(SessionInput::Node(sample_node(sidecar_id, 1)))
        .unwrap();
    for output in [
        next_output(&mut client_one_out).await,
        next_output(&mut client_two_out).await,
    ] {
        let nodes = expect_peer_update(output);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].id, sidecar_id);
    }

    client_one_tx
        .send(SessionInput::Node(sample_node(client_one_id, 2)))
        .unwrap();
    let nodes = expect_peer_update(next_output(&mut sidecar_out).await);
    assert_eq!(nodes.len(), 1);
    assert_eq!(nodes[0].id, client_one_id);

    client_two_tx
        .send(SessionInput::Node(sample_node(client_two_id, 3)))
        .unwrap();
    let nodes = expect_peer_update(next_output(&mut sidecar_out).await);
    assert_eq!(nodes.len(), 2);
    assert!(nodes.iter().any(|node| node.id == client_one_id));
    assert!(nodes.iter().any(|node| node.id == client_two_id));

    drop(client_one_tx);
    match next_output(&mut sidecar_out).await {
        SessionOutput::Peer(PeerEvent::Remove(peer_id)) => {
            assert_eq!(peer_id, client_one_id);
        }
        other => panic!("expected peer removal, got {other:?}"),
    }

    drop(client_two_tx);
    drop(sidecar_tx);
    for task in [client_one_task, client_two_task, sidecar_task] {
        tokio::time::timeout(std::time::Duration::from_secs(5), task)
            .await
            .expect("session teardown timed out")
            .expect("session task panicked");
    }
}

/// A client's access as the test sets it, counting re-checks.
struct ScriptedAccess {
    outcome: std::sync::Mutex<ClientRecheck>,
    rechecks: std::sync::atomic::AtomicUsize,
}

impl ClientAccess for Arc<ScriptedAccess> {
    fn recheck(&self) -> Pin<Box<dyn Future<Output = ClientRecheck> + Send + '_>> {
        self.rechecks.fetch_add(1, Ordering::SeqCst);
        let outcome = *self.outcome.lock().unwrap();
        Box::pin(async move { outcome })
    }
}

/// #3828: a client is re-checked while its session lives. Unreadable
/// records keep it; a refusal tells it why and ends its session, and the
/// environment peer is told to drop it.
#[tokio::test]
async fn a_refused_client_recheck_ends_the_session_and_removes_the_client() {
    let peers = Arc::new(PeerRegistry::default());
    let sidecar_id = Uuid::new_v4();
    let client_id = Uuid::new_v4();
    let access = Arc::new(ScriptedAccess {
        outcome: std::sync::Mutex::new(ClientRecheck::Unavailable),
        rechecks: std::sync::atomic::AtomicUsize::new(0),
    });

    let (sidecar_tx, mut sidecar_out, sidecar_task) =
        spawn_session(peers.clone(), sidecar_id, None, PeerKind::Sidecar);
    let (client_tx, client_rx) = mpsc::unbounded_channel();
    let (client_out_tx, mut client_out) = mpsc::unbounded_channel();
    let client_task = tokio::spawn(run_peer_session(
        ChannelSource { rx: client_rx },
        ChannelSink { tx: client_out_tx },
        SessionContext {
            peers,
            coordination: None,
            derp_map: crate::test_derp_map(),
            revocations: crate::test_revocations(),
        },
        SessionPeer {
            peer_id: client_id,
            principal: Principal::User(USER.into()),
            sidecar_id: Some(sidecar_id),
            kind: PeerKind::Client,
            transport: Transport::Connect,
            proof: None,
        },
        Some(test_checks(Some(1), Duration::from_millis(20))),
        Some(Box::new(access.clone())),
        None,
    ));
    assert!(matches!(
        next_output(&mut sidecar_out).await,
        SessionOutput::DerpMap(_)
    ));
    assert!(matches!(
        next_output(&mut client_out).await,
        SessionOutput::DerpMap(_)
    ));
    client_tx
        .send(SessionInput::Node(sample_node(client_id, 2)))
        .unwrap();
    let nodes = expect_peer_update(next_output(&mut sidecar_out).await);
    assert_eq!(nodes[0].id, client_id);

    // Records that can't be read keep the session across re-checks.
    tokio::time::timeout(Duration::from_secs(5), async {
        while access.rechecks.load(Ordering::SeqCst) < 3 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the client was not re-checked");
    assert!(!client_task.is_finished());

    *access.outcome.lock().unwrap() = ClientRecheck::Refused;
    assert!(matches!(
        next_output(&mut client_out).await,
        SessionOutput::AccessRevoked
    ));
    ends(client_task).await;
    match next_output(&mut sidecar_out).await {
        SessionOutput::Peer(PeerEvent::Remove(peer_id)) => assert_eq!(peer_id, client_id),
        other => panic!("expected the client's removal, got {other:?}"),
    }

    drop(client_tx);
    drop(sidecar_tx);
    ends(sidecar_task).await;
}

/// #2844: DERP's admission call, made by DERP's own verifier against the
/// coordinator's listener, knows the key of a node a live session sent and
/// forgets it when the session ends. A malformed key is refused.
#[tokio::test]
async fn derp_admission_knows_a_live_session_key_until_it_ends() {
    use codewire_derp::{HttpKeyVerifier, KeyVerifier as _, Verdict};
    use tower::ServiceExt as _;

    let peers = Arc::new(PeerRegistry::default());
    let state = crate::CoordinatorState {
        pool: sqlx::PgPool::connect_lazy("postgres://unused@127.0.0.1:1/unused").unwrap(),
        session_secret: Arc::from(SECRET),
        peers: peers.clone(),
        coordination: None,
        derp_map: crate::test_derp_map(),
        revocation: codewire_server_core::revocation::Fence::new(),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(codewire_server_core::serve_with_listener(
        crate::derp_verify_router(state.clone()),
        listener,
    ));
    let verifier = HttpKeyVerifier::parse(&format!("http://{addr}")).unwrap();
    let derp_key = |raw: [u8; 32]| codewire_tailnet::derp::NodePublic::from_raw(raw);

    let sidecar_id = Uuid::new_v4();
    let client_id = Uuid::new_v4();
    let key = derp_key(*sample_node(client_id, 1).key.as_bytes());
    assert_eq!(verifier.verify(&key).await, Verdict::Unknown);

    let (client_tx, mut client_out, client_task) =
        spawn_session(peers.clone(), client_id, Some(sidecar_id), PeerKind::Client);
    assert!(matches!(
        next_output(&mut client_out).await,
        SessionOutput::DerpMap(_)
    ));
    client_tx
        .send(SessionInput::Node(sample_node(client_id, 1)))
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while verifier.verify(&key).await != Verdict::Known {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the live session's key is registered");
    assert_eq!(
        verifier.verify(&derp_key([0x22; 32])).await,
        Verdict::Unknown
    );

    // A key that is not 32 bytes is an invalid argument.
    let response = crate::derp_verify_router(state)
        .oneshot(
            axum::http::Request::post(codewire_derp::CHECK_NODE_KEY_PATH)
                .header("content-type", "application/json")
                .header("connect-protocol-version", "1")
                .body(axum::body::Body::from(r#"{"nodeKey":"AAAA"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);

    drop(client_tx);
    ends(client_task).await;
    assert_eq!(verifier.verify(&key).await, Verdict::Unknown);
    server.abort();
}

/// #5962: orchestration's peer relay admission call, against the
/// coordinator's closed listener, sees a daemon's disco key as its own
/// environment's while the session lives, as bound elsewhere from another
/// environment, and as unbound once the session ends. Another environment's
/// daemon announcing the same disco key is refused. A key that is not 32
/// bytes is an invalid argument.
#[tokio::test]
async fn peer_relay_admission_sees_a_live_daemons_disco_key_as_its_own() {
    use base64::Engine as _;
    use tower::ServiceExt as _;

    let peers = Arc::new(PeerRegistry::default());
    let state = crate::CoordinatorState {
        pool: sqlx::PgPool::connect_lazy("postgres://unused@127.0.0.1:1/unused").unwrap(),
        session_secret: Arc::from(SECRET),
        peers: peers.clone(),
        coordination: None,
        derp_map: crate::test_derp_map(),
        revocation: codewire_server_core::revocation::Fence::new(),
    };
    let check = |disco: &[u8], environment: Uuid| {
        let router = crate::derp_verify_router(state.clone());
        let body = serde_json::json!({
            "discoKey": base64::engine::general_purpose::STANDARD.encode(disco),
            "environmentId": environment.to_string(),
        });
        async move {
            let response = router
                .oneshot(
                    axum::http::Request::post(
                        "/codewire.internal.v1.PeerRelayAdmissionService/CheckDiscoKey",
                    )
                    .header("content-type", "application/json")
                    .header("connect-protocol-version", "1")
                    .body(axum::body::Body::from(body.to_string()))
                    .unwrap(),
                )
                .await
                .unwrap();
            let status = response.status();
            let bytes = axum::body::to_bytes(response.into_body(), 1 << 16)
                .await
                .unwrap();
            let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_default();
            (
                status,
                json["binding"].as_str().unwrap_or_default().to_owned(),
            )
        }
    };

    let env = Uuid::new_v4();
    let other = Uuid::new_v4();
    let disco = *disco_key(env).as_bytes();
    let (env_tx, mut env_out, env_task) =
        spawn_session(peers.clone(), env, None, PeerKind::Sidecar);
    assert!(matches!(
        next_output(&mut env_out).await,
        SessionOutput::DerpMap(_)
    ));
    env_tx
        .send(SessionInput::Node(sample_node(env, 1)))
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while check(&disco, env).await.1 != "DISCO_KEY_BINDING_BOUND_HERE" {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the daemon's disco key is its environment's own");
    assert_eq!(
        check(&disco, other).await.1,
        "DISCO_KEY_BINDING_BOUND_ELSEWHERE"
    );
    assert_eq!(check(&[0x77; 32], env).await.1, "DISCO_KEY_BINDING_UNBOUND");

    let (intruder_tx, mut intruder_out, intruder_task) =
        spawn_session(peers.clone(), other, None, PeerKind::Sidecar);
    assert!(matches!(
        next_output(&mut intruder_out).await,
        SessionOutput::DerpMap(_)
    ));
    intruder_tx
        .send(SessionInput::Node(Node {
            disco_key: disco_key(env),
            ..sample_node(other, 1)
        }))
        .unwrap();
    loop {
        match next_output(&mut intruder_out).await {
            SessionOutput::NodeKeyRefused(Refusal::BoundElsewhere) => break,
            SessionOutput::Heartbeat | SessionOutput::Peer(_) => {}
            output => panic!("expected the disco key's refusal, got {output:?}"),
        }
    }
    drop(intruder_tx);
    ends(intruder_task).await;
    assert_eq!(check(&disco, env).await.1, "DISCO_KEY_BINDING_BOUND_HERE");

    let (status, _) = check(&[0x01; 4], env).await;
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);

    drop(env_tx);
    ends(env_task).await;
    assert_eq!(check(&disco, env).await.1, "DISCO_KEY_BINDING_UNBOUND");
}

/// A node sent by `id` under another peer's node key.
fn node_with_key(id: Uuid, key: NodePublic) -> Node {
    Node {
        key,
        ..sample_node(id, 1)
    }
}

/// The next peer event, past the heartbeats a paused clock lets pile up.
async fn next_peer_event(rx: &mut mpsc::UnboundedReceiver<SessionOutput>) -> SessionOutput {
    loop {
        match next_output(rx).await {
            SessionOutput::Heartbeat => {}
            output => return output,
        }
    }
}

fn update_ids(output: SessionOutput) -> Vec<Uuid> {
    expect_peer_update(output)
        .iter()
        .map(|node| node.id)
        .collect()
}

async fn expect_removal(rx: &mut mpsc::UnboundedReceiver<SessionOutput>, removed: Uuid) {
    match next_peer_event(rx).await {
        SessionOutput::Peer(PeerEvent::Remove(peer_id)) => assert_eq!(peer_id, removed),
        other => panic!("expected the removal of {removed}, got {other:?}"),
    }
}

/// Spec "Retired" (#5120): a reconnect announces the same node key under a
/// new session while the old stream lingers. The old session is retired and
/// its environment peer told to drop it, leaving one session and one peer.
#[tokio::test]
async fn a_reconnect_while_the_old_session_lingers_leaves_one_session_and_one_peer() {
    let peers = Arc::new(PeerRegistry::default());
    let env_id = Uuid::new_v4();
    let (old_id, new_id) = (Uuid::new_v4(), Uuid::new_v4());
    let key = node_key(old_id);

    let (sidecar_tx, mut sidecar_out, sidecar_task) =
        spawn_session(peers.clone(), env_id, None, PeerKind::Sidecar);
    let (old_tx, mut old_out, old_task) =
        spawn_session(peers.clone(), old_id, Some(env_id), PeerKind::Client);
    for output in [&mut sidecar_out, &mut old_out] {
        assert!(matches!(
            next_output(output).await,
            SessionOutput::DerpMap(_)
        ));
    }
    old_tx
        .send(SessionInput::Node(node_with_key(old_id, key)))
        .unwrap();
    assert_eq!(
        expect_peer_update(next_output(&mut sidecar_out).await)[0].id,
        old_id
    );

    let (new_tx, mut new_out, new_task) =
        spawn_session(peers.clone(), new_id, Some(env_id), PeerKind::Client);
    assert!(matches!(
        next_output(&mut new_out).await,
        SessionOutput::DerpMap(_)
    ));
    // A client joining replays the environment's known clients to its peer.
    assert_eq!(update_ids(next_output(&mut sidecar_out).await), [old_id]);
    new_tx
        .send(SessionInput::Node(node_with_key(new_id, key)))
        .unwrap();

    expect_removal(&mut sidecar_out, old_id).await;
    assert_eq!(
        update_ids(next_output(&mut sidecar_out).await),
        [new_id],
        "the environment peer holds only the new session"
    );
    // The old session ends although its stream is still open.
    ends(old_task).await;
    assert!(!new_task.is_finished());

    drop(old_tx);
    drop(new_tx);
    drop(sidecar_tx);
    ends(new_task).await;
    ends(sidecar_task).await;
}

/// Spec "Refused": a node key bound to another principal is refused. The
/// announcing session is told and ends, and its node reaches no peer.
#[tokio::test]
async fn a_node_key_bound_to_another_principal_is_refused_and_reaches_no_peer() {
    let peers = Arc::new(PeerRegistry::default());
    let env_id = Uuid::new_v4();
    let (owner_id, intruder_id) = (Uuid::new_v4(), Uuid::new_v4());
    let key = node_key(owner_id);

    let (sidecar_tx, mut sidecar_out, sidecar_task) =
        spawn_session(peers.clone(), env_id, None, PeerKind::Sidecar);
    let (owner_tx, mut owner_out, owner_task) =
        spawn_session(peers.clone(), owner_id, Some(env_id), PeerKind::Client);
    for output in [&mut sidecar_out, &mut owner_out] {
        assert!(matches!(
            next_output(output).await,
            SessionOutput::DerpMap(_)
        ));
    }
    owner_tx
        .send(SessionInput::Node(node_with_key(owner_id, key)))
        .unwrap();
    assert_eq!(
        expect_peer_update(next_output(&mut sidecar_out).await)[0].id,
        owner_id
    );

    let (intruder_tx, mut intruder_out, intruder_task) = spawn_session_as(
        peers.clone(),
        intruder_id,
        Some(env_id),
        PeerKind::Client,
        Principal::User("user-2".into()),
    );
    assert!(matches!(
        next_output(&mut intruder_out).await,
        SessionOutput::DerpMap(_)
    ));
    assert_eq!(update_ids(next_output(&mut sidecar_out).await), [owner_id]);
    intruder_tx
        .send(SessionInput::Node(node_with_key(intruder_id, key)))
        .unwrap();
    assert!(matches!(
        next_output(&mut intruder_out).await,
        SessionOutput::NodeKeyRefused(Refusal::BoundElsewhere)
    ));
    ends(intruder_task).await;

    // The intruder registered, so its end is a removal; its node never came.
    expect_removal(&mut sidecar_out, intruder_id).await;
    assert!(
        sidecar_out.try_recv().is_err(),
        "the refused node reached no peer"
    );
    assert!(!owner_task.is_finished());

    drop(owner_tx);
    drop(intruder_tx);
    drop(sidecar_tx);
    ends(owner_task).await;
    ends(sidecar_task).await;
}

/// Spec "Quiet sessions end": a session that never pinged keeps the earlier
/// behaviour; one that pinged ends 45 s after the last thing it sent, its
/// peer is told, and its owner's next session binds the same key again.
#[tokio::test(start_paused = true)]
async fn a_session_that_pinged_ends_after_45_seconds_of_silence() {
    let peers = Arc::new(PeerRegistry::default());
    let env_id = Uuid::new_v4();
    let (quiet_id, pinging_id, next_id) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let key = node_key(pinging_id);

    let (sidecar_tx, mut sidecar_out, sidecar_task) =
        spawn_session(peers.clone(), env_id, None, PeerKind::Sidecar);
    let (quiet_tx, mut quiet_out, quiet_task) =
        spawn_session(peers.clone(), quiet_id, Some(env_id), PeerKind::Client);
    let (pinging_tx, mut pinging_out, pinging_task) =
        spawn_session(peers.clone(), pinging_id, Some(env_id), PeerKind::Client);
    for output in [&mut sidecar_out, &mut quiet_out, &mut pinging_out] {
        assert!(matches!(
            next_output(output).await,
            SessionOutput::DerpMap(_)
        ));
    }
    pinging_tx
        .send(SessionInput::Node(node_with_key(pinging_id, key)))
        .unwrap();
    assert_eq!(
        expect_peer_update(next_output(&mut sidecar_out).await)[0].id,
        pinging_id
    );

    tokio::time::sleep(Duration::from_secs(30)).await;
    pinging_tx.send(SessionInput::Ping).unwrap();
    tokio::time::sleep(SESSION_SILENCE_LIMIT - Duration::from_secs(1)).await;
    assert!(!pinging_task.is_finished(), "a ping restarts the silence");
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(pinging_task.is_finished(), "45 s of silence ends it");
    expect_removal(&mut sidecar_out, pinging_id).await;

    tokio::time::sleep(Duration::from_secs(600)).await;
    assert!(
        !quiet_task.is_finished(),
        "a session that never pinged stays"
    );
    assert!(!sidecar_task.is_finished());

    let (next_tx, mut next_out, next_task) =
        spawn_session(peers.clone(), next_id, Some(env_id), PeerKind::Client);
    assert!(matches!(
        next_output(&mut next_out).await,
        SessionOutput::DerpMap(_)
    ));
    next_tx
        .send(SessionInput::Node(node_with_key(next_id, key)))
        .unwrap();
    assert_eq!(
        update_ids(next_peer_event(&mut sidecar_out).await),
        [next_id]
    );
    assert!(!next_task.is_finished());

    drop((quiet_tx, pinging_tx, next_tx, sidecar_tx));
    for task in [quiet_task, next_task, sidecar_task] {
        ends(task).await;
    }
}

/// Spec "Retired", across replicas: a reconnect that reaches another
/// replica retires the session the first replica still holds, over the
/// environment's remove subject, and the environment peer drops it.
#[tokio::test]
#[ignore = "requires NATS_URL pointing at a JetStream-enabled NATS server"]
async fn a_reconnect_to_another_replica_retires_the_session_on_the_first() {
    let nats_url =
        std::env::var("NATS_URL").expect("set NATS_URL to a JetStream-enabled NATS server");
    let mut replicas = Vec::new();
    for _ in 0..2 {
        let client = async_nats::connect(&nats_url).await.unwrap();
        replicas.push(SessionContext {
            peers: Arc::new(PeerRegistry::default()),
            coordination: Some(CoordinationPlane::setup(client, 1).await.unwrap()),
            derp_map: crate::test_derp_map(),
            revocations: crate::test_revocations(),
        });
    }
    let env_id = Uuid::new_v4();
    let (old_id, new_id) = (Uuid::new_v4(), Uuid::new_v4());
    let key = node_key(old_id);
    let user = || Principal::User(USER.into());

    let (sidecar_tx, mut sidecar_out, sidecar_task) = spawn_on(
        replicas[0].clone(),
        env_id,
        None,
        PeerKind::Sidecar,
        Principal::Environment(env_id),
    );
    let (old_tx, mut old_out, old_task) = spawn_on(
        replicas[0].clone(),
        old_id,
        Some(env_id),
        PeerKind::Client,
        user(),
    );
    for output in [&mut sidecar_out, &mut old_out] {
        assert!(matches!(
            next_output(output).await,
            SessionOutput::DerpMap(_)
        ));
    }
    old_tx
        .send(SessionInput::Node(node_with_key(old_id, key)))
        .unwrap();
    assert_eq!(
        update_ids(next_peer_event(&mut sidecar_out).await),
        [old_id]
    );

    let (new_tx, mut new_out, new_task) = spawn_on(
        replicas[1].clone(),
        new_id,
        Some(env_id),
        PeerKind::Client,
        user(),
    );
    assert!(matches!(
        next_output(&mut new_out).await,
        SessionOutput::DerpMap(_)
    ));
    new_tx
        .send(SessionInput::Node(node_with_key(new_id, key)))
        .unwrap();

    ends(old_task).await;
    let (mut removed_old, mut saw_new) = (false, false);
    tokio::time::timeout(Duration::from_secs(5), async {
        while !(removed_old && saw_new) {
            match next_peer_event(&mut sidecar_out).await {
                SessionOutput::Peer(PeerEvent::Remove(id)) => removed_old |= id == old_id,
                SessionOutput::Peer(PeerEvent::Update(nodes)) => {
                    saw_new |= nodes.iter().any(|node| node.id == new_id);
                }
                other => panic!("unexpected output {other:?}"),
            }
        }
    })
    .await
    .expect("the environment peer dropped the old session and gained the new");
    assert!(!new_task.is_finished());

    drop((old_tx, new_tx, sidecar_tx));
    ends(new_task).await;
    ends(sidecar_task).await;
    if let Some(coordination) = replicas[0].coordination.as_ref() {
        coordination
            .node_bindings
            .0
            .purge(crate::node_keys::key_hex(&key))
            .await
            .unwrap();
    }
}

/// #5561: a client node whose address is refused ends the client's session
/// and never reaches its environment.
#[tokio::test]
async fn a_client_node_with_a_refused_address_ends_its_session() {
    use codewire_tailnet::node::Prefix;

    let peers = Arc::new(PeerRegistry::default());
    let sidecar_id = Uuid::new_v4();
    let (sidecar_tx, mut sidecar_out, _sidecar_task) =
        spawn_session(peers.clone(), sidecar_id, None, PeerKind::Sidecar);
    assert!(matches!(
        next_output(&mut sidecar_out).await,
        SessionOutput::DerpMap(_)
    ));
    sidecar_tx
        .send(SessionInput::Node(sample_node(sidecar_id, 1)))
        .unwrap();

    let refused = |id: Uuid, addresses: Vec<Prefix>| Node {
        addresses,
        ..sample_node(id, 2)
    };
    let cases = |id: Uuid| {
        let own = prefix_from_uuid(&id);
        [
            vec![own, prefix_from_uuid(&Uuid::new_v4())],
            vec![Prefix::new(own.addr(), 64)],
            vec![Prefix::new("fd00::1".parse().unwrap(), 128)],
            vec![prefix_from_uuid(&sidecar_id)],
        ]
    };
    for index in 0..4 {
        let client_id = Uuid::new_v4();
        let (client_tx, mut client_out, client_task) =
            spawn_session(peers.clone(), client_id, Some(sidecar_id), PeerKind::Client);
        assert!(matches!(
            next_output(&mut client_out).await,
            SessionOutput::DerpMap(_)
        ));
        let _environment = next_output(&mut client_out).await;
        let addresses = cases(client_id)[index].clone();
        client_tx
            .send(SessionInput::Node(refused(client_id, addresses.clone())))
            .unwrap();
        assert!(
            matches!(
                next_output(&mut client_out).await,
                SessionOutput::AddressRefused(_)
            ),
            "{addresses:?}"
        );
        tokio::time::timeout(Duration::from_secs(5), client_task)
            .await
            .expect("the refused session ends")
            .unwrap();
    }

    // A second address later in the session ends it the same way.
    let client_id = Uuid::new_v4();
    let (client_tx, mut client_out, client_task) =
        spawn_session(peers.clone(), client_id, Some(sidecar_id), PeerKind::Client);
    let _derp = next_output(&mut client_out).await;
    let _environment = next_output(&mut client_out).await;
    client_tx
        .send(SessionInput::Node(sample_node(client_id, 2)))
        .unwrap();
    // A refused session's teardown removes it, though its node never came.
    let nodes = loop {
        match next_output(&mut sidecar_out).await {
            SessionOutput::Peer(PeerEvent::Remove(_)) => {}
            output => break expect_peer_update(output),
        }
    };
    assert_eq!(
        nodes.iter().map(|node| node.id).collect::<Vec<_>>(),
        [client_id],
        "no refused node reached the environment"
    );
    client_tx
        .send(SessionInput::Node(refused(
            client_id,
            vec![prefix_from_uuid(&Uuid::new_v4())],
        )))
        .unwrap();
    assert!(matches!(
        next_output(&mut client_out).await,
        SessionOutput::AddressRefused(AddressRefusal::Changed)
    ));
    tokio::time::timeout(Duration::from_secs(5), client_task)
        .await
        .expect("the refused session ends")
        .unwrap();
    match next_output(&mut sidecar_out).await {
        SessionOutput::Peer(PeerEvent::Remove(id)) => assert_eq!(id, client_id),
        other => panic!("expected the client's removal, got {other:?}"),
    }
}

/// #5561: a second client announcing an address another client holds is not
/// forwarded to the environment while the holder is there; once the holder
/// leaves, it is.
#[tokio::test]
async fn a_second_client_announcing_a_held_address_is_not_forwarded() {
    let peers = Arc::new(PeerRegistry::default());
    let sidecar_id = Uuid::new_v4();
    let holder_id = Uuid::new_v4();
    let squatter_id = Uuid::new_v4();
    let (sidecar_tx, mut sidecar_out, _sidecar_task) =
        spawn_session(peers.clone(), sidecar_id, None, PeerKind::Sidecar);
    let _derp = next_output(&mut sidecar_out).await;
    sidecar_tx
        .send(SessionInput::Node(sample_node(sidecar_id, 1)))
        .unwrap();
    let (holder_tx, mut holder_out, _holder_task) =
        spawn_session(peers.clone(), holder_id, Some(sidecar_id), PeerKind::Client);
    let (squatter_tx, mut squatter_out, _squatter_task) = spawn_session(
        peers.clone(),
        squatter_id,
        Some(sidecar_id),
        PeerKind::Client,
    );
    for out in [&mut holder_out, &mut squatter_out] {
        let _derp = next_output(out).await;
        let _environment = next_output(out).await;
    }

    let holder = sample_node(holder_id, 2);
    holder_tx.send(SessionInput::Node(holder.clone())).unwrap();
    let nodes = expect_peer_update(next_output(&mut sidecar_out).await);
    assert_eq!(
        nodes.iter().map(|node| node.id).collect::<Vec<_>>(),
        [holder_id]
    );

    let squatter = Node {
        addresses: holder.addresses.clone(),
        ..sample_node(squatter_id, 3)
    };
    squatter_tx
        .send(SessionInput::Node(squatter.clone()))
        .unwrap();
    // The registry sends both local clients; only the holder goes on.
    let nodes = expect_peer_update(next_output(&mut sidecar_out).await);
    assert_eq!(
        nodes.iter().map(|node| node.id).collect::<Vec<_>>(),
        [holder_id]
    );

    drop(holder_tx);
    match next_output(&mut sidecar_out).await {
        SessionOutput::Peer(PeerEvent::Remove(id)) => assert_eq!(id, holder_id),
        other => panic!("expected the holder's removal, got {other:?}"),
    }
    squatter_tx.send(SessionInput::Node(squatter)).unwrap();
    let nodes = expect_peer_update(next_output(&mut sidecar_out).await);
    assert_eq!(
        nodes.iter().map(|node| node.id).collect::<Vec<_>>(),
        [squatter_id]
    );
}

/// #5561: a holder on another replica keeps its address against a local
/// client announcing it, and its removal over NATS releases the address.
#[tokio::test]
#[ignore = "requires NATS_URL pointing at a JetStream-enabled NATS server"]
async fn a_remote_holders_removal_over_nats_releases_its_address() {
    let nats_url =
        std::env::var("NATS_URL").expect("set NATS_URL to a JetStream-enabled NATS server");
    let mut replicas = Vec::new();
    for _ in 0..2 {
        let client = async_nats::connect(&nats_url).await.unwrap();
        replicas.push(SessionContext {
            peers: Arc::new(PeerRegistry::default()),
            coordination: Some(CoordinationPlane::setup(client, 1).await.unwrap()),
            derp_map: crate::test_derp_map(),
            revocations: crate::test_revocations(),
        });
    }
    let env_id = Uuid::new_v4();
    let (holder_id, squatter_id) = (Uuid::new_v4(), Uuid::new_v4());
    let user = || Principal::User(USER.into());

    let (sidecar_tx, mut sidecar_out, _sidecar_task) = spawn_on(
        replicas[0].clone(),
        env_id,
        None,
        PeerKind::Sidecar,
        Principal::Environment(env_id),
    );
    let _derp = next_peer_event(&mut sidecar_out).await;
    sidecar_tx
        .send(SessionInput::Node(sample_node(env_id, 1)))
        .unwrap();
    let (holder_tx, mut holder_out, _holder_task) = spawn_on(
        replicas[1].clone(),
        holder_id,
        Some(env_id),
        PeerKind::Client,
        user(),
    );
    let _derp = next_peer_event(&mut holder_out).await;
    let holder = sample_node(holder_id, 2);
    holder_tx.send(SessionInput::Node(holder.clone())).unwrap();
    assert_eq!(
        update_ids(next_peer_event(&mut sidecar_out).await),
        [holder_id]
    );

    let (squatter_tx, mut squatter_out, _squatter_task) = spawn_on(
        replicas[0].clone(),
        squatter_id,
        Some(env_id),
        PeerKind::Client,
        user(),
    );
    let _derp = next_peer_event(&mut squatter_out).await;
    let squatter = Node {
        addresses: holder.addresses.clone(),
        ..sample_node(squatter_id, 3)
    };
    squatter_tx
        .send(SessionInput::Node(squatter.clone()))
        .unwrap();
    // A refused node is left out; a heartbeat comes before anything else.
    tokio::time::sleep(Duration::from_millis(500)).await;
    while let Ok(output) = sidecar_out.try_recv() {
        if let SessionOutput::Peer(PeerEvent::Update(nodes)) = output {
            assert!(
                nodes.iter().all(|node| node.id != squatter_id),
                "the squatter's node reached the environment"
            );
        }
    }

    drop(holder_tx);
    expect_removal(&mut sidecar_out, holder_id).await;
    squatter_tx.send(SessionInput::Node(squatter)).unwrap();
    assert_eq!(
        update_ids(next_peer_event(&mut sidecar_out).await),
        [squatter_id]
    );
}
