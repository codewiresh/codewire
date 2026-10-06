use std::net::SocketAddr;
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::time::UNIX_EPOCH;

use codewire_daemon::access::AccessFields;
use codewire_proto::codewire::internal::v1::{
    CoordinateDerpMap, CoordinateRequest, CoordinateResponse, CoordinatorService,
    coordinate_request,
};
use connectrpc::{ConnectError, InboundStream, RequestContext, ServiceResult, ServiceStream};
use futures::StreamExt as _;
use tokio::sync::Notify;
use tokio::time::Instant;

use super::*;

const ENVIRONMENT: Uuid = Uuid::from_u128(0x2460_0000_0000_4000_8000_0000_0000_0001);

/// A grant for `token` that expires `lifetime_seconds` from now, at
/// `generation`.
fn grant(token: &str, lifetime_seconds: i64, generation: i64) -> WorkspaceAccessGrant {
    let now = SystemTime::now();
    let now_seconds = i64::try_from(now.duration_since(UNIX_EPOCH).unwrap().as_secs()).unwrap();
    WorkspaceAccessGrant::validate(
        &AccessFields {
            peer_token: token,
            peer_token_expires_at: now_seconds + lifetime_seconds,
            operation_generation: generation,
            coordinator_url: "https://coordinator.codewire.test",
            direct_udp_endpoints: &[],
            peer_relay_endpoints: &[],
        },
        now,
    )
    .unwrap()
}

/// Orchestration's binding exchange: each renewal issues the next numbered
/// peer token with `lifetime_seconds`, at the current generation.
struct FakePlane {
    lifetime_seconds: i64,
    generation: AtomicU32,
    refreshes: AtomicUsize,
    refreshed_at: StdMutex<Vec<Instant>>,
    recorded: StdMutex<Vec<String>>,
    allocations: StdMutex<Vec<([String; 2], u32, Instant)>>,
    allocation: StdMutex<Option<PeerRelayAllocation>>,
}

impl FakePlane {
    fn new(lifetime_seconds: i64) -> Arc<Self> {
        Arc::new(Self {
            lifetime_seconds,
            generation: AtomicU32::new(4),
            refreshes: AtomicUsize::new(0),
            refreshed_at: StdMutex::new(Vec::new()),
            recorded: StdMutex::new(Vec::new()),
            allocations: StdMutex::new(Vec::new()),
            allocation: StdMutex::new(None),
        })
    }
}

#[async_trait]
impl AccessControlPlane for FakePlane {
    async fn record_host_key(&self, public_key_openssh: &str) -> Result<(), ControlPlaneError> {
        self.recorded
            .lock()
            .unwrap()
            .push(public_key_openssh.to_owned());
        Ok(())
    }

    async fn refresh_access(&self) -> Result<WorkspaceAccessGrant, ControlPlaneError> {
        let number = self.refreshes.fetch_add(1, Ordering::SeqCst) + 1;
        self.refreshed_at.lock().unwrap().push(Instant::now());
        Ok(grant(
            &format!("peer-token-{number}"),
            self.lifetime_seconds,
            i64::from(self.generation.load(Ordering::SeqCst)),
        ))
    }

    async fn allocate_peer_relay(
        &self,
        disco_keys: [String; 2],
        relay_generation: u32,
    ) -> Result<PeerRelayAllocation, ControlPlaneError> {
        self.allocations
            .lock()
            .unwrap()
            .push((disco_keys, relay_generation, Instant::now()));
        self.allocation
            .lock()
            .unwrap()
            .clone()
            .ok_or(ControlPlaneError::Retryable)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Seen {
    Connected { bearer: String, environment: String },
    Proof(String),
}

/// A primary coordinator that records each session's bearer and in-band
/// proofs. It ends the first `end_sessions` sessions right after setup, the
/// way it ends a session whose proof lapsed or whose generation changed.
#[derive(Clone)]
struct FakeCoordinator {
    seen: Arc<StdMutex<Vec<Seen>>>,
    changed: Arc<Notify>,
    end_sessions: Arc<AtomicUsize>,
}

#[allow(refining_impl_trait)]
impl CoordinatorService for FakeCoordinator {
    async fn coordinate(
        &self,
        ctx: RequestContext,
        mut requests: InboundStream<CoordinateRequest>,
    ) -> ServiceResult<ServiceStream<CoordinateResponse>> {
        let hello = match requests
            .next()
            .await
            .ok_or_else(|| ConnectError::invalid_argument("hello is required"))??
            .to_owned_message()
            .msg
        {
            Some(coordinate_request::Msg::Hello(hello)) => hello,
            _ => return Err(ConnectError::invalid_argument("hello must come first")),
        };
        let bearer = ctx
            .headers()
            .get(http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .unwrap_or_default()
            .to_owned();
        self.record(Seen::Connected {
            bearer,
            environment: hello.environment_id,
        });
        let (responses, response_rx) = mpsc::channel(4);
        responses
            .send(Ok(CoordinateResponse {
                msg: CoordinateDerpMap {
                    derp_map_json: br#"{"Regions":{}}"#.to_vec(),
                    ..Default::default()
                }
                .into(),
                ..Default::default()
            }))
            .await
            .map_err(|_| ConnectError::internal("response stream closed"))?;
        let end = self
            .end_sessions
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |left| {
                left.checked_sub(1)
            })
            .is_ok();
        if !end {
            let coordinator = self.clone();
            tokio::spawn(async move {
                let _responses = responses;
                while let Some(Ok(request)) = requests.next().await {
                    if let Some(coordinate_request::Msg::Proof(proof)) =
                        request.to_owned_message().msg
                    {
                        coordinator.record(Seen::Proof(proof.peer_token));
                    }
                }
            });
        }
        connectrpc::Response::stream_ok(futures::stream::unfold(
            response_rx,
            |mut receiver| async move { receiver.recv().await.map(|item| (item, receiver)) },
        ))
    }
}

impl FakeCoordinator {
    fn record(&self, seen: Seen) {
        self.seen.lock().unwrap().push(seen);
        self.changed.notify_waiters();
    }

    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }

    async fn wait_for(&self, count: usize, within: Duration) -> Vec<Seen> {
        tokio::time::timeout(within, async {
            loop {
                let changed = self.changed.notified();
                let seen = self.seen();
                if seen.len() >= count {
                    return seen;
                }
                changed.await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("coordinator saw only {:?}", self.seen()))
    }
}

async fn serve_coordinator(end_sessions: usize) -> (FakeCoordinator, SocketAddr) {
    let coordinator = FakeCoordinator {
        seen: Arc::default(),
        changed: Arc::default(),
        end_sessions: Arc::new(AtomicUsize::new(end_sessions)),
    };
    let router = connectrpc::Router::new().add_service(Arc::new(coordinator.clone()));
    let server = connectrpc::Server::bind("127.0.0.1:0").await.unwrap();
    let address = server.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = server.serve(router).await;
    });
    (coordinator, address)
}

/// Dials the local fake over cleartext HTTP/2 with the public edge's gRPC
/// protocol, using the grant's peer token like the public coordinator.
struct LocalCoordinator(SocketAddr);

#[async_trait]
impl CoordinatorDialer for LocalCoordinator {
    async fn dial(
        &self,
        grant: &WorkspaceAccessGrant,
        environment_id: Uuid,
    ) -> Result<CoordinatorPeerSession, CoordinatorError> {
        CoordinatorPeerSession::connect_public_edge_grpc_with_setup_timeout(
            &format!("http://{}", self.0),
            grant.peer_token().expose_secret(),
            PrimaryCoordinateIdentity::sidecar(environment_id),
            Duration::from_secs(5),
        )
        .await
    }
}

#[derive(Default)]
struct RecordingDataPlane {
    peers: StdMutex<Vec<usize>>,
    publishing: StdMutex<Vec<mpsc::UnboundedSender<Node>>>,
}

impl PeerDataPlane for RecordingDataPlane {
    fn publish_nodes(&self) -> mpsc::UnboundedReceiver<Node> {
        let (nodes, node_rx) = mpsc::unbounded_channel();
        self.publishing.lock().unwrap().push(nodes);
        node_rx
    }

    fn stop_publishing(&self) {
        self.publishing.lock().unwrap().clear();
    }

    fn apply_peers(&self, nodes: &[Node]) {
        self.peers.lock().unwrap().push(nodes.len());
    }
}

fn connected(bearer: &str) -> Seen {
    Seen::Connected {
        bearer: bearer.to_owned(),
        environment: ENVIRONMENT.to_string(),
    }
}

#[tokio::test]
async fn access_is_renewed_at_half_life_and_each_token_reproves_the_session() {
    let (coordinator, address) = serve_coordinator(0).await;
    let plane = FakePlane::new(4);
    let grants = AccessGrants::new(plane.clone(), grant("peer-token-0", 4, 4));
    let started = Instant::now();
    let dialer: Arc<dyn CoordinatorDialer> = Arc::new(LocalCoordinator(address));
    let first = DialedSession::dial(&grants, dialer.as_ref(), ENVIRONMENT)
        .await
        .unwrap();
    assert!(
        first.setup_derp_map().is_some(),
        "the setup DERP map is kept"
    );
    let (stop, shutdown) = watch::channel(false);
    tokio::spawn(grants.clone().keep_fresh(shutdown.clone()));
    tokio::spawn(run_coordinator_sessions(
        Some(first),
        ENVIRONMENT,
        grants.clone(),
        dialer,
        Arc::new(RecordingDataPlane::default()),
        Duration::from_millis(50),
        shutdown,
    ));

    let seen = coordinator.wait_for(3, Duration::from_secs(8)).await;
    assert_eq!(
        seen[..3],
        [
            connected("peer-token-0"),
            Seen::Proof("peer-token-1".into()),
            Seen::Proof("peer-token-2".into()),
        ],
        "one session, re-proven in-band with each renewed token"
    );
    // A 4-second token (3 to 4 s left at whole-second expiry) is renewed at
    // half its remaining lifetime, never at once and never after expiry.
    let refreshed = plane.refreshed_at.lock().unwrap().clone();
    let first_renewal = refreshed[0].duration_since(started);
    assert!(
        first_renewal >= Duration::from_millis(1400)
            && first_renewal <= Duration::from_millis(2300),
        "first renewal after {first_renewal:?}"
    );
    let second_renewal = refreshed[1].duration_since(refreshed[0]);
    assert!(
        second_renewal >= Duration::from_millis(1400)
            && second_renewal <= Duration::from_millis(2300),
        "second renewal after {second_renewal:?}"
    );
    assert_eq!(
        grants.current().peer_token().expose_secret(),
        "peer-token-2"
    );
    let _ = stop.send(true);
}

#[tokio::test]
async fn an_ended_session_is_replaced_only_after_renewal() {
    let (coordinator, address) = serve_coordinator(1).await;
    let plane = FakePlane::new(600);
    let grants = AccessGrants::new(plane.clone(), grant("peer-token-0", 600, 4));
    let (stop, shutdown) = watch::channel(false);
    tokio::spawn(run_coordinator_sessions(
        None,
        ENVIRONMENT,
        grants.clone(),
        Arc::new(LocalCoordinator(address)),
        Arc::new(RecordingDataPlane::default()),
        Duration::from_millis(50),
        shutdown,
    ));
    // Each dial follows a renewal. The first session is ended by the
    // coordinator (a new generation, say); the daemon renews its grant and
    // reconnects with the newer token, never the ended session's.
    coordinator.wait_for(2, Duration::from_secs(8)).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        coordinator.seen(),
        [connected("peer-token-1"), connected("peer-token-2")],
        "a session opened with the current grant needs no proof yet"
    );
    assert_eq!(plane.refreshes.load(Ordering::SeqCst), 2);
    let _ = stop.send(true);
}

#[tokio::test]
async fn the_host_key_is_recorded_again_for_a_new_generation() {
    let plane = FakePlane::new(600);
    let grants = AccessGrants::new(plane.clone(), grant("peer-token-0", 600, 4));
    let (stop, shutdown) = watch::channel(false);
    let recorder = tokio::spawn(record_host_key_per_generation(
        plane.clone(),
        grants.subscribe(),
        "ssh-ed25519 AAAA".into(),
        4,
        shutdown,
    ));
    // A renewal at the same generation records nothing.
    grants.refresh().await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(plane.recorded.lock().unwrap().is_empty());
    // A new generation records the same key again.
    plane.generation.store(5, Ordering::SeqCst);
    grants.refresh().await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while plane.recorded.lock().unwrap().is_empty() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("recorded for the new generation");
    assert_eq!(*plane.recorded.lock().unwrap(), ["ssh-ed25519 AAAA"]);
    let _ = stop.send(true);
    recorder.await.unwrap();
}

fn disco(byte: u8) -> DiscoPublic {
    DiscoPublic::from_raw([byte; 32])
}

fn allocation(generation: u32, keys: [DiscoPublic; 2]) -> PeerRelayAllocation {
    PeerRelayAllocation {
        relay_generation: generation,
        server_disco_key: disco_text(&disco(0x11)),
        disco_keys: keys.iter().map(disco_text).collect(),
        lamport_id: 9,
        vni: 7,
        bind_lifetime_ns: 3_000_000_000,
        steady_state_lifetime_ns: 60_000_000_000,
        addr_ports: vec!["203.0.113.9:41641".into()],
    }
}

#[test]
fn a_relay_allocation_must_answer_its_own_request() {
    let requested = [disco(0x22), disco(0x33)];
    let endpoint = relay_endpoint(allocation(3, requested), requested, 3).unwrap();
    assert_eq!(endpoint.server_disco, disco(0x11));
    assert_eq!(endpoint.client_disco, requested);
    assert_eq!(endpoint.vni, 7);
    assert_eq!(endpoint.bind_lifetime, Duration::from_secs(3));
    assert_eq!(endpoint.steady_state_lifetime, Duration::from_secs(60));
    assert_eq!(
        endpoint.addr_ports,
        ["203.0.113.9:41641".parse::<SocketAddr>().unwrap()]
    );

    assert!(relay_endpoint(allocation(4, requested), requested, 3).is_err());
    assert!(relay_endpoint(allocation(3, [disco(0x33), disco(0x22)]), requested, 3).is_err());
    assert!(relay_endpoint(allocation(3, [disco(0x22), disco(0x44)]), requested, 3).is_err());
    let mut unaddressed = allocation(3, requested);
    unaddressed.addr_ports.clear();
    assert!(relay_endpoint(unaddressed, requested, 3).is_err());
    let mut named = allocation(3, requested);
    named.addr_ports = vec!["relay.codewire.test:41641".into()];
    assert!(relay_endpoint(named, requested, 3).is_err());
    let mut bad_server = allocation(3, requested);
    bad_server.server_disco_key = "nodekey:00".into();
    assert!(relay_endpoint(bad_server, requested, 3).is_err());
}

#[tokio::test(start_paused = true)]
async fn relay_allocations_go_through_orchestration_and_are_spaced() {
    let plane = FakePlane::new(600);
    let requested = [disco(0x22), disco(0x33)];
    *plane.allocation.lock().unwrap() = Some(allocation(0, requested));
    let relay = OrchestratedPeerRelay::new(plane.clone());
    let started = Instant::now();
    relay.allocate(requested, 0).await.unwrap();
    relay.allocate(requested, 0).await.unwrap();
    let calls = plane.allocations.lock().unwrap().clone();
    assert_eq!(calls.len(), 2);
    assert_eq!(
        calls[0].0,
        [
            format!("discokey:{}", "22".repeat(32)),
            format!("discokey:{}", "33".repeat(32)),
        ]
    );
    assert_eq!(calls[0].1, 0);
    assert_eq!(calls[0].2.duration_since(started), Duration::ZERO);
    assert!(calls[1].2.duration_since(calls[0].2) >= PEER_RELAY_CALL_SPACING);
}

#[test]
fn derp_falls_back_to_the_coordinator_origin_with_verified_tls() {
    assert_eq!(
        derp_target_from_origin("https://codewire.sh").unwrap(),
        DerpTarget {
            host: "codewire.sh".into(),
            port: 443,
            transport: DerpTransport::Tls { skip_verify: false },
        }
    );
    assert_eq!(
        derp_target_from_origin("https://codewire.test:8443")
            .unwrap()
            .port,
        8443
    );
    assert!(derp_target_from_origin("http://codewire.sh").is_err());
}
