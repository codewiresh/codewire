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

/// Bounds a wait that ends on its event: a coordinator session's setup, a
/// session or proof the fake coordinator records, a recorded host key. It only
/// turns a hang into a failure; 5 and 8 s bounds failed while a slow CI slot
/// stalled I/O (#3239).
const HANG_GUARD: Duration = Duration::from_secs(120);

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
            app_ports: &[],
            mesh: None,
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
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |left| {
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

fn fake_coordinator(end_sessions: usize) -> FakeCoordinator {
    FakeCoordinator {
        seen: Arc::default(),
        changed: Arc::default(),
        end_sessions: Arc::new(AtomicUsize::new(end_sessions)),
    }
}

async fn serve_coordinator(end_sessions: usize) -> (FakeCoordinator, SocketAddr) {
    let coordinator = fake_coordinator(end_sessions);
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
            HANG_GUARD,
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
    // Each token lives LIFETIME seconds. The renewal time is the subject, so
    // its bounds stay: never before half the remaining lifetime, and never
    // after expiry. The lifetime is long enough that a renewal delayed by a
    // stalled slot still lands well before expiry; 4 s left 1 s of slack, and
    // a slow CI slot stalled longer than that (#3239). `refresh_at`'s own
    // tests pin the exact half.
    const LIFETIME: i64 = 16;
    let lifetime = Duration::from_secs(LIFETIME as u64);
    // Whole-second expiry leaves between LIFETIME - 1 and LIFETIME seconds.
    let shortest = lifetime - Duration::from_secs(1);
    let (coordinator, address) = serve_coordinator(0).await;
    let plane = FakePlane::new(LIFETIME);
    let grants = AccessGrants::new(plane.clone(), grant("peer-token-0", LIFETIME, 4));
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

    let seen = coordinator.wait_for(3, HANG_GUARD).await;
    // Stopped first, so no later renewal changes what is checked below.
    let _ = stop.send(true);
    assert_eq!(
        seen[..3],
        [
            connected("peer-token-0"),
            Seen::Proof("peer-token-1".into()),
            Seen::Proof("peer-token-2".into()),
        ],
        "one session, re-proven in-band with each renewed token"
    );
    // Each token is renewed at half its remaining lifetime, never at once
    // and never after expiry. A sleep never ends early, so the lower bound is
    // exact (less 100 ms for the two clocks); a stall only delays a renewal.
    let refreshed = plane.refreshed_at.lock().unwrap().clone();
    let half = shortest / 2 - Duration::from_millis(100);
    let first_renewal = refreshed[0].duration_since(started);
    assert!(
        first_renewal >= half && first_renewal < shortest,
        "first renewal after {first_renewal:?}"
    );
    let second_renewal = refreshed[1].duration_since(refreshed[0]);
    assert!(
        second_renewal >= half && second_renewal < shortest,
        "second renewal after {second_renewal:?}"
    );
    // Each renewal became the current grant.
    assert_eq!(
        grants.current().peer_token().expose_secret(),
        format!("peer-token-{}", refreshed.len())
    );
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
    coordinator.wait_for(2, HANG_GUARD).await;
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
    tokio::time::timeout(HANG_GUARD, async {
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
    assert!(relay_endpoint(allocation(3, [disco(0x22), disco(0x44)]), requested, 3).is_err());
    assert!(relay_endpoint(allocation(3, [disco(0x22), disco(0x22)]), requested, 3).is_err());
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

/// The relay sorts each pair, so half of all daemon/client key pairs come
/// back in the other order; rejecting them left those clients with no relay.
#[test]
fn a_relay_allocation_may_answer_in_the_relays_canonical_order() {
    let requested = [disco(0x33), disco(0x22)];
    let canonical = [disco(0x22), disco(0x33)];
    let endpoint = relay_endpoint(allocation(3, canonical), requested, 3)
        .expect("the same pair in sorted order");
    assert_eq!(endpoint.client_disco, canonical);
}

#[tokio::test(start_paused = true)]
async fn relay_allocations_go_through_orchestration() {
    let plane = FakePlane::new(600);
    let requested = [disco(0x22), disco(0x33)];
    *plane.allocation.lock().unwrap() = Some(allocation(0, requested));
    let relay = OrchestratedPeerRelay::new(plane.clone());
    relay.allocate(requested, 0).await.unwrap();
    let calls = plane.allocations.lock().unwrap().clone();
    assert_eq!(calls.len(), 1);
    assert_eq!(
        calls[0].0,
        [
            format!("discokey:{}", "22".repeat(32)),
            format!("discokey:{}", "33".repeat(32)),
        ]
    );
    assert_eq!(calls[0].1, 0);
}

/// Orchestration's binding listener refuses a Pod's call once its bucket
/// (one call per second, a burst of five) is empty. Relay allocations admitted
/// back to back for a minute never leave it with fewer than two calls for
/// renewal, host-key and Mesh calls, and keep to half its rate.
#[tokio::test(start_paused = true)]
async fn relay_admissions_leave_room_in_orchestrations_budget() {
    const SERVER_PER_SECOND: f64 = 1.0;
    const SERVER_BURST: f64 = 5.0;
    let relay = OrchestratedPeerRelay::new(FakePlane::new(600));
    let started = Instant::now();
    let mut server_tokens = SERVER_BURST;
    let mut last = started;
    let mut fewest = SERVER_BURST;
    let mut admitted = 0_u32;
    while started.elapsed() < Duration::from_secs(60) {
        relay.admit().await;
        let now = Instant::now();
        server_tokens = (server_tokens
            + now.duration_since(last).as_secs_f64() * SERVER_PER_SECOND)
            .min(SERVER_BURST);
        last = now;
        server_tokens -= 1.0;
        fewest = fewest.min(server_tokens);
        admitted += 1;
    }
    assert!(
        fewest >= SERVER_BURST - f64::from(PEER_RELAY_CALL_BURST) - 1e-9,
        "relay calls left {fewest} of orchestration's burst"
    );
    // The burst, then one every two seconds.
    assert_eq!(admitted, PEER_RELAY_CALL_BURST + 30);
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

/// A grant naming `origin` as the coordinator.
fn grant_for(origin: &str) -> WorkspaceAccessGrant {
    let now = SystemTime::now();
    let now_seconds = i64::try_from(now.duration_since(UNIX_EPOCH).unwrap().as_secs()).unwrap();
    WorkspaceAccessGrant::validate(
        &AccessFields {
            peer_token: "peer-token-0",
            peer_token_expires_at: now_seconds + 600,
            operation_generation: 4,
            coordinator_url: origin,
            direct_udp_endpoints: &[],
            peer_relay_endpoints: &[],
            app_ports: &[],
            mesh: None,
        },
        now,
    )
    .unwrap()
}

#[tokio::test]
async fn the_coordinator_is_trusted_through_mounted_extra_roots_only() {
    // A coordinator edge with a cluster-owned authority, as on a local
    // cluster.
    let coordinator = fake_coordinator(0);
    let pki = codewire_tls::test_support::SyntheticPki::new("localhost");
    let app = connectrpc::Router::new()
        .add_service(Arc::new(coordinator.clone()))
        .into_axum_router();
    let address = pki.serve(app).await;
    let grant = grant_for(&format!("https://localhost:{}", address.port()));
    let mounts = tempfile::tempdir().unwrap();

    // Not mounted: the public roots alone refuse the cluster authority.
    let unmounted = PublicCoordinator::with_extra_roots_file(mounts.path().join("ca.crt"));
    assert!(unmounted.dial(&grant, ENVIRONMENT).await.is_err());
    assert!(coordinator.seen().is_empty());

    // Mounted: the extra bundle is trusted beside the public roots.
    let mounted = PublicCoordinator::with_extra_roots_file(&pki.roots);
    let session = mounted.dial(&grant, ENVIRONMENT).await.unwrap();
    assert!(session.setup_derp_map().is_some());
    assert_eq!(coordinator.seen(), [connected("peer-token-0")]);

    // Present but malformed: refused before any connection.
    let malformed = mounts.path().join("malformed.crt");
    std::fs::write(&malformed, b"-----BEGIN CERTIFICATE-----\nAAAA\n").unwrap();
    let broken = PublicCoordinator::with_extra_roots_file(&malformed);
    assert!(matches!(
        broken.dial(&grant, ENVIRONMENT).await,
        Err(CoordinatorError::Trust)
    ));
    assert_eq!(coordinator.seen().len(), 1);
}

mod app_ports {
    use std::net::{IpAddr, Ipv6Addr};

    use codewire_tailnet::conn::{Options as ConnOptions, Transport, WgDatagram};
    use codewire_tailnet::derp::NodePublic as DerpPublic;
    use codewire_tailnet::node::Prefix;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    use super::*;

    const DAEMON_IP: Ipv6Addr = Ipv6Addr::new(0xfd7a, 0x115c, 0xa1e0, 0, 0, 0, 0, 0x0d);
    const CLIENT_IP: Ipv6Addr = Ipv6Addr::new(0xfd7a, 0x115c, 0xa1e0, 0, 0, 0, 0, 0x0c);

    /// Two tailnet connections wired to each other in-process, standing in
    /// for DERP.
    fn tailnet_pair() -> (Arc<Conn>, Conn) {
        let daemon_secret = StaticSecret::random_from_rng(OsRng);
        let client_secret = StaticSecret::random_from_rng(OsRng);
        let daemon_key = PublicKey::from(&daemon_secret).to_bytes();
        let client_key = PublicKey::from(&client_secret).to_bytes();
        let (daemon_out, mut daemon_out_rx) = mpsc::unbounded_channel::<WgDatagram>();
        let (client_out, mut client_out_rx) = mpsc::unbounded_channel::<WgDatagram>();
        let (daemon_in, daemon_in_rx) = mpsc::unbounded_channel::<WgDatagram>();
        let (client_in, client_in_rx) = mpsc::unbounded_channel::<WgDatagram>();
        tokio::spawn(async move {
            while let Some(datagram) = daemon_out_rx.recv().await {
                let _ = client_in.send(WgDatagram {
                    peer: DerpPublic::from_raw(daemon_key),
                    data: datagram.data,
                });
            }
        });
        tokio::spawn(async move {
            while let Some(datagram) = client_out_rx.recv().await {
                let _ = daemon_in.send(WgDatagram {
                    peer: DerpPublic::from_raw(client_key),
                    data: datagram.data,
                });
            }
        });
        let transport = |to_transport, from_transport| Transport {
            to_transport,
            from_transport,
            peer_updates: None,
            path_probe: None,
            local_endpoint_updates: None,
        };
        let options = |secret: &StaticSecret, ip| ConnOptions {
            id: Uuid::new_v4(),
            addresses: vec![Prefix::new(IpAddr::V6(ip), 128)],
            endpoints: Vec::new(),
            private_key: Some(secret.clone()),
            disco_private: None,
        };
        let daemon = Conn::new(
            options(&daemon_secret, DAEMON_IP),
            transport(daemon_out, daemon_in_rx),
        )
        .unwrap();
        let client = Conn::new(
            options(&client_secret, CLIENT_IP),
            transport(client_out, client_in_rx),
        )
        .unwrap();
        let node = |key: [u8; 32], ip| Node {
            id: Uuid::new_v4(),
            as_of: chrono::DateTime::<chrono::Utc>::UNIX_EPOCH,
            key: NodePublic::from_raw(key),
            disco_key: DiscoPublic::default(),
            preferred_derp: 1,
            derp_latency: None,
            endpoints: Vec::new(),
            addresses: vec![Prefix::new(IpAddr::V6(ip), 128)],
        };
        daemon.update_peers(&[node(client_key, CLIENT_IP)]).unwrap();
        client.update_peers(&[node(daemon_key, DAEMON_IP)]).unwrap();
        (Arc::new(daemon), client)
    }

    /// An application on the workspace's loopback that answers each line
    /// with `name`.
    async fn local_app(name: &'static str) -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buffer = [0u8; 4];
                    if stream.read_exact(&mut buffer).await.is_ok() {
                        let _ = stream.write_all(name.as_bytes()).await;
                        let _ = stream.flush().await;
                        let mut rest = [0u8; 1];
                        let _ = stream.read(&mut rest).await;
                    }
                });
            }
        });
        port
    }

    /// What `port` on the daemon's tailnet address answers, if anything,
    /// within a short bound.
    async fn answer(client: &Conn, port: u16) -> Option<String> {
        tokio::time::timeout(Duration::from_secs(3), async {
            let mut stream = client
                .dial_context_tcp(SocketAddr::new(IpAddr::V6(DAEMON_IP), port))
                .await
                .ok()?;
            stream.write_all(b"ping").await.ok()?;
            stream.flush().await.ok()?;
            let mut reply = vec![0u8; 3];
            stream.read_exact(&mut reply).await.ok()?;
            String::from_utf8(reply).ok()
        })
        .await
        .ok()
        .flatten()
    }

    #[tokio::test]
    async fn application_ports_follow_the_allowed_set() {
        let (daemon, client) = tailnet_pair();
        let web = local_app("web").await;
        let api = local_app("api").await;
        let own = local_app("own").await;
        let (allowed, allowed_rx) = watch::channel(AppPorts::from([web, own]));
        let (stop, shutdown) = watch::channel(false);
        tokio::spawn(forward_app_ports(
            daemon,
            allowed_rx,
            BTreeSet::from([own]),
            shutdown,
        ));

        // An allowed port reaches the workspace's loopback application.
        assert_eq!(answer(&client, web).await.as_deref(), Some("web"));
        // A listening port outside the set, and a reserved one, are not served.
        assert_eq!(answer(&client, api).await, None);
        assert_eq!(answer(&client, own).await, None);

        // Exposing adds a listener.
        allowed.send_replace(AppPorts::from([web, api, own]));
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(answer(&client, api).await.as_deref(), Some("api"));

        // Unexposing removes it; the other port stays.
        allowed.send_replace(AppPorts::from([api]));
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(answer(&client, web).await, None);
        assert_eq!(answer(&client, api).await.as_deref(), Some("api"));
        let _ = stop.send(true);
    }
}

/// Orchestration answering relay allocations the way Dev does, in about
/// 35 ms, for whichever disco pair it is asked about.
struct AnsweringRelayPlane {
    relay_addr: SocketAddr,
    calls: StdMutex<Vec<(String, Instant)>>,
}

#[async_trait]
impl AccessControlPlane for AnsweringRelayPlane {
    async fn record_host_key(&self, _public_key_openssh: &str) -> Result<(), ControlPlaneError> {
        Ok(())
    }

    async fn refresh_access(&self) -> Result<WorkspaceAccessGrant, ControlPlaneError> {
        Err(ControlPlaneError::Retryable)
    }

    async fn allocate_peer_relay(
        &self,
        disco_keys: [String; 2],
        relay_generation: u32,
    ) -> Result<PeerRelayAllocation, ControlPlaneError> {
        let vni = {
            let mut calls = self.calls.lock().unwrap();
            calls.push((disco_keys[1].clone(), Instant::now()));
            u32::try_from(calls.len()).unwrap()
        };
        tokio::time::sleep(Duration::from_millis(35)).await;
        Ok(PeerRelayAllocation {
            relay_generation,
            server_disco_key: disco_text(&disco(0x11)),
            disco_keys: disco_keys.to_vec(),
            lamport_id: 1,
            vni,
            bind_lifetime_ns: 60_000_000_000,
            steady_state_lifetime_ns: 600_000_000_000,
            addr_ports: vec![self.relay_addr.to_string()],
        })
    }
}

/// A tailnet client as the coordinator announces it to the daemon.
fn client_node(id: u128) -> Node {
    let secret = StaticSecret::random_from_rng(OsRng);
    Node {
        id: Uuid::from_u128(id),
        as_of: chrono::Utc::now(),
        key: NodePublic::from_raw(PublicKey::from(&secret).to_bytes()),
        disco_key: DiscoPrivate::generate(&mut OsRng).public(),
        preferred_derp: 1,
        derp_latency: None,
        endpoints: Vec::new(),
        addresses: Vec::new(),
    }
}

/// promote-dev 23687: four tailnet clients came and went in the same
/// Sandbox (two concurrent doctor probes, tailnet SSH, DERP SSH), then the
/// relay leg's two concurrent doctor probes. Each earlier client queued a
/// relay allocation behind the previous one, the attempt deadline counted
/// that queue, and the relay client's own allocation timed out about 0.3 s
/// before its turn, after the smoke's 5 s wait for a relay path. Its relay
/// must be offered within that wait however many clients came before it.
#[tokio::test(start_paused = true)]
async fn a_relay_client_after_four_other_clients_gets_its_relay_within_its_wait() {
    let relay_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let plane = Arc::new(AnsweringRelayPlane {
        relay_addr: relay_socket.local_addr().unwrap(),
        calls: StdMutex::new(Vec::new()),
    });
    let (derp_out, _derp_sent) = mpsc::unbounded_channel();
    let (_derp_in, derp_received) = mpsc::unbounded_channel();
    let fallback = codewire_tailnet::conn::Transport {
        to_transport: derp_out,
        from_transport: derp_received,
        peer_updates: None,
        path_probe: None,
        local_endpoint_updates: None,
    };
    let secret = StaticSecret::random_from_rng(OsRng);
    let disco_private = DiscoPrivate::generate(&mut OsRng);
    let (transport, handle) = direct_udp::wrap_transport(
        fallback,
        direct_udp::Options::new(
            "127.0.0.1:0".parse().unwrap(),
            Vec::new(),
            NodePublic::from_raw(PublicKey::from(&secret).to_bytes()),
            disco_private.clone(),
        ),
    )
    .await
    .unwrap();
    let adapter_peers = transport.peer_updates.clone().unwrap();
    let relay = PeerRelayAllocator::new(
        Arc::new(OrchestratedPeerRelay::new(plane.clone())),
        LOG_COMPONENT,
        Vec::new(),
        disco_private.public(),
        handle.clone(),
    )
    .with_attempt_timeout(PEER_RELAY_ATTEMPT_TIMEOUT);
    let _reconciler = AbortOnDropHandle::new(relay.spawn_reconciler());
    let set_peers = |nodes: &[Node]| {
        adapter_peers.send(nodes.to_vec()).unwrap();
        relay.observe_peers(nodes);
    };
    let started = Instant::now();
    let at = |offset_ms: u64| tokio::time::sleep_until(started + Duration::from_millis(offset_ms));

    let doctor = client_node(1);
    let forced_derp = client_node(2);
    set_peers(std::slice::from_ref(&doctor));
    at(130).await;
    set_peers(&[doctor.clone(), forced_derp.clone()]);
    at(1_300).await;
    set_peers(&[]);
    at(1_390).await;
    let tailnet_ssh = client_node(3);
    set_peers(std::slice::from_ref(&tailnet_ssh));
    at(2_000).await;
    set_peers(&[]);
    at(2_570).await;
    let derp_ssh = client_node(4);
    set_peers(std::slice::from_ref(&derp_ssh));
    at(4_000).await;
    set_peers(&[]);

    // The relay leg: its forced-DERP probe registers first, the relay
    // client a moment later.
    at(4_800).await;
    let relay_forced_derp = client_node(5);
    set_peers(std::slice::from_ref(&relay_forced_derp));
    at(4_810).await;
    let relay_client = client_node(6);
    set_peers(&[relay_forced_derp.clone(), relay_client.clone()]);
    let arrived = Instant::now();
    let wait = Duration::from_secs(5);
    let offered = loop {
        if handle.peer_relay_endpoint_state(&relay_client.key, &relay_client.disco_key)
            != direct_udp::PeerRelayEndpointState::Missing
        {
            break Some(arrived.elapsed());
        }
        if arrived.elapsed() >= wait {
            break None;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    let calls = plane
        .calls
        .lock()
        .unwrap()
        .iter()
        .map(|(_, at)| at.duration_since(started).as_millis())
        .collect::<Vec<_>>();
    assert!(
        offered.is_some(),
        "the relay client had no relay {wait:?} after it arrived; allocations reached orchestration at {calls:?} ms"
    );
}
