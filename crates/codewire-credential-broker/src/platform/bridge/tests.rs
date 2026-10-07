//! Real generated tonic client/server with synthetic identities. Ordinary tests
//! use a closed database pool for admission/transport/worker ownership. The
//! ignored rotation module uses isolated PostgreSQL and synthetic providers to
//! prove publication drain through this same generated service and managed loop.

mod authenticated;
mod rotation;

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use codewire_access::{
    EnvironmentId, GrantContext, GrantPlacement, Owner, OwnerId, builtin_provider_catalog,
};
use codewire_daemon_proto::CREDENTIAL_BRIDGE_PROTOCOL_VERSION;
use codewire_daemon_proto::broker::v1::credential_broker_service_client::CredentialBrokerServiceClient;
use codewire_protected_store::secret_envelope::{
    DEK_BYTES, DekContext, GeneratedDek, KekProvider, KekProviderKind, SecretEnvelopeError,
    TestKekProvider, WrappedDek,
};
use sqlx::postgres::PgPoolOptions;
use tokio::net::TcpListener;
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::Code;
use tonic::transport::{Channel, Server};
use zeroize::Zeroizing;

use super::*;
use crate::platform::{PlatformPodIdentity, PlatformRuntimeSession};
use crate::{BrokerUpstreamError, BrokerUpstreamRequest, BrokerUpstreamResponse};

const TEST_TIMEOUT: Duration = Duration::from_secs(3);
/// A full stream budget small enough to open; production limits come from
/// `new` and are checked separately.
const TEST_STREAMS: usize = 4;

#[derive(Default)]
struct Gate {
    paused: AtomicBool,
    entered: Notify,
    release: Notify,
}

impl Gate {
    async fn pass(&self) {
        if self.paused.load(Ordering::SeqCst) {
            self.entered.notify_one();
            self.release.notified().await;
        }
    }
}

struct Authority {
    session: Mutex<PlatformRuntimeSession>,
    calls: AtomicUsize,
    captured: Notify,
}

#[async_trait]
impl PlatformRuntimeAuthority for Authority {
    async fn current_session(&self) -> Result<PlatformRuntimeSession, PlatformRuntimeError> {
        let session = self.session.lock().unwrap().clone();
        if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
            self.captured.notify_one();
        }
        Ok(session)
    }
}

struct Authenticator {
    authority: Arc<Authority>,
    calls: AtomicUsize,
    gate: Gate,
}

#[async_trait]
impl PlatformBridgeAuthenticator for Authenticator {
    type Authority = Authority;

    async fn authenticate(
        &self,
        metadata: &MetadataMap,
    ) -> Result<Arc<Authority>, PlatformBridgeAuthenticationError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.gate.pass().await;
        match metadata
            .get("x-synthetic-identity")
            .and_then(|value| value.to_str().ok())
        {
            Some("synthetic-allow") => Ok(Arc::clone(&self.authority)),
            Some("synthetic-deny") => Err(PlatformBridgeAuthenticationError::Denied),
            Some("synthetic-unavailable") => Err(PlatformBridgeAuthenticationError::Unavailable),
            _ => Err(PlatformBridgeAuthenticationError::Unauthenticated),
        }
    }
}

#[derive(Default)]
struct CountingKek {
    calls: AtomicUsize,
}

#[async_trait]
impl KekProvider for CountingKek {
    fn kind(&self) -> KekProviderKind {
        KekProviderKind::OpenBaoTransit
    }
    async fn generate(&self, context: &DekContext) -> Result<GeneratedDek, SecretEnvelopeError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        TestKekProvider.generate(context).await
    }
    async fn unwrap(
        &self,
        context: &DekContext,
        wrapped: &WrappedDek,
    ) -> Result<Zeroizing<[u8; DEK_BYTES]>, SecretEnvelopeError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        TestKekProvider.unwrap(context, wrapped).await
    }
    async fn rewrap(
        &self,
        context: &DekContext,
        wrapped: &WrappedDek,
    ) -> Result<WrappedDek, SecretEnvelopeError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        TestKekProvider.rewrap(context, wrapped).await
    }
    async fn authority_id(&self) -> Result<Option<String>, SecretEnvelopeError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        TestKekProvider.authority_id().await
    }
}

#[derive(Clone, Default)]
struct Upstream {
    calls: Arc<AtomicUsize>,
}

#[async_trait]
impl BrokerUpstreamTransport for Upstream {
    async fn execute(
        &self,
        _request: BrokerUpstreamRequest,
    ) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(BrokerUpstreamError::Protocol)
    }
}

type Service = PlatformCredentialBridgeService<Authenticator, Upstream>;
type Client = CredentialBrokerServiceClient<Channel>;

struct Fixture {
    service: Service,
    authenticator: Arc<Authenticator>,
    kek: Arc<CountingKek>,
    upstream: Upstream,
    endpoint: String,
    stop_listener: CancellationToken,
    server: JoinHandle<Result<(), tonic::transport::Error>>,
}

impl Fixture {
    /// The production limits.
    async fn new() -> Self {
        Self::with_limits(
            PLATFORM_CREDENTIAL_BRIDGE_MAX_STREAMS,
            PLATFORM_CREDENTIAL_BRIDGE_MAX_LEASES,
        )
        .await
    }

    async fn with_limits(streams: usize, leases: usize) -> Self {
        let pool = PgPoolOptions::new()
            .connect_lazy("postgresql://synthetic:synthetic@127.0.0.1:1/synthetic")
            .unwrap();
        pool.close().await;
        let owner = OwnerId::parse("synthetic-owner").unwrap();
        let context = GrantContext {
            environment_id: EnvironmentId::parse(Uuid::new_v4().to_string()).unwrap(),
            environment_generation: 7,
            placement: GrantPlacement::Platform,
            user_id: owner.clone(),
            organization_id: Some(OwnerId::parse("synthetic-org").unwrap()),
            allow_personal_credentials: true,
            authorized_credentials: Default::default(),
        };
        let pod = |name: &str| PlatformPodIdentity {
            namespace: "synthetic-workloads".into(),
            name: name.into(),
            uid: Uuid::new_v4(),
        };
        let session = PlatformRuntimeSession::new(
            pod("relay"),
            pod("workspace"),
            context,
            Owner::User(owner),
            crate::platform::unix_now().unwrap() + 3600,
        )
        .unwrap();
        let authority = Arc::new(Authority {
            session: Mutex::new(session),
            calls: AtomicUsize::new(0),
            captured: Notify::new(),
        });
        let authenticator = Arc::new(Authenticator {
            authority,
            calls: AtomicUsize::new(0),
            gate: Gate::default(),
        });
        let kek = Arc::new(CountingKek::default());
        let upstream = Upstream::default();
        let store = Arc::new(PlatformCredentialStore::new(
            pool.clone(),
            kek.clone(),
            builtin_provider_catalog(),
        ));
        let service = Service::with_limits(
            authenticator.clone(),
            store,
            PlatformAccessProfileStore::new(pool, builtin_provider_catalog()),
            upstream.clone(),
            streams,
            leases,
        );
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let stop_listener = CancellationToken::new();
        let stop = stop_listener.clone();
        let generated = service.clone().into_server();
        let server = tokio::spawn(async move {
            Server::builder()
                .add_service(generated)
                .serve_with_incoming_shutdown(
                    TcpListenerStream::new(listener),
                    stop.cancelled_owned(),
                )
                .await
        });
        Self {
            service,
            authenticator,
            kek,
            upstream,
            endpoint,
            stop_listener,
            server,
        }
    }

    async fn client(&self) -> Client {
        Client::connect(self.endpoint.clone())
            .await
            .unwrap()
            .max_decoding_message_size(CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES)
            .max_encoding_message_size(CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES * 2)
    }

    fn ready(&self) -> v1::CredentialBridgeGuestMessage {
        let session = self.authenticator.authority.session.lock().unwrap();
        v1::CredentialBridgeGuestMessage {
            payload: Some(v1::credential_bridge_guest_message::Payload::Ready(
                v1::CredentialBridgeReady {
                    protocol_version: CREDENTIAL_BRIDGE_PROTOCOL_VERSION,
                    environment_id: session.context.environment_id.to_string(),
                    environment_generation: session.context.environment_generation,
                },
            )),
        }
    }

    async fn open(
        &self,
        identity: Option<&str>,
        first: v1::CredentialBridgeGuestMessage,
    ) -> (
        mpsc::Sender<v1::CredentialBridgeGuestMessage>,
        Result<Response<Streaming<v1::CredentialBridgeHostMessage>>, Status>,
    ) {
        let (input, receiver) = mpsc::channel(4);
        input.send(first).await.unwrap();
        let result = self
            .client()
            .await
            .credential_bridge(rpc_request(receiver, identity))
            .await;
        (input, result)
    }

    async fn slots_released(&self) {
        let permit = tokio::time::timeout(
            TEST_TIMEOUT,
            self.service
                .state
                .permits
                .acquire_many(self.service.state.stream_capacity as u32),
        )
        .await
        .unwrap()
        .unwrap();
        drop(permit);
    }

    async fn finish(self) {
        self.service.shutdown().await.unwrap();
        assert_eq!(self.kek.calls.load(Ordering::SeqCst), 0);
        assert_eq!(self.upstream.calls.load(Ordering::SeqCst), 0);
        self.stop_listener.cancel();
        tokio::time::timeout(TEST_TIMEOUT, self.server)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
}

fn rpc_request(
    receiver: mpsc::Receiver<v1::CredentialBridgeGuestMessage>,
    identity: Option<&str>,
) -> Request<ReceiverStream<v1::CredentialBridgeGuestMessage>> {
    let mut request = Request::new(ReceiverStream::new(receiver));
    if let Some(identity) = identity {
        request
            .metadata_mut()
            .insert("x-synthetic-identity", identity.parse().unwrap());
    }
    request
}

#[tokio::test]
async fn authentication_precedes_ready_and_domain_work_on_generated_service() {
    let fixture = Fixture::new().await;
    for (identity, code) in [
        (None, Code::Unauthenticated),
        (Some("synthetic-secret-marker"), Code::Unauthenticated),
        (Some("synthetic-deny"), Code::PermissionDenied),
        (Some("synthetic-unavailable"), Code::Unavailable),
    ] {
        let (input, result) = fixture
            .open(identity, v1::CredentialBridgeGuestMessage { payload: None })
            .await;
        let error = result.unwrap_err();
        assert_eq!(error.code(), code);
        assert!(!format!("{error:?} {error}").contains("synthetic"));
        assert_eq!(
            fixture.authenticator.authority.calls.load(Ordering::SeqCst),
            0
        );
        drop(input);
    }
    fixture.slots_released().await;
    fixture.finish().await;
}

#[tokio::test]
async fn ready_requires_exact_captured_coordinates_and_protocol() {
    let fixture = Fixture::new().await;
    for fault in 0..4 {
        let mut first = fixture.ready();
        let Some(v1::credential_bridge_guest_message::Payload::Ready(ready)) =
            first.payload.as_mut()
        else {
            unreachable!()
        };
        let expected = match fault {
            0 => {
                ready.environment_id = Uuid::new_v4().to_string();
                Code::PermissionDenied
            }
            1 => {
                ready.environment_generation += 1;
                Code::PermissionDenied
            }
            2 => {
                ready.protocol_version += 1;
                Code::InvalidArgument
            }
            _ => {
                first.payload = None;
                Code::InvalidArgument
            }
        };
        let (input, result) = fixture.open(Some("synthetic-allow"), first).await;
        assert_eq!(result.unwrap_err().code(), expected);
        drop(input);
    }
    fixture.slots_released().await;
    fixture.finish().await;
}

#[tokio::test]
async fn admission_rechecks_authority_after_waiting_for_ready() {
    let fixture = Fixture::new().await;
    let first = fixture.ready();
    let mut client = fixture.client().await;
    let (input, receiver) = mpsc::channel(1);
    let open = tokio::spawn(async move {
        client
            .credential_bridge(rpc_request(receiver, Some("synthetic-allow")))
            .await
    });
    tokio::time::timeout(
        TEST_TIMEOUT,
        fixture.authenticator.authority.captured.notified(),
    )
    .await
    .unwrap();
    fixture
        .authenticator
        .authority
        .session
        .lock()
        .unwrap()
        .workspace_mut()
        .uid = Uuid::new_v4();
    input.send(first).await.unwrap();
    assert_eq!(
        open.await.unwrap().unwrap_err().code(),
        Code::PermissionDenied
    );
    drop(input);
    fixture.slots_released().await;
    fixture.finish().await;
}

#[tokio::test]
async fn whole_admission_timeout_includes_authentication() {
    let fixture = Fixture::new().await;
    fixture
        .authenticator
        .gate
        .paused
        .store(true, Ordering::SeqCst);
    let mut client = fixture.client().await;
    let (input, receiver) = mpsc::channel(1);
    input.send(fixture.ready()).await.unwrap();
    let open = tokio::spawn(async move {
        client
            .credential_bridge(rpc_request(receiver, Some("synthetic-allow")))
            .await
    });
    tokio::time::timeout(TEST_TIMEOUT, fixture.authenticator.gate.entered.notified())
        .await
        .unwrap();
    tokio::time::pause();
    tokio::time::advance(ADMISSION_TIMEOUT + Duration::from_millis(1)).await;
    tokio::time::resume();
    assert_eq!(
        open.await.unwrap().unwrap_err().code(),
        Code::DeadlineExceeded
    );
    assert_eq!(
        fixture.authenticator.authority.calls.load(Ordering::SeqCst),
        0
    );
    drop(input);
    fixture.slots_released().await;
    fixture.finish().await;
}

#[tokio::test]
async fn shared_frame_validation_and_server_message_ceiling_remain_active() {
    let fixture = Fixture::new().await;
    let (input, response) = fixture.open(Some("synthetic-allow"), fixture.ready()).await;
    let mut output = response.unwrap().into_inner();
    let id = Uuid::new_v4().to_string();
    input
        .send(v1::CredentialBridgeGuestMessage {
            payload: Some(v1::credential_bridge_guest_message::Payload::Request(
                v1::CredentialBridgeRequest {
                    capability_slot: "codex".into(),
                    route: "openai-api".into(),
                    request_id: id.clone(),
                    method: "DELETE".into(),
                    path: "/responses".into(),
                    query: String::new(),
                    headers: vec![],
                    body: vec![],
                },
            )),
        })
        .await
        .unwrap();
    let frame = output.message().await.unwrap().unwrap();
    assert!(
        matches!(frame.payload, Some(v1::credential_bridge_host_message::Payload::ResponseFailure(failure))
        if failure.request_id == id && failure.reason == v1::CredentialBridgeFailureReason::Denied as i32)
    );
    input
        .send(v1::CredentialBridgeGuestMessage {
            payload: Some(v1::credential_bridge_guest_message::Payload::Request(
                v1::CredentialBridgeRequest {
                    capability_slot: "codex".into(),
                    route: "openai-api".into(),
                    request_id: Uuid::new_v4().to_string(),
                    method: "POST".into(),
                    path: "/responses".into(),
                    query: String::new(),
                    headers: vec![],
                    body: vec![b'x'; CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES + 1],
                },
            )),
        })
        .await
        .unwrap();
    assert_eq!(
        output.message().await.unwrap_err().code(),
        Code::Unavailable
    );
    drop((input, output));
    fixture.slots_released().await;
    fixture.finish().await;
}

#[tokio::test]
async fn rpc_disconnect_and_input_half_close_release_idle_epochs() {
    let fixture = Fixture::new().await;
    let (input, response) = fixture.open(Some("synthetic-allow"), fixture.ready()).await;
    drop(response.unwrap());
    // h2 deliberately does not send RST_STREAM for a response-half drop while
    // outgoing DATA remains possible. A gateway's response owner must close
    // the outgoing half too; test that actual observable RPC cancellation.
    drop(input);
    fixture.slots_released().await;
    let (input, response) = fixture.open(Some("synthetic-allow"), fixture.ready()).await;
    let mut output = response.unwrap().into_inner();
    // Separately preserve the input-only half-close proof: its response owner
    // is still alive and receives the server's terminal status.
    drop(input);
    assert_eq!(
        output.message().await.unwrap_err().code(),
        Code::Unavailable
    );
    drop(output);
    fixture.slots_released().await;
    fixture.finish().await;
}

#[tokio::test]
async fn original_verified_expiry_ends_an_idle_epoch_without_extension() {
    let fixture = Fixture::new().await;
    fixture
        .authenticator
        .authority
        .session
        .lock()
        .unwrap()
        .identity_expires_at_unix = crate::platform::unix_now().unwrap() + 60;
    let (input, response) = fixture.open(Some("synthetic-allow"), fixture.ready()).await;
    let mut output = response.unwrap().into_inner();
    fixture
        .authenticator
        .authority
        .session
        .lock()
        .unwrap()
        .identity_expires_at_unix += 3600;
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(61)).await;
    tokio::time::resume();
    assert_eq!(
        output.message().await.unwrap_err().code(),
        Code::Unavailable
    );
    drop((input, output));
    fixture.slots_released().await;
    fixture.finish().await;
}

#[tokio::test]
async fn admitted_streams_carry_their_expiry_and_overlapping_epochs_hold_two_slots() {
    let fixture = Fixture::new().await;
    let expiry = |response: &Response<Streaming<v1::CredentialBridgeHostMessage>>| {
        let values: Vec<_> = response
            .metadata()
            .get_all(codewire_daemon_proto::CREDENTIAL_BRIDGE_EXPIRES_AT_HEADER)
            .iter()
            .map(|value| value.to_str().unwrap().to_owned())
            .collect();
        assert_eq!(values.len(), 1);
        values[0].parse::<u64>().unwrap()
    };
    let session_expiry = || {
        fixture
            .authenticator
            .authority
            .session
            .lock()
            .unwrap()
            .identity_expires_at_unix
    };
    let first_expiry = session_expiry();
    let (first_input, first) = fixture.open(Some("synthetic-allow"), fixture.ready()).await;
    let first = first.unwrap();
    assert_eq!(expiry(&first), first_expiry);
    assert_eq!(fixture.service.streams_in_use(), 1);
    // The gateway admits the next epoch, with a later identity expiry, while
    // the current one still drains: both hold a stream slot.
    fixture
        .authenticator
        .authority
        .session
        .lock()
        .unwrap()
        .identity_expires_at_unix += 600;
    let (second_input, second) = fixture.open(Some("synthetic-allow"), fixture.ready()).await;
    let second = second.unwrap();
    assert_eq!(expiry(&second), first_expiry + 600);
    assert_eq!(fixture.service.streams_in_use(), 2);
    // Ending the replaced epoch releases only its slot.
    drop((first_input, first));
    tokio::time::timeout(TEST_TIMEOUT, async {
        while fixture.service.streams_in_use() != 1 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    drop((second_input, second));
    fixture.slots_released().await;
    fixture.finish().await;
}

#[tokio::test]
async fn cloned_services_share_stream_slots_and_shutdown_closes_all_epochs() {
    let fixture = Fixture::with_limits(TEST_STREAMS, PLATFORM_CREDENTIAL_BRIDGE_MAX_LEASES).await;
    let mut streams = Vec::new();
    for _ in 0..TEST_STREAMS {
        let (input, response) = fixture.open(Some("synthetic-allow"), fixture.ready()).await;
        streams.push((input, response.unwrap().into_inner()));
    }
    let calls = fixture.authenticator.calls.load(Ordering::SeqCst);
    let (input, rejected) = fixture.open(Some("synthetic-allow"), fixture.ready()).await;
    assert_eq!(rejected.unwrap_err().code(), Code::ResourceExhausted);
    assert_eq!(calls, fixture.authenticator.calls.load(Ordering::SeqCst));
    drop(input);
    fixture.service.clone().shutdown().await.unwrap();
    for (input, mut output) in streams {
        assert_eq!(
            output.message().await.unwrap_err().code(),
            Code::Unavailable
        );
        drop(input);
    }
    fixture.slots_released().await;
    let (input, rejected) = fixture.open(Some("synthetic-allow"), fixture.ready()).await;
    assert_eq!(rejected.unwrap_err().code(), Code::Unavailable);
    drop(input);
    fixture.finish().await;
}

#[tokio::test]
async fn admissions_and_capacity_rejections_write_secret_free_timing_lines() {
    let (log, _guard) = crate::timing::tests::TimingLog::install();
    let fixture = Fixture::with_limits(TEST_STREAMS, PLATFORM_CREDENTIAL_BRIDGE_MAX_LEASES).await;
    let (input, denied) = fixture.open(Some("synthetic-deny"), fixture.ready()).await;
    assert_eq!(denied.unwrap_err().code(), Code::PermissionDenied);
    drop(input);
    fixture.slots_released().await;
    let mut streams = Vec::new();
    for _ in 0..TEST_STREAMS {
        let (input, response) = fixture.open(Some("synthetic-allow"), fixture.ready()).await;
        streams.push((input, response.unwrap().into_inner()));
    }
    let (input, rejected) = fixture.open(Some("synthetic-allow"), fixture.ready()).await;
    assert_eq!(rejected.unwrap_err().code(), Code::ResourceExhausted);
    drop(input);
    drop(streams);
    fixture.slots_released().await;
    fixture.finish().await;

    let lines = log.lines();
    for line in &lines {
        crate::timing::tests::assert_secret_free(line);
    }
    let fields = |event: &str| -> Vec<serde_json::Value> {
        lines
            .iter()
            .filter(|line| line["fields"]["event"] == event)
            .map(|line| line["fields"].clone())
            .collect()
    };
    let admissions = fields("epoch_admission");
    assert_eq!(admissions.len(), TEST_STREAMS + 1);
    assert_eq!(admissions[0]["outcome"], "denied");
    assert_eq!(admissions[0]["authority_checks"], 0);
    // A refused admission still counts its own slot until it returns.
    assert_eq!(admissions[0]["streams_in_use"], 1);
    for (live, admitted) in admissions[1..].iter().enumerate() {
        assert_eq!(admitted["outcome"], "admitted");
        // Connect, then the recheck after the guest's Ready frame.
        assert_eq!(admitted["authority_checks"], 2);
        // Every earlier epoch is still live, plus this one.
        assert_eq!(admitted["streams_in_use"], live + 1);
    }
    let rejected = fields("capacity_rejected");
    assert_eq!(rejected.len(), 1);
    assert_eq!(rejected[0]["limit"], "bridge_streams");
    assert_eq!(rejected[0]["operation"], "epoch");
    assert_eq!(rejected[0]["capacity"], TEST_STREAMS);
    assert_eq!(rejected[0]["in_use"], TEST_STREAMS);
    assert!(fields("proxied_request").is_empty());
}

#[tokio::test]
async fn shutdown_cancels_pending_authentication_without_admitting_a_worker() {
    let fixture = Fixture::new().await;
    fixture
        .authenticator
        .gate
        .paused
        .store(true, Ordering::SeqCst);
    let mut client = fixture.client().await;
    let (input, receiver) = mpsc::channel(1);
    input.send(fixture.ready()).await.unwrap();
    let open = tokio::spawn(async move {
        client
            .credential_bridge(rpc_request(receiver, Some("synthetic-allow")))
            .await
    });
    tokio::time::timeout(TEST_TIMEOUT, fixture.authenticator.gate.entered.notified())
        .await
        .unwrap();
    fixture.service.shutdown().await.unwrap();
    assert_eq!(open.await.unwrap().unwrap_err().code(), Code::Unavailable);
    assert_eq!(
        fixture.authenticator.authority.calls.load(Ordering::SeqCst),
        0
    );
    assert!(fixture.service.state.workers.is_empty());
    drop(input);
    fixture.slots_released().await;
    fixture.finish().await;
}

#[tokio::test]
async fn shutdown_holds_worker_capacity_until_drain_and_rejects_late_spawn() {
    let fixture = Fixture::new().await;
    let service = fixture.service.clone();
    let release = Arc::new(Notify::new());
    let permit = service.acquire().unwrap();
    let drain_release = release.clone();
    // This gates the exact worker-owner mechanism, not a simulated claim that
    // a provider refresh occurred. Real rotation remains separate DB proof.
    service
        .spawn_worker(permit, async move { drain_release.notified().await })
        .unwrap();
    let closing = service.clone();
    let shutdown = tokio::spawn(async move { closing.shutdown().await });
    service.state.shutdown.cancelled().await;
    assert!(!shutdown.is_finished());
    assert_eq!(
        service.state.permits.available_permits(),
        PLATFORM_CREDENTIAL_BRIDGE_MAX_STREAMS - 1
    );
    assert_eq!(service.acquire().unwrap_err().code(), Code::Unavailable);
    let late_permit = service.state.permits.clone().try_acquire_owned().unwrap();
    let ran = Arc::new(AtomicBool::new(false));
    let marker = ran.clone();
    assert_eq!(
        service
            .spawn_worker(
                late_permit,
                async move { marker.store(true, Ordering::SeqCst) }
            )
            .unwrap_err()
            .code(),
        Code::Unavailable
    );
    assert!(!ran.load(Ordering::SeqCst));
    release.notify_one();
    tokio::time::timeout(TEST_TIMEOUT, shutdown)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    fixture.slots_released().await;
    fixture.finish().await;
}

#[test]
fn authentication_errors_have_no_input_or_source_chain() {
    for error in [
        PlatformBridgeAuthenticationError::Unauthenticated,
        PlatformBridgeAuthenticationError::Denied,
        PlatformBridgeAuthenticationError::Unavailable,
    ] {
        assert!(std::error::Error::source(&error).is_none());
        assert!(!format!("{error:?} {error}").contains("synthetic-secret-marker"));
        assert!(!error.status().message().contains("synthetic-secret-marker"));
    }
}

#[tokio::test]
async fn production_limits_admit_more_than_eight_epochs_and_shutdown_drains_them() {
    const EPOCHS: usize = 12;
    let fixture = Fixture::new().await;
    assert_eq!(
        fixture.service.state.stream_capacity,
        PLATFORM_CREDENTIAL_BRIDGE_MAX_STREAMS
    );
    assert_eq!(
        fixture.service.state.leases.available(),
        PLATFORM_CREDENTIAL_BRIDGE_MAX_LEASES
    );
    let mut streams = Vec::new();
    for _ in 0..EPOCHS {
        let (input, response) = fixture.open(Some("synthetic-allow"), fixture.ready()).await;
        streams.push((input, response.unwrap().into_inner()));
    }
    assert_eq!(fixture.service.state.workers.len(), EPOCHS);
    assert_eq!(fixture.service.streams_in_use(), EPOCHS);
    fixture.service.clone().shutdown().await.unwrap();
    for (input, mut output) in streams {
        assert_eq!(
            output.message().await.unwrap_err().code(),
            Code::Unavailable
        );
        drop(input);
    }
    fixture.slots_released().await;
    fixture.finish().await;
}

/// A request that passes validation and reaches `lease_operation`.
fn leased_request() -> v1::CredentialBridgeGuestMessage {
    v1::CredentialBridgeGuestMessage {
        payload: Some(v1::credential_bridge_guest_message::Payload::Request(
            v1::CredentialBridgeRequest {
                capability_slot: "github".into(),
                route: "github-api".into(),
                request_id: Uuid::new_v4().to_string(),
                method: "GET".into(),
                path: "/user".into(),
                query: String::new(),
                headers: vec![v1::CredentialHttpHeader {
                    name: "content-type".into(),
                    value: b"application/json".to_vec(),
                }],
                body: vec![],
            },
        )),
    }
}

/// Wait until the authority has been asked `calls` times in total.
async fn authority_calls_reach(fixture: &Fixture, calls: usize) {
    tokio::time::timeout(TEST_TIMEOUT, async {
        while fixture.authenticator.authority.calls.load(Ordering::SeqCst) < calls {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn a_lease_waits_for_a_free_slot_instead_of_failing() {
    let fixture = Fixture::with_limits(TEST_STREAMS, 1).await;
    let held = Arc::clone(&fixture.service.state.leases.permits)
        .try_acquire_owned()
        .unwrap();
    let (input, response) = fixture.open(Some("synthetic-allow"), fixture.ready()).await;
    let mut output = response.unwrap().into_inner();
    // Connect and the recheck after Ready.
    authority_calls_reach(&fixture, 2).await;
    input.send(leased_request()).await.unwrap();
    // Queued: no answer and no authority work while the only slot is held.
    assert!(
        tokio::time::timeout(Duration::from_millis(200), output.message())
            .await
            .is_err()
    );
    assert_eq!(
        fixture.authenticator.authority.calls.load(Ordering::SeqCst),
        2
    );
    drop(held);
    // The freed slot admits the queued lease, which reaches the authority and
    // then fails only on the synthetic closed database.
    let frame = tokio::time::timeout(TEST_TIMEOUT, output.message())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(matches!(frame.payload,
        Some(v1::credential_bridge_host_message::Payload::ResponseFailure(failure))
        if failure.reason == v1::CredentialBridgeFailureReason::Unavailable as i32));
    assert_eq!(
        fixture.authenticator.authority.calls.load(Ordering::SeqCst),
        3
    );
    assert_eq!(
        fixture.service.state.leases.available(),
        1,
        "the lease returned its slot"
    );
    drop((input, output));
    fixture.slots_released().await;
    fixture.finish().await;
}

#[tokio::test]
async fn shutdown_fails_queued_leases_and_still_drains() {
    let fixture = Fixture::with_limits(TEST_STREAMS, 1).await;
    let held = Arc::clone(&fixture.service.state.leases.permits)
        .try_acquire_owned()
        .unwrap();
    let (input, response) = fixture.open(Some("synthetic-allow"), fixture.ready()).await;
    let mut output = response.unwrap().into_inner();
    authority_calls_reach(&fixture, 2).await;
    input.send(leased_request()).await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(200), output.message())
            .await
            .is_err()
    );
    // The test still holds the only slot: shutdown must not wait for it.
    tokio::time::timeout(TEST_TIMEOUT, fixture.service.clone().shutdown())
        .await
        .unwrap()
        .unwrap();
    // Either a failure frame for the queued request or only the terminal
    // status may arrive first; the epoch always ends unavailable.
    let terminal = loop {
        match tokio::time::timeout(TEST_TIMEOUT, output.message())
            .await
            .unwrap()
        {
            Ok(Some(frame)) => assert!(matches!(frame.payload,
                Some(v1::credential_bridge_host_message::Payload::ResponseFailure(failure))
                if failure.reason == v1::CredentialBridgeFailureReason::Unavailable as i32)),
            Ok(None) => panic!("epoch ended without a terminal status"),
            Err(status) => break status,
        }
    };
    assert_eq!(terminal.code(), Code::Unavailable);
    // The queued lease never did authority, database or KEK work.
    assert_eq!(
        fixture.authenticator.authority.calls.load(Ordering::SeqCst),
        2
    );
    assert!(fixture.service.state.workers.is_empty());
    drop((input, output, held));
    fixture.slots_released().await;
    fixture.finish().await;
}

fn codex_login_request() -> v1::CredentialBridgeGuestMessage {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    v1::CredentialBridgeGuestMessage {
        payload: Some(v1::credential_bridge_guest_message::Payload::CodexLogin(
            v1::CodexLoginRequest {
                request_id: Uuid::new_v4().to_string(),
                recipient_public_key: codewire_workload_secrets::ProjectionRecipient::new()
                    .public_key()
                    .to_vec(),
                deadline_unix_ms: now + 10_000,
            },
        )),
    }
}

#[tokio::test]
async fn admitted_streams_list_codex_login_and_answer_it_under_the_lease_budget() {
    for creator_confirmed in [false, true] {
        let fixture = Fixture::with_limits(TEST_STREAMS, 1).await;
        // Without the creator's own confirmed personal profile, the session
        // alone fails the delivery predicate, before any grant or record read.
        fixture
            .authenticator
            .authority
            .session
            .lock()
            .unwrap()
            .context
            .allow_personal_credentials = creator_confirmed;
        let held = Arc::clone(&fixture.service.state.leases.permits)
            .try_acquire_owned()
            .unwrap();
        let (input, response) = fixture.open(Some("synthetic-allow"), fixture.ready()).await;
        let response = response.unwrap();
        let capabilities: Vec<_> = response
            .metadata()
            .get_all(codewire_daemon_proto::CREDENTIAL_BRIDGE_CAPABILITIES_HEADER)
            .iter()
            .map(|value| value.to_str().unwrap().to_owned())
            .collect();
        assert_eq!(capabilities, ["codex-login"]);
        let mut output = response.into_inner();
        authority_calls_reach(&fixture, 2).await;
        input.send(codex_login_request()).await.unwrap();
        // A login lease waits for the shared lease budget like any lease.
        assert!(
            tokio::time::timeout(Duration::from_millis(200), output.message())
                .await
                .is_err()
        );
        assert_eq!(
            fixture.authenticator.authority.calls.load(Ordering::SeqCst),
            2
        );
        drop(held);
        let expected = if creator_confirmed {
            // The session passes; the closed synthetic database then fails
            // the grant read, which is not a decision about the login.
            v1::CredentialBridgeFailureReason::Unavailable
        } else {
            v1::CredentialBridgeFailureReason::Denied
        };
        for answered in 0..2 {
            let frame = tokio::time::timeout(TEST_TIMEOUT, output.message())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            assert!(matches!(frame.payload,
                Some(v1::credential_bridge_host_message::Payload::CodexLogin(response))
                if response.result == Some(v1::codex_login_response::Result::Failure(expected as i32))));
            if answered == 0 {
                // The epoch survives either answer.
                input.send(codex_login_request()).await.unwrap();
            }
        }
        assert_eq!(fixture.service.state.leases.available(), 1);
        drop((input, output));
        fixture.slots_released().await;
        fixture.finish().await;
    }
}
