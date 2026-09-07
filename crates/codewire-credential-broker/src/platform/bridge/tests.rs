//! Real generated tonic client/server with synthetic identities. Ordinary tests
//! use a closed database pool for admission/transport/worker ownership. The
//! ignored rotation module uses isolated PostgreSQL and synthetic providers to
//! prove publication drain through this same generated service and managed loop.

mod rotation;

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use codewire_access::{
    EnvironmentId, GrantContext, Owner, OwnerId, Placement, builtin_provider_catalog,
};
use codewire_gateway_proto::CREDENTIAL_BRIDGE_PROTOCOL_VERSION;
use codewire_gateway_proto::broker::v1::credential_broker_service_client::CredentialBrokerServiceClient;
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
    async fn new() -> Self {
        let pool = PgPoolOptions::new()
            .connect_lazy("postgresql://synthetic:synthetic@127.0.0.1:1/synthetic")
            .unwrap();
        pool.close().await;
        let owner = OwnerId::parse("synthetic-owner").unwrap();
        let context = GrantContext {
            environment_id: EnvironmentId::parse(Uuid::new_v4().to_string()).unwrap(),
            environment_generation: 7,
            placement: Placement::Platform,
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
            pod("gateway"),
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
        let service = Service::new(
            authenticator.clone(),
            store,
            PlatformAccessProfileStore::new(pool, builtin_provider_catalog()),
            upstream.clone(),
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
                .acquire_many(PLATFORM_CREDENTIAL_BRIDGE_MAX_STREAMS as u32),
        )
        .await
        .unwrap()
        .unwrap();
        drop(permit);
    }

    async fn finish(self) {
        self.service.shutdown().await;
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
        .workspace
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
async fn cloned_services_share_eight_slots_and_shutdown_closes_all_epochs() {
    let fixture = Fixture::new().await;
    let mut streams = Vec::new();
    for _ in 0..PLATFORM_CREDENTIAL_BRIDGE_MAX_STREAMS {
        let (input, response) = fixture.open(Some("synthetic-allow"), fixture.ready()).await;
        streams.push((input, response.unwrap().into_inner()));
    }
    let calls = fixture.authenticator.calls.load(Ordering::SeqCst);
    let (input, rejected) = fixture.open(Some("synthetic-allow"), fixture.ready()).await;
    assert_eq!(rejected.unwrap_err().code(), Code::ResourceExhausted);
    assert_eq!(calls, fixture.authenticator.calls.load(Ordering::SeqCst));
    drop(input);
    fixture.service.clone().shutdown().await;
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
    fixture.service.shutdown().await;
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
