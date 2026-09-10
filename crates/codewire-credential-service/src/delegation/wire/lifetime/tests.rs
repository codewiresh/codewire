//! Synthetic, unauthenticated TEST mount solely for dispatcher/body ownership.
//! Production OAuth and selection parsing are exercised by their own fixtures.

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use codewire_access::{
    EnvironmentId, GrantContext, GrantPlacement, Owner, OwnerId, builtin_provider_catalog,
};
use codewire_credential_broker::platform::bridge::{
    PLATFORM_CREDENTIAL_BRIDGE_MAX_STREAMS, PlatformBridgeAuthenticationError,
    PlatformBridgeAuthenticator, PlatformCredentialBridgeService,
};
use codewire_credential_broker::platform::{
    PlatformRuntimeAuthority, PlatformRuntimeError, PlatformRuntimeSession,
};
use codewire_credential_broker::{
    BrokerUpstreamError, BrokerUpstreamRequest, BrokerUpstreamResponse, BrokerUpstreamTransport,
};
use codewire_gateway_proto::codewire::bridge::v1 as bridge;
use codewire_platform_credentials::{PlatformAccessProfileStore, PlatformCredentialStore};
use codewire_protected_store::secret_envelope::TestKekProvider;
use codewire_proto::codewire::v1::{self as proto, CredentialDelegationService};
use codewire_server_core::connect::{ProtocolPolicy, connect_router_with_protocol_policy};
use connectrpc::{InboundStream, RequestContext, ServiceResult, ServiceStream};
use futures::{StreamExt, stream};
use sqlx::postgres::PgPoolOptions;
use tokio::sync::Notify;
use tonic::codegen::Service as _;
use uuid::Uuid;

use super::*;

const TIMEOUT: Duration = Duration::from_secs(2);
const PATH: &str = "/codewire.v1.CredentialDelegationService/DelegateCredentials";

struct Identity {
    session: PlatformRuntimeSession,
    ready: bridge::CredentialBridgeGuestMessage,
}

#[async_trait]
impl PlatformRuntimeAuthority for Identity {
    async fn current_session(&self) -> Result<PlatformRuntimeSession, PlatformRuntimeError> {
        Ok(self.session.clone())
    }
}

#[async_trait]
impl PlatformBridgeAuthenticator for Identity {
    type Authority = Self;

    async fn authenticate(
        &self,
        _: &tonic::metadata::MetadataMap,
    ) -> Result<Arc<Self>, PlatformBridgeAuthenticationError> {
        Err(PlatformBridgeAuthenticationError::Denied)
    }
}

#[derive(Clone)]
struct NoUpstream;

#[async_trait]
impl BrokerUpstreamTransport for NoUpstream {
    async fn execute(
        &self,
        _: BrokerUpstreamRequest,
    ) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
        panic!("body-lifetime fixture must never dispatch provider traffic")
    }
}

struct Probe {
    bridge: PlatformCredentialBridgeService<Identity, NoUpstream>,
    identity: Arc<Identity>,
    lazy_calls: AtomicUsize,
    require_lifetime: bool,
}

#[allow(refining_impl_trait)]
impl CredentialDelegationService for Probe {
    async fn delegate_credentials(
        &self,
        ctx: RequestContext,
        mut input: InboundStream<proto::DelegateCredentialsRequest>,
    ) -> ServiceResult<ServiceStream<proto::DelegateCredentialsResponse>> {
        let guard = admission_guard(&ctx);
        assert!(
            !self.require_lifetime || guard.is_some(),
            "fixture middleware missing"
        );
        drop(ctx);
        let output = self
            .bridge
            .serve_authenticated(async {
                self.lazy_calls.fetch_add(1, Ordering::SeqCst);
                // A synthetic marker models selection-frame consumption inside the
                // REAL shared permit/deadline; it authenticates no product caller.
                input
                    .next()
                    .await
                    .ok_or(PlatformBridgeAuthenticationError::Denied)?
                    .map_err(|_| PlatformBridgeAuthenticationError::Denied)?;
                let ready = self.identity.ready.clone();
                let remaining = input.map(|_| {
                    Err(tonic::Status::permission_denied(
                        "fixture has no operations",
                    ))
                });
                Ok((
                    self.identity.clone(),
                    stream::once(async { Ok(ready) }).chain(remaining),
                ))
            })
            .await
            .map_err(super::super::wire_error)?;
        if let Some(guard) = guard {
            guard.disarm();
        }
        connectrpc::Response::stream_ok(output.map(|item| {
            item.map_err(super::super::wire_error)?;
            Ok(proto::DelegateCredentialsResponse::default())
        }))
    }
}

impl Probe {
    async fn new() -> Arc<Self> {
        let pool = PgPoolOptions::new()
            .connect_lazy("postgresql://synthetic:synthetic@127.0.0.1:1/synthetic")
            .unwrap();
        pool.close().await;
        let user = OwnerId::parse("synthetic-owner").unwrap();
        let environment_id = Uuid::new_v4();
        let context = GrantContext {
            environment_id: EnvironmentId::parse(environment_id.to_string()).unwrap(),
            environment_generation: 7,
            placement: GrantPlacement::PlatformToLocal,
            user_id: user.clone(),
            organization_id: Some(OwnerId::parse("synthetic-org").unwrap()),
            allow_personal_credentials: false,
            authorized_credentials: Default::default(),
        };
        let expiry = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        let identity = Arc::new(Identity {
            session: PlatformRuntimeSession::owner_local(
                context,
                Owner::User(user),
                None,
                [7; 32],
                expiry,
            )
            .unwrap(),
            ready: bridge::CredentialBridgeGuestMessage {
                payload: Some(bridge::credential_bridge_guest_message::Payload::Ready(
                    bridge::CredentialBridgeReady {
                        protocol_version:
                            codewire_gateway_proto::CREDENTIAL_BRIDGE_PROTOCOL_VERSION,
                        environment_id: environment_id.to_string(),
                        environment_generation: 7,
                    },
                )),
            },
        });
        let store = Arc::new(PlatformCredentialStore::new(
            pool.clone(),
            Arc::new(TestKekProvider),
            builtin_provider_catalog(),
        ));
        Arc::new(Self {
            bridge: PlatformCredentialBridgeService::new(
                identity.clone(),
                store,
                PlatformAccessProfileStore::new(pool, builtin_provider_catalog()),
                NoUpstream,
            ),
            identity,
            lazy_calls: AtomicUsize::new(0),
            require_lifetime: true,
        })
    }

    fn router(self: &Arc<Self>) -> axum::Router {
        connect_router_with_protocol_policy(
            connectrpc::Router::new().add_service(self.clone()),
            ProtocolPolicy::ConnectAndGrpc,
        )
        .layer(axum::middleware::from_fn(bind))
    }

    async fn finish(&self) {
        tokio::time::timeout(TIMEOUT, self.bridge.shutdown())
            .await
            .unwrap()
            .unwrap();
    }
}

#[derive(Default)]
struct Observed {
    pending: Notify,
    dropped: Notify,
    drops: AtomicUsize,
}

impl Observed {
    async fn dropped(&self) {
        tokio::time::timeout(TIMEOUT, self.dropped.notified())
            .await
            .unwrap();
        assert_eq!(self.drops.load(Ordering::SeqCst), 1);
    }
}

struct ProbeBody {
    frames: VecDeque<Result<Frame<Bytes>, axum::Error>>,
    pending: bool,
    observed: Arc<Observed>,
}

impl HttpBody for ProbeBody {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        let this = self.get_mut();
        if let Some(frame) = this.frames.pop_front() {
            return Poll::Ready(Some(frame));
        }
        if this.pending {
            this.observed.pending.notify_one();
            Poll::Pending
        } else {
            Poll::Ready(None)
        }
    }
}

impl Drop for ProbeBody {
    fn drop(&mut self) {
        self.observed.drops.fetch_add(1, Ordering::SeqCst);
        self.observed.dropped.notify_one();
    }
}

fn request(content_type: &str, first: bool) -> (Request, Arc<Observed>) {
    let observed = Arc::new(Observed::default());
    // One legal empty synthetic marker, followed by an indefinitely pending
    // body. The dispatcher must not keep that body after route ownership ends.
    let frames = if first {
        VecDeque::from([Ok(Frame::data(Bytes::from_static(&[0, 0, 0, 0, 0])))])
    } else {
        VecDeque::new()
    };
    let body = Body::new(ProbeBody {
        frames,
        pending: true,
        observed: observed.clone(),
    });
    let request = Request::builder()
        .method("POST")
        .uri(PATH)
        .version(http::Version::HTTP_2)
        .header(http::header::CONTENT_TYPE, content_type)
        .header("connect-protocol-version", "1")
        .body(body)
        .unwrap();
    (request, observed)
}

#[tokio::test]
async fn response_drop_closes_actual_dispatcher_pending_reader_for_both_protocols() {
    for protocol in ["application/connect+proto", "application/grpc+proto"] {
        let probe = Probe::new().await;
        let (request, observed) = request(protocol, true);
        let response = tokio::time::timeout(TIMEOUT, probe.router().call(request))
            .await
            .unwrap()
            .unwrap();
        tokio::time::timeout(TIMEOUT, observed.pending.notified())
            .await
            .unwrap();
        assert_eq!(observed.drops.load(Ordering::SeqCst), 0);
        drop(response);
        observed.dropped().await;
        probe.finish().await;
    }
}

#[tokio::test]
async fn exhausted_shared_capacity_drops_reader_without_polling_selection_or_error_response() {
    let probe = Probe::new().await;
    let mut occupied = Vec::new();
    for _ in 0..PLATFORM_CREDENTIAL_BRIDGE_MAX_STREAMS {
        let ready = probe.identity.ready.clone();
        occupied.push(
            probe
                .bridge
                .serve_authenticated(async {
                    Ok((
                        probe.identity.clone(),
                        stream::once(async { Ok(ready) }).chain(stream::pending()),
                    ))
                })
                .await
                .unwrap(),
        );
    }
    let (request, observed) = request("application/grpc+proto", false);
    let response = tokio::time::timeout(TIMEOUT, probe.router().call(request))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(probe.lazy_calls.load(Ordering::SeqCst), 0);
    // Keep this HTTP200 error response entirely unread during the assertion.
    observed.dropped().await;
    drop(response);
    drop(occupied);
    probe.finish().await;
}

// Test-only peer-controlled EOF: the sender below can wake the exact pinned
// dispatcher's pending reader after admission has failed, then drain it. This
// adds no cancellation mechanism to the unwrapped router under comparison.
struct UnwrappedPendingBody {
    frames: tokio::sync::mpsc::Receiver<Frame<Bytes>>,
    observed: Arc<Observed>,
}

impl HttpBody for UnwrappedPendingBody {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        let this = self.get_mut();
        match this.frames.poll_recv(cx) {
            Poll::Ready(frame) => Poll::Ready(frame.map(Ok)),
            Poll::Pending => {
                this.observed.pending.notify_one();
                Poll::Pending
            }
        }
    }
}

impl Drop for UnwrappedPendingBody {
    fn drop(&mut self) {
        self.observed.drops.fetch_add(1, Ordering::SeqCst);
        self.observed.dropped.notify_one();
    }
}

#[tokio::test]
async fn unwrapped_pinned_dispatcher_retains_reader_after_failed_admission_until_peer_eof() {
    let mut probe = Probe::new().await;
    Arc::get_mut(&mut probe).unwrap().require_lifetime = false;
    let mut occupied = Vec::new();
    for _ in 0..PLATFORM_CREDENTIAL_BRIDGE_MAX_STREAMS {
        let ready = probe.identity.ready.clone();
        occupied.push(
            probe
                .bridge
                .serve_authenticated(async {
                    Ok((
                        probe.identity.clone(),
                        stream::once(async { Ok(ready) }).chain(stream::pending()),
                    ))
                })
                .await
                .unwrap(),
        );
    }
    // Deliberately omit bind only on this synthetic, unauthenticated TEST
    // mount. The shared bridge still rejects using its real exhausted budget.
    let mut router = connect_router_with_protocol_policy(
        connectrpc::Router::new().add_service(probe.clone()),
        ProtocolPolicy::ConnectAndGrpc,
    );
    let (peer, frames) = tokio::sync::mpsc::channel(1);
    let observed = Arc::new(Observed::default());
    let request = Request::builder()
        .method("POST")
        .uri(PATH)
        .version(http::Version::HTTP_2)
        .header(http::header::CONTENT_TYPE, "application/grpc+proto")
        .body(Body::new(UnwrappedPendingBody {
            frames,
            observed: observed.clone(),
        }))
        .unwrap();
    let mut response = tokio::time::timeout(TIMEOUT, router.call(request))
        .await
        .unwrap()
        .unwrap();
    let rejected_without_admission = probe.lazy_calls.load(Ordering::SeqCst) == 0;
    let frame = tokio::time::timeout(
        TIMEOUT,
        std::future::poll_fn(|cx| Pin::new(response.body_mut()).poll_frame(cx)),
    )
    .await
    .unwrap()
    .unwrap()
    .unwrap();
    let grpc_status = frame.into_trailers().unwrap().get("grpc-status").cloned();
    drop(response);
    tokio::time::timeout(TIMEOUT, observed.pending.notified())
        .await
        .unwrap();
    // Force a second real reader poll AFTER the error response is gone; this
    // distinguishes retained ownership from an unscheduled Drop notification.
    tokio::time::timeout(TIMEOUT, peer.send(Frame::data(Bytes::new())))
        .await
        .unwrap()
        .unwrap();
    tokio::time::timeout(TIMEOUT, observed.pending.notified())
        .await
        .unwrap();
    let retained_after_error = observed.drops.load(Ordering::SeqCst) == 0;
    // Always release the test peer and real occupied epochs before assertions.
    // Dropping peer on panic also wakes the retained reader with actual EOF.
    drop(peer);
    observed.dropped().await;
    drop(occupied);
    probe.finish().await;
    assert!(rejected_without_admission);
    assert_eq!(grpc_status.unwrap(), "8");
    assert!(retained_after_error);
}

#[tokio::test]
async fn original_five_second_admission_timeout_drops_reader_before_error_response_is_read() {
    let probe = Probe::new().await;
    let (request, observed) = request("application/connect+proto", false);
    let mut router = probe.router();
    let mut response = Box::pin(router.call(request));
    assert!(futures::poll!(response.as_mut()).is_pending());
    tokio::time::timeout(TIMEOUT, observed.pending.notified())
        .await
        .unwrap();
    assert_eq!(probe.lazy_calls.load(Ordering::SeqCst), 1);
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(4)).await;
    assert!(futures::poll!(response.as_mut()).is_pending());
    tokio::time::advance(Duration::from_millis(1001)).await;
    let response = response.await.unwrap();
    tokio::time::resume();
    observed.dropped().await;
    drop(response);
    probe.finish().await;
}

#[tokio::test]
async fn middleware_future_drop_before_response_cancels_the_pending_reader() {
    let probe = Probe::new().await;
    let (request, observed) = request("application/grpc+proto", false);
    let mut router = probe.router();
    let mut response = Box::pin(router.call(request));
    assert!(futures::poll!(response.as_mut()).is_pending());
    tokio::time::timeout(TIMEOUT, observed.pending.notified())
        .await
        .unwrap();
    drop(response);
    observed.dropped().await;
    probe.finish().await;
}

#[tokio::test]
async fn output_eof_and_error_cancel_and_both_wrappers_preserve_trailers() {
    for fail in [false, true] {
        let cancellation = CancellationToken::new();
        let frame = if fail {
            Err(axum::Error::new(std::io::Error::other(
                "synthetic transport failure",
            )))
        } else {
            Ok(Frame::trailers(http::HeaderMap::from_iter([(
                http::header::HeaderName::from_static("grpc-status"),
                http::HeaderValue::from_static("0"),
            )])))
        };
        let body = Body::new(ProbeBody {
            frames: VecDeque::from([frame]),
            pending: false,
            observed: Arc::new(Observed::default()),
        });
        let mut output = Box::pin(OutputBody {
            body: Box::pin(body),
            guard: Some(cancellation.clone().drop_guard()),
        });
        let frame = std::future::poll_fn(|cx| output.as_mut().poll_frame(cx))
            .await
            .unwrap();
        if fail {
            assert!(frame.is_err());
        } else {
            assert_eq!(frame.unwrap().into_trailers().unwrap()["grpc-status"], "0");
            assert!(!cancellation.is_cancelled());
            assert!(
                std::future::poll_fn(|cx| output.as_mut().poll_frame(cx))
                    .await
                    .is_none()
            );
        }
        assert!(cancellation.is_cancelled());
    }
    let cancellation = CancellationToken::new();
    let body = Body::new(ProbeBody {
        frames: VecDeque::from([Ok(Frame::trailers(http::HeaderMap::from_iter([(
            http::header::HeaderName::from_static("synthetic-trailer"),
            http::HeaderValue::from_static("public"),
        )])))]),
        pending: true,
        observed: Arc::new(Observed::default()),
    });
    let mut input = Box::pin(InputBody {
        body: Some(Box::pin(body)),
        cancelled: Box::pin(cancellation.clone().cancelled_owned()),
    });
    let frame = std::future::poll_fn(|cx| input.as_mut().poll_frame(cx))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        frame.into_trailers().unwrap()["synthetic-trailer"],
        "public"
    );
    cancellation.cancel();
    assert!(
        std::future::poll_fn(|cx| input.as_mut().poll_frame(cx))
            .await
            .is_none()
    );
}
