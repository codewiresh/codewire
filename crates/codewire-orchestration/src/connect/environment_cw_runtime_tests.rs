//! Actual in-process Connect framing, limits and auth middleware. The leaf
//! service is synthetic: these tests do not claim database or Pod execution.
use super::*;
use axum::body::{Body, Bytes, to_bytes};
use axum::http::{Request, StatusCode};
use buffa::Message as _;
use codewire_server_core::auth::{AuthState, AuthUser};
use codewire_server_core::connect::{ConnectAuthLayer, connect_router, connect_router_with_auth};
use futures_util::stream;
use std::convert::Infallible;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use tower::ServiceExt as _;

const PREFIX: &str = "/codewire.v1.EnvironmentCwRuntimeService/";

#[derive(Default)]
struct Probe {
    calls: AtomicUsize,
    frames: AtomicUsize,
    generation: AtomicU64,
}

#[allow(refining_impl_trait)]
impl proto::EnvironmentCwRuntimeService for Probe {
    async fn get_environment_cw_runtime(
        &self,
        ctx: RequestContext,
        _request: ServiceRequest<'_, proto::GetEnvironmentCwRuntimeRequest>,
    ) -> ServiceResult<proto::GetEnvironmentCwRuntimeResponse> {
        auth_user(&ctx)?;
        self.calls.fetch_add(1, Ordering::SeqCst);
        connectrpc::Response::ok(proto::GetEnvironmentCwRuntimeResponse::default())
    }
    async fn update_environment_cw_runtime(
        &self,
        ctx: RequestContext,
        mut requests: InboundStream<proto::UpdateEnvironmentCwRuntimeRequest>,
    ) -> ServiceResult<proto::UpdateEnvironmentCwRuntimeResponse> {
        auth_user(&ctx)?;
        self.calls.fetch_add(1, Ordering::SeqCst);
        while let Some(frame) = requests.next().await {
            let request = frame?.to_owned_message();
            if let Some(proto::update_environment_cw_runtime_request::Payload::Header(header)) =
                request.payload
            {
                self.generation
                    .store(header.expected_selection.generation, Ordering::SeqCst);
            }
            self.frames.fetch_add(1, Ordering::SeqCst);
        }
        connectrpc::Response::ok(proto::UpdateEnvironmentCwRuntimeResponse::default())
    }
    async fn rollback_environment_cw_runtime(
        &self,
        ctx: RequestContext,
        _request: ServiceRequest<'_, proto::RollbackEnvironmentCwRuntimeRequest>,
    ) -> ServiceResult<proto::RollbackEnvironmentCwRuntimeResponse> {
        auth_user(&ctx)?;
        self.calls.fetch_add(1, Ordering::SeqCst);
        connectrpc::Response::ok(proto::RollbackEnvironmentCwRuntimeResponse::default())
    }
    async fn observe_environment_cw_runtime(
        &self,
        ctx: RequestContext,
        _request: ServiceRequest<'_, proto::ObserveEnvironmentCwRuntimeRequest>,
    ) -> ServiceResult<proto::ObserveEnvironmentCwRuntimeResponse> {
        auth_user(&ctx)?;
        self.calls.fetch_add(1, Ordering::SeqCst);
        connectrpc::Response::ok(proto::ObserveEnvironmentCwRuntimeResponse::default())
    }
}

fn routes(probe: &Arc<Probe>) -> connectrpc::Router {
    with_limits(connectrpc::Router::new().add_service(probe.clone()))
}

fn request(method: &str, content_type: &str, body: Body, principal: bool) -> Request<Body> {
    let mut request = Request::post(format!("{PREFIX}{method}"))
        .header("content-type", content_type)
        .header("connect-protocol-version", "1")
        .body(body)
        .unwrap();
    if principal {
        // Test-context identity only. No credential resolver, SQL or network
        // is substituted by this extension.
        request.extensions_mut().insert(AuthUser {
            user_id: "synthetic-route-principal".into(),
            org_id: None,
            is_admin: false,
            via_api_key: false,
        });
    }
    request
}

fn frame(message: &impl buffa::Message) -> Vec<u8> {
    let bytes = message.encode_to_vec();
    let mut framed = vec![0];
    framed.extend_from_slice(&u32::try_from(bytes.len()).unwrap().to_be_bytes());
    framed.extend_from_slice(&bytes);
    framed
}

#[tokio::test]
async fn connect_only_and_missing_auth_refuse_before_reading_body_or_handler() {
    let probe = Arc::new(Probe::default());
    let auth = ConnectAuthLayer::authenticated(AuthState {
        // Lazy, synthetic and never contacted: absent credentials must fail
        // before any database lookup, request-body poll or leaf invocation.
        pool: sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://fixture:fixture@192.0.2.1:1/fixture")
            .unwrap(),
    });
    let app = connect_router_with_auth(routes(&probe), auth);
    for (method, content_type, expected) in [
        (
            "UpdateEnvironmentCwRuntime",
            "application/grpc",
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
        ),
        (
            "UpdateEnvironmentCwRuntime",
            "application/grpc-web+proto",
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
        ),
        (
            "GetEnvironmentCwRuntime",
            "application/proto",
            StatusCode::UNAUTHORIZED,
        ),
        // Connect streaming errors use a final error frame on HTTP200;
        // validate that exact error rather than treating 200 as success.
        (
            "UpdateEnvironmentCwRuntime",
            "application/connect+proto",
            StatusCode::OK,
        ),
    ] {
        let polls = Arc::new(AtomicUsize::new(0));
        let observed = polls.clone();
        let body = Body::from_stream(stream::once(async move {
            observed.fetch_add(1, Ordering::SeqCst);
            Ok::<_, Infallible>(Bytes::from_static(b"must not be read"))
        }));
        let response = app
            .clone()
            .oneshot(request(method, content_type, body, false))
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
        if content_type == "application/connect+proto" {
            let body = to_bytes(response.into_body(), 32 * 1024).await.unwrap();
            assert_eq!(body[0], 2);
            assert_eq!(
                u32::from_be_bytes(body[1..5].try_into().unwrap()) as usize,
                body.len() - 5
            );
            let error: serde_json::Value = serde_json::from_slice(&body[5..]).unwrap();
            assert_eq!(error["error"]["code"], "unauthenticated");
        }
        assert_eq!(polls.load(Ordering::SeqCst), 0);
    }
    assert_eq!(probe.calls.load(Ordering::SeqCst), 0);
    assert_eq!(probe.frames.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn actual_unary_and_stream_message_limits_refuse_oversized_payloads() {
    let probe = Arc::new(Probe::default());
    let app = connect_router(routes(&probe));
    let unary = proto::GetEnvironmentCwRuntimeRequest {
        org_id: "x".repeat(32 * 1024 + 1),
        ..Default::default()
    };
    let response = app
        .clone()
        .oneshot(request(
            "GetEnvironmentCwRuntime",
            "application/proto",
            Body::from(unary.encode_to_vec()),
            true,
        ))
        .await
        .unwrap();
    let body = to_bytes(response.into_body(), 32 * 1024).await.unwrap();
    assert!(String::from_utf8_lossy(&body).contains("resource_exhausted"));
    assert_eq!(probe.calls.load(Ordering::SeqCst), 0);
    let oversized = proto::UpdateEnvironmentCwRuntimeRequest {
        payload: Some(
            proto::update_environment_cw_runtime_request::Payload::Chunk(vec![0; 64 * 1024 + 1025]),
        ),
        ..Default::default()
    };
    let response = app
        .oneshot(request(
            "UpdateEnvironmentCwRuntime",
            "application/connect+proto",
            Body::from(frame(&oversized)),
            true,
        ))
        .await
        .unwrap();
    let body = to_bytes(response.into_body(), 32 * 1024).await.unwrap();
    assert!(String::from_utf8_lossy(&body).contains("resource_exhausted"));
    assert_eq!(probe.frames.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn binary_connect_stream_preserves_uint64_and_accepts_only_bounded_frames() {
    let probe = Arc::new(Probe::default());
    let app = connect_router(routes(&probe));
    let header = proto::UpdateEnvironmentCwRuntimeRequest {
        payload: Some(
            proto::update_environment_cw_runtime_request::Payload::Header(Box::new(
                proto::UpdateEnvironmentCwRuntimeHeader {
                    expected_selection: Some(proto::EnvironmentCwRuntimeExpectation {
                        generation: u64::MAX,
                        ..Default::default()
                    })
                    .into(),
                    ..Default::default()
                },
            )),
        ),
        ..Default::default()
    };
    let chunk = proto::UpdateEnvironmentCwRuntimeRequest {
        payload: Some(
            proto::update_environment_cw_runtime_request::Payload::Chunk(vec![0; 64 * 1024]),
        ),
        ..Default::default()
    };
    let mut body = frame(&header);
    body.extend_from_slice(&frame(&chunk));
    let response = app
        .oneshot(request(
            "UpdateEnvironmentCwRuntime",
            "application/connect+proto",
            Body::from(body),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 32 * 1024).await.unwrap();
    assert!(!String::from_utf8_lossy(&body).contains("\"error\""));
    assert_eq!(probe.calls.load(Ordering::SeqCst), 1);
    assert_eq!(probe.frames.load(Ordering::SeqCst), 2);
    assert_eq!(probe.generation.load(Ordering::SeqCst), u64::MAX);
}
