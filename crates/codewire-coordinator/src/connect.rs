//! Native Connect-RPC adapter for the shared coordinator peer session.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use axum::body::to_bytes;
use axum::http::{HeaderMap, StatusCode};
use codewire_proto::codewire::internal::v1::{
    CoordinateDerpMap as DerpMap, CoordinateHello as Hello, CoordinateNode,
    CoordinatePeerRemove as PeerRemove, CoordinatePeerUpdate as PeerUpdate, CoordinatePing as Ping,
    CoordinateRequest, CoordinateResponse, CoordinatorService, coordinate_request,
};
use codewire_server_core::auth::{AuthState, authenticate_headers_with_context};
use codewire_server_core::connect::app_error_to_wire;
use connectrpc::{ConnectError, InboundStream, RequestContext, ServiceResult, ServiceStream};
use futures_util::StreamExt;
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::session::{
    SessionInput, SessionOutput, SessionPeer, SessionSink, SessionSource, run_peer_session,
};
use crate::{
    CoordinationPlane, CoordinatorState, PeerEvent, PeerKind, PeerRegistry, SCOPE_COORDINATE,
    Transport, authorize_client, authorize_sidecar, bearer_token, sidecar_token,
};

pub(crate) fn router(state: CoordinatorState, auth: AuthState) -> axum::Router {
    router_with_authorizer(
        state.clone(),
        Arc::new(ProductionAuthorizer { state, auth }),
    )
}

fn router_with_authorizer(
    state: CoordinatorState,
    authorizer: Arc<dyn CoordinateAuthorizer>,
) -> axum::Router {
    let connect = connectrpc::Router::new().add_service(Arc::new(CoordinateService {
        peers: state.peers,
        coordination: state.coordination,
        authorizer,
    }));
    codewire_server_core::connect::connect_router_with_protocol_policy(
        connect,
        codewire_server_core::connect::ProtocolPolicy::ConnectAndGrpc,
    )
}

#[derive(Clone, Copy)]
struct AuthorizedPeer {
    peer_id: Uuid,
    sidecar_id: Option<Uuid>,
    kind: PeerKind,
}

type AuthorizationFuture<'a> =
    Pin<Box<dyn Future<Output = Result<AuthorizedPeer, ConnectError>> + Send + 'a>>;

trait CoordinateAuthorizer: Send + Sync {
    fn authorize<'a>(&'a self, ctx: &'a RequestContext, hello: Hello) -> AuthorizationFuture<'a>;
}

struct ProductionAuthorizer {
    state: CoordinatorState,
    auth: AuthState,
}

impl CoordinateAuthorizer for ProductionAuthorizer {
    fn authorize<'a>(&'a self, ctx: &'a RequestContext, hello: Hello) -> AuthorizationFuture<'a> {
        Box::pin(async move {
            let request_id = ctx
                .headers()
                .get("x-request-id")
                .and_then(|value| value.to_str().ok());
            self.authorize(ctx.headers(), request_id, hello).await
        })
    }
}

impl ProductionAuthorizer {
    async fn authorize(
        &self,
        headers: &HeaderMap,
        request_id: Option<&str>,
        hello: Hello,
    ) -> Result<AuthorizedPeer, ConnectError> {
        if hello.environment_id.trim().is_empty() {
            return Err(ConnectError::invalid_argument(
                "hello.environment_id is required",
            ));
        }

        let bearer = bearer_token(headers);
        if let Some((token, claims)) = bearer.and_then(|token| {
            sidecar_token::validate(&self.state.session_secret, token)
                .ok()
                .map(|claims| (token, claims))
        }) {
            if !hello.org_id.trim().is_empty() {
                return Err(ConnectError::invalid_argument(
                    "sidecar hello must not include org_id",
                ));
            }
            if claims.scope != SCOPE_COORDINATE {
                return Err(ConnectError::permission_denied(
                    "invalid sidecar token scope",
                ));
            }
            if claims.environment_id != hello.environment_id {
                return Err(ConnectError::permission_denied(
                    "hello environment does not match sidecar token",
                ));
            }
            let environment_id = Uuid::parse_str(&hello.environment_id)
                .map_err(|_| ConnectError::invalid_argument("invalid environment id"))?;
            if let Err(response) = authorize_sidecar(&self.state, environment_id, token).await {
                return Err(response_to_connect_error(response).await);
            }
            return Ok(AuthorizedPeer {
                peer_id: environment_id,
                sidecar_id: None,
                kind: PeerKind::Sidecar,
            });
        }

        if hello.org_id.trim().is_empty() {
            return Err(ConnectError::invalid_argument(
                "client hello must include org_id",
            ));
        }
        let authentication = authenticate_headers_with_context(&self.auth, headers)
            .await
            .map_err(|error| app_error_to_wire(&error, request_id))?;
        let environment_id = match authorize_client(
            &self.state,
            &authentication,
            hello.org_id.trim(),
            hello.environment_id.trim(),
        )
        .await
        {
            Ok(environment_id) => environment_id,
            Err(response) => return Err(response_to_connect_error(response).await),
        };
        Ok(AuthorizedPeer {
            peer_id: Uuid::new_v4(),
            sidecar_id: Some(environment_id),
            kind: PeerKind::Client,
        })
    }
}

async fn response_to_connect_error(response: axum::response::Response) -> ConnectError {
    let status = response.status();
    let body = to_bytes(response.into_body(), 64 * 1024)
        .await
        .unwrap_or_default();
    let text = String::from_utf8_lossy(&body);
    let message = serde_json::from_slice::<serde_json::Value>(&body)
        .ok()
        .and_then(|value| value.get("error")?.as_str().map(str::to_owned))
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| {
            let text = text.trim();
            if text.is_empty() {
                status
                    .canonical_reason()
                    .unwrap_or("request failed")
                    .to_owned()
            } else {
                text.to_owned()
            }
        });

    match status {
        StatusCode::UNAUTHORIZED => ConnectError::unauthenticated(message),
        StatusCode::FORBIDDEN => ConnectError::permission_denied(message),
        StatusCode::NOT_FOUND => ConnectError::not_found(message),
        StatusCode::BAD_REQUEST if message == "environment must be running" => {
            ConnectError::failed_precondition(message)
        }
        StatusCode::BAD_REQUEST => ConnectError::invalid_argument(message),
        status if status.is_server_error() => ConnectError::internal("internal error"),
        _ => ConnectError::internal("internal error"),
    }
}

struct CoordinateService {
    peers: Arc<PeerRegistry>,
    coordination: Option<Arc<CoordinationPlane>>,
    authorizer: Arc<dyn CoordinateAuthorizer>,
}

#[allow(refining_impl_trait)]
impl CoordinatorService for CoordinateService {
    async fn coordinate(
        &self,
        ctx: RequestContext,
        mut requests: InboundStream<CoordinateRequest>,
    ) -> ServiceResult<ServiceStream<CoordinateResponse>> {
        let first = requests
            .next()
            .await
            .ok_or_else(|| ConnectError::invalid_argument("hello is required"))??
            .to_owned_message();
        let hello = match first.msg {
            Some(coordinate_request::Msg::Hello(hello)) => *hello,
            _ => {
                return Err(ConnectError::invalid_argument(
                    "hello must be the first message",
                ));
            }
        };
        let peer = self.authorizer.authorize(&ctx, hello).await?;

        let (tx, rx) = mpsc::channel(16);
        let session = run_peer_session(
            ConnectSource {
                requests,
                peer_id: peer.peer_id,
            },
            ConnectSink {
                tx,
                peer_id: peer.peer_id,
            },
            self.peers.clone(),
            self.coordination.clone(),
            SessionPeer {
                peer_id: peer.peer_id,
                sidecar_id: peer.sidecar_id,
                kind: peer.kind,
                transport: Transport::Connect,
            },
        );
        tokio::spawn(session);

        let output = futures_util::stream::unfold(rx, |mut rx| async move {
            rx.recv().await.map(|item| (item, rx))
        });
        connectrpc::Response::stream_ok(output)
    }
}

struct ConnectSource {
    requests: InboundStream<CoordinateRequest>,
    peer_id: Uuid,
}

impl SessionSource for ConnectSource {
    async fn next(&mut self) -> Option<SessionInput> {
        match self.requests.next().await {
            Some(Ok(request)) => match request.to_owned_message().msg {
                Some(coordinate_request::Msg::Node(node)) => match proto_node_to_tailnet(*node) {
                    Ok(node) => Some(SessionInput::Node(node)),
                    Err(err) => {
                        tracing::warn!(error = ?err, peer_id = %self.peer_id, "coordinator Connect node decode failed");
                        Some(SessionInput::Noop)
                    }
                },
                Some(coordinate_request::Msg::Ping(_)) => Some(SessionInput::Ping),
                Some(coordinate_request::Msg::Hello(_)) | None => Some(SessionInput::Noop),
            },
            Some(Err(err)) => {
                tracing::warn!(error = ?err, peer_id = %self.peer_id, "coordinator Connect stream read failed");
                None
            }
            None => None,
        }
    }
}

struct ConnectSink {
    tx: mpsc::Sender<Result<CoordinateResponse, ConnectError>>,
    peer_id: Uuid,
}

impl SessionSink for ConnectSink {
    async fn send(&mut self, output: SessionOutput) -> bool {
        let response = session_output_to_proto(output);
        if let Err(err) = &response {
            tracing::warn!(error = ?err, peer_id = %self.peer_id, "coordinator Connect response encode failed");
        }
        self.tx.send(response).await.is_ok()
    }
}

fn session_output_to_proto(output: SessionOutput) -> Result<CoordinateResponse, ConnectError> {
    let msg = match output {
        SessionOutput::DerpMap(value) => DerpMap {
            derp_map_json: serde_json::to_vec(&value)
                .map_err(|_| ConnectError::internal("encode DERP map"))?,
            ..Default::default()
        }
        .into(),
        SessionOutput::Peer(PeerEvent::Update(nodes)) => PeerUpdate {
            nodes: nodes
                .into_iter()
                .map(tailnet_node_to_proto)
                .collect::<Result<_, _>>()?,
            ..Default::default()
        }
        .into(),
        SessionOutput::Peer(PeerEvent::Remove(peer_id)) => PeerRemove {
            peer_id: peer_id.to_string(),
            ..Default::default()
        }
        .into(),
        SessionOutput::Heartbeat => Ping::default().into(),
    };
    Ok(CoordinateResponse {
        msg,
        ..Default::default()
    })
}

fn proto_node_to_tailnet(
    node: CoordinateNode,
) -> Result<codewire_tailnet::node::Node, ConnectError> {
    let mut value =
        serde_json::to_value(node).map_err(|_| ConnectError::invalid_argument("invalid node"))?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| ConnectError::invalid_argument("invalid node"))?;
    for (proto, tailnet) in [
        ("asOf", "as_of"),
        ("discoKey", "disco_key"),
        ("preferredDerp", "preferred_derp"),
        ("derpLatency", "derp_latency"),
    ] {
        if let Some(value) = object.remove(proto) {
            object.insert(tailnet.to_owned(), value);
        }
    }
    object
        .entry("endpoints".to_owned())
        .or_insert_with(|| serde_json::Value::Array(Vec::new()));
    object
        .entry("addresses".to_owned())
        .or_insert_with(|| serde_json::Value::Array(Vec::new()));
    serde_json::from_value(value).map_err(|_| ConnectError::invalid_argument("invalid node"))
}

fn tailnet_node_to_proto(
    node: codewire_tailnet::node::Node,
) -> Result<CoordinateNode, ConnectError> {
    serde_json::from_value(
        serde_json::to_value(node).map_err(|_| ConnectError::internal("encode node"))?,
    )
    .map_err(|_| ConnectError::internal("encode node"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::response::IntoResponse;
    use base64::Engine;
    use codewire_proto::codewire::internal::v1::{
        CoordinateNode as ProtoNode, CoordinatorServiceClient, coordinate_response,
    };
    use codewire_server_core::auth::{
        api_key_prefix, authenticate_headers, generate_api_key, hash_api_key, hash_oauth_token,
    };
    use codewire_tailnet::node::{DiscoPublic, NodePublic, prefix_from_uuid};
    use connectrpc::Protocol;
    use connectrpc::client::{ClientConfig, HttpClient};
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    use sqlx::postgres::PgPoolOptions;
    use tokio::task::JoinHandle;

    struct HermeticAuthorizer;

    impl CoordinateAuthorizer for HermeticAuthorizer {
        fn authorize<'a>(
            &'a self,
            _ctx: &'a RequestContext,
            hello: Hello,
        ) -> AuthorizationFuture<'a> {
            Box::pin(async move {
                let environment_id = Uuid::parse_str(&hello.environment_id)
                    .map_err(|_| ConnectError::invalid_argument("invalid environment id"))?;
                if hello.org_id.is_empty() {
                    Ok(AuthorizedPeer {
                        peer_id: environment_id,
                        sidecar_id: None,
                        kind: PeerKind::Sidecar,
                    })
                } else {
                    Ok(AuthorizedPeer {
                        peer_id: Uuid::new_v4(),
                        sidecar_id: Some(environment_id),
                        kind: PeerKind::Client,
                    })
                }
            })
        }
    }

    fn lazy_state() -> (CoordinatorState, AuthState) {
        let pool = PgPoolOptions::new()
            .connect_lazy("postgres://codewire:codewire@127.0.0.1:1/codewire")
            .unwrap();
        (
            CoordinatorState::new(pool.clone(), "secret".into()),
            AuthState { pool },
        )
    }

    async fn start_hermetic_app() -> (std::net::SocketAddr, JoinHandle<()>) {
        let (state, _) = lazy_state();
        start_hermetic_app_with_state(state).await
    }

    async fn start_hermetic_app_with_state(
        state: CoordinatorState,
    ) -> (std::net::SocketAddr, JoinHandle<()>) {
        let routes = router_with_authorizer(state, Arc::new(HermeticAuthorizer));
        let app = codewire_server_core::AppBuilder::new("coordinator-connect-test")
            .with_routes(routes)
            .into_router();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            codewire_server_core::serve_with_listener_h2_keepalive(
                app,
                listener,
                codewire_server_core::Http2KeepaliveConfig::new(
                    std::time::Duration::from_secs(15),
                    std::time::Duration::from_secs(20),
                ),
            )
            .await
            .unwrap();
        });
        (addr, task)
    }

    async fn start_production_auth_app(
        pool: sqlx::PgPool,
    ) -> (std::net::SocketAddr, JoinHandle<()>) {
        let state = CoordinatorState::new(pool.clone(), "protocol-parity-secret".into());
        let app = codewire_server_core::AppBuilder::new("coordinator-production-auth-parity-test")
            .with_routes(router(state, AuthState { pool }))
            .into_router();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            codewire_server_core::serve_with_listener_h2_keepalive(
                app,
                listener,
                codewire_server_core::Http2KeepaliveConfig::new(
                    std::time::Duration::from_secs(15),
                    std::time::Duration::from_secs(20),
                ),
            )
            .await
            .unwrap();
        });
        (addr, task)
    }

    struct ProductionAuthFixtures {
        user_id: String,
        org_a: String,
        org_b: String,
        env_a: Uuid,
        env_b: Uuid,
        preset_id: String,
        session_token: String,
        api_key: String,
        oidc_token: String,
        identity_oidc_token: String,
        oidc_client_id: String,
    }

    async fn seed_production_auth_fixtures(pool: &sqlx::PgPool) -> ProductionAuthFixtures {
        let ns = Uuid::new_v4().simple().to_string();
        let user_id = format!("u_coord_protocol_{ns}");
        let org_a = format!("org_coord_protocol_a_{ns}");
        let org_b = format!("org_coord_protocol_b_{ns}");
        let preset_id = format!("preset_coord_protocol_{ns}");
        let session_token = format!("session_coord_protocol_{ns}");
        let oidc_token = format!("opaque_coord_protocol_{ns}");
        let identity_oidc_token = format!("identity_coord_protocol_{ns}");
        let oidc_client_id = format!("client_coord_protocol_{ns}");
        let env_a = Uuid::new_v4();
        let env_b = Uuid::new_v4();

        sqlx::query(
            "INSERT INTO users (id, email, name, email_verified, is_admin) \
             VALUES ($1, $2, $3, true, false)",
        )
        .bind(&user_id)
        .bind(format!("{ns}@coordinator-protocol.test"))
        .bind("Coordinator protocol parity")
        .execute(pool)
        .await
        .unwrap();

        for (org_id, suffix) in [(&org_a, "a"), (&org_b, "b")] {
            sqlx::query(
                "INSERT INTO organizations (id, name, slug, created_by) VALUES ($1, $2, $3, $4)",
            )
            .bind(org_id)
            .bind(format!("Coordinator protocol {suffix} {ns}"))
            .bind(format!("coord-{suffix}-{ns}"))
            .bind(&user_id)
            .execute(pool)
            .await
            .unwrap();
            sqlx::query(
                "INSERT INTO org_members (id, org_id, user_id, role) VALUES ($1, $2, $3, 'owner')",
            )
            .bind(format!("om_coord_protocol_{suffix}_{ns}"))
            .bind(org_id)
            .bind(&user_id)
            .execute(pool)
            .await
            .unwrap();
        }

        sqlx::query(
            r#"INSERT INTO environment_presets (id, name, slug, official, project_spec)
               VALUES ($1, $2, $3, true,
                       '{"schema_version":1,"working_directory":"/workspace"}'::jsonb)"#,
        )
        .bind(&preset_id)
        .bind(format!("Coordinator protocol {ns}"))
        .bind(format!("coord-protocol-{ns}"))
        .execute(pool)
        .await
        .unwrap();

        for (environment_id, org_id, suffix) in [(env_a, &org_a, "a"), (env_b, &org_b, "b")] {
            sqlx::query(
                r#"INSERT INTO environments
                   (id, org_id, created_by, type, name, state, preset_id, project_spec)
                   VALUES ($1, $2, $3, 'sandbox', $4, 'running', $5,
                           '{"schema_version":1,"working_directory":"/workspace"}'::jsonb)"#,
            )
            .bind(environment_id.to_string())
            .bind(org_id)
            .bind(&user_id)
            .bind(format!("Coordinator protocol {suffix}"))
            .bind(&preset_id)
            .execute(pool)
            .await
            .unwrap();
        }

        sqlx::query(
            "INSERT INTO sessions (id, user_id, expires_at, token_hash) \
             VALUES ($1, $2, NOW() + interval '1 hour', $3)",
        )
        .bind(format!("session_coord_protocol_{ns}"))
        .bind(&user_id)
        .bind(codewire_server_core::auth::hash_session_token(
            &session_token,
        ))
        .execute(pool)
        .await
        .unwrap();

        let api_key = generate_api_key();
        sqlx::query(
            "INSERT INTO api_keys (id, user_id, org_id, name, key_hash, key_prefix) \
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(format!("api_key_coord_protocol_{ns}"))
        .bind(&user_id)
        .bind(&org_a)
        .bind(format!("Coordinator protocol {ns}"))
        .bind(hash_api_key(&api_key))
        .bind(api_key_prefix(&api_key))
        .execute(pool)
        .await
        .unwrap();

        sqlx::query(
            "INSERT INTO oidc_clients \
             (id, name, application_type, auth_method, redirect_uris) \
             VALUES ($1, $2, 'native', 'none', ARRAY['http://localhost/callback'])",
        )
        .bind(&oidc_client_id)
        .bind(format!("Coordinator protocol {ns}"))
        .execute(pool)
        .await
        .unwrap();
        for (raw, scopes) in [
            (&oidc_token, vec!["openid", "codewire.api"]),
            (&identity_oidc_token, vec!["openid"]),
        ] {
            sqlx::query(
                "INSERT INTO oidc_access_tokens \
                 (token_hash, client_id, user_id, scopes, expires_at) \
                 VALUES ($1, $2, $3, $4, NOW() + interval '1 hour')",
            )
            .bind(hash_oauth_token(raw))
            .bind(&oidc_client_id)
            .bind(&user_id)
            .bind(scopes)
            .execute(pool)
            .await
            .unwrap();
        }

        ProductionAuthFixtures {
            user_id,
            org_a,
            org_b,
            env_a,
            env_b,
            preset_id,
            session_token,
            api_key,
            oidc_token,
            identity_oidc_token,
            oidc_client_id,
        }
    }

    async fn clean_production_auth_fixtures(
        pool: &sqlx::PgPool,
        fixtures: &ProductionAuthFixtures,
    ) {
        for environment_id in [fixtures.env_a, fixtures.env_b] {
            sqlx::query("DELETE FROM environments WHERE id = $1")
                .bind(environment_id.to_string())
                .execute(pool)
                .await
                .unwrap();
        }
        sqlx::query("DELETE FROM api_keys WHERE user_id = $1")
            .bind(&fixtures.user_id)
            .execute(pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM sessions WHERE user_id = $1")
            .bind(&fixtures.user_id)
            .execute(pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM oidc_access_tokens WHERE user_id = $1")
            .bind(&fixtures.user_id)
            .execute(pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM oidc_clients WHERE id = $1")
            .bind(&fixtures.oidc_client_id)
            .execute(pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM environment_presets WHERE id = $1")
            .bind(&fixtures.preset_id)
            .execute(pool)
            .await
            .unwrap();
        for org_id in [&fixtures.org_a, &fixtures.org_b] {
            sqlx::query("DELETE FROM org_members WHERE org_id = $1")
                .bind(org_id)
                .execute(pool)
                .await
                .unwrap();
            sqlx::query("DELETE FROM organizations WHERE id = $1")
                .bind(org_id)
                .execute(pool)
                .await
                .unwrap();
        }
        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(&fixtures.user_id)
            .execute(pool)
            .await
            .unwrap();
    }

    fn h2c_client(addr: std::net::SocketAddr) -> CoordinatorServiceClient<HttpClient> {
        h2c_client_with_protocol(addr, Protocol::Connect)
    }

    fn h2c_client_with_protocol(
        addr: std::net::SocketAddr,
        protocol: Protocol,
    ) -> CoordinatorServiceClient<HttpClient> {
        CoordinatorServiceClient::new(
            HttpClient::plaintext_http2_only(),
            ClientConfig::new(format!("http://{addr}").parse().unwrap()).with_protocol(protocol),
        )
    }

    fn h2c_client_with_protocol_and_headers(
        addr: std::net::SocketAddr,
        protocol: Protocol,
        headers: HeaderMap,
    ) -> CoordinatorServiceClient<HttpClient> {
        let config = ClientConfig::new(format!("http://{addr}").parse().unwrap())
            .with_protocol(protocol)
            .with_default_headers(headers);
        CoordinatorServiceClient::new(HttpClient::plaintext_http2_only(), config)
    }

    fn request(message: impl Into<Option<coordinate_request::Msg>>) -> CoordinateRequest {
        CoordinateRequest {
            msg: message.into(),
            ..Default::default()
        }
    }

    async fn next_response(
        stream: &mut connectrpc::client::BidiStream<
            <HttpClient as connectrpc::client::ClientTransport>::ResponseBody,
            CoordinateRequest,
            codewire_proto::codewire::internal::v1::CoordinateResponseView<'static>,
        >,
    ) -> CoordinateResponse {
        let message: connectrpc::StreamMessage<CoordinateResponse> =
            tokio::time::timeout(std::time::Duration::from_secs(5), stream.message())
                .await
                .expect("Connect response timed out")
                .expect("Connect response failed")
                .expect("Connect response ended");
        message.to_owned_message()
    }

    fn sign_sidecar_token(secret: &str, environment_id: &str, scope: &str) -> String {
        let payload = serde_json::to_vec(&serde_json::json!({
            "environment_id": environment_id,
            "scope": scope,
        }))
        .unwrap();
        let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let payload = engine.encode(payload);
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(payload.as_bytes());
        format!("{payload}.{}", engine.encode(mac.finalize().into_bytes()))
    }

    #[tokio::test]
    async fn authorization_response_codes_follow_d3() {
        let cases = [
            (
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                connectrpc::ErrorCode::Unauthenticated,
            ),
            (
                StatusCode::FORBIDDEN,
                "access denied",
                connectrpc::ErrorCode::PermissionDenied,
            ),
            (
                StatusCode::NOT_FOUND,
                "environment not found",
                connectrpc::ErrorCode::NotFound,
            ),
            (
                StatusCode::BAD_REQUEST,
                "environment must be running",
                connectrpc::ErrorCode::FailedPrecondition,
            ),
            (
                StatusCode::BAD_REQUEST,
                "invalid environment id",
                connectrpc::ErrorCode::InvalidArgument,
            ),
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "database exploded",
                connectrpc::ErrorCode::Internal,
            ),
        ];
        for (status, message, expected) in cases {
            let error = response_to_connect_error((status, message).into_response()).await;
            assert_eq!(error.code, expected, "{status} {message}");
        }
    }

    #[tokio::test]
    async fn coordinator_rejects_a_daemon_scoped_capability() {
        let (state, auth) = lazy_state();
        let authorizer = ProductionAuthorizer { state, auth };
        let environment_id = Uuid::new_v4().to_string();
        let daemon_scope = sign_sidecar_token("secret", &environment_id, "daemon");

        let error = match authorizer
            .authorize(
                &headers_with_bearer(&daemon_scope),
                None,
                Hello {
                    environment_id,
                    ..Default::default()
                },
            )
            .await
        {
            Err(error) => error,
            Ok(_) => panic!("daemon capability unexpectedly authorized coordinator access"),
        };
        assert_eq!(error.code, connectrpc::ErrorCode::PermissionDenied);
    }

    #[tokio::test]
    async fn production_credential_dispatch_rejects_with_d3_codes_without_db() {
        let (state, auth) = lazy_state();
        let authorizer = ProductionAuthorizer { state, auth };
        let environment_id = Uuid::new_v4().to_string();
        let sidecar = sign_sidecar_token("secret", &environment_id, SCOPE_COORDINATE);
        let daemon_scope = sign_sidecar_token("secret", &environment_id, "daemon");
        let other_environment = Uuid::new_v4().to_string();

        let cases = [
            (
                HeaderMap::new(),
                Hello {
                    org_id: "org-1".into(),
                    environment_id: environment_id.clone(),
                    ..Default::default()
                },
                connectrpc::ErrorCode::Unauthenticated,
            ),
            (
                headers_with_bearer(&daemon_scope),
                Hello {
                    environment_id: environment_id.clone(),
                    ..Default::default()
                },
                connectrpc::ErrorCode::PermissionDenied,
            ),
            (
                headers_with_bearer(&sidecar),
                Hello {
                    environment_id: other_environment,
                    ..Default::default()
                },
                connectrpc::ErrorCode::PermissionDenied,
            ),
            (
                headers_with_bearer(&sidecar),
                Hello {
                    org_id: "org-1".into(),
                    environment_id: environment_id.clone(),
                    ..Default::default()
                },
                connectrpc::ErrorCode::InvalidArgument,
            ),
        ];

        for (headers, hello, expected) in cases {
            let error = match authorizer.authorize(&headers, None, hello).await {
                Err(error) => error,
                Ok(_) => panic!("authorization unexpectedly succeeded"),
            };
            assert_eq!(error.code, expected);
        }
    }

    #[derive(Debug, PartialEq)]
    enum ProductionAuthOutcome {
        DerpMap,
        Error {
            code: connectrpc::ErrorCode,
            message: Option<String>,
            details: serde_json::Value,
        },
    }

    async fn production_auth_outcome(
        pool: sqlx::PgPool,
        protocol: Protocol,
        headers: HeaderMap,
        org_id: &str,
        environment_id: Uuid,
    ) -> ProductionAuthOutcome {
        let (addr, server) = start_production_auth_app(pool).await;
        let mut stream = h2c_client_with_protocol_and_headers(addr, protocol, headers)
            .coordinate()
            .await
            .unwrap();
        stream
            .send(request(Hello {
                org_id: org_id.into(),
                environment_id: environment_id.to_string(),
                ..Default::default()
            }))
            .await
            .unwrap();
        stream.close_send();
        let outcome = match tokio::time::timeout(
            std::time::Duration::from_secs(5),
            stream.message::<CoordinateResponse>(),
        )
        .await
        .expect("production auth response timed out")
        {
            Ok(Some(message)) => {
                assert!(matches!(
                    message.to_owned_message().msg,
                    Some(coordinate_response::Msg::DerpMap(_))
                ));
                ProductionAuthOutcome::DerpMap
            }
            Ok(None) => panic!("production auth stream closed before DERP map"),
            Err(error) => ProductionAuthOutcome::Error {
                code: error.code,
                message: error.message,
                details: serde_json::to_value(error.details).unwrap(),
            },
        };
        server.abort();
        outcome
    }

    fn session_headers(token: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            format!("codewire.session_token={token}").parse().unwrap(),
        );
        headers
    }

    #[tokio::test]
    async fn production_user_credentials_match_for_connect_and_grpc() {
        let Ok(database_url) = std::env::var("DATABASE_URL") else {
            eprintln!(
                "DATABASE_URL unset — skipping coordinator production credential protocol matrix"
            );
            return;
        };
        let pool = sqlx::PgPool::connect(&database_url).await.unwrap();
        let fixtures = seed_production_auth_fixtures(&pool).await;

        assert!(fixtures.api_key.starts_with("cw_"));
        assert_eq!(fixtures.api_key.len(), 67);
        let api_user = authenticate_headers(
            &AuthState { pool: pool.clone() },
            &headers_with_bearer(&fixtures.api_key),
        )
        .await
        .unwrap();
        assert_eq!(api_user.org_id.as_deref(), Some(fixtures.org_a.as_str()));

        let success_cases = [
            (
                "session org A",
                session_headers(&fixtures.session_token),
                fixtures.org_a.as_str(),
                fixtures.env_a,
            ),
            (
                "org-scoped API key org A",
                headers_with_bearer(&fixtures.api_key),
                fixtures.org_a.as_str(),
                fixtures.env_a,
            ),
            (
                "opaque OIDC bearer org A",
                headers_with_bearer(&fixtures.oidc_token),
                fixtures.org_a.as_str(),
                fixtures.env_a,
            ),
            (
                "session org B control",
                session_headers(&fixtures.session_token),
                fixtures.org_b.as_str(),
                fixtures.env_b,
            ),
        ];
        for (label, headers, org_id, environment_id) in success_cases {
            let connect = production_auth_outcome(
                pool.clone(),
                Protocol::Connect,
                headers.clone(),
                org_id,
                environment_id,
            )
            .await;
            let grpc = production_auth_outcome(
                pool.clone(),
                Protocol::Grpc,
                headers,
                org_id,
                environment_id,
            )
            .await;
            assert_eq!(connect, ProductionAuthOutcome::DerpMap, "{label}");
            assert_eq!(grpc, connect, "{label}");
        }

        for protocol in [Protocol::Connect, Protocol::Grpc] {
            let outcome = production_auth_outcome(
                pool.clone(),
                protocol,
                headers_with_bearer(&fixtures.identity_oidc_token),
                &fixtures.org_a,
                fixtures.env_a,
            )
            .await;
            let ProductionAuthOutcome::Error {
                code,
                message,
                details,
            } = outcome
            else {
                panic!("identity-only OIDC token reached coordinator product authorization");
            };
            assert_eq!(code, connectrpc::ErrorCode::PermissionDenied);
            assert_eq!(
                message.as_deref(),
                Some("OIDC access token lacks required codewire.api scope")
            );
            if protocol == Protocol::Connect {
                let details = details.as_array().expect("Connect error details");
                assert_eq!(details.len(), 1, "{protocol:?} details: {details:?}");
                assert_eq!(details[0]["type"], "google.rpc.ErrorInfo");
                assert!(
                    details[0]["value"]
                        .as_str()
                        .is_some_and(|value| !value.is_empty()),
                    "canonical ErrorInfo must carry encoded reason/hint metadata"
                );
            }
        }

        let wrong_org_headers = headers_with_bearer(&fixtures.api_key);
        let connect = production_auth_outcome(
            pool.clone(),
            Protocol::Connect,
            wrong_org_headers.clone(),
            &fixtures.org_b,
            fixtures.env_b,
        )
        .await;
        let grpc = production_auth_outcome(
            pool.clone(),
            Protocol::Grpc,
            wrong_org_headers,
            &fixtures.org_b,
            fixtures.env_b,
        )
        .await;
        let expected = ProductionAuthOutcome::Error {
            code: connectrpc::ErrorCode::NotFound,
            message: Some("organization not found".into()),
            details: serde_json::json!([]),
        };
        assert_eq!(connect, expected);
        assert_eq!(grpc, connect);

        clean_production_auth_fixtures(&pool, &fixtures).await;
    }

    fn headers_with_bearer(token: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );
        headers
    }

    #[test]
    fn proto_node_boundary_round_trips_tailnet_shape() {
        let id = Uuid::new_v4();
        let node = codewire_tailnet::node::Node {
            id,
            as_of: "2026-07-11T12:00:00Z".parse().unwrap(),
            key: NodePublic::from_raw([0x11; 32]),
            disco_key: DiscoPublic::from_raw([0x22; 32]),
            preferred_derp: 7,
            derp_latency: None,
            endpoints: vec![],
            addresses: vec![prefix_from_uuid(&id)],
        };
        let proto = tailnet_node_to_proto(node.clone()).unwrap();
        let roundtrip = proto_node_to_tailnet(proto).unwrap();
        assert_eq!(
            serde_json::to_value(roundtrip).unwrap(),
            serde_json::to_value(node).unwrap()
        );
    }

    #[test]
    fn malformed_proto_node_is_invalid_argument() {
        let error = proto_node_to_tailnet(ProtoNode {
            id: "not-a-uuid".into(),
            ..Default::default()
        })
        .unwrap_err();
        assert_eq!(error.code, connectrpc::ErrorCode::InvalidArgument);
    }

    #[test]
    fn session_heartbeat_is_a_typed_ping() {
        let response = session_output_to_proto(SessionOutput::Heartbeat).unwrap();
        assert!(matches!(
            response.msg,
            Some(coordinate_response::Msg::Ping(_))
        ));
    }

    #[tokio::test]
    async fn first_non_hello_error_is_identical_for_connect_and_grpc() {
        let mut outcomes = Vec::new();
        for protocol in [Protocol::Connect, Protocol::Grpc] {
            let (addr, server) = start_hermetic_app().await;
            let mut stream = h2c_client_with_protocol(addr, protocol)
                .coordinate()
                .await
                .unwrap();
            stream.send(request(ProtoNode::default())).await.unwrap();
            stream.close_send();
            let error = stream.message::<CoordinateResponse>().await.unwrap_err();
            assert_eq!(error.code, connectrpc::ErrorCode::InvalidArgument);
            outcomes.push((
                error.code,
                error.message,
                serde_json::to_value(error.details).unwrap(),
            ));
            server.abort();
        }
        assert_eq!(outcomes[0], outcomes[1]);
    }

    #[tokio::test]
    async fn empty_stream_requires_hello() {
        let (addr, server) = start_hermetic_app().await;
        let mut stream = h2c_client(addr).coordinate().await.unwrap();
        stream.close_send();
        let error = stream.message::<CoordinateResponse>().await.unwrap_err();
        assert_eq!(error.code, connectrpc::ErrorCode::InvalidArgument);
        server.abort();
    }

    #[tokio::test]
    async fn connect_and_grpc_hello_derp_node_peer_update_roundtrip() {
        for protocol in [Protocol::Connect, Protocol::Grpc] {
            let (addr, server) = start_hermetic_app().await;
            let client = h2c_client_with_protocol(addr, protocol);
            let environment_id = Uuid::new_v4();
            let mut sidecar = client.coordinate().await.unwrap();
            let mut user = client.coordinate().await.unwrap();

            sidecar
                .send(request(Hello {
                    environment_id: environment_id.to_string(),
                    ..Default::default()
                }))
                .await
                .unwrap();
            user.send(request(Hello {
                org_id: "org-1".into(),
                environment_id: environment_id.to_string(),
                ..Default::default()
            }))
            .await
            .unwrap();

            for stream in [&mut sidecar, &mut user] {
                assert!(
                    matches!(
                        next_response(stream).await.msg,
                        Some(coordinate_response::Msg::DerpMap(_))
                    ),
                    "{protocol:?}"
                );
                assert_eq!(
                    stream
                        .headers()
                        .and_then(|headers| headers.get("x-accel-buffering"))
                        .and_then(|value| value.to_str().ok()),
                    Some("no"),
                    "{protocol:?} streaming responses must disable proxy buffering"
                );
            }

            let sidecar_node = codewire_tailnet::node::Node {
                id: environment_id,
                as_of: "2026-07-11T12:00:00Z".parse().unwrap(),
                key: NodePublic::from_raw([0x11; 32]),
                disco_key: DiscoPublic::from_raw([0x22; 32]),
                preferred_derp: 7,
                derp_latency: None,
                endpoints: vec![],
                addresses: vec![prefix_from_uuid(&environment_id)],
            };
            sidecar
                .send(request(tailnet_node_to_proto(sidecar_node).unwrap()))
                .await
                .unwrap();
            let response = next_response(&mut user).await;
            let Some(coordinate_response::Msg::PeerUpdate(update)) = response.msg else {
                panic!("expected {protocol:?} peer_update, got {response:?}");
            };
            assert_eq!(update.nodes.len(), 1, "{protocol:?}");
            assert_eq!(
                update.nodes[0].id,
                environment_id.to_string(),
                "{protocol:?}"
            );

            sidecar.close_send();
            user.close_send();
            server.abort();
        }
    }

    #[tokio::test]
    #[ignore = "requires NATS_URL pointing at a JetStream-enabled NATS server"]
    async fn generated_protocol_cross_replica_fanout_round_trips_over_nats() {
        let nats_url =
            std::env::var("NATS_URL").expect("set NATS_URL to a JetStream-enabled NATS server");
        let sidecar_plane =
            CoordinationPlane::setup(async_nats::connect(nats_url.clone()).await.unwrap())
                .await
                .unwrap();
        let client_plane = CoordinationPlane::setup(async_nats::connect(nats_url).await.unwrap())
            .await
            .unwrap();

        let environment_id = Uuid::new_v4();
        let (mut sidecar_state, _) = lazy_state();
        sidecar_state.coordination = Some(sidecar_plane.clone());
        let (sidecar_addr, sidecar_server) = start_hermetic_app_with_state(sidecar_state).await;
        let (mut client_state, _) = lazy_state();
        client_state.coordination = Some(client_plane);
        let (client_addr, client_server) = start_hermetic_app_with_state(client_state).await;

        let mut sidecar = h2c_client_with_protocol(sidecar_addr, Protocol::Connect)
            .coordinate()
            .await
            .unwrap();
        let mut client = h2c_client_with_protocol(client_addr, Protocol::Grpc)
            .coordinate()
            .await
            .unwrap();
        sidecar
            .send(request(Hello {
                environment_id: environment_id.to_string(),
                ..Default::default()
            }))
            .await
            .unwrap();
        client
            .send(request(Hello {
                org_id: "org-1".into(),
                environment_id: environment_id.to_string(),
                ..Default::default()
            }))
            .await
            .unwrap();
        for stream in [&mut sidecar, &mut client] {
            assert!(matches!(
                next_response(stream).await.msg,
                Some(coordinate_response::Msg::DerpMap(_))
            ));
        }

        let sidecar_node = codewire_tailnet::node::Node {
            id: environment_id,
            as_of: "2026-07-11T12:00:00Z".parse().unwrap(),
            key: NodePublic::from_raw([0x31; 32]),
            disco_key: DiscoPublic::from_raw([0x32; 32]),
            preferred_derp: 11,
            derp_latency: None,
            endpoints: vec![],
            addresses: vec![prefix_from_uuid(&environment_id)],
        };
        sidecar
            .send(request(tailnet_node_to_proto(sidecar_node).unwrap()))
            .await
            .unwrap();
        let response = next_response(&mut client).await;
        let Some(coordinate_response::Msg::PeerUpdate(update)) = response.msg else {
            panic!("expected cross-replica sidecar peer update, got {response:?}");
        };
        assert_eq!(update.nodes.len(), 1);
        assert_eq!(update.nodes[0].id, environment_id.to_string());
        assert_eq!(update.nodes[0].preferred_derp, 11);
        let persisted = sidecar_plane
            .get_sidecar_node(environment_id)
            .await
            .unwrap()
            .expect("sidecar node must be persisted in coordinator KV");
        assert_eq!(persisted.id, environment_id);
        assert_eq!(persisted.preferred_derp, 11);

        let proposed_client_id = Uuid::new_v4();
        let client_node = codewire_tailnet::node::Node {
            id: proposed_client_id,
            as_of: "2026-07-11T12:00:00Z".parse().unwrap(),
            key: NodePublic::from_raw([0x41; 32]),
            disco_key: DiscoPublic::from_raw([0x42; 32]),
            preferred_derp: 7,
            derp_latency: None,
            endpoints: vec![],
            addresses: vec![prefix_from_uuid(&proposed_client_id)],
        };
        client
            .send(request(tailnet_node_to_proto(client_node).unwrap()))
            .await
            .unwrap();
        let response = next_response(&mut sidecar).await;
        let Some(coordinate_response::Msg::PeerUpdate(update)) = response.msg else {
            panic!("expected cross-replica client peer update, got {response:?}");
        };
        assert_eq!(update.nodes.len(), 1);
        assert_eq!(update.nodes[0].preferred_derp, 7);
        let assigned_client_id = Uuid::parse_str(&update.nodes[0].id).unwrap();
        assert_ne!(assigned_client_id, proposed_client_id);

        client.close_send();
        let response = next_response(&mut sidecar).await;
        let Some(coordinate_response::Msg::PeerRemove(remove)) = response.msg else {
            panic!("expected cross-replica client removal, got {response:?}");
        };
        assert_eq!(remove.peer_id, assigned_client_id.to_string());

        sidecar.close_send();
        sidecar_plane
            .kv
            .delete(crate::sidecar_key(environment_id))
            .await
            .ok();
        sidecar_server.abort();
        client_server.abort();
    }

    #[tokio::test]
    async fn coordinator_policy_rejects_grpc_web_and_unrelated_content_types() {
        let (state, _) = lazy_state();
        let router = router_with_authorizer(state, Arc::new(HermeticAuthorizer));
        for content_type in [
            "application/grpc-web",
            "application/grpc-web+proto",
            "application/grpc-web-text",
            "application/grpc+json",
            "application/connect+thrift",
            "text/plain",
        ] {
            let response = tower::ServiceExt::oneshot(
                router.clone(),
                axum::http::Request::post("/codewire.internal.v1.CoordinatorService/Coordinate")
                    .header("content-type", content_type)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
            assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
            assert_eq!(
                response
                    .headers()
                    .get("accept-post")
                    .and_then(|value| value.to_str().ok()),
                Some(codewire_server_core::connect::ACCEPT_POST_WITH_GRPC),
                "{content_type}"
            );
        }
    }

    #[tokio::test]
    async fn generated_route_is_mounted_and_legacy_websocket_routes_are_absent() {
        let (state, auth) = lazy_state();
        let app = super::super::router(state, auth);
        let generated = tower::ServiceExt::oneshot(
            app.clone(),
            axum::http::Request::post("/codewire.internal.v1.CoordinatorService/Coordinate")
                .header("content-type", "application/connect+proto")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
        assert_ne!(generated.status(), StatusCode::NOT_FOUND);

        for path in [
            "/api/v1/internal/gateway/coordinate",
            "/api/v1/organizations/org/environments/env/coordinate",
        ] {
            let response = tower::ServiceExt::oneshot(
                app.clone(),
                axum::http::Request::get(path).body(Body::empty()).unwrap(),
            )
            .await
            .unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
        }
    }
}
