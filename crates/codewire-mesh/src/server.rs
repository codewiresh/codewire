use std::borrow::Cow;
use std::collections::HashMap;
use std::fs;
use std::future::Future;
use std::io;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path as FsPath, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration as StdDuration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use axum::body::Bytes;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Extension, FromRequestParts, Path, Query, Request, State};
use axum::http::header::{
    ACCEPT, AUTHORIZATION, CONTENT_TYPE, COOKIE, HeaderName, HeaderValue, LOCATION, SET_COOKIE,
};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use chrono::{DateTime, Duration, SecondsFormat, Utc};
use codewire_server_core::http::AppBuilder;
use codewire_tailnet::node::Node as TailnetNode;
use ed25519_dalek::pkcs8::DecodePrivateKey;
use rand::RngCore;
use rand::rngs::OsRng;
use russh::keys::ssh_key::private::Ed25519Keypair;
use russh::keys::ssh_key::{Algorithm, LineEnding, PrivateKey};
use russh::{Channel, ChannelId, MethodKind, MethodSet, Preferred, Pty, kex, server};
use serde::{Deserialize, Serialize};
use serde_json::{Map as JsonMap, Value as JsonValue};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::net::TcpListener;
use tokio::sync::{OnceCell, mpsc, watch};
use tokio::task::JoinSet;
use url::Url;
use uuid::Uuid;

use crate::auth::{AuthIdentity, authenticate_headers, bearer_token};
use crate::network_auth::{
    DEFAULT_BUNDLE_VALIDITY, DEFAULT_OBSERVER_TTL, DEFAULT_RUNTIME_TTL, DEFAULT_SENDER_TTL,
    IssuerState, NETWORK_AUTH_ISSUER_KEY, NETWORK_AUTH_NAMESPACE, ObserverDelegationInput,
    ObserverDelegationResponse, RuntimeClaims, RuntimeCredentialResponse, SUBJECT_KIND_CLIENT,
    SUBJECT_KIND_NODE, SenderDelegationInput, SenderDelegationResponse, new_issuer_state,
    parse_runtime_credential, sign_observer_delegation, sign_runtime_credential,
    sign_sender_delegation, verify_runtime_credential,
};
use crate::store::{
    AccessGrant, AccessGrantFilter, GROUP_DEBUG_FULL, GROUP_DEBUG_NONE, GROUP_DEBUG_OBSERVE_ONLY,
    GROUP_MESSAGES_INTERNAL_ONLY, GROUP_MESSAGES_OPEN, Group, GroupBinding, GroupMember,
    GroupPolicy, Invite, NETWORK_ROLE_MEMBER, NETWORK_ROLE_OWNER, NetworkMember, NodeEnrollment,
    NodeRecord, OAuthState, OidcDeviceFlow, OidcSession, OidcUser, SharedStore, StoreError,
    TaskEvent, TaskFilter, store_from_config,
};
use crate::{AuthMode, Config};

const INVITE_TOKEN_PREFIX: &str = "CW-INV-";
const ALPHANUMERIC: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const MAX_KV_VALUE_BYTES: usize = 1 << 20;
const MESH_KEX_ORDER: &[kex::Name] = &[
    kex::CURVE25519,
    kex::ECDH_SHA2_NISTP256,
    kex::ECDH_SHA2_NISTP384,
    kex::ECDH_SHA2_NISTP521,
    kex::DH_G14_SHA256,
];

#[derive(Clone)]
struct AppState {
    config: Config,
    store: SharedStore,
    node_hub: NodeHub,
    pending_sessions: PendingSessions,
    tailnet_coord: TailnetCoordinator,
    runtime_replay: RuntimeCredentialReplay,
    oidc_client: OidcClient,
}

#[derive(Clone)]
struct OidcClient {
    http: reqwest::Client,
    endpoints: Arc<OnceCell<Result<OidcEndpoints, String>>>,
}

#[derive(Clone, Debug)]
struct OidcEndpoints {
    authorization: String,
    token: String,
    userinfo: String,
    device_authorization: String,
}

#[derive(Deserialize)]
struct OidcDiscoveryDocument {
    authorization_endpoint: String,
    token_endpoint: String,
    userinfo_endpoint: String,
    #[serde(default)]
    device_authorization_endpoint: String,
}

impl OidcClient {
    fn new() -> Self {
        Self {
            http: reqwest::Client::new(),
            endpoints: Arc::new(OnceCell::new()),
        }
    }

    async fn endpoints(&self, config: &Config) -> Result<OidcEndpoints, String> {
        self.endpoints
            .get_or_init(|| async { discover_oidc_endpoints(config, &self.http).await })
            .await
            .clone()
    }
}

async fn discover_oidc_endpoints(
    config: &Config,
    http: &reqwest::Client,
) -> Result<OidcEndpoints, String> {
    let issuer = config
        .oidc_issuer
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "OIDC issuer is not configured".to_string())?;
    let discovery_url = format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    );
    let response = http
        .get(&discovery_url)
        .header(ACCEPT, "application/json")
        .send()
        .await
        .map_err(|err| format!("fetching OIDC discovery document from {discovery_url}: {err}"))?;
    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|err| format!("reading OIDC discovery document: {err}"))?;
    if status != reqwest::StatusCode::OK {
        return Err(format!(
            "discovery endpoint returned {}: {}",
            status.as_u16(),
            trim_for_log(&body)
        ));
    }
    let doc: OidcDiscoveryDocument = serde_json::from_str(&body)
        .map_err(|err| format!("parsing OIDC discovery document: {err}"))?;
    if doc.authorization_endpoint.trim().is_empty() || doc.token_endpoint.trim().is_empty() {
        return Err(
            "incomplete discovery document (missing authorization or token endpoint)".to_string(),
        );
    }
    Ok(OidcEndpoints {
        authorization: doc.authorization_endpoint,
        token: doc.token_endpoint,
        userinfo: doc.userinfo_endpoint,
        device_authorization: doc.device_authorization_endpoint,
    })
}

fn trim_for_log(body: &str) -> String {
    const MAX: usize = 512;
    if body.len() <= MAX {
        return body.to_string();
    }
    format!("{}...", &body[..MAX])
}

pub async fn serve<F>(config: Config, shutdown: F) -> Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    let http_listener = TcpListener::bind(config.bind_addr)
        .await
        .with_context(|| format!("listen codewire-mesh {}", config.bind_addr))?;
    let http_addr = http_listener
        .local_addr()
        .context("read codewire-mesh listener addr")?;
    let ssh_listener = TcpListener::bind(config.ssh_bind_addr)
        .await
        .with_context(|| format!("listen codewire-mesh SSH {}", config.ssh_bind_addr))?;
    let ssh_addr = ssh_listener
        .local_addr()
        .context("read codewire-mesh SSH listener addr")?;
    let host_key = load_or_create_mesh_host_key(&config.ssh_host_key_path).with_context(|| {
        format!(
            "load codewire-mesh SSH host key {}",
            config.ssh_host_key_path
        )
    })?;
    let mut ssh_config = mesh_ssh_server_config();
    ssh_config.keys.push(host_key);
    let ssh_config = Arc::new(ssh_config);

    tracing::info!(
        listen_addr = %http_addr,
        ssh_listen_addr = %ssh_addr,
        base_url = %config.base_url,
        auth_mode = config.auth_mode.as_str(),
        "codewire mesh service listening"
    );

    let store = store_from_config(&config)
        .await
        .context("initialize codewire-mesh store")?;
    let state = AppState::new(config, store);
    let router = router_from_state(state.clone());
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut tasks = JoinSet::new();

    let mut http_shutdown_rx = shutdown_rx.clone();
    tasks.spawn(async move {
        axum::serve(http_listener, router)
            .with_graceful_shutdown(async move {
                let _ = http_shutdown_rx.changed().await;
            })
            .await
            .context("serve codewire-mesh HTTP")
    });

    tasks.spawn(serve_mesh_ssh_listener(
        ssh_listener,
        state,
        ssh_config,
        shutdown_rx,
    ));

    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            _ = &mut shutdown => {
                let _ = shutdown_tx.send(true);
                while let Some(joined) = tasks.join_next().await {
                    match joined {
                        Ok(Ok(())) => {}
                        Ok(Err(err)) => return Err(err),
                        Err(err) => return Err(err).context("codewire-mesh task join"),
                    }
                }
                return Ok(());
            }
            joined = tasks.join_next(), if !tasks.is_empty() => {
                match joined {
                    Some(Ok(Ok(()))) => {}
                    Some(Ok(Err(err))) => {
                        let _ = shutdown_tx.send(true);
                        return Err(err);
                    }
                    Some(Err(err)) => {
                        let _ = shutdown_tx.send(true);
                        return Err(err).context("codewire-mesh task join");
                    }
                    None => return Ok(()),
                }
            }
        }
    }
}

pub fn router(config: Config) -> Router {
    let store = std::sync::Arc::new(crate::store::MemoryStore::new());
    router_with_store(config, store)
}

pub fn router_with_store(config: Config, store: SharedStore) -> Router {
    router_from_state(AppState::new(config, store))
}

impl AppState {
    fn new(config: Config, store: SharedStore) -> Self {
        Self {
            config,
            store,
            node_hub: NodeHub::new(),
            pending_sessions: PendingSessions::new(),
            tailnet_coord: TailnetCoordinator::new(),
            runtime_replay: RuntimeCredentialReplay::new(),
            oidc_client: OidcClient::new(),
        }
    }
}

async fn serve_mesh_ssh_listener(
    listener: TcpListener,
    state: AppState,
    config: Arc<server::Config>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> Result<()> {
    loop {
        tokio::select! {
            changed = shutdown_rx.changed() => {
                let _ = changed;
                return Ok(());
            }
            accepted = listener.accept() => {
                let (stream, peer_addr) = accepted.context("accept codewire-mesh SSH connection")?;
                let config = config.clone();
                let state = state.clone();
                tokio::spawn(async move {
                    match server::run_stream(config, stream, MeshSshHandler::new(state)).await {
                        Ok(session) => {
                            let _ = session.await;
                        }
                        Err(err) => {
                            tracing::warn!(
                                %peer_addr,
                                error = %err,
                                "codewire-mesh SSH handshake failed"
                            );
                        }
                    }
                });
            }
        }
    }
}

fn mesh_ssh_server_config() -> server::Config {
    server::Config {
        methods: MethodSet::from(&[MethodKind::Password][..]),
        preferred: Preferred {
            kex: Cow::Borrowed(MESH_KEX_ORDER),
            ..Preferred::DEFAULT
        },
        ..Default::default()
    }
}

fn load_or_create_mesh_host_key(path: impl AsRef<FsPath>) -> Result<PrivateKey> {
    let path = normalize_host_key_path(path.as_ref());
    match fs::read_to_string(&path) {
        Ok(encoded) => {
            let key = parse_mesh_host_key(&encoded)
                .with_context(|| format!("parse SSH host key {}", path.display()))?;
            validate_mesh_host_key(&path, &key)?;
            Ok(key)
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            let key = generate_mesh_host_key();
            write_mesh_host_key(&path, &key)?;
            Ok(key)
        }
        Err(err) => Err(err).with_context(|| format!("read host key {}", path.display())),
    }
}

fn parse_mesh_host_key(encoded: &str) -> Result<PrivateKey> {
    match PrivateKey::from_openssh(encoded) {
        Ok(key) => return Ok(key),
        Err(err) if !encoded.contains("-----BEGIN PRIVATE KEY-----") => return Err(err.into()),
        Err(_) => {}
    }

    let signing_key =
        ed25519_dalek::SigningKey::from_pkcs8_pem(encoded).context("parse PKCS#8 Ed25519 key")?;
    let seed = signing_key.to_bytes();
    Ok(PrivateKey::from(Ed25519Keypair::from_seed(&seed)))
}

fn validate_mesh_host_key(path: &FsPath, key: &PrivateKey) -> Result<()> {
    if key.algorithm() != Algorithm::Ed25519 {
        bail!(
            "codewire-mesh SSH host key {} must be Ed25519, got {:?}",
            path.display(),
            key.algorithm()
        );
    }
    Ok(())
}

fn normalize_host_key_path(path: &FsPath) -> PathBuf {
    if path.as_os_str().is_empty() {
        PathBuf::from(crate::config::DEFAULT_SSH_HOST_KEY_PATH)
    } else {
        path.to_path_buf()
    }
}

fn generate_mesh_host_key() -> PrivateKey {
    let mut seed = [0_u8; 32];
    OsRng.fill_bytes(&mut seed);
    PrivateKey::from(Ed25519Keypair::from_seed(&seed))
}

fn write_mesh_host_key(path: &FsPath, key: &PrivateKey) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| FsPath::new("."));
    fs::create_dir_all(parent)
        .with_context(|| format!("create host key directory {}", parent.display()))?;
    #[cfg(unix)]
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("set permissions on {}", parent.display()))?;

    let encoded = key
        .to_openssh(LineEnding::LF)
        .context("encode codewire-mesh SSH host key")?;
    let tmp_path = temporary_host_key_path(path);
    fs::write(&tmp_path, encoded.as_bytes())
        .with_context(|| format!("write host key {}", tmp_path.display()))?;
    #[cfg(unix)]
    fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("set permissions on {}", tmp_path.display()))?;
    fs::rename(&tmp_path, path)
        .with_context(|| format!("rename host key into {}", path.display()))?;
    Ok(())
}

fn temporary_host_key_path(path: &FsPath) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("ssh_host_ed25519");
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    path.with_file_name(format!(".{file_name}.{}.{}.tmp", std::process::id(), nanos))
}

fn router_from_state(state: AppState) -> Router {
    let mut public_routes = Router::new()
        .route("/api/v1/auth/config", get(auth_config))
        .route("/node/connect", get(node_connect))
        .route("/node/back/{session_id}", get(node_back))
        .route("/api/v1/tailnet/coordinate", get(tailnet_coordinate))
        .route("/api/v1/nodes", get(node_list))
        .route(
            "/api/v1/node-enrollments/redeem",
            post(node_enrollment_redeem),
        )
        .route("/api/v1/join", post(join_bootstrap))
        .route("/join", get(join_page))
        .route("/api/v1/groups/bindings", get(group_bindings))
        .route("/api/v1/network-auth/bundle", get(verifier_bundle))
        .route(
            "/api/v1/network-auth/runtime/node",
            post(node_runtime_credential),
        )
        .route(
            "/api/v1/network-auth/delegation/node",
            post(node_sender_delegation),
        )
        .route(
            "/api/v1/groups/{name}/members",
            post(group_member_add).delete(group_member_remove),
        );

    if state.config.auth_mode == AuthMode::Oidc {
        public_routes = public_routes
            .route("/", get(oidc_index))
            .route("/auth/oidc", get(oidc_login))
            .route("/auth/oidc/callback", get(oidc_callback))
            .route("/auth/session", get(oidc_session_info))
            .route("/api/v1/device/authorize", post(oidc_device_authorize))
            .route("/api/v1/device/poll", post(oidc_device_poll));
    }

    let public_routes = public_routes.with_state(state.clone());

    let protected_routes = Router::new()
        .route("/api/v1/auth/validate", get(auth_validate))
        .route("/api/v1/groups", get(group_list).post(group_create))
        .route("/api/v1/groups/{name}", get(group_get).delete(group_delete))
        .route("/api/v1/groups/{name}/policy", put(group_policy_set))
        .route("/api/v1/invites", get(invite_list).post(invite_create))
        .route("/api/v1/invites/{token}", delete(invite_delete))
        .route("/api/v1/kv/{namespace}", get(kv_list))
        .route(
            "/api/v1/kv/{namespace}/{key}",
            get(kv_get).put(kv_set).delete(kv_delete),
        )
        .route("/api/v1/node-enrollments", post(node_enrollment_create))
        .route("/api/v1/nodes", post(node_register_deprecated))
        .route("/api/v1/nodes/{name}", delete(node_revoke))
        .route("/api/v1/networks", get(network_list).post(network_create))
        .route("/api/v1/networks/join", post(network_join))
        .route(
            "/api/v1/access-grants",
            get(access_grant_list).post(access_grant_create),
        )
        .route(
            "/api/v1/access-grants/{id}",
            get(access_grant_get).delete(access_grant_revoke),
        )
        .route("/api/v1/tasks", get(task_list))
        .route(
            "/api/v1/network-auth/runtime/client",
            post(client_runtime_credential),
        )
        .route_layer(middleware::from_fn_with_state(state.clone(), require_auth))
        .with_state(state);

    AppBuilder::new("mesh")
        .with_health()
        .with_routes(public_routes.merge(protected_routes))
        .into_router()
}

#[derive(Serialize)]
struct AuthConfigResponse {
    auth_mode: &'static str,
}

async fn auth_config(State(state): State<AppState>) -> Json<AuthConfigResponse> {
    Json(AuthConfigResponse {
        auth_mode: state.config.auth_mode.as_str(),
    })
}

async fn oidc_login(State(state): State<AppState>) -> Response {
    let endpoints = match state.oidc_client.endpoints(&state.config).await {
        Ok(endpoints) => endpoints,
        Err(err) => {
            tracing::error!(error = %err, "OIDC discovery failed");
            return plain_error(StatusCode::BAD_GATEWAY, "upstream OIDC error");
        }
    };
    let oauth_state = generate_oauth_state();
    let now = Utc::now();
    if state
        .store
        .oauth_state_create(OAuthState {
            state: oauth_state.clone(),
            created_at: now,
            expires_at: now + Duration::minutes(10),
        })
        .await
        .is_err()
    {
        return plain_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error");
    }
    let redirect_uri = oidc_redirect_uri(&state.config);
    let location = match oidc_auth_code_url(&state, &endpoints, &oauth_state, &redirect_uri) {
        Ok(location) => location,
        Err(message) => return plain_error(StatusCode::BAD_GATEWAY, message),
    };
    redirect_found(&location)
}

#[derive(Deserialize)]
struct OidcCallbackQuery {
    state: Option<String>,
    code: Option<String>,
}

async fn oidc_callback(
    State(state): State<AppState>,
    Query(query): Query<OidcCallbackQuery>,
) -> Response {
    let Some(oauth_state) = query
        .state
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    else {
        return plain_error(StatusCode::BAD_REQUEST, "missing state parameter");
    };
    if state.store.oauth_state_consume(oauth_state).await.is_err() {
        return plain_error(
            StatusCode::BAD_REQUEST,
            "invalid or expired state parameter",
        );
    }
    let Some(code) = query
        .code
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    else {
        return plain_error(StatusCode::BAD_REQUEST, "missing code parameter");
    };
    let endpoints = match state.oidc_client.endpoints(&state.config).await {
        Ok(endpoints) => endpoints,
        Err(err) => {
            tracing::error!(error = %err, "OIDC discovery failed");
            return plain_error(StatusCode::BAD_GATEWAY, "upstream OIDC error");
        }
    };
    let redirect_uri = oidc_redirect_uri(&state.config);
    let access_token = match exchange_oidc_code(&state, &endpoints, code, &redirect_uri).await {
        Ok(access_token) => access_token,
        Err(response) => return response,
    };
    let claims = match fetch_oidc_userinfo(&state, &endpoints, &access_token).await {
        Ok(claims) => claims,
        Err(response) => return response,
    };
    if let Err(message) = check_oidc_groups(&state.config.oidc_allowed_groups, &claims.groups) {
        let message = format!("access denied: {message}");
        return plain_error(StatusCode::FORBIDDEN, &message);
    }

    let now = Utc::now();
    if state
        .store
        .oidc_user_upsert(OidcUser {
            sub: claims.sub.clone(),
            username: oidc_username(&claims),
            avatar_url: claims.picture.clone(),
            created_at: now,
            last_login_at: now,
        })
        .await
        .is_err()
    {
        return plain_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error");
    }

    let session_token = generate_session_token();
    if state
        .store
        .oidc_session_create(OidcSession {
            token: session_token.clone(),
            sub: claims.sub,
            created_at: now,
            expires_at: now + Duration::days(30),
        })
        .await
        .is_err()
    {
        return plain_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error");
    }

    redirect_with_cookie("/", &oidc_session_cookie(&state.config, &session_token))
}

async fn oidc_session_info(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(token) = oidc_session_token_from_headers(&headers) else {
        return plain_error(StatusCode::UNAUTHORIZED, r#"{"error":"unauthorized"}"#);
    };
    let session = match state.store.oidc_session_get(&token).await {
        Ok(Some(session)) => session,
        Ok(None) | Err(_) => {
            return plain_error(StatusCode::UNAUTHORIZED, r#"{"error":"unauthorized"}"#);
        }
    };
    let user = match state.store.oidc_user_get_by_sub(&session.sub).await {
        Ok(Some(user)) => user,
        Ok(None) | Err(_) => {
            return plain_error(StatusCode::UNAUTHORIZED, r#"{"error":"user not found"}"#);
        }
    };
    Json(serde_json::json!({
        "sub": user.sub,
        "username": user.username,
        "avatar_url": user.avatar_url,
        "expires_at": session.expires_at,
    }))
    .into_response()
}

async fn oidc_index() -> Response {
    (
        [(CONTENT_TYPE, HeaderValue::from_static("text/html; charset=utf-8"))],
        r#"<!DOCTYPE html>
<html><head><title>Codewire Mesh</title>
<style>
body{font-family:system-ui,-apple-system,sans-serif;max-width:480px;margin:80px auto;text-align:center;color:#1a1a1a}
h2{font-weight:600}
.badge{display:inline-block;padding:6px 16px;background:#dcfce7;color:#166534;border-radius:20px;font-size:14px;margin-top:8px}
a{color:#2563eb}
</style></head><body>
<h2>Codewire Mesh</h2>
<div class="badge">Mesh is running</div>
<p><a href="/auth/oidc">Sign in</a></p>
</body></html>"#,
    )
        .into_response()
}

#[derive(Deserialize)]
struct OidcDeviceAuthorizeRequest {
    node_name: Option<String>,
    network_id: Option<String>,
}

#[derive(Deserialize)]
struct OidcDeviceAuthorizationResponse {
    device_code: String,
    user_code: String,
    verification_uri: String,
    expires_in: Option<i64>,
    interval: Option<i64>,
}

#[derive(Serialize)]
struct OidcDeviceAuthorizeResponse {
    poll_token: String,
    user_code: String,
    verification_uri: String,
    expires_in: i64,
    interval: i64,
}

async fn oidc_device_authorize(State(state): State<AppState>, body: Bytes) -> Response {
    let req = match serde_json::from_slice::<OidcDeviceAuthorizeRequest>(&body) {
        Ok(req)
            if req
                .node_name
                .as_deref()
                .is_some_and(|name| !name.trim().is_empty()) =>
        {
            req
        }
        _ => return plain_error(StatusCode::BAD_REQUEST, "node_name required"),
    };
    let network_id = match required_network_id(req.network_id.as_deref()) {
        Ok(network_id) => network_id,
        Err(message) => return plain_error(StatusCode::BAD_REQUEST, message),
    };
    let node_name = req.node_name.unwrap_or_default().trim().to_string();
    let endpoints = match state.oidc_client.endpoints(&state.config).await {
        Ok(endpoints) => endpoints,
        Err(err) => {
            tracing::error!(error = %err, "OIDC discovery failed");
            return plain_error(StatusCode::BAD_GATEWAY, "upstream OIDC error");
        }
    };
    if endpoints.device_authorization.trim().is_empty() {
        tracing::error!("OIDC discovery document missing device authorization endpoint");
        return plain_error(StatusCode::BAD_GATEWAY, "upstream OIDC error");
    }

    let response = state
        .oidc_client
        .http
        .post(&endpoints.device_authorization)
        .header(ACCEPT, "application/json")
        .form(&[
            (
                "client_id",
                state.config.oidc_client_id.as_deref().unwrap_or_default(),
            ),
            (
                "client_secret",
                state
                    .config
                    .oidc_client_secret
                    .as_deref()
                    .unwrap_or_default(),
            ),
            ("scope", "openid profile email groups"),
        ])
        .send()
        .await;
    let response = match response {
        Ok(response) => response,
        Err(err) => {
            tracing::error!(error = %err, "device authorize: OIDC provider unreachable");
            return plain_error(StatusCode::BAD_GATEWAY, "upstream OIDC error");
        }
    };
    let status = response.status();
    let response_body = response.text().await.unwrap_or_default();
    if status != reqwest::StatusCode::OK {
        tracing::error!(
            status = status.as_u16(),
            body = %trim_for_log(&response_body),
            "device authorize: OIDC provider error"
        );
        return plain_error(StatusCode::BAD_GATEWAY, "upstream OIDC error");
    }
    let device_response: OidcDeviceAuthorizationResponse =
        match serde_json::from_str(&response_body) {
            Ok(response) => response,
            Err(err) => {
                let message = format!("parsing device auth response: {err}");
                return plain_error(StatusCode::BAD_GATEWAY, &message);
            }
        };

    let expires_in = device_response
        .expires_in
        .filter(|value| *value > 0)
        .unwrap_or(300);
    let interval = device_response
        .interval
        .filter(|value| *value > 0)
        .unwrap_or(5);
    let flow = OidcDeviceFlow {
        poll_token: generate_hex_token(),
        device_code: device_response.device_code,
        network_id,
        node_name,
        node_token: String::new(),
        expires_at: Utc::now() + Duration::seconds(expires_in),
    };
    if state
        .store
        .oidc_device_flow_create(flow.clone())
        .await
        .is_err()
    {
        return plain_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error");
    }

    Json(OidcDeviceAuthorizeResponse {
        poll_token: flow.poll_token,
        user_code: device_response.user_code,
        verification_uri: device_response.verification_uri,
        expires_in,
        interval,
    })
    .into_response()
}

#[derive(Deserialize)]
struct OidcDevicePollRequest {
    poll_token: Option<String>,
}

#[derive(Deserialize)]
struct OidcTokenResponse {
    #[serde(default)]
    access_token: String,
    #[serde(default)]
    error: String,
}

#[derive(Deserialize)]
struct OidcUserinfoResponse {
    sub: String,
    #[serde(default)]
    preferred_username: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    groups: Vec<String>,
    #[serde(default)]
    picture: String,
}

#[derive(Serialize)]
struct OidcDevicePollAuthorizedResponse {
    status: &'static str,
    node_token: String,
    node_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    network_id: Option<String>,
}

async fn oidc_device_poll(State(state): State<AppState>, body: Bytes) -> Response {
    let req = match serde_json::from_slice::<OidcDevicePollRequest>(&body) {
        Ok(req)
            if req
                .poll_token
                .as_deref()
                .is_some_and(|token| !token.trim().is_empty()) =>
        {
            req
        }
        _ => return plain_error(StatusCode::BAD_REQUEST, "poll_token required"),
    };
    let poll_token = req.poll_token.unwrap_or_default();
    let flow = match state.store.oidc_device_flow_get(&poll_token).await {
        Ok(Some(flow)) => flow,
        Ok(None) => return plain_error(StatusCode::GONE, "expired or invalid poll token"),
        Err(_) => return plain_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    };
    if !flow.node_token.trim().is_empty() {
        return Json(OidcDevicePollAuthorizedResponse {
            status: "authorized",
            node_token: flow.node_token,
            node_name: flow.node_name,
            network_id: None,
        })
        .into_response();
    }

    let endpoints = match state.oidc_client.endpoints(&state.config).await {
        Ok(endpoints) => endpoints,
        Err(err) => {
            tracing::error!(error = %err, "OIDC discovery failed");
            return plain_error(StatusCode::BAD_GATEWAY, "upstream OIDC error");
        }
    };
    let token_response = match poll_oidc_device_token(&state, &endpoints, &flow).await {
        Ok(response) => response,
        Err(response) => return response,
    };

    match token_response.error.as_str() {
        "authorization_pending" => {
            return (
                StatusCode::ACCEPTED,
                Json(serde_json::json!({"status": "pending"})),
            )
                .into_response();
        }
        "slow_down" => {
            return (
                StatusCode::ACCEPTED,
                Json(serde_json::json!({"status": "slow_down"})),
            )
                .into_response();
        }
        "" => {}
        error => {
            tracing::error!(error, "device poll: OIDC authorization failed");
            return plain_error(StatusCode::FORBIDDEN, "OIDC authorization failed");
        }
    }

    if token_response.access_token.trim().is_empty() {
        return plain_error(
            StatusCode::BAD_GATEWAY,
            "empty access_token from OIDC provider",
        );
    }

    let claims = match fetch_oidc_userinfo(&state, &endpoints, &token_response.access_token).await {
        Ok(claims) => claims,
        Err(response) => return response,
    };
    if let Err(message) = check_oidc_groups(&state.config.oidc_allowed_groups, &claims.groups) {
        let message = format!("access denied: {message}");
        return plain_error(StatusCode::FORBIDDEN, &message);
    }

    let now = Utc::now();
    if state
        .store
        .oidc_user_upsert(OidcUser {
            sub: claims.sub.clone(),
            username: oidc_username(&claims),
            avatar_url: claims.picture.clone(),
            created_at: now,
            last_login_at: now,
        })
        .await
        .is_err()
    {
        return plain_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error");
    }

    let subject = format!("oidc:{}", claims.sub);
    let (_, enrollment_token) = match create_node_enrollment(
        state.store.as_ref(),
        &flow.network_id,
        &subject,
        &subject,
        &flow.node_name,
        1,
        Duration::minutes(10),
    )
    .await
    {
        Ok(created) => created,
        Err(_) => return plain_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    };
    let redeemed = match redeem_node_enrollment(
        state.store.as_ref(),
        &enrollment_token,
        &flow.node_name,
        "",
        None,
    )
    .await
    {
        Ok(redeemed) => redeemed,
        Err(_) => return plain_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    };
    if state
        .store
        .oidc_device_flow_complete(&poll_token, &redeemed.node_token)
        .await
        .is_err()
    {
        return plain_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error");
    }

    Json(OidcDevicePollAuthorizedResponse {
        status: "authorized",
        node_token: redeemed.node_token,
        node_name: redeemed.node_name,
        network_id: Some(redeemed.network_id),
    })
    .into_response()
}

async fn poll_oidc_device_token(
    state: &AppState,
    endpoints: &OidcEndpoints,
    flow: &OidcDeviceFlow,
) -> Result<OidcTokenResponse, Response> {
    let response = state
        .oidc_client
        .http
        .post(&endpoints.token)
        .header(ACCEPT, "application/json")
        .form(&[
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ("device_code", flow.device_code.as_str()),
            (
                "client_id",
                state.config.oidc_client_id.as_deref().unwrap_or_default(),
            ),
            (
                "client_secret",
                state
                    .config
                    .oidc_client_secret
                    .as_deref()
                    .unwrap_or_default(),
            ),
        ])
        .send()
        .await
        .map_err(|err| {
            tracing::error!(error = %err, "device poll: OIDC provider unreachable");
            plain_error(StatusCode::BAD_GATEWAY, "upstream OIDC error")
        })?;
    let body = response.text().await.unwrap_or_default();
    serde_json::from_str::<OidcTokenResponse>(&body).map_err(|err| {
        let message = format!("parsing token response: {err}");
        plain_error(StatusCode::BAD_GATEWAY, &message)
    })
}

async fn exchange_oidc_code(
    state: &AppState,
    endpoints: &OidcEndpoints,
    code: &str,
    redirect_uri: &str,
) -> Result<String, Response> {
    let response = state
        .oidc_client
        .http
        .post(&endpoints.token)
        .header(ACCEPT, "application/json")
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
            (
                "client_id",
                state.config.oidc_client_id.as_deref().unwrap_or_default(),
            ),
            (
                "client_secret",
                state
                    .config
                    .oidc_client_secret
                    .as_deref()
                    .unwrap_or_default(),
            ),
        ])
        .send()
        .await
        .map_err(|err| {
            let message = format!("token exchange failed: token request: {err}");
            plain_error(StatusCode::BAD_GATEWAY, &message)
        })?;
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    if status != reqwest::StatusCode::OK {
        let message = format!(
            "token exchange failed: token endpoint returned {}: {}",
            status.as_u16(),
            trim_for_log(&body)
        );
        return Err(plain_error(StatusCode::BAD_GATEWAY, &message));
    }
    let token_response: OidcTokenResponse = serde_json::from_str(&body).map_err(|err| {
        let message = format!("token exchange failed: parsing token response: {err}");
        plain_error(StatusCode::BAD_GATEWAY, &message)
    })?;
    if token_response.access_token.trim().is_empty() {
        let message = format!("token exchange failed: empty access_token in response: {body}");
        return Err(plain_error(StatusCode::BAD_GATEWAY, &message));
    }
    Ok(token_response.access_token)
}

async fn fetch_oidc_userinfo(
    state: &AppState,
    endpoints: &OidcEndpoints,
    access_token: &str,
) -> Result<OidcUserinfoResponse, Response> {
    if endpoints.userinfo.trim().is_empty() {
        return Err(plain_error(
            StatusCode::BAD_GATEWAY,
            "userinfo failed: missing userinfo endpoint",
        ));
    }
    let response = state
        .oidc_client
        .http
        .get(&endpoints.userinfo)
        .header(AUTHORIZATION, format!("Bearer {access_token}"))
        .send()
        .await
        .map_err(|err| {
            let message = format!("userinfo failed: userinfo request: {err}");
            plain_error(StatusCode::BAD_GATEWAY, &message)
        })?;
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    if status != reqwest::StatusCode::OK {
        let message = format!(
            "userinfo failed: userinfo returned {}: {}",
            status.as_u16(),
            trim_for_log(&body)
        );
        return Err(plain_error(StatusCode::BAD_GATEWAY, &message));
    }
    serde_json::from_str::<OidcUserinfoResponse>(&body).map_err(|err| {
        let message = format!("userinfo failed: parsing userinfo response: {err}");
        plain_error(StatusCode::BAD_GATEWAY, &message)
    })
}

fn oidc_username(claims: &OidcUserinfoResponse) -> String {
    if !claims.preferred_username.trim().is_empty() {
        return claims.preferred_username.trim().to_string();
    }
    claims.name.trim().to_string()
}

fn check_oidc_groups(allowed_groups: &[String], user_groups: &[String]) -> Result<(), String> {
    if allowed_groups.is_empty() {
        return Ok(());
    }
    if allowed_groups
        .iter()
        .any(|allowed| user_groups.iter().any(|group| group == allowed))
    {
        return Ok(());
    }
    Err(format!(
        "not a member of any allowed group ([{}])",
        allowed_groups.join(" ")
    ))
}

fn oidc_redirect_uri(config: &Config) -> String {
    format!(
        "{}/auth/oidc/callback",
        config.base_url.trim_end_matches('/')
    )
}

fn oidc_auth_code_url(
    state: &AppState,
    endpoints: &OidcEndpoints,
    oauth_state: &str,
    redirect_uri: &str,
) -> Result<String, &'static str> {
    let mut url = url::Url::parse(&endpoints.authorization)
        .map_err(|_| "invalid OIDC authorization endpoint")?;
    url.query_pairs_mut()
        .append_pair(
            "client_id",
            state.config.oidc_client_id.as_deref().unwrap_or_default(),
        )
        .append_pair("redirect_uri", redirect_uri)
        .append_pair("response_type", "code")
        .append_pair("scope", "openid profile email groups")
        .append_pair("state", oauth_state);
    Ok(url.to_string())
}

fn oidc_session_cookie(config: &Config, token: &str) -> String {
    let secure = url::Url::parse(&config.base_url)
        .map(|url| url.scheme() == "https")
        .unwrap_or(false);
    format!(
        "cw_session={token}; Path=/; Max-Age=2592000; HttpOnly{}; SameSite=Lax",
        if secure { "; Secure" } else { "" }
    )
}

fn oidc_session_token_from_headers(headers: &HeaderMap) -> Option<String> {
    if let Some(token) = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|token| !token.is_empty())
    {
        return Some(token.to_string());
    }
    headers.get_all(COOKIE).iter().find_map(|value| {
        value.to_str().ok().and_then(|raw| {
            raw.split(';').find_map(|cookie| {
                let cookie = cookie.trim();
                let value = cookie.strip_prefix("cw_session=")?;
                (!value.is_empty()).then(|| value.to_string())
            })
        })
    })
}

fn redirect_found(location: &str) -> Response {
    match HeaderValue::from_str(location) {
        Ok(location) => (StatusCode::FOUND, [(LOCATION, location)]).into_response(),
        Err(_) => plain_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    }
}

fn redirect_with_cookie(location: &str, cookie: &str) -> Response {
    let location = match HeaderValue::from_str(location) {
        Ok(location) => location,
        Err(_) => return plain_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    };
    let cookie = match HeaderValue::from_str(cookie) {
        Ok(cookie) => cookie,
        Err(_) => return plain_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    };
    (
        StatusCode::FOUND,
        [(LOCATION, location), (SET_COOKIE, cookie)],
    )
        .into_response()
}

#[derive(Serialize)]
struct AuthValidateResponse {
    status: &'static str,
}

async fn auth_validate(
    Extension(_identity): Extension<AuthIdentity>,
) -> Json<AuthValidateResponse> {
    Json(AuthValidateResponse { status: "ok" })
}

#[derive(Serialize)]
struct NetworkResponse {
    id: String,
    created_at: chrono::DateTime<Utc>,
    node_count: i64,
    invite_count: i64,
}

async fn network_list(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthIdentity>,
) -> Response {
    let networks = if identity.is_admin {
        state.store.network_list().await
    } else {
        let subject = match membership_subject(&identity) {
            Ok(subject) => subject,
            Err(_) => return plain_error(StatusCode::UNAUTHORIZED, "unauthorized"),
        };
        state.store.network_list_by_member(&subject).await
    };

    match networks {
        Ok(networks) => {
            let body = networks
                .into_iter()
                .map(|network| NetworkResponse {
                    id: network.id,
                    created_at: network.created_at,
                    node_count: network.node_count,
                    invite_count: network.invite_count,
                })
                .collect::<Vec<_>>();
            Json(body).into_response()
        }
        Err(_) => plain_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    }
}

#[derive(Deserialize)]
struct NetworkCreateRequest {
    network_id: Option<String>,
}

async fn network_create(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthIdentity>,
    body: Bytes,
) -> Response {
    let req = match serde_json::from_slice::<NetworkCreateRequest>(&body) {
        Ok(req) => req,
        Err(_) => return plain_error(StatusCode::BAD_REQUEST, "network_id required"),
    };
    let network_id = req.network_id.unwrap_or_default().trim().to_string();
    if let Err(message) = validate_network_id(&network_id) {
        return plain_error(StatusCode::BAD_REQUEST, message);
    }

    if identity.is_admin {
        return match state.store.network_ensure(&network_id).await {
            Ok(()) => Json(NetworkCreateResponse::created(network_id)).into_response(),
            Err(_) => plain_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
        };
    }

    let subject = match membership_subject(&identity) {
        Ok(subject) => subject,
        Err(_) => return plain_error(StatusCode::UNAUTHORIZED, "unauthorized"),
    };

    if state.store.network_ensure(&network_id).await.is_err() {
        return plain_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error");
    }
    let count = match state.store.network_member_count(&network_id).await {
        Ok(count) => count,
        Err(_) => return plain_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    };
    let member = match state.store.network_member_get(&network_id, &subject).await {
        Ok(member) => member,
        Err(_) => return plain_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    };
    if count > 0 && member.is_none() {
        return plain_error(StatusCode::CONFLICT, "network already claimed");
    }
    if member.is_none()
        && state
            .store
            .network_member_upsert(NetworkMember {
                network_id: network_id.clone(),
                subject: subject.clone(),
                role: NETWORK_ROLE_OWNER.to_string(),
                created_at: Utc::now(),
                created_by: subject,
            })
            .await
            .is_err()
    {
        return plain_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error");
    }

    Json(NetworkCreateResponse::created(network_id)).into_response()
}

#[derive(Serialize)]
struct NetworkCreateResponse {
    status: &'static str,
    network_id: String,
}

impl NetworkCreateResponse {
    fn created(network_id: String) -> Self {
        Self {
            status: "created",
            network_id,
        }
    }
}

#[derive(Default)]
struct InviteCreateRequest {
    network_id: Option<String>,
    uses: i32,
    ttl: Option<String>,
}

#[derive(Deserialize)]
struct NetworkIDQuery {
    network_id: Option<String>,
}

#[derive(Deserialize)]
struct TailnetCoordinateQuery {
    role: Option<String>,
}

#[derive(Deserialize)]
struct TailnetCoordinateRequest {
    #[serde(rename = "type")]
    typ: String,
    #[serde(default)]
    node: Option<TailnetNode>,
    #[serde(default)]
    target_node: String,
}

#[derive(Serialize)]
struct TailnetCoordinateResponse {
    #[serde(rename = "type")]
    typ: &'static str,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    nodes: Vec<TailnetNode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    derp_map: Option<JsonValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Deserialize)]
struct TaskQuery {
    network_id: Option<String>,
    node: Option<String>,
    session_id: Option<String>,
    state: Option<String>,
}

#[derive(Deserialize)]
struct NodeAgentEnvelope {
    #[serde(rename = "type")]
    kind: String,
}

#[derive(Deserialize)]
struct TaskReportMessage {
    event_id: Option<String>,
    session_id: Option<u32>,
    session_name: Option<String>,
    summary: Option<String>,
    state: Option<String>,
    timestamp: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
struct HubMessage {
    #[serde(rename = "type")]
    kind: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    session_id: String,
    #[serde(skip_serializing_if = "is_zero_u32")]
    cols: u32,
    #[serde(skip_serializing_if = "is_zero_u32")]
    rows: u32,
}

#[derive(Deserialize)]
struct KVListQuery {
    network_id: Option<String>,
    prefix: Option<String>,
}

#[derive(Deserialize)]
struct GroupCreateRequest {
    network_id: Option<String>,
    name: Option<String>,
}

#[derive(Deserialize)]
struct GroupMemberRequest {
    network_id: Option<String>,
    node_name: Option<String>,
    session_name: Option<String>,
}

#[derive(Deserialize)]
struct GroupMemberQuery {
    network_id: Option<String>,
    node_name: Option<String>,
    session_name: Option<String>,
}

#[derive(Deserialize)]
struct GroupPolicyRequest {
    network_id: Option<String>,
    messages_policy: Option<String>,
    debug_policy: Option<String>,
}

#[derive(Serialize)]
struct GroupResponse {
    network_id: String,
    name: String,
    created_at: chrono::DateTime<Utc>,
    #[serde(skip_serializing_if = "String::is_empty")]
    created_by: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    members: Vec<GroupMember>,
    #[serde(skip_serializing_if = "Option::is_none")]
    policy: Option<GroupPolicy>,
}

#[derive(Serialize)]
struct GroupDeleteResponse {
    status: &'static str,
    network_id: String,
    name: String,
}

#[derive(Serialize)]
struct GroupMemberRemoveResponse {
    status: &'static str,
    network_id: String,
    group_name: String,
    node_name: String,
    session_name: String,
}

#[derive(Deserialize)]
struct NodeEnrollmentCreateRequest {
    network_id: Option<String>,
    node_name: Option<String>,
    uses: Option<i32>,
    ttl: Option<String>,
}

#[derive(Serialize)]
struct NodeEnrollmentCreateResponse {
    id: String,
    network_id: String,
    node_name: String,
    owner_subject: String,
    issued_by: String,
    uses_remaining: i32,
    expires_at: chrono::DateTime<Utc>,
    enrollment_token: String,
}

#[derive(Deserialize)]
struct NodeEnrollmentRedeemRequest {
    node_name: Option<String>,
    enrollment_token: Option<String>,
    peer_url: Option<String>,
}

#[derive(Serialize)]
struct NodeEnrollmentRedeemResponse {
    status: &'static str,
    node_token: String,
    node_name: String,
    network_id: String,
    enrollment_id: String,
}

#[derive(Deserialize)]
struct NodesListQuery {
    network_id: Option<String>,
    all: Option<String>,
}

#[derive(Serialize)]
struct NodeResponse {
    network_id: String,
    name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    peer_url: String,
    connected: bool,
}

#[derive(Deserialize)]
struct SenderDelegationRequest {
    network_id: Option<String>,
    source_node: Option<String>,
    from_session_id: Option<u32>,
    from_session_name: Option<String>,
    verbs: Option<Vec<String>>,
    audience_node: Option<String>,
}

#[derive(Deserialize)]
struct AccessGrantCreateRequest {
    network_id: Option<String>,
    target_node: Option<String>,
    session_id: Option<u32>,
    session_name: Option<String>,
    audience: Option<String>,
    verbs: Option<Vec<String>>,
    ttl: Option<String>,
}

#[derive(Deserialize)]
struct AccessGrantListQuery {
    network_id: Option<String>,
    target_node: Option<String>,
    mine: Option<String>,
    active: Option<String>,
    audience: Option<String>,
}

#[derive(Serialize)]
struct AccessGrantRevokeResponse<'a> {
    status: &'static str,
    grant_id: &'a str,
}

#[derive(Serialize)]
struct NodeRevokeResponse<'a> {
    status: &'static str,
    node: &'a str,
}

struct NodeRedeemResult {
    node_token: String,
    node_name: String,
    network_id: String,
    enrollment_id: String,
}

async fn node_enrollment_create(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthIdentity>,
    body: Bytes,
) -> Response {
    let req = match serde_json::from_slice::<NodeEnrollmentCreateRequest>(&body) {
        Ok(req) => req,
        Err(_) => return plain_error(StatusCode::BAD_REQUEST, "bad request"),
    };

    let network_id = match required_network_id(req.network_id.as_deref()) {
        Ok(network_id) => network_id,
        Err(message) => return plain_error(StatusCode::BAD_REQUEST, message),
    };
    let member = match require_membership(&state, &network_id, &identity).await {
        Ok(Some(member)) => member,
        Ok(None) => return plain_error(StatusCode::FORBIDDEN, "membership required"),
        Err(_) => return plain_error(StatusCode::UNAUTHORIZED, "unauthorized"),
    };

    let uses = req.uses.unwrap_or_default();
    let ttl = match req.ttl.as_deref() {
        None => Duration::minutes(10),
        Some(raw) if raw.trim().is_empty() => Duration::minutes(10),
        Some(raw) => match parse_go_duration(raw) {
            Some(ttl) => ttl,
            None => return plain_error(StatusCode::BAD_REQUEST, "invalid ttl"),
        },
    };

    match create_node_enrollment(
        state.store.as_ref(),
        &network_id,
        &member.subject,
        &member.subject,
        req.node_name.as_deref().unwrap_or_default(),
        uses,
        ttl,
    )
    .await
    {
        Ok((enrollment, token)) => Json(NodeEnrollmentCreateResponse {
            id: enrollment.id,
            network_id: enrollment.network_id,
            node_name: enrollment.node_name,
            owner_subject: enrollment.owner_subject,
            issued_by: enrollment.issued_by,
            uses_remaining: enrollment.uses_remaining,
            expires_at: enrollment.expires_at,
            enrollment_token: token,
        })
        .into_response(),
        Err(_) => plain_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    }
}

async fn node_enrollment_redeem(State(state): State<AppState>, body: Bytes) -> Response {
    let req = match serde_json::from_slice::<NodeEnrollmentRedeemRequest>(&body) {
        Ok(req) => req,
        Err(_) => return plain_error(StatusCode::BAD_REQUEST, "bad request"),
    };

    match redeem_node_enrollment(
        state.store.as_ref(),
        req.enrollment_token.as_deref().unwrap_or_default(),
        req.node_name.as_deref().unwrap_or_default(),
        req.peer_url.as_deref().unwrap_or_default(),
        None,
    )
    .await
    {
        Ok(redeemed) => Json(NodeEnrollmentRedeemResponse {
            status: "registered",
            node_token: redeemed.node_token,
            node_name: redeemed.node_name,
            network_id: redeemed.network_id,
            enrollment_id: redeemed.enrollment_id,
        })
        .into_response(),
        Err(NodeEnrollmentError::TokenRequired) => {
            plain_error(StatusCode::BAD_REQUEST, "enrollment_token required")
        }
        Err(NodeEnrollmentError::NodeNameRequired) => {
            plain_error(StatusCode::BAD_REQUEST, "node_name required")
        }
        Err(NodeEnrollmentError::Invalid) => {
            plain_error(StatusCode::FORBIDDEN, "invalid or expired enrollment token")
        }
        Err(NodeEnrollmentError::NodeNameMismatch) => {
            plain_error(StatusCode::FORBIDDEN, "node_name does not match enrollment")
        }
        Err(NodeEnrollmentError::Store) => {
            plain_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
        }
    }
}

async fn node_register_deprecated() -> Response {
    plain_error(
        StatusCode::GONE,
        "direct node registration is disabled; use /api/v1/node-enrollments and /api/v1/node-enrollments/redeem",
    )
}

async fn node_connect(State(state): State<AppState>, req: Request) -> Response {
    let (mut parts, _body) = req.into_parts();
    let Some(mut node) = node_auth_from_headers(&parts.headers, state.store.as_ref()).await else {
        return unauthorized_response();
    };

    node.peer_url = parts
        .headers
        .get("x-codewire-peer-url")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .trim()
        .to_string();
    node.last_seen_at = Utc::now();
    if state.store.node_register(node.clone()).await.is_err() {
        return plain_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error");
    }

    let ws = match WebSocketUpgrade::from_request_parts(&mut parts, &state).await {
        Ok(ws) => ws,
        Err(rejection) => return rejection.into_response(),
    };
    ws.on_upgrade(move |socket| node_connect_session(socket, state, node))
        .into_response()
}

async fn node_connect_session(mut socket: WebSocket, state: AppState, node: NodeRecord) {
    tracing::info!(
        network_id = %node.network_id,
        node = %node.name,
        "mesh node agent connected"
    );
    let network_id = node.network_id.clone();
    let node_name = node.name.clone();
    let (connection_id, mut hub_rx) = state.node_hub.register(&network_id, &node_name);
    loop {
        tokio::select! {
            hub_msg = hub_rx.recv() => {
                let Some(hub_msg) = hub_msg else {
                    break;
                };
                let data = match serde_json::to_string(&hub_msg) {
                    Ok(data) => data,
                    Err(err) => {
                        tracing::warn!(
                            network_id = %network_id,
                            node = %node_name,
                            error = %err,
                            "failed to encode node hub message"
                        );
                        continue;
                    }
                };
                if socket.send(Message::Text(data.into())).await.is_err() {
                    break;
                }
            }
            next = socket.recv() => {
                let data = match next {
                    Some(Ok(Message::Text(text))) => text.as_bytes().to_vec(),
                    Some(Ok(Message::Binary(bytes))) => bytes.to_vec(),
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Ok(Message::Ping(_))) | Some(Ok(Message::Pong(_))) => continue,
                    Some(Err(err)) => {
                        tracing::info!(
                            network_id = %network_id,
                            node = %node_name,
                            error = %err,
                            "mesh node agent disconnected"
                        );
                        break;
                    }
                };
                if let Err(err) = dispatch_node_agent_message(&state, &node, &data).await {
                    tracing::warn!(
                        network_id = %network_id,
                        node = %node_name,
                        error = %err,
                        "failed to handle node websocket message"
                    );
                }
            }
        }
    }
    state
        .node_hub
        .unregister(&network_id, &node_name, connection_id);
}

async fn node_back(
    Path(session_id): Path<String>,
    State(state): State<AppState>,
    req: Request,
) -> Response {
    let (mut parts, _body) = req.into_parts();
    let Some(node) = node_auth_from_headers(&parts.headers, state.store.as_ref()).await else {
        return unauthorized_response();
    };

    let ws = match WebSocketUpgrade::from_request_parts(&mut parts, &state).await {
        Ok(ws) => ws,
        Err(rejection) => return rejection.into_response(),
    };
    ws.on_upgrade(move |socket| node_back_session(socket, state, node, session_id))
        .into_response()
}

async fn node_back_session(
    socket: WebSocket,
    state: AppState,
    node: NodeRecord,
    session_id: String,
) {
    let conn = BackConnection {
        network_id: node.network_id,
        node_name: node.name,
        socket: Box::new(socket),
    };
    if let Err(conn) = state.pending_sessions.deliver(&session_id, conn) {
        conn.close_no_waiter().await;
    }
}

async fn dispatch_node_agent_message(
    state: &AppState,
    node: &NodeRecord,
    data: &[u8],
) -> Result<(), String> {
    let Ok(envelope) = serde_json::from_slice::<NodeAgentEnvelope>(data) else {
        return Ok(());
    };
    if envelope.kind.trim() != "TaskReport" {
        return Ok(());
    }

    let msg = serde_json::from_slice::<TaskReportMessage>(data).map_err(|_| "bad request")?;
    let event = task_event_from_node_report(node, msg)?;
    state
        .store
        .task_event_create(event)
        .await
        .map_err(|err| err.to_string())?;
    Ok(())
}

fn task_event_from_node_report(
    node: &NodeRecord,
    msg: TaskReportMessage,
) -> Result<TaskEvent, String> {
    let event_id = msg.event_id.unwrap_or_default().trim().to_string();
    if event_id.is_empty() {
        return Err("event_id required".to_string());
    }
    let session_id = msg.session_id.unwrap_or_default();
    if session_id == 0 {
        return Err("session_id required".to_string());
    }
    let summary = msg.summary.unwrap_or_default().trim().to_string();
    if summary.is_empty() {
        return Err("summary required".to_string());
    }
    let state = msg.state.unwrap_or_default().trim().to_string();
    if !is_valid_task_state(&state) {
        return Err(format!("invalid task state {state:?}"));
    }
    let timestamp = normalize_task_timestamp(msg.timestamp.unwrap_or_default().as_str())?;

    Ok(TaskEvent {
        event_id,
        network_id: node.network_id.trim().to_string(),
        node_name: node.name.trim().to_string(),
        session_id,
        session_name: msg.session_name.unwrap_or_default().trim().to_string(),
        summary,
        state,
        timestamp,
    })
}

fn normalize_task_timestamp(raw: &str) -> Result<String, String> {
    DateTime::parse_from_rfc3339(raw.trim())
        .map(|timestamp| {
            timestamp
                .with_timezone(&Utc)
                .to_rfc3339_opts(SecondsFormat::AutoSi, true)
        })
        .map_err(|_| format!("invalid timestamp {raw:?}"))
}

async fn kv_set(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthIdentity>,
    Path((namespace, key)): Path<(String, String)>,
    Query(query): Query<NetworkIDQuery>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let network_id = match required_network_id(query.network_id.as_deref()) {
        Ok(network_id) => network_id,
        Err(message) => return plain_error(StatusCode::BAD_REQUEST, message),
    };
    match require_membership(&state, &network_id, &identity).await {
        Ok(Some(_)) => {}
        Ok(None) => return plain_error(StatusCode::FORBIDDEN, "membership required"),
        Err(_) => return plain_error(StatusCode::UNAUTHORIZED, "unauthorized"),
    }

    let ttl = match parse_xttl_header(&headers) {
        Ok(ttl) => ttl,
        Err(message) => return plain_error(StatusCode::BAD_REQUEST, message),
    };
    let value = body
        .iter()
        .take(MAX_KV_VALUE_BYTES)
        .copied()
        .collect::<Vec<_>>();

    match state
        .store
        .kv_set(&network_id, &namespace, &key, value, ttl)
        .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(_) => plain_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    }
}

async fn kv_get(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthIdentity>,
    Path((namespace, key)): Path<(String, String)>,
    Query(query): Query<NetworkIDQuery>,
) -> Response {
    let network_id = match required_network_id(query.network_id.as_deref()) {
        Ok(network_id) => network_id,
        Err(message) => return plain_error(StatusCode::BAD_REQUEST, message),
    };
    match require_membership(&state, &network_id, &identity).await {
        Ok(Some(_)) => {}
        Ok(None) => return plain_error(StatusCode::FORBIDDEN, "membership required"),
        Err(_) => return plain_error(StatusCode::UNAUTHORIZED, "unauthorized"),
    }

    match state.store.kv_get(&network_id, &namespace, &key).await {
        Ok(Some(value)) => (
            StatusCode::OK,
            [(
                CONTENT_TYPE,
                HeaderValue::from_static("application/octet-stream"),
            )],
            value,
        )
            .into_response(),
        Ok(None) => plain_error(StatusCode::NOT_FOUND, "not found"),
        Err(_) => plain_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    }
}

async fn kv_delete(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthIdentity>,
    Path((namespace, key)): Path<(String, String)>,
    Query(query): Query<NetworkIDQuery>,
) -> Response {
    let network_id = match required_network_id(query.network_id.as_deref()) {
        Ok(network_id) => network_id,
        Err(message) => return plain_error(StatusCode::BAD_REQUEST, message),
    };
    match require_owner(&state, &network_id, &identity).await {
        Ok(true) => {}
        Ok(false) => return plain_error(StatusCode::FORBIDDEN, "owner access required"),
        Err(_) => return plain_error(StatusCode::UNAUTHORIZED, "unauthorized"),
    }

    match state.store.kv_delete(&network_id, &namespace, &key).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(_) => plain_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    }
}

async fn kv_list(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthIdentity>,
    Path(namespace): Path<String>,
    Query(query): Query<KVListQuery>,
) -> Response {
    let network_id = match required_network_id(query.network_id.as_deref()) {
        Ok(network_id) => network_id,
        Err(message) => return plain_error(StatusCode::BAD_REQUEST, message),
    };
    match require_membership(&state, &network_id, &identity).await {
        Ok(Some(_)) => {}
        Ok(None) => return plain_error(StatusCode::FORBIDDEN, "membership required"),
        Err(_) => return plain_error(StatusCode::UNAUTHORIZED, "unauthorized"),
    }

    match state
        .store
        .kv_list(
            &network_id,
            &namespace,
            query.prefix.as_deref().unwrap_or_default(),
        )
        .await
    {
        Ok(entries) => Json(entries).into_response(),
        Err(_) => plain_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    }
}

async fn group_create(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthIdentity>,
    body: Bytes,
) -> Response {
    let req = match serde_json::from_slice::<GroupCreateRequest>(&body) {
        Ok(req) => req,
        Err(_) => return plain_error(StatusCode::BAD_REQUEST, "bad request"),
    };
    let network_id = match required_network_id(req.network_id.as_deref()) {
        Ok(network_id) => network_id,
        Err(message) => return plain_error(StatusCode::BAD_REQUEST, message),
    };
    let group_name = match validate_group_name(req.name.as_deref().unwrap_or_default()) {
        Ok(group_name) => group_name,
        Err(message) => return plain_error(StatusCode::BAD_REQUEST, message),
    };
    match require_owner(&state, &network_id, &identity).await {
        Ok(true) => {}
        Ok(false) => return plain_error(StatusCode::FORBIDDEN, "owner access required"),
        Err(_) => return unauthorized_response(),
    }

    let created_by = match membership_subject(&identity) {
        Ok(subject) => subject,
        Err(_) if identity.is_admin => String::new(),
        Err(_) => return unauthorized_response(),
    };
    let now = Utc::now();
    let group = Group {
        network_id,
        name: group_name,
        created_at: now,
        created_by,
    };
    match state.store.group_create(group.clone()).await {
        Ok(()) => match state
            .store
            .group_policy_get(&group.network_id, &group.name)
            .await
        {
            Ok(policy) => Json(group_response(group, Vec::new(), policy)).into_response(),
            Err(_) => plain_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
        },
        Err(StoreError::AlreadyExists) => plain_error(StatusCode::CONFLICT, "group already exists"),
        Err(_) => plain_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    }
}

async fn group_list(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthIdentity>,
    Query(query): Query<NetworkIDQuery>,
) -> Response {
    let network_id = match required_network_id(query.network_id.as_deref()) {
        Ok(network_id) => network_id,
        Err(message) => return plain_error(StatusCode::BAD_REQUEST, message),
    };
    match require_owner(&state, &network_id, &identity).await {
        Ok(true) => {}
        Ok(false) => return plain_error(StatusCode::FORBIDDEN, "owner access required"),
        Err(_) => return unauthorized_response(),
    }

    let groups = match state.store.group_list(&network_id).await {
        Ok(groups) => groups,
        Err(_) => return plain_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    };
    let mut responses = Vec::with_capacity(groups.len());
    for group in groups {
        let policy = match state
            .store
            .group_policy_get(&group.network_id, &group.name)
            .await
        {
            Ok(policy) => policy,
            Err(_) => return plain_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
        };
        responses.push(group_response(group, Vec::new(), policy));
    }
    Json(responses).into_response()
}

async fn group_bindings(
    State(state): State<AppState>,
    Query(query): Query<GroupMemberQuery>,
    headers: HeaderMap,
) -> Response {
    let session_name = query
        .session_name
        .as_deref()
        .unwrap_or_default()
        .trim()
        .to_string();
    if session_name.is_empty() {
        return plain_error(StatusCode::BAD_REQUEST, "session_name required");
    }

    let (network_id, node_name) =
        if let Some(node) = node_auth_from_headers(&headers, state.store.as_ref()).await {
            let requested_node_name = query
                .node_name
                .as_deref()
                .unwrap_or_default()
                .trim()
                .to_string();
            let node_name = if requested_node_name.is_empty() {
                node.name.clone()
            } else {
                requested_node_name
            };
            if node_name != node.name {
                return plain_error(StatusCode::FORBIDDEN, "forbidden");
            }
            (node.network_id, node_name)
        } else {
            let Some(identity) =
                authenticate_headers(&headers, &state.config, state.store.as_ref()).await
            else {
                return unauthorized_response();
            };
            let network_id = match required_network_id(query.network_id.as_deref()) {
                Ok(network_id) => network_id,
                Err(message) => return plain_error(StatusCode::BAD_REQUEST, message),
            };
            let node_name = query
                .node_name
                .as_deref()
                .unwrap_or_default()
                .trim()
                .to_string();
            if node_name.is_empty() {
                return plain_error(StatusCode::BAD_REQUEST, "node_name required");
            }
            match require_owner(&state, &network_id, &identity).await {
                Ok(true) => {}
                Ok(false) => return plain_error(StatusCode::FORBIDDEN, "owner access required"),
                Err(_) => return unauthorized_response(),
            }
            (network_id, node_name)
        };

    let bindings: Vec<GroupBinding> = match state
        .store
        .group_bindings_for_session(&network_id, &node_name, &session_name)
        .await
    {
        Ok(bindings) => bindings,
        Err(_) => return plain_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    };
    Json(bindings).into_response()
}

async fn group_get(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthIdentity>,
    Path(name): Path<String>,
    Query(query): Query<NetworkIDQuery>,
) -> Response {
    let network_id = match required_network_id(query.network_id.as_deref()) {
        Ok(network_id) => network_id,
        Err(message) => return plain_error(StatusCode::BAD_REQUEST, message),
    };
    let group_name = match validate_group_name(&name) {
        Ok(group_name) => group_name,
        Err(message) => return plain_error(StatusCode::BAD_REQUEST, message),
    };
    match require_owner(&state, &network_id, &identity).await {
        Ok(true) => {}
        Ok(false) => return plain_error(StatusCode::FORBIDDEN, "owner access required"),
        Err(_) => return unauthorized_response(),
    }

    match load_group_response(&state, &network_id, &group_name).await {
        Ok(Some(response)) => Json(response).into_response(),
        Ok(None) => plain_error(StatusCode::NOT_FOUND, "group not found"),
        Err(_) => plain_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    }
}

async fn group_delete(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthIdentity>,
    Path(name): Path<String>,
    Query(query): Query<NetworkIDQuery>,
) -> Response {
    let network_id = match required_network_id(query.network_id.as_deref()) {
        Ok(network_id) => network_id,
        Err(message) => return plain_error(StatusCode::BAD_REQUEST, message),
    };
    let group_name = match validate_group_name(&name) {
        Ok(group_name) => group_name,
        Err(message) => return plain_error(StatusCode::BAD_REQUEST, message),
    };
    match require_owner(&state, &network_id, &identity).await {
        Ok(true) => {}
        Ok(false) => return plain_error(StatusCode::FORBIDDEN, "owner access required"),
        Err(_) => return unauthorized_response(),
    }

    match state.store.group_delete(&network_id, &group_name).await {
        Ok(()) => Json(GroupDeleteResponse {
            status: "deleted",
            network_id,
            name: group_name,
        })
        .into_response(),
        Err(StoreError::NotFound) => plain_error(StatusCode::NOT_FOUND, "group not found"),
        Err(_) => plain_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    }
}

async fn group_member_add(
    State(state): State<AppState>,
    Path(name): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let group_name = match validate_group_name(&name) {
        Ok(group_name) => group_name,
        Err(message) => return plain_error(StatusCode::BAD_REQUEST, message),
    };
    let req = match serde_json::from_slice::<GroupMemberRequest>(&body) {
        Ok(req) => req,
        Err(_) => return plain_error(StatusCode::BAD_REQUEST, "bad request"),
    };
    let session_name = req
        .session_name
        .as_deref()
        .unwrap_or_default()
        .trim()
        .to_string();
    if session_name.is_empty() {
        return plain_error(StatusCode::BAD_REQUEST, "session_name required");
    }

    let (network_id, node_name) =
        if let Some(node) = node_auth_from_headers(&headers, state.store.as_ref()).await {
            let requested_node_name = req
                .node_name
                .as_deref()
                .unwrap_or_default()
                .trim()
                .to_string();
            let node_name = if requested_node_name.is_empty() {
                node.name.clone()
            } else {
                requested_node_name
            };
            if node_name != node.name {
                return plain_error(StatusCode::FORBIDDEN, "forbidden");
            }
            (node.network_id, node_name)
        } else {
            let Some(identity) =
                authenticate_headers(&headers, &state.config, state.store.as_ref()).await
            else {
                return unauthorized_response();
            };
            let network_id = match required_network_id(req.network_id.as_deref()) {
                Ok(network_id) => network_id,
                Err(message) => return plain_error(StatusCode::BAD_REQUEST, message),
            };
            let node_name = req
                .node_name
                .as_deref()
                .unwrap_or_default()
                .trim()
                .to_string();
            if node_name.is_empty() {
                return plain_error(StatusCode::BAD_REQUEST, "node_name required");
            }
            match require_owner(&state, &network_id, &identity).await {
                Ok(true) => {}
                Ok(false) => return plain_error(StatusCode::FORBIDDEN, "owner access required"),
                Err(_) => return unauthorized_response(),
            }
            (network_id, node_name)
        };

    let member = GroupMember {
        network_id,
        group_name,
        node_name,
        session_name,
        created_at: Utc::now(),
    };
    match state.store.group_member_add(member.clone()).await {
        Ok(()) => Json(member).into_response(),
        Err(StoreError::NotFound) => plain_error(StatusCode::NOT_FOUND, "group not found"),
        Err(_) => plain_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    }
}

async fn group_member_remove(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Query(query): Query<GroupMemberQuery>,
    headers: HeaderMap,
) -> Response {
    let group_name = match validate_group_name(&name) {
        Ok(group_name) => group_name,
        Err(message) => return plain_error(StatusCode::BAD_REQUEST, message),
    };
    let session_name = query
        .session_name
        .as_deref()
        .unwrap_or_default()
        .trim()
        .to_string();
    if session_name.is_empty() {
        return plain_error(StatusCode::BAD_REQUEST, "session_name required");
    }

    let (network_id, node_name) =
        if let Some(node) = node_auth_from_headers(&headers, state.store.as_ref()).await {
            let requested_node_name = query
                .node_name
                .as_deref()
                .unwrap_or_default()
                .trim()
                .to_string();
            let node_name = if requested_node_name.is_empty() {
                node.name.clone()
            } else {
                requested_node_name
            };
            if node_name != node.name {
                return plain_error(StatusCode::FORBIDDEN, "forbidden");
            }
            (node.network_id, node_name)
        } else {
            let Some(identity) =
                authenticate_headers(&headers, &state.config, state.store.as_ref()).await
            else {
                return unauthorized_response();
            };
            let network_id = match required_network_id(query.network_id.as_deref()) {
                Ok(network_id) => network_id,
                Err(message) => return plain_error(StatusCode::BAD_REQUEST, message),
            };
            let node_name = query
                .node_name
                .as_deref()
                .unwrap_or_default()
                .trim()
                .to_string();
            if node_name.is_empty() {
                return plain_error(StatusCode::BAD_REQUEST, "node_name required");
            }
            match require_owner(&state, &network_id, &identity).await {
                Ok(true) => {}
                Ok(false) => return plain_error(StatusCode::FORBIDDEN, "owner access required"),
                Err(_) => return unauthorized_response(),
            }
            (network_id, node_name)
        };

    match state
        .store
        .group_member_remove(&network_id, &group_name, &node_name, &session_name)
        .await
    {
        Ok(()) => Json(GroupMemberRemoveResponse {
            status: "removed",
            network_id,
            group_name,
            node_name,
            session_name,
        })
        .into_response(),
        Err(StoreError::NotFound) => plain_error(StatusCode::NOT_FOUND, "group member not found"),
        Err(_) => plain_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    }
}

async fn group_policy_set(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthIdentity>,
    Path(name): Path<String>,
    body: Bytes,
) -> Response {
    let group_name = match validate_group_name(&name) {
        Ok(group_name) => group_name,
        Err(message) => return plain_error(StatusCode::BAD_REQUEST, message),
    };
    let req = match serde_json::from_slice::<GroupPolicyRequest>(&body) {
        Ok(req) => req,
        Err(_) => return plain_error(StatusCode::BAD_REQUEST, "bad request"),
    };
    let network_id = match required_network_id(req.network_id.as_deref()) {
        Ok(network_id) => network_id,
        Err(message) => return plain_error(StatusCode::BAD_REQUEST, message),
    };
    let messages_policy = match normalize_group_messages_policy(req.messages_policy.as_deref()) {
        Ok(policy) => policy,
        Err(message) => return plain_error(StatusCode::BAD_REQUEST, message),
    };
    let debug_policy = match normalize_group_debug_policy(req.debug_policy.as_deref()) {
        Ok(policy) => policy,
        Err(message) => return plain_error(StatusCode::BAD_REQUEST, message),
    };
    match require_owner(&state, &network_id, &identity).await {
        Ok(true) => {}
        Ok(false) => return plain_error(StatusCode::FORBIDDEN, "owner access required"),
        Err(_) => return unauthorized_response(),
    }

    let policy = GroupPolicy {
        network_id,
        group_name,
        messages_policy,
        debug_policy,
        updated_at: Utc::now(),
    };
    match state.store.group_policy_set(policy.clone()).await {
        Ok(()) => Json(policy).into_response(),
        Err(StoreError::NotFound) => plain_error(StatusCode::NOT_FOUND, "group not found"),
        Err(_) => plain_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    }
}

async fn node_list(
    State(state): State<AppState>,
    Query(query): Query<NodesListQuery>,
    headers: HeaderMap,
) -> Response {
    if let Some(node) = node_auth_from_headers(&headers, state.store.as_ref()).await {
        return match state.store.node_list(&node.network_id).await {
            Ok(nodes) => Json(node_responses(nodes)).into_response(),
            Err(_) => plain_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
        };
    }

    let Some(identity) = authenticate_headers(&headers, &state.config, state.store.as_ref()).await
    else {
        return unauthorized_response();
    };

    let all = query
        .all
        .as_deref()
        .unwrap_or_default()
        .trim()
        .eq_ignore_ascii_case("true");

    let nodes = if identity.is_admin && all {
        state.store.node_list_all().await
    } else if all {
        let subject = match membership_subject(&identity) {
            Ok(subject) => subject,
            Err(_) => return unauthorized_response(),
        };
        let networks = match state.store.network_list_by_member(&subject).await {
            Ok(networks) => networks,
            Err(_) => return plain_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
        };
        let mut nodes = Vec::new();
        for network in networks {
            match state.store.node_list(&network.id).await {
                Ok(mut network_nodes) => nodes.append(&mut network_nodes),
                Err(_) => return plain_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
            }
        }
        Ok(nodes)
    } else {
        let network_id = match required_network_id(query.network_id.as_deref()) {
            Ok(network_id) => network_id,
            Err(message) => return plain_error(StatusCode::BAD_REQUEST, message),
        };
        match require_membership(&state, &network_id, &identity).await {
            Ok(Some(_)) => state.store.node_list(&network_id).await,
            Ok(None) => return plain_error(StatusCode::FORBIDDEN, "membership required"),
            Err(_) => return unauthorized_response(),
        }
    };

    match nodes {
        Ok(nodes) => Json(node_responses(nodes)).into_response(),
        Err(_) => plain_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    }
}

async fn node_revoke(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthIdentity>,
    Path(name): Path<String>,
    Query(query): Query<NodesListQuery>,
) -> Response {
    let network_id = match required_network_id(query.network_id.as_deref()) {
        Ok(network_id) => network_id,
        Err(message) => return plain_error(StatusCode::BAD_REQUEST, message),
    };
    match require_owner(&state, &network_id, &identity).await {
        Ok(true) => {}
        Ok(false) => return plain_error(StatusCode::FORBIDDEN, "owner access required"),
        Err(_) => return unauthorized_response(),
    }

    match state.store.node_get(&network_id, &name).await {
        Ok(Some(_)) => {}
        Ok(None) | Err(_) => return plain_error(StatusCode::NOT_FOUND, "node not found"),
    }
    if state.store.node_delete(&network_id, &name).await.is_err() {
        return plain_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error");
    }

    Json(NodeRevokeResponse {
        status: "revoked",
        node: &name,
    })
    .into_response()
}

async fn tailnet_coordinate(
    State(state): State<AppState>,
    Query(query): Query<TailnetCoordinateQuery>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    let claims = match verify_tailnet_runtime_credential(&state, &headers).await {
        Ok(claims) => claims,
        Err(status) if status == StatusCode::INTERNAL_SERVER_ERROR => {
            return plain_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error");
        }
        Err(_) => return unauthorized_response(),
    };
    let derp_map_url = state
        .config
        .derp_url
        .as_deref()
        .unwrap_or(&state.config.base_url);
    let derp_map = match tailnet_derp_map_from_base_url(derp_map_url) {
        Ok(derp_map) => derp_map,
        Err(err) => {
            tracing::error!(error = %err, derp_url = %derp_map_url, "invalid codewire-mesh DERP map URL");
            return plain_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error");
        }
    };
    let peer_id = tailnet_peer_id(&claims, query.role.as_deref());

    ws.protocols(["coordinate"]).on_upgrade(move |socket| {
        tailnet_coordinate_session(socket, state, claims, peer_id, derp_map)
    })
}

async fn tailnet_coordinate_session(
    mut socket: WebSocket,
    state: AppState,
    claims: RuntimeClaims,
    peer_id: Uuid,
    derp_map: JsonValue,
) {
    let mut updates = state.tailnet_coord.register(
        peer_id,
        format!("{}:{}", claims.subject_kind, claims.subject_id),
    );
    tracing::info!(
        %peer_id,
        kind = %claims.subject_kind,
        subject = %claims.subject_id,
        network_id = %claims.network_id,
        "tailnet coordinate connected"
    );

    let result = tailnet_coordinate_session_inner(
        &mut socket,
        &state,
        &claims,
        peer_id,
        derp_map,
        &mut updates,
    )
    .await;

    state.tailnet_coord.deregister(peer_id);
    tracing::info!(
        %peer_id,
        kind = %claims.subject_kind,
        subject = %claims.subject_id,
        network_id = %claims.network_id,
        "tailnet coordinate disconnected"
    );
    if let Err(err) = result {
        tracing::debug!(%peer_id, error = %err, "tailnet coordinate session closed");
    }
}

async fn tailnet_coordinate_session_inner(
    socket: &mut WebSocket,
    state: &AppState,
    claims: &RuntimeClaims,
    peer_id: Uuid,
    derp_map: JsonValue,
    updates: &mut mpsc::Receiver<Vec<TailnetNode>>,
) -> Result<(), String> {
    send_tailnet_response(
        socket,
        TailnetCoordinateResponse {
            typ: "derp_map",
            nodes: Vec::new(),
            derp_map: Some(derp_map),
            error: None,
        },
    )
    .await?;

    loop {
        tokio::select! {
            update = updates.recv() => {
                let Some(nodes) = update else {
                    return Ok(());
                };
                if nodes.is_empty() {
                    continue;
                }
                send_tailnet_response(
                    socket,
                    TailnetCoordinateResponse {
                        typ: "peer_update",
                        nodes,
                        derp_map: None,
                        error: None,
                    },
                ).await?;
            }
            message = socket.recv() => {
                let data = match message {
                    Some(Ok(Message::Text(text))) => text.as_bytes().to_vec(),
                    Some(Ok(Message::Binary(bytes))) => bytes.to_vec(),
                    Some(Ok(Message::Close(_))) | None => return Ok(()),
                    Some(Ok(Message::Ping(_))) | Some(Ok(Message::Pong(_))) => continue,
                    Some(Err(err)) => return Err(err.to_string()),
                };
                let req = match serde_json::from_slice::<TailnetCoordinateRequest>(&data) {
                    Ok(req) => req,
                    Err(_) => {
                        send_tailnet_error(socket, "bad request").await?;
                        continue;
                    }
                };
                match req.typ.as_str() {
                    "node" => {
                        let Some(node) = req.node else {
                            send_tailnet_error(socket, "node update requires node payload").await?;
                            continue;
                        };
                        tracing::info!(
                            %peer_id,
                            subject = %claims.subject_id,
                            "tailnet node update"
                        );
                        state.tailnet_coord.update_node(peer_id, node);
                    }
                    "subscribe" => {
                        let target = req.target_node.trim();
                        if target.is_empty() {
                            send_tailnet_error(socket, "subscribe requires target_node").await?;
                            continue;
                        }
                        let target_uuid =
                            stable_principal_uuid(&claims.network_id, SUBJECT_KIND_NODE, target);
                        let delivered = state.tailnet_coord.add_tunnel(peer_id, target_uuid);
                        tracing::info!(
                            %peer_id,
                            target,
                            %target_uuid,
                            delivered,
                            "tailnet subscribe"
                        );
                    }
                    other => {
                        send_tailnet_error(socket, format!("unsupported request type {other:?}")).await?;
                    }
                }
            }
        }
    }
}

async fn send_tailnet_error(
    socket: &mut WebSocket,
    error: impl Into<String>,
) -> Result<(), String> {
    send_tailnet_response(
        socket,
        TailnetCoordinateResponse {
            typ: "error",
            nodes: Vec::new(),
            derp_map: None,
            error: Some(error.into()),
        },
    )
    .await
}

async fn send_tailnet_response(
    socket: &mut WebSocket,
    response: TailnetCoordinateResponse,
) -> Result<(), String> {
    let payload = serde_json::to_string(&response).map_err(|err| err.to_string())?;
    socket
        .send(Message::Text(payload.into()))
        .await
        .map_err(|err| err.to_string())
}

async fn verify_tailnet_runtime_credential(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<RuntimeClaims, StatusCode> {
    let token = bearer_token(headers)
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let (unverified, _, _) =
        parse_runtime_credential(token).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let issuer = load_issuer_state(state, &unverified.network_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let now = Utc::now();
    let claims =
        verify_runtime_credential(token, &issuer.bundle(now, DEFAULT_BUNDLE_VALIDITY), now)
            .map_err(|_| StatusCode::UNAUTHORIZED)?;
    if claims.subject_kind != SUBJECT_KIND_CLIENT && claims.subject_kind != SUBJECT_KIND_NODE {
        return Err(StatusCode::UNAUTHORIZED);
    }

    match claims.subject_kind.as_str() {
        SUBJECT_KIND_CLIENT if claims.subject_id != "admin" => {
            match state
                .store
                .network_member_get(&claims.network_id, &claims.subject_id)
                .await
            {
                Ok(Some(_)) => {}
                Ok(None) => return Err(StatusCode::UNAUTHORIZED),
                Err(_) => return Err(StatusCode::INTERNAL_SERVER_ERROR),
            }
        }
        SUBJECT_KIND_NODE => {
            match state
                .store
                .node_get(&claims.network_id, &claims.subject_id)
                .await
            {
                Ok(Some(_)) => {}
                Ok(None) => return Err(StatusCode::UNAUTHORIZED),
                Err(_) => return Err(StatusCode::INTERNAL_SERVER_ERROR),
            }
        }
        _ => {}
    }

    state.runtime_replay.remember(&claims, now);
    Ok(claims)
}

fn tailnet_peer_id(claims: &RuntimeClaims, role: Option<&str>) -> Uuid {
    if claims.subject_kind == SUBJECT_KIND_CLIENT || role == Some("dial") {
        return Uuid::new_v4();
    }
    stable_principal_uuid(&claims.network_id, &claims.subject_kind, &claims.subject_id)
}

fn stable_principal_uuid(network_id: &str, subject_kind: &str, subject_id: &str) -> Uuid {
    let mut hasher = Sha256::new();
    hasher.update(network_id.trim().as_bytes());
    hasher.update(b"\0");
    hasher.update(subject_kind.trim().as_bytes());
    hasher.update(b"\0");
    hasher.update(subject_id.trim().as_bytes());
    let sum = hasher.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&sum[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

fn tailnet_derp_map_from_base_url(base_url: &str) -> Result<JsonValue, String> {
    let url = Url::parse(base_url.trim()).map_err(|err| err.to_string())?;
    let hostname = url
        .host_str()
        .filter(|host| !host.is_empty())
        .ok_or_else(|| "base URL has no hostname".to_string())?;
    let port = match url.port() {
        Some(port) => i64::from(port),
        None => match url.scheme() {
            "http" | "ws" => 80,
            "https" | "wss" => 443,
            scheme => return Err(format!("unsupported base URL scheme {scheme:?}")),
        },
    };
    let insecure = matches!(url.scheme(), "http" | "ws");

    let mut node = JsonMap::new();
    node.insert("Name".to_string(), JsonValue::String("1a".to_string()));
    node.insert("RegionID".to_string(), JsonValue::from(1));
    node.insert(
        "HostName".to_string(),
        JsonValue::String(hostname.to_string()),
    );
    node.insert("DERPPort".to_string(), JsonValue::from(port));
    node.insert("STUNPort".to_string(), JsonValue::from(-1));
    if insecure {
        node.insert("InsecureForTests".to_string(), JsonValue::Bool(true));
    }

    Ok(serde_json::json!({
        "Regions": {
            "1": {
                "RegionID": 1,
                "RegionCode": "cw",
                "RegionName": "Codewire Embedded",
                "Nodes": [JsonValue::Object(node)],
            }
        }
    }))
}

async fn verifier_bundle(
    State(state): State<AppState>,
    Query(query): Query<NetworkIDQuery>,
    headers: HeaderMap,
) -> Response {
    let network_id = match required_network_id(query.network_id.as_deref()) {
        Ok(network_id) => network_id,
        Err(message) => return plain_error(StatusCode::BAD_REQUEST, message),
    };

    if let Some(node) = node_auth_from_headers(&headers, state.store.as_ref()).await {
        if node.network_id != network_id {
            return plain_error(StatusCode::FORBIDDEN, "forbidden");
        }
    } else {
        let Some(identity) =
            authenticate_headers(&headers, &state.config, state.store.as_ref()).await
        else {
            return unauthorized_response();
        };
        if !identity.is_admin {
            match require_membership(&state, &network_id, &identity).await {
                Ok(Some(_)) => {}
                Ok(None) => return plain_error(StatusCode::FORBIDDEN, "membership required"),
                Err(_) => return unauthorized_response(),
            }
        }
    }

    match load_issuer_state(&state, &network_id).await {
        Ok(Some(issuer)) => {
            Json(issuer.bundle(Utc::now(), DEFAULT_BUNDLE_VALIDITY)).into_response()
        }
        Ok(None) => plain_error(StatusCode::NOT_FOUND, "not found"),
        Err(_) => plain_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    }
}

async fn client_runtime_credential(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthIdentity>,
    Query(query): Query<NetworkIDQuery>,
) -> Response {
    let network_id = match required_network_id(query.network_id.as_deref()) {
        Ok(network_id) => network_id,
        Err(message) => return plain_error(StatusCode::BAD_REQUEST, message),
    };
    if !identity.is_admin {
        match require_membership(&state, &network_id, &identity).await {
            Ok(Some(_)) => {}
            Ok(None) => return plain_error(StatusCode::FORBIDDEN, "membership required"),
            Err(_) => return unauthorized_response(),
        }
    }

    let issuer = match load_or_create_issuer_state(&state, &network_id).await {
        Ok(issuer) => issuer,
        Err(_) => return plain_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    };
    let subject_id = client_subject_id(&identity);
    let (credential, claims) = match sign_runtime_credential(
        &issuer,
        SUBJECT_KIND_CLIENT,
        &subject_id,
        Utc::now(),
        DEFAULT_RUNTIME_TTL,
    ) {
        Ok(signed) => signed,
        Err(_) => return plain_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    };

    Json(RuntimeCredentialResponse {
        credential,
        network_id: claims.network_id,
        subject_kind: claims.subject_kind,
        subject_id: claims.subject_id,
        expires_at: claims.expires_at,
    })
    .into_response()
}

async fn node_runtime_credential(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(node) = node_auth_from_headers(&headers, state.store.as_ref()).await else {
        return unauthorized_response();
    };
    let issuer = match load_or_create_issuer_state(&state, &node.network_id).await {
        Ok(issuer) => issuer,
        Err(_) => return plain_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    };
    let (credential, claims) = match sign_runtime_credential(
        &issuer,
        SUBJECT_KIND_NODE,
        &node.name,
        Utc::now(),
        DEFAULT_RUNTIME_TTL,
    ) {
        Ok(signed) => signed,
        Err(_) => return plain_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    };

    Json(RuntimeCredentialResponse {
        credential,
        network_id: claims.network_id,
        subject_kind: claims.subject_kind,
        subject_id: claims.subject_id,
        expires_at: claims.expires_at,
    })
    .into_response()
}

async fn node_sender_delegation(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let req = match serde_json::from_slice::<SenderDelegationRequest>(&body) {
        Ok(req) => req,
        Err(_) => return plain_error(StatusCode::BAD_REQUEST, "bad request"),
    };
    let network_id = req.network_id.unwrap_or_default().trim().to_string();
    let source_node = req.source_node.unwrap_or_default().trim().to_string();
    let node = match node_auth_from_headers(&headers, state.store.as_ref()).await {
        Some(node) => {
            if !network_id.is_empty() && network_id != node.network_id {
                return plain_error(
                    StatusCode::FORBIDDEN,
                    "network_id must match authenticated node",
                );
            }
            if !source_node.is_empty() && source_node != node.name {
                return plain_error(
                    StatusCode::FORBIDDEN,
                    "source_node must match authenticated node",
                );
            }
            node
        }
        None => {
            let Some(identity) =
                authenticate_headers(&headers, &state.config, state.store.as_ref()).await
            else {
                return unauthorized_response();
            };
            if source_node.is_empty() {
                return plain_error(StatusCode::BAD_REQUEST, "source_node is required");
            }
            if network_id.is_empty() {
                return plain_error(StatusCode::BAD_REQUEST, "network_id is required");
            }
            let nodes = match state.store.node_list_all().await {
                Ok(nodes) => nodes
                    .into_iter()
                    .filter(|node| node.network_id == network_id && node.name == source_node)
                    .collect::<Vec<_>>(),
                Err(_) => return plain_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
            };
            let [node] = nodes.as_slice() else {
                return plain_error(
                    StatusCode::BAD_REQUEST,
                    "source_node is ambiguous or unknown",
                );
            };
            match require_membership(&state, &node.network_id, &identity).await {
                Ok(Some(_)) => node.clone(),
                Ok(None) => return plain_error(StatusCode::FORBIDDEN, "membership required"),
                Err(_) => return unauthorized_response(),
            }
        }
    };
    let from_session_name = req.from_session_name.unwrap_or_default().trim().to_string();
    let mut source_groups = Vec::new();
    if !from_session_name.is_empty() {
        let bindings = match state
            .store
            .group_bindings_for_session(&node.network_id, &node.name, &from_session_name)
            .await
        {
            Ok(bindings) => bindings,
            Err(_) => return plain_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
        };
        source_groups = bindings
            .into_iter()
            .map(|binding| binding.group_name)
            .collect();
    }

    let issuer = match load_or_create_issuer_state(&state, &node.network_id).await {
        Ok(issuer) => issuer,
        Err(_) => return plain_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    };
    let verbs = req.verbs.unwrap_or_default();
    let audience_node = req.audience_node.unwrap_or_default();
    let (delegation, claims) = match sign_sender_delegation(
        &issuer,
        Utc::now(),
        SenderDelegationInput {
            source_node: node.name.clone(),
            from_session_id: req.from_session_id,
            from_session_name,
            source_groups,
            verbs,
            audience_node,
            ttl: DEFAULT_SENDER_TTL,
        },
    ) {
        Ok(signed) => signed,
        Err(_) => return plain_error(StatusCode::BAD_REQUEST, "bad request"),
    };

    Json(SenderDelegationResponse {
        delegation,
        network_id: claims.network_id,
        source_node: claims.source_node,
        from_session_id: claims.from_session_id,
        from_session_name: claims.from_session_name,
        source_groups: claims.source_groups,
        audience_node: claims.audience_node,
        expires_at: claims.expires_at,
    })
    .into_response()
}

async fn access_grant_create(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthIdentity>,
    body: Bytes,
) -> Response {
    let req = match serde_json::from_slice::<AccessGrantCreateRequest>(&body) {
        Ok(req) => req,
        Err(_) => return plain_error(StatusCode::BAD_REQUEST, "bad request"),
    };
    let network_id = match required_network_id(req.network_id.as_deref()) {
        Ok(network_id) => network_id,
        Err(message) => return plain_error(StatusCode::BAD_REQUEST, message),
    };
    match require_owner(&state, &network_id, &identity).await {
        Ok(true) => {}
        Ok(false) => return plain_error(StatusCode::FORBIDDEN, "owner access required"),
        Err(_) => return plain_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    }

    let target_node = req.target_node.unwrap_or_default().trim().to_string();
    if target_node.is_empty() {
        return plain_error(StatusCode::BAD_REQUEST, "target_node required");
    }
    let session_name = req.session_name.unwrap_or_default().trim().to_string();
    if req.session_id.is_none() && session_name.is_empty() {
        return plain_error(
            StatusCode::BAD_REQUEST,
            "session_id or session_name required",
        );
    }
    if req.session_id.is_some() && !session_name.is_empty() {
        return plain_error(
            StatusCode::BAD_REQUEST,
            "session_id and session_name are mutually exclusive",
        );
    }

    let verbs = match normalize_observer_verbs(req.verbs.unwrap_or_default()) {
        Ok(verbs) => verbs,
        Err(message) => return plain_error(StatusCode::BAD_REQUEST, message),
    };
    let ttl = match req
        .ttl
        .as_deref()
        .map(str::trim)
        .filter(|raw| !raw.is_empty())
    {
        None => DEFAULT_OBSERVER_TTL,
        Some(raw) => match parse_go_duration(raw) {
            Some(ttl) => ttl,
            None => return plain_error(StatusCode::BAD_REQUEST, "invalid ttl"),
        },
    };
    if ttl <= Duration::zero() {
        return plain_error(StatusCode::BAD_REQUEST, "ttl must be positive");
    }

    let (audience_subject_kind, audience_subject_id, audience_display) =
        match resolve_access_grant_audience(&state, req.audience.unwrap_or_default().trim()).await {
            Ok(audience) => audience,
            Err(message) => return plain_error(StatusCode::BAD_REQUEST, message),
        };
    let issuer = match load_or_create_issuer_state(&state, &network_id).await {
        Ok(issuer) => issuer,
        Err(_) => return plain_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    };
    let issued_by = match membership_subject(&identity) {
        Ok(subject) => subject,
        Err(_) if identity.is_admin => String::new(),
        Err(_) => return unauthorized_response(),
    };

    let now = Utc::now();
    let (delegation, claims) = match sign_observer_delegation(
        &issuer,
        now,
        ObserverDelegationInput {
            target_node,
            session_id: req.session_id,
            session_name,
            verbs,
            audience_subject_kind,
            audience_subject_id,
            ttl,
        },
    ) {
        Ok(signed) => signed,
        Err(message) => return plain_error(StatusCode::BAD_REQUEST, &message),
    };

    let grant = AccessGrant {
        id: claims.jti.clone(),
        network_id: claims.network_id.clone(),
        target_node: claims.target_node.clone(),
        session_id: claims.session_id,
        session_name: claims.session_name.clone(),
        verbs: claims.verbs.clone(),
        audience_subject_kind: claims.audience_subject_kind.clone(),
        audience_subject_id: claims.audience_subject_id.clone(),
        audience_display: audience_display.clone(),
        issued_by,
        created_at: now,
        expires_at: claims.expires_at,
        revoked_at: None,
    };
    if state.store.access_grant_create(grant).await.is_err() {
        return plain_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error");
    }

    Json(ObserverDelegationResponse {
        delegation,
        grant_id: claims.jti,
        network_id: claims.network_id,
        target_node: claims.target_node,
        session_id: claims.session_id,
        session_name: claims.session_name,
        verbs: claims.verbs,
        audience_subject_kind: claims.audience_subject_kind,
        audience_subject_id: claims.audience_subject_id,
        audience_display,
        expires_at: claims.expires_at,
    })
    .into_response()
}

async fn access_grant_list(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthIdentity>,
    Query(query): Query<AccessGrantListQuery>,
) -> Response {
    let network_id = match required_network_id(query.network_id.as_deref()) {
        Ok(network_id) => network_id,
        Err(message) => return plain_error(StatusCode::BAD_REQUEST, message),
    };

    let mut filter = AccessGrantFilter {
        target_node: query.target_node.unwrap_or_default().trim().to_string(),
        ..Default::default()
    };
    if let Some(raw) = query
        .mine
        .as_deref()
        .map(str::trim)
        .filter(|raw| !raw.is_empty())
    {
        let mine = match parse_bool_query(raw) {
            Some(mine) => mine,
            None => return plain_error(StatusCode::BAD_REQUEST, "invalid mine filter"),
        };
        if mine {
            let subject = match membership_subject(&identity) {
                Ok(subject) => subject,
                Err(_) => return unauthorized_response(),
            };
            match require_membership(&state, &network_id, &identity).await {
                Ok(Some(_)) => {}
                Ok(None) => return plain_error(StatusCode::FORBIDDEN, "membership required"),
                Err(_) => return plain_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
            }
            filter.audience_subject_id = subject;
        }
    }
    if filter.audience_subject_id.is_empty() {
        match require_owner(&state, &network_id, &identity).await {
            Ok(true) => {}
            Ok(false) => return plain_error(StatusCode::FORBIDDEN, "owner access required"),
            Err(_) => return plain_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
        }
    }
    if let Some(raw) = query
        .active
        .as_deref()
        .map(str::trim)
        .filter(|raw| !raw.is_empty())
    {
        filter.active_only = match parse_bool_query(raw) {
            Some(active) => active,
            None => return plain_error(StatusCode::BAD_REQUEST, "invalid active filter"),
        };
    }
    if let Some(audience) = query
        .audience
        .as_deref()
        .map(str::trim)
        .filter(|raw| !raw.is_empty())
        && filter.audience_subject_id.is_empty()
    {
        let (_, audience_subject_id, _) =
            match resolve_access_grant_audience(&state, audience).await {
                Ok(audience) => audience,
                Err(message) => return plain_error(StatusCode::BAD_REQUEST, message),
            };
        filter.audience_subject_id = audience_subject_id;
    }

    match state.store.access_grant_list(&network_id, filter).await {
        Ok(grants) => Json(grants).into_response(),
        Err(_) => plain_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    }
}

async fn access_grant_get(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthIdentity>,
    Path(grant_id): Path<String>,
    Query(query): Query<NetworkIDQuery>,
) -> Response {
    let network_id = match required_network_id(query.network_id.as_deref()) {
        Ok(network_id) => network_id,
        Err(message) => return plain_error(StatusCode::BAD_REQUEST, message),
    };
    let grant_id = grant_id.trim().to_string();
    if grant_id.is_empty() {
        return plain_error(StatusCode::BAD_REQUEST, "grant id required");
    }
    let grant = match state.store.access_grant_get(&network_id, &grant_id).await {
        Ok(Some(grant)) => grant,
        Ok(None) => return plain_error(StatusCode::NOT_FOUND, "access grant not found"),
        Err(_) => return plain_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    };

    let subject = membership_subject(&identity).ok();
    if subject.as_deref() == Some(grant.audience_subject_id.as_str()) {
        match require_membership(&state, &network_id, &identity).await {
            Ok(Some(_)) => {}
            Ok(None) => return plain_error(StatusCode::FORBIDDEN, "membership required"),
            Err(_) => return plain_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
        }
    } else {
        match require_owner(&state, &network_id, &identity).await {
            Ok(true) => {}
            Ok(false) => return plain_error(StatusCode::FORBIDDEN, "owner access required"),
            Err(_) => return plain_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
        }
    }

    Json(grant).into_response()
}

async fn access_grant_revoke(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthIdentity>,
    Path(grant_id): Path<String>,
    Query(query): Query<NetworkIDQuery>,
) -> Response {
    let network_id = match required_network_id(query.network_id.as_deref()) {
        Ok(network_id) => network_id,
        Err(message) => return plain_error(StatusCode::BAD_REQUEST, message),
    };
    match require_owner(&state, &network_id, &identity).await {
        Ok(true) => {}
        Ok(false) => return plain_error(StatusCode::FORBIDDEN, "owner access required"),
        Err(_) => return plain_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    }

    let grant_id = grant_id.trim().to_string();
    if grant_id.is_empty() {
        return plain_error(StatusCode::BAD_REQUEST, "grant id required");
    }
    match state.store.access_grant_get(&network_id, &grant_id).await {
        Ok(Some(_)) => {}
        Ok(None) => return plain_error(StatusCode::NOT_FOUND, "access grant not found"),
        Err(_) => return plain_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    }
    let revoked_at = Utc::now();
    if state
        .store
        .access_grant_revoke(&network_id, &grant_id, revoked_at)
        .await
        .is_err()
    {
        return plain_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error");
    }

    Json(AccessGrantRevokeResponse {
        status: "revoked",
        grant_id: &grant_id,
    })
    .into_response()
}

async fn task_list(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthIdentity>,
    Query(query): Query<TaskQuery>,
) -> Response {
    let filter = match task_filter_from_query(query) {
        Ok(filter) => filter,
        Err(message) => return plain_error(StatusCode::BAD_REQUEST, message),
    };
    match require_membership(&state, &filter.network_id, &identity).await {
        Ok(Some(_)) => {}
        Ok(None) => return plain_error(StatusCode::FORBIDDEN, "membership required"),
        Err(_) => return plain_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    }

    match state.store.task_latest_list(filter).await {
        Ok(values) => Json(values).into_response(),
        Err(_) => plain_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    }
}

async fn invite_create(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthIdentity>,
    body: Bytes,
) -> Response {
    let req = decode_invite_create_request(&body);
    let uses = if req.uses <= 0 { 1 } else { req.uses };

    let network_id = match required_network_id(req.network_id.as_deref()) {
        Ok(network_id) => network_id,
        Err(message) => return plain_error(StatusCode::BAD_REQUEST, message),
    };
    match require_owner(&state, &network_id, &identity).await {
        Ok(true) => {}
        Ok(false) => return plain_error(StatusCode::FORBIDDEN, "owner access required"),
        Err(_) => return plain_error(StatusCode::UNAUTHORIZED, "unauthorized"),
    }

    let ttl = match req.ttl.as_deref() {
        None | Some("") => Duration::hours(1),
        Some(raw) => match parse_go_duration(raw) {
            Some(ttl) => ttl,
            None => return plain_error(StatusCode::BAD_REQUEST, "invalid ttl"),
        },
    };

    let now = Utc::now();
    let invite = Invite {
        network_id,
        token: generate_invite_token(),
        created_by: identity.user_id,
        uses_remaining: uses,
        expires_at: now + ttl,
        created_at: now,
    };
    match state.store.invite_create(invite.clone()).await {
        Ok(()) => Json(invite).into_response(),
        Err(_) => plain_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    }
}

fn decode_invite_create_request(body: &Bytes) -> InviteCreateRequest {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
        return InviteCreateRequest::default();
    };
    let network_id = value
        .get("network_id")
        .and_then(|value| value.as_str())
        .map(str::to_string);
    let uses = value
        .get("uses")
        .and_then(|value| value.as_i64())
        .and_then(|value| i32::try_from(value).ok())
        .unwrap_or_default();
    let ttl = value
        .get("ttl")
        .and_then(|value| value.as_str())
        .map(str::to_string);
    InviteCreateRequest {
        network_id,
        uses,
        ttl,
    }
}

async fn invite_list(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthIdentity>,
    Query(query): Query<NetworkIDQuery>,
) -> Response {
    let network_id = match required_network_id(query.network_id.as_deref()) {
        Ok(network_id) => network_id,
        Err(message) => return plain_error(StatusCode::BAD_REQUEST, message),
    };
    match require_owner(&state, &network_id, &identity).await {
        Ok(true) => {}
        Ok(false) => return plain_error(StatusCode::FORBIDDEN, "owner access required"),
        Err(_) => return plain_error(StatusCode::UNAUTHORIZED, "unauthorized"),
    }

    match state.store.invite_list(&network_id).await {
        Ok(invites) => Json(invites).into_response(),
        Err(_) => plain_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    }
}

async fn invite_delete(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthIdentity>,
    Path(token): Path<String>,
    Query(query): Query<NetworkIDQuery>,
) -> Response {
    let network_id = match required_network_id(query.network_id.as_deref()) {
        Ok(network_id) => network_id,
        Err(message) => return plain_error(StatusCode::BAD_REQUEST, message),
    };
    match require_owner(&state, &network_id, &identity).await {
        Ok(true) => {}
        Ok(false) => return plain_error(StatusCode::FORBIDDEN, "owner access required"),
        Err(_) => return plain_error(StatusCode::UNAUTHORIZED, "unauthorized"),
    }

    match state.store.invite_delete(&network_id, &token).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(_) => plain_error(StatusCode::NOT_FOUND, "invite not found"),
    }
}

#[derive(Deserialize)]
struct NetworkJoinRequest {
    invite_token: Option<String>,
}

#[derive(Serialize)]
struct NetworkJoinResponse {
    status: &'static str,
    network_id: String,
}

#[derive(Deserialize)]
struct JoinRequest {
    invite_token: Option<String>,
    node_name: Option<String>,
}

#[derive(Serialize)]
struct JoinBootstrapResponse {
    status: &'static str,
    node_token: String,
    node_name: String,
    network_id: String,
    enrollment_id: String,
}

#[derive(Deserialize)]
struct JoinPageQuery {
    invite: Option<String>,
}

async fn network_join(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthIdentity>,
    body: Bytes,
) -> Response {
    let req = match serde_json::from_slice::<NetworkJoinRequest>(&body) {
        Ok(req) => req,
        Err(_) => return plain_error(StatusCode::BAD_REQUEST, "bad request"),
    };
    let invite_token = req.invite_token.unwrap_or_default();
    if invite_token.trim().is_empty() {
        return plain_error(StatusCode::BAD_REQUEST, "invite_token required");
    }

    let invite = match state.store.invite_get(&invite_token).await {
        Ok(Some(invite)) => invite,
        Ok(None) | Err(_) => {
            return plain_error(StatusCode::FORBIDDEN, "invalid or expired invite");
        }
    };
    if state.store.invite_consume(&invite_token).await.is_err() {
        return plain_error(StatusCode::FORBIDDEN, "invalid or expired invite");
    }

    let subject = match membership_subject(&identity) {
        Ok(subject) => subject,
        Err(_) => return plain_error(StatusCode::UNAUTHORIZED, "unauthorized"),
    };
    let role = match state
        .store
        .network_member_get(&invite.network_id, &subject)
        .await
    {
        Ok(Some(existing)) => existing.role,
        Ok(None) => NETWORK_ROLE_MEMBER.to_string(),
        Err(_) => return plain_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    };
    if state
        .store
        .network_member_upsert(NetworkMember {
            network_id: invite.network_id.clone(),
            subject,
            role,
            created_at: Utc::now(),
            created_by: invite.token,
        })
        .await
        .is_err()
    {
        return plain_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error");
    }

    Json(NetworkJoinResponse {
        status: "joined",
        network_id: invite.network_id,
    })
    .into_response()
}

async fn join_bootstrap(State(state): State<AppState>, body: Bytes) -> Response {
    let req = match serde_json::from_slice::<JoinRequest>(&body) {
        Ok(req) => req,
        Err(_) => return plain_error(StatusCode::BAD_REQUEST, "bad request"),
    };
    let invite_token = req.invite_token.unwrap_or_default();
    let node_name = req.node_name.unwrap_or_default();
    if node_name.is_empty() || invite_token.is_empty() {
        return plain_error(
            StatusCode::BAD_REQUEST,
            "node_name and invite_token required",
        );
    }

    let invite = match state.store.invite_get(&invite_token).await {
        Ok(invite) => invite,
        Err(_) => return plain_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    };
    if state.store.invite_consume(&invite_token).await.is_err() {
        return plain_error(StatusCode::FORBIDDEN, "invalid or expired invite");
    }
    let Some(invite) = invite else {
        return plain_error(StatusCode::FORBIDDEN, "invalid or expired invite");
    };
    if invite.network_id.trim().is_empty() {
        return plain_error(StatusCode::FORBIDDEN, "invalid or expired invite");
    }

    let owner_subject = invite
        .created_by
        .map(|github_id| format!("github:{github_id}"))
        .unwrap_or_default();
    let (_, enrollment_token) = match create_node_enrollment(
        state.store.as_ref(),
        &invite.network_id,
        &owner_subject,
        &owner_subject,
        &node_name,
        1,
        Duration::minutes(10),
    )
    .await
    {
        Ok(created) => created,
        Err(_) => return plain_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    };

    match redeem_node_enrollment(
        state.store.as_ref(),
        &enrollment_token,
        &node_name,
        "",
        invite.created_by,
    )
    .await
    {
        Ok(redeemed) => Json(JoinBootstrapResponse {
            status: "registered",
            node_token: redeemed.node_token,
            node_name: redeemed.node_name,
            network_id: redeemed.network_id,
            enrollment_id: redeemed.enrollment_id,
        })
        .into_response(),
        Err(_) => plain_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    }
}

async fn join_page(State(state): State<AppState>, Query(query): Query<JoinPageQuery>) -> Response {
    let safe_base_url = escape_html(&state.config.base_url);
    let safe_invite = escape_html(query.invite.as_deref().unwrap_or_default());
    let body = format!(
        r#"<!DOCTYPE html>
<html><head><title>Join Codewire Mesh</title>
<style>body{{font-family:system-ui;max-width:480px;margin:80px auto;text-align:center;color:#1a1a1a}}
h2{{font-weight:600}}
.code{{font-family:monospace;background:#f5f5f5;padding:8px 16px;border-radius:6px;display:inline-block;margin:12px 0;word-break:break-all}}
p{{color:#525252;line-height:1.6}}
</style></head><body>
<h2>Join Codewire Mesh</h2>
<p>Use this invite code to join the network:</p>
<div class="code">{safe_invite}</div>
<p>Run on your device:</p>
<div class="code">cw login && cw network join --mesh-url {safe_base_url} {safe_invite}</div>
</body></html>"#
    );
    (
        StatusCode::OK,
        [(
            CONTENT_TYPE,
            HeaderValue::from_static("text/html; charset=utf-8"),
        )],
        body,
    )
        .into_response()
}

fn normalize_observer_verbs(raw: Vec<String>) -> Result<Vec<String>, &'static str> {
    if raw.is_empty() {
        return Ok(vec!["msg.read".to_string(), "msg.listen".to_string()]);
    }

    let mut verbs = Vec::with_capacity(raw.len());
    for verb in raw {
        let normalized = match verb.trim().to_ascii_lowercase().as_str() {
            "read" | "msg.read" => "msg.read",
            "listen" | "msg.listen" => "msg.listen",
            _ => return Err("unsupported verb"),
        };
        if !verbs.iter().any(|existing| existing == normalized) {
            verbs.push(normalized.to_string());
        }
    }
    if verbs.is_empty() {
        Err("at least one verb required")
    } else {
        Ok(verbs)
    }
}

async fn resolve_access_grant_audience(
    state: &AppState,
    raw: &str,
) -> Result<(String, String, String), &'static str> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err("audience required");
    }
    if raw == "admin" {
        return Ok((
            SUBJECT_KIND_CLIENT.to_string(),
            "admin".to_string(),
            "admin".to_string(),
        ));
    }
    if raw.starts_with("github:") || raw.starts_with("oidc:") || raw.starts_with("user:") {
        return Ok((
            SUBJECT_KIND_CLIENT.to_string(),
            raw.to_string(),
            raw.to_string(),
        ));
    }

    let mut matches = Vec::new();
    match state.store.user_get_by_username(raw).await {
        Ok(Some(user)) => matches.push((format!("github:{}", user.github_id), user.username)),
        Ok(None) => {}
        Err(_) => return Err("resolving audience"),
    }
    match state.store.oidc_user_list_by_username(raw).await {
        Ok(users) => {
            matches.extend(
                users
                    .into_iter()
                    .map(|user| (format!("oidc:{}", user.sub), user.username)),
            );
        }
        Err(_) => return Err("resolving audience"),
    }

    match matches.len() {
        0 => Err("principal not found"),
        1 => {
            let (id, display) = matches.remove(0);
            Ok((SUBJECT_KIND_CLIENT.to_string(), id, display))
        }
        _ => Err("principal is ambiguous; use an explicit subject like github:<id> or oidc:<sub>"),
    }
}

fn parse_bool_query(raw: &str) -> Option<bool> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "t" | "true" => Some(true),
        "0" | "f" | "false" => Some(false),
        _ => None,
    }
}

fn task_filter_from_query(query: TaskQuery) -> Result<TaskFilter, &'static str> {
    let network_id = required_network_id(query.network_id.as_deref())?;
    let node_name = query.node.unwrap_or_default().trim().to_string();
    let state = query.state.unwrap_or_default().trim().to_string();
    if !state.is_empty() && !is_valid_task_state(&state) {
        return Err("invalid state");
    }
    let session_id = match query
        .session_id
        .as_deref()
        .map(str::trim)
        .filter(|raw| !raw.is_empty())
    {
        Some(raw) => match raw.parse::<u32>() {
            Ok(id) if id > 0 => Some(id),
            _ => return Err("invalid session_id"),
        },
        None => None,
    };
    Ok(TaskFilter {
        network_id,
        node_name,
        session_id,
        state,
    })
}

fn is_valid_task_state(state: &str) -> bool {
    matches!(state.trim(), "working" | "complete" | "blocked" | "failed")
}

fn is_zero_u32(value: &u32) -> bool {
    *value == 0
}

type RuntimeReplayKey = (String, String);
type RuntimeReplayMap = HashMap<RuntimeReplayKey, DateTime<Utc>>;

#[derive(Clone)]
struct RuntimeCredentialReplay {
    inner: Arc<Mutex<RuntimeReplayMap>>,
}

impl RuntimeCredentialReplay {
    fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn remember(&self, claims: &RuntimeClaims, now: DateTime<Utc>) {
        let mut used = self.inner.lock().unwrap();
        used.retain(|_, expires_at| *expires_at > now);
        let key = (claims.network_id.clone(), claims.jti.clone());
        used.insert(key, claims.expires_at);
    }
}

#[derive(Clone)]
struct TailnetCoordinator {
    inner: Arc<Mutex<TailnetCoordinatorState>>,
}

#[derive(Default)]
struct TailnetCoordinatorState {
    peers: HashMap<Uuid, TailnetPeer>,
    tunnels: HashMap<Uuid, Uuid>,
}

struct TailnetPeer {
    node: Option<TailnetNode>,
    tx: mpsc::Sender<Vec<TailnetNode>>,
}

impl TailnetCoordinator {
    fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(TailnetCoordinatorState::default())),
        }
    }

    fn register(&self, id: Uuid, _name: String) -> mpsc::Receiver<Vec<TailnetNode>> {
        let (tx, rx) = mpsc::channel(64);
        let mut state = self.inner.lock().unwrap();
        state.peers.insert(id, TailnetPeer { node: None, tx });
        rx
    }

    fn deregister(&self, id: Uuid) {
        let mut state = self.inner.lock().unwrap();
        state.peers.remove(&id);
        state.tunnels.retain(|src, dst| *src != id && *dst != id);
    }

    fn update_node(&self, id: Uuid, node: TailnetNode) {
        let updates = {
            let mut state = self.inner.lock().unwrap();
            let Some(peer) = state.peers.get_mut(&id) else {
                return;
            };
            peer.node = Some(node);

            let mut updates = Vec::new();
            let tunnels = state
                .tunnels
                .iter()
                .map(|(src, dst)| (*src, *dst))
                .collect::<Vec<_>>();
            for (src, dst) in tunnels {
                if src == id
                    && let Some((tx, nodes)) = collect_tunnel_client_nodes(&state, dst)
                    && !nodes.is_empty()
                {
                    updates.push((tx, nodes));
                }
                if dst == id
                    && let (Some(client), Some(agent)) =
                        (state.peers.get(&src), state.peers.get(&dst))
                    && let Some(agent_node) = agent.node.clone()
                {
                    updates.push((client.tx.clone(), vec![agent_node]));
                }
            }
            updates
        };
        send_tailnet_updates(id, updates);
    }

    fn add_tunnel(&self, client_id: Uuid, agent_id: Uuid) -> bool {
        let (delivered, updates) = {
            let mut state = self.inner.lock().unwrap();
            state.tunnels.insert(client_id, agent_id);

            let mut updates = Vec::new();
            let mut delivered = false;
            if let (Some(client), Some(agent)) =
                (state.peers.get(&client_id), state.peers.get(&agent_id))
                && let Some(agent_node) = agent.node.clone()
            {
                updates.push((client.tx.clone(), vec![agent_node]));
                delivered = true;
            }
            if let Some((tx, nodes)) = collect_tunnel_client_nodes(&state, agent_id)
                && !nodes.is_empty()
            {
                updates.push((tx, nodes));
            }
            (delivered, updates)
        };
        send_tailnet_updates(client_id, updates);
        delivered
    }
}

fn collect_tunnel_client_nodes(
    state: &TailnetCoordinatorState,
    agent_id: Uuid,
) -> Option<(mpsc::Sender<Vec<TailnetNode>>, Vec<TailnetNode>)> {
    let agent = state.peers.get(&agent_id)?;
    let nodes = state
        .tunnels
        .iter()
        .filter_map(|(src, dst)| {
            (*dst == agent_id)
                .then(|| state.peers.get(src).and_then(|client| client.node.clone()))
                .flatten()
        })
        .collect::<Vec<_>>();
    Some((agent.tx.clone(), nodes))
}

fn send_tailnet_updates(
    target: Uuid,
    updates: Vec<(mpsc::Sender<Vec<TailnetNode>>, Vec<TailnetNode>)>,
) {
    for (tx, nodes) in updates {
        if tx.try_send(nodes).is_err() {
            tracing::warn!(%target, "tailnet coordinator dropped peer update for slow consumer");
        }
    }
}

#[derive(Clone, Default)]
struct NodeHub {
    inner: Arc<Mutex<NodeHubState>>,
}

#[derive(Default)]
struct NodeHubState {
    next_connection_id: i64,
    nodes: HashMap<String, NodeHubEntry>,
}

struct NodeHubEntry {
    connection_id: i64,
    tx: mpsc::Sender<HubMessage>,
}

impl NodeHub {
    fn new() -> Self {
        Self::default()
    }

    fn register(&self, network_id: &str, node_name: &str) -> (i64, mpsc::Receiver<HubMessage>) {
        let (tx, rx) = mpsc::channel(16);
        let mut inner = self.inner.lock().expect("node hub lock");
        inner.next_connection_id += 1;
        let connection_id = inner.next_connection_id;
        inner.nodes.insert(
            hub_key(network_id, node_name),
            NodeHubEntry { connection_id, tx },
        );
        (connection_id, rx)
    }

    fn unregister(&self, network_id: &str, node_name: &str, connection_id: i64) {
        let mut inner = self.inner.lock().expect("node hub lock");
        let key = hub_key(network_id, node_name);
        let should_remove = inner
            .nodes
            .get(&key)
            .is_some_and(|entry| entry.connection_id == connection_id);
        if should_remove && let Some(NodeHubEntry { tx, .. }) = inner.nodes.remove(&key) {
            drop(tx);
        }
    }

    fn send(&self, network_id: &str, node_name: &str, msg: HubMessage) -> Result<(), String> {
        let tx = {
            let inner = self.inner.lock().expect("node hub lock");
            inner
                .nodes
                .get(&hub_key(network_id, node_name))
                .map(|entry| entry.tx.clone())
        }
        .ok_or_else(|| format!("node {node_name:?} not connected in network {network_id:?}"))?;

        tx.try_send(msg).map_err(|_| {
            format!("node {node_name:?} message buffer full in network {network_id:?}")
        })
    }

    #[cfg(test)]
    fn has(&self, network_id: &str, node_name: &str) -> bool {
        let inner = self.inner.lock().expect("node hub lock");
        inner.nodes.contains_key(&hub_key(network_id, node_name))
    }
}

fn hub_key(network_id: &str, node_name: &str) -> String {
    format!("{network_id}:{node_name}")
}

#[derive(Clone, Default)]
struct PendingSessions {
    inner: Arc<Mutex<HashMap<String, mpsc::Sender<BackConnection>>>>,
}

impl PendingSessions {
    fn new() -> Self {
        Self::default()
    }

    fn deliver(&self, session_id: &str, conn: BackConnection) -> Result<(), BackConnection> {
        let tx = {
            let mut inner = self.inner.lock().expect("pending sessions lock");
            inner.remove(session_id)
        };
        let Some(tx) = tx else {
            return Err(conn);
        };
        tx.try_send(conn).map_err(|err| err.into_inner())
    }

    fn expect(&self, session_id: &str) -> mpsc::Receiver<BackConnection> {
        let (tx, rx) = mpsc::channel(1);
        let mut inner = self.inner.lock().expect("pending sessions lock");
        inner.insert(session_id.to_string(), tx);
        rx
    }

    fn cancel(&self, session_id: &str) {
        let mut inner = self.inner.lock().expect("pending sessions lock");
        inner.remove(session_id);
    }

    #[cfg(test)]
    fn expect_for_test(&self, session_id: &str) -> mpsc::Receiver<BackConnection> {
        self.expect(session_id)
    }
}

struct BackConnection {
    network_id: String,
    node_name: String,
    socket: Box<WebSocket>,
}

impl BackConnection {
    async fn close_no_waiter(mut self) {
        tracing::info!(
            network_id = %self.network_id,
            node = %self.node_name,
            "closing mesh node back-connection without pending session"
        );
        let _ = self.socket.send(Message::Close(None)).await;
    }

    async fn send_binary(&mut self, data: Vec<u8>) -> Result<(), axum::Error> {
        self.socket.send(Message::Binary(data.into())).await
    }

    async fn recv(&mut self) -> Option<Result<Message, axum::Error>> {
        self.socket.recv().await
    }

    #[cfg(test)]
    fn network_id(&self) -> &str {
        &self.network_id
    }

    #[cfg(test)]
    fn node_name(&self) -> &str {
        &self.node_name
    }
}

#[derive(Debug, Error)]
enum MeshSshError {
    #[error(transparent)]
    Russh(#[from] russh::Error),
    #[error("mesh store failed: {0}")]
    Store(String),
    #[error("unknown SSH channel {0}")]
    UnknownChannel(ChannelId),
    #[error("SSH connection is not authenticated")]
    Unauthenticated,
}

impl From<StoreError> for MeshSshError {
    fn from(value: StoreError) -> Self {
        Self::Store(value.to_string())
    }
}

struct MeshSshHandler {
    state: AppState,
    node: Option<NodeRecord>,
    channels: HashMap<ChannelId, MeshSshChannelState>,
}

impl MeshSshHandler {
    fn new(state: AppState) -> Self {
        Self {
            state,
            node: None,
            channels: HashMap::new(),
        }
    }

    async fn start_channel_session(
        &mut self,
        channel: ChannelId,
        session: &mut server::Session,
    ) -> Result<(), MeshSshError> {
        let Some(node) = self.node.clone() else {
            session.channel_failure(channel)?;
            return Err(MeshSshError::Unauthenticated);
        };
        let Some(state) = self.channels.get_mut(&channel) else {
            session.channel_failure(channel)?;
            return Err(MeshSshError::UnknownChannel(channel));
        };
        if state.started {
            session.channel_failure(channel)?;
            return Ok(());
        }

        let session_id = generate_ssh_session_id();
        let rows = state.rows;
        let cols = state.cols;
        let mut pending_rx = self.state.pending_sessions.expect(&session_id);
        if let Err(err) = self.state.node_hub.send(
            &node.network_id,
            &node.name,
            HubMessage {
                kind: "SSHRequest".to_string(),
                session_id: session_id.clone(),
                cols,
                rows,
            },
        ) {
            self.state.pending_sessions.cancel(&session_id);
            session.channel_success(channel)?;
            let handle = session.handle();
            tokio::spawn(async move {
                send_ssh_error_and_close(
                    handle,
                    channel,
                    format!("node not connected: {err}\r\n"),
                    1,
                )
                .await;
            });
            state.started = true;
            return Ok(());
        }

        let (input_tx, input_rx) = mpsc::channel(64);
        state.session_id = Some(session_id.clone());
        state.input_tx = Some(input_tx);
        state.started = true;
        session.channel_success(channel)?;

        let pending_sessions = self.state.pending_sessions.clone();
        let handle = session.handle();
        tokio::spawn(async move {
            match tokio::time::timeout(StdDuration::from_secs(10), pending_rx.recv()).await {
                Ok(Some(conn)) => {
                    bridge_mesh_ssh_backconnection(handle, channel, conn, input_rx).await;
                }
                Ok(None) => {
                    send_ssh_error_and_close(
                        handle,
                        channel,
                        "node back-connection channel closed\r\n",
                        1,
                    )
                    .await;
                }
                Err(_) => {
                    pending_sessions.cancel(&session_id);
                    send_ssh_error_and_close(handle, channel, "node connection timed out\r\n", 1)
                        .await;
                }
            }
        });
        Ok(())
    }

    async fn send_input(&self, channel: ChannelId, data: Vec<u8>) -> Result<(), MeshSshError> {
        let Some(state) = self.channels.get(&channel) else {
            return Err(MeshSshError::UnknownChannel(channel));
        };
        let Some(tx) = state.input_tx.as_ref() else {
            return Ok(());
        };
        let _ = tx.send(data).await;
        Ok(())
    }
}

struct MeshSshChannelState {
    cols: u32,
    rows: u32,
    session_id: Option<String>,
    input_tx: Option<mpsc::Sender<Vec<u8>>>,
    started: bool,
}

impl MeshSshChannelState {
    fn new() -> Self {
        Self {
            cols: 80,
            rows: 24,
            session_id: None,
            input_tx: None,
            started: false,
        }
    }
}

impl server::Handler for MeshSshHandler {
    type Error = MeshSshError;

    async fn auth_password(
        &mut self,
        user: &str,
        password: &str,
    ) -> Result<server::Auth, Self::Error> {
        let Some(node) = self.state.store.node_get_by_token(password).await? else {
            return Ok(server::Auth::reject());
        };
        let (requested_network, requested_name) = parse_mesh_ssh_user(user);
        if requested_name != node.name {
            return Ok(server::Auth::reject());
        }
        if let Some(network) = requested_network
            && network != node.network_id
        {
            return Ok(server::Auth::reject());
        }
        self.node = Some(node);
        Ok(server::Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<server::Msg>,
        _session: &mut server::Session,
    ) -> Result<bool, Self::Error> {
        self.channels
            .insert(channel.id(), MeshSshChannelState::new());
        Ok(true)
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _term: &str,
        col_width: u32,
        row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(Pty, u32)],
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        let Some(state) = self.channels.get_mut(&channel) else {
            session.channel_failure(channel)?;
            return Err(MeshSshError::UnknownChannel(channel));
        };
        state.cols = col_width;
        state.rows = row_height;
        session.channel_success(channel)?;
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        self.start_channel_session(channel, session).await
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        _data: &[u8],
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        self.start_channel_session(channel, session).await
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        _session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        self.send_input(channel, data.to_vec()).await
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        _session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        self.send_input(channel, vec![0x04]).await
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        if let Some(state) = self.channels.remove(&channel)
            && let Some(session_id) = state.session_id
        {
            self.state.pending_sessions.cancel(&session_id);
        }
        Ok(())
    }

    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        let Some(state) = self.channels.get_mut(&channel) else {
            session.channel_failure(channel)?;
            return Err(MeshSshError::UnknownChannel(channel));
        };
        state.cols = col_width;
        state.rows = row_height;
        session.channel_success(channel)?;
        Ok(())
    }
}

fn parse_mesh_ssh_user(user: &str) -> (Option<&str>, &str) {
    match user.split_once('/') {
        Some((network, name)) => (Some(network), name),
        None => (None, user),
    }
}

fn generate_ssh_session_id() -> String {
    let mut bytes = [0_u8; 16];
    OsRng.fill_bytes(&mut bytes);
    lower_hex(&bytes)
}

async fn bridge_mesh_ssh_backconnection(
    handle: server::Handle,
    channel: ChannelId,
    mut conn: BackConnection,
    mut input_rx: mpsc::Receiver<Vec<u8>>,
) {
    loop {
        tokio::select! {
            input = input_rx.recv() => {
                let Some(data) = input else {
                    break;
                };
                if conn.send_binary(data).await.is_err() {
                    break;
                }
            }
            frame = conn.recv() => {
                match frame {
                    Some(Ok(Message::Binary(data))) => {
                        if handle.data(channel, data.to_vec()).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(Message::Text(text))) => {
                        if handle.data(channel, text.as_bytes().to_vec()).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Ok(Message::Ping(_))) | Some(Ok(Message::Pong(_))) => {}
                    Some(Err(_)) => break,
                }
            }
        }
    }
    let _ = handle.exit_status_request(channel, 0).await;
    let _ = handle.eof(channel).await;
    let _ = handle.close(channel).await;
}

async fn send_ssh_error_and_close(
    handle: server::Handle,
    channel: ChannelId,
    message: impl Into<String>,
    exit_status: u32,
) {
    let _ = handle
        .extended_data(channel, 1, message.into().into_bytes())
        .await;
    let _ = handle.exit_status_request(channel, exit_status).await;
    let _ = handle.eof(channel).await;
    let _ = handle.close(channel).await;
}

async fn require_auth(
    State(state): State<AppState>,
    mut req: axum::extract::Request,
    next: Next,
) -> Response {
    match authenticate_headers(req.headers(), &state.config, state.store.as_ref()).await {
        Some(identity) => {
            req.extensions_mut().insert(identity);
            next.run(req).await
        }
        None => unauthorized_response(),
    }
}

async fn node_auth_from_headers(
    headers: &HeaderMap,
    store: &dyn crate::store::MeshStore,
) -> Option<NodeRecord> {
    let header = headers.get(AUTHORIZATION)?.to_str().ok()?;
    let token = header.strip_prefix("Bearer ")?;
    if token.is_empty() {
        return None;
    }
    store.node_get_by_token(token).await.ok().flatten()
}

fn node_responses(nodes: Vec<NodeRecord>) -> Vec<NodeResponse> {
    let now = Utc::now();
    nodes
        .into_iter()
        .map(|node| NodeResponse {
            network_id: node.network_id,
            name: node.name,
            peer_url: node.peer_url,
            connected: now.signed_duration_since(node.last_seen_at) < Duration::minutes(2),
        })
        .collect()
}

fn parse_xttl_header(headers: &HeaderMap) -> Result<Option<Duration>, &'static str> {
    let Some(value) = headers.get("x-ttl") else {
        return Ok(None);
    };
    let raw = value.to_str().map_err(|_| "invalid X-TTL header")?;
    if raw.is_empty() {
        return Ok(None);
    }
    parse_go_duration(raw)
        .map(Some)
        .ok_or("invalid X-TTL header")
}

fn unauthorized_response() -> Response {
    plain_error(StatusCode::UNAUTHORIZED, "unauthorized")
}

fn plain_error(status: StatusCode, message: &str) -> Response {
    (
        status,
        [
            (
                CONTENT_TYPE,
                HeaderValue::from_static("text/plain; charset=utf-8"),
            ),
            (
                HeaderName::from_static("x-content-type-options"),
                HeaderValue::from_static("nosniff"),
            ),
        ],
        format!("{message}\n"),
    )
        .into_response()
}

fn normalize_identity_subject(sub: &str) -> String {
    let sub = sub.trim();
    if sub.is_empty()
        || sub.starts_with("github:")
        || sub.starts_with("oidc:")
        || sub.starts_with("user:")
    {
        sub.to_string()
    } else if let Some(rest) = sub.strip_prefix("platform:") {
        format!("user:{rest}")
    } else {
        format!("oidc:{sub}")
    }
}

fn membership_subject(identity: &AuthIdentity) -> Result<String, &'static str> {
    if identity.is_admin {
        return Ok("admin".to_string());
    }
    if let Some(sub) = identity.sub.as_deref().filter(|sub| !sub.is_empty()) {
        return Ok(normalize_identity_subject(sub));
    }
    if let Some(user_id) = identity.user_id {
        return Ok(format!("github:{user_id}"));
    }
    Err("unsupported identity")
}

async fn require_owner(
    state: &AppState,
    network_id: &str,
    identity: &AuthIdentity,
) -> Result<bool, &'static str> {
    if identity.is_admin {
        return Ok(true);
    }
    let subject = membership_subject(identity)?;
    let member = state
        .store
        .network_member_get(network_id, &subject)
        .await
        .map_err(|_| "store error")?;
    Ok(member.is_some_and(|member| member.role.eq_ignore_ascii_case(NETWORK_ROLE_OWNER)))
}

async fn require_membership(
    state: &AppState,
    network_id: &str,
    identity: &AuthIdentity,
) -> Result<Option<NetworkMember>, &'static str> {
    if identity.is_admin {
        return Ok(Some(NetworkMember {
            network_id: network_id.to_string(),
            subject: "admin".to_string(),
            role: NETWORK_ROLE_OWNER.to_string(),
            created_at: Utc::now(),
            created_by: String::new(),
        }));
    }
    let subject = membership_subject(identity)?;
    state
        .store
        .network_member_get(network_id, &subject)
        .await
        .map_err(|_| "store error")
}

async fn load_issuer_state(
    state: &AppState,
    network_id: &str,
) -> Result<Option<IssuerState>, StoreError> {
    let Some(raw) = state
        .store
        .kv_get(network_id, NETWORK_AUTH_NAMESPACE, NETWORK_AUTH_ISSUER_KEY)
        .await?
    else {
        return Ok(None);
    };
    serde_json::from_slice(&raw)
        .map(Some)
        .map_err(|_| StoreError::NotFound)
}

async fn load_or_create_issuer_state(
    state: &AppState,
    network_id: &str,
) -> Result<IssuerState, StoreError> {
    if let Some(issuer) = load_issuer_state(state, network_id).await? {
        return Ok(issuer);
    }
    state.store.network_ensure(network_id).await?;
    let issuer = new_issuer_state(network_id);
    let encoded = serde_json::to_vec(&issuer).map_err(|_| StoreError::NotFound)?;
    state
        .store
        .kv_set(
            network_id,
            NETWORK_AUTH_NAMESPACE,
            NETWORK_AUTH_ISSUER_KEY,
            encoded,
            None,
        )
        .await?;
    Ok(issuer)
}

fn client_subject_id(identity: &AuthIdentity) -> String {
    if identity.is_admin {
        return "admin".to_string();
    }
    if let Some(sub) = identity.sub.as_deref().filter(|sub| !sub.trim().is_empty()) {
        return normalize_identity_subject(sub);
    }
    if let Some(user_id) = identity.user_id {
        return format!("github:{user_id}");
    }
    if !identity.username.trim().is_empty() {
        return format!("user:{}", identity.username.trim());
    }
    "client".to_string()
}

#[derive(Debug, PartialEq, Eq)]
enum NodeEnrollmentError {
    TokenRequired,
    Invalid,
    NodeNameMismatch,
    NodeNameRequired,
    Store,
}

async fn create_node_enrollment(
    store: &dyn crate::store::MeshStore,
    network_id: &str,
    owner_subject: &str,
    issued_by: &str,
    node_name: &str,
    uses: i32,
    ttl: Duration,
) -> Result<(NodeEnrollment, String), NodeEnrollmentError> {
    let uses = if uses <= 0 { 1 } else { uses };
    let ttl = if ttl <= Duration::zero() {
        Duration::minutes(10)
    } else {
        ttl
    };
    let now = Utc::now();
    let token = format!("cw_enr_{}", generate_hex_token());
    let enrollment = NodeEnrollment {
        id: generate_hex_token(),
        network_id: network_id.trim().to_string(),
        owner_subject: owner_subject.trim().to_string(),
        issued_by: issued_by.trim().to_string(),
        node_name: node_name.trim().to_string(),
        token_hash: hash_enrollment_token(&token),
        uses_remaining: uses,
        expires_at: now + ttl,
        created_at: now,
        redeemed_at: None,
    };
    store
        .node_enrollment_create(enrollment.clone())
        .await
        .map_err(|_| NodeEnrollmentError::Store)?;
    Ok((enrollment, token))
}

async fn redeem_node_enrollment(
    store: &dyn crate::store::MeshStore,
    enrollment_token: &str,
    node_name: &str,
    peer_url: &str,
    github_id: Option<i64>,
) -> Result<NodeRedeemResult, NodeEnrollmentError> {
    let enrollment_token = enrollment_token.trim();
    if enrollment_token.is_empty() {
        return Err(NodeEnrollmentError::TokenRequired);
    }

    let now = Utc::now();
    let token_hash = hash_enrollment_token(enrollment_token);
    let enrollment = store
        .node_enrollment_get_by_token_hash(&token_hash)
        .await
        .map_err(|_| NodeEnrollmentError::Store)?
        .ok_or(NodeEnrollmentError::Invalid)?;
    if enrollment.expires_at < now || enrollment.uses_remaining <= 0 {
        return Err(NodeEnrollmentError::Invalid);
    }

    let node_name = match (enrollment.node_name.trim(), node_name.trim()) {
        (fixed, "") if !fixed.is_empty() => fixed.to_string(),
        (fixed, requested) if !fixed.is_empty() && fixed != requested => {
            return Err(NodeEnrollmentError::NodeNameMismatch);
        }
        (_, "") => return Err(NodeEnrollmentError::NodeNameRequired),
        (_, requested) => requested.to_string(),
    };

    let consumed = store
        .node_enrollment_consume(&token_hash, now)
        .await
        .map_err(|_| NodeEnrollmentError::Store)?
        .ok_or(NodeEnrollmentError::Invalid)?;
    if consumed.expires_at < now {
        return Err(NodeEnrollmentError::Invalid);
    }

    let node_token = generate_hex_token();
    store
        .node_register(NodeRecord {
            network_id: consumed.network_id.clone(),
            name: node_name.clone(),
            token: node_token.clone(),
            peer_url: peer_url.trim().to_string(),
            github_id,
            owner_subject: consumed.owner_subject,
            authorized_by: consumed.issued_by,
            enrollment_id: consumed.id.clone(),
            authorized_at: now,
            last_seen_at: now,
        })
        .await
        .map_err(|_| NodeEnrollmentError::Store)?;

    Ok(NodeRedeemResult {
        node_token,
        node_name,
        network_id: consumed.network_id,
        enrollment_id: consumed.id,
    })
}

async fn load_group_response(
    state: &AppState,
    network_id: &str,
    group_name: &str,
) -> Result<Option<GroupResponse>, StoreError> {
    let Some(group) = state.store.group_get(network_id, group_name).await? else {
        return Ok(None);
    };
    let members = state
        .store
        .group_member_list(network_id, group_name)
        .await?;
    let policy = state.store.group_policy_get(network_id, group_name).await?;
    Ok(Some(group_response(group, members, policy)))
}

fn group_response(
    group: Group,
    members: Vec<GroupMember>,
    policy: Option<GroupPolicy>,
) -> GroupResponse {
    GroupResponse {
        network_id: group.network_id,
        name: group.name,
        created_at: group.created_at,
        created_by: group.created_by,
        members,
        policy,
    }
}

fn required_network_id(raw: Option<&str>) -> Result<String, &'static str> {
    let network_id = raw.unwrap_or_default().trim().to_string();
    if network_id.is_empty() {
        Err("network_id required")
    } else {
        Ok(network_id)
    }
}

fn validate_network_id(raw: &str) -> Result<(), &'static str> {
    if raw.trim().is_empty() {
        return Err("network id required");
    }
    if raw.chars().all(|ch| {
        ch.is_ascii_lowercase()
            || ch.is_ascii_uppercase()
            || ch.is_ascii_digit()
            || ch == '-'
            || ch == '_'
    }) {
        Ok(())
    } else {
        Err("network id may only contain letters, numbers, '-' or '_'")
    }
}

fn validate_group_name(raw: &str) -> Result<String, &'static str> {
    let group_name = raw.trim();
    if group_name.is_empty() {
        return Err("group name required");
    }
    if group_name.chars().all(|ch| {
        ch.is_ascii_lowercase()
            || ch.is_ascii_uppercase()
            || ch.is_ascii_digit()
            || ch == '-'
            || ch == '_'
    }) {
        Ok(group_name.to_string())
    } else {
        Err("group name may only contain letters, numbers, '-' or '_'")
    }
}

fn normalize_group_messages_policy(raw: Option<&str>) -> Result<String, &'static str> {
    match raw.unwrap_or_default().trim().to_ascii_lowercase().as_str() {
        "" | GROUP_MESSAGES_INTERNAL_ONLY => Ok(GROUP_MESSAGES_INTERNAL_ONLY.to_string()),
        GROUP_MESSAGES_OPEN => Ok(GROUP_MESSAGES_OPEN.to_string()),
        _ => Err("invalid messages_policy"),
    }
}

fn normalize_group_debug_policy(raw: Option<&str>) -> Result<String, &'static str> {
    match raw.unwrap_or_default().trim().to_ascii_lowercase().as_str() {
        "" | GROUP_DEBUG_OBSERVE_ONLY => Ok(GROUP_DEBUG_OBSERVE_ONLY.to_string()),
        GROUP_DEBUG_NONE => Ok(GROUP_DEBUG_NONE.to_string()),
        GROUP_DEBUG_FULL => Ok(GROUP_DEBUG_FULL.to_string()),
        _ => Err("invalid debug_policy"),
    }
}

fn escape_html(raw: &str) -> String {
    let mut escaped = String::with_capacity(raw.len());
    for ch in raw.chars() {
        match ch {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&#34;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

fn generate_invite_token() -> String {
    format!("{}{}", INVITE_TOKEN_PREFIX, random_alphanumeric(24))
}

fn generate_session_token() -> String {
    format!("sess_{}", random_alphanumeric(32))
}

fn generate_oauth_state() -> String {
    let mut bytes = [0_u8; 16];
    OsRng.fill_bytes(&mut bytes);
    lower_hex(&bytes)
}

fn random_alphanumeric(len: usize) -> String {
    let mut bytes = vec![0_u8; len];
    OsRng.fill_bytes(&mut bytes);
    let mut token = String::with_capacity(len);
    for byte in bytes {
        token.push(ALPHANUMERIC[usize::from(byte) % ALPHANUMERIC.len()] as char);
    }
    token
}

fn generate_hex_token() -> String {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    lower_hex(&bytes)
}

fn hash_enrollment_token(token: &str) -> String {
    lower_hex(&Sha256::digest(token.trim().as_bytes()))
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[usize::from(byte >> 4)] as char);
        out.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    out
}

fn parse_go_duration(raw: &str) -> Option<Duration> {
    if raw.is_empty() {
        return None;
    }
    let bytes = raw.as_bytes();
    let mut idx = 0;
    let sign = match bytes[idx] {
        b'+' => {
            idx += 1;
            1_i128
        }
        b'-' => {
            idx += 1;
            -1_i128
        }
        _ => 1_i128,
    };
    if idx == bytes.len() {
        return None;
    }

    let mut total = 0_i128;
    while idx < bytes.len() {
        let int_start = idx;
        while idx < bytes.len() && bytes[idx].is_ascii_digit() {
            idx += 1;
        }
        let int_part = if int_start == idx {
            0_i128
        } else {
            raw[int_start..idx].parse::<i128>().ok()?
        };

        let mut frac_part = 0_i128;
        let mut frac_scale = 1_i128;
        if idx < bytes.len() && bytes[idx] == b'.' {
            idx += 1;
            let frac_start = idx;
            while idx < bytes.len() && bytes[idx].is_ascii_digit() {
                frac_part = frac_part
                    .checked_mul(10)?
                    .checked_add(i128::from(bytes[idx] - b'0'))?;
                frac_scale = frac_scale.checked_mul(10)?;
                idx += 1;
            }
            if frac_start == idx && int_start == frac_start - 1 {
                return None;
            }
        } else if int_start == idx {
            return None;
        }

        let (unit_nanos, unit_len) = duration_unit(&raw[idx..])?;
        idx += unit_len;
        let whole = int_part.checked_mul(unit_nanos)?;
        let frac = frac_part.checked_mul(unit_nanos)?.checked_div(frac_scale)?;
        total = total.checked_add(whole.checked_add(frac)?)?;
    }

    let nanos = total.checked_mul(sign)?;
    let nanos = i64::try_from(nanos).ok()?;
    Some(Duration::nanoseconds(nanos))
}

fn duration_unit(raw: &str) -> Option<(i128, usize)> {
    for (unit, nanos) in [
        ("ns", 1_i128),
        ("us", 1_000),
        ("ms", 1_000_000),
        ("s", 1_000_000_000),
        ("m", 60 * 1_000_000_000),
        ("h", 60 * 60 * 1_000_000_000),
    ] {
        if raw.starts_with(unit) {
            return Some((nanos, unit.len()));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use axum::body::{Body, to_bytes};
    use axum::http::header::{AUTHORIZATION, COOKIE, LOCATION, SET_COOKIE};
    use axum::http::{HeaderValue, Request, StatusCode};
    use chrono::{Duration, Utc};
    use ed25519_dalek::pkcs8::EncodePrivateKey;
    use ed25519_dalek::pkcs8::spki::der::pem::LineEnding as Pkcs8LineEnding;
    use futures_util::{SinkExt, StreamExt};
    use russh::{ChannelMsg, client};
    use serde_json::json;
    use tokio::net::TcpStream;
    use tokio_tungstenite::tungstenite::Message as ClientMessage;
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
    use tower::ServiceExt;

    use super::*;
    use crate::AuthMode;
    use crate::network_auth::{
        VerifierBundle, verify_observer_delegation, verify_runtime_credential,
        verify_sender_delegation,
    };
    use crate::{Invite, LatestTaskValue, MemoryStore, MeshStore, TaskEvent};

    fn test_config(auth_mode: AuthMode) -> Config {
        Config {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            ssh_bind_addr: "127.0.0.1:0".parse().unwrap(),
            ssh_host_key_path: std::env::temp_dir()
                .join("codewire-mesh-test-host-key")
                .display()
                .to_string(),
            base_url: "https://mesh.codewire.sh".to_string(),
            auth_mode,
            auth_token: Some("relay-admin".to_string()),
            derp_url: None,
            oidc_issuer: None,
            oidc_client_id: None,
            oidc_client_secret: None,
            oidc_allowed_groups: Vec::new(),
            database_url: None,
        }
    }

    fn test_state(auth_mode: AuthMode, store: MemoryStore) -> AppState {
        AppState {
            config: test_config(auth_mode),
            store: std::sync::Arc::new(store),
            node_hub: NodeHub::new(),
            pending_sessions: PendingSessions::new(),
            tailnet_coord: TailnetCoordinator::new(),
            runtime_replay: RuntimeCredentialReplay::new(),
            oidc_client: OidcClient::new(),
        }
    }

    async fn seeded_github_store(token: &str, github_id: i64, username: &str) -> MemoryStore {
        let store = MemoryStore::new();
        store
            .upsert_github_session(token, github_id, username, Utc::now() + Duration::hours(1))
            .await;
        store
    }

    async fn seeded_member_store(
        token: &str,
        github_id: i64,
        username: &str,
        network_id: &str,
        role: &str,
    ) -> MemoryStore {
        let store = seeded_github_store(token, github_id, username).await;
        store
            .network_member_upsert(NetworkMember {
                network_id: network_id.to_string(),
                subject: format!("github:{github_id}"),
                role: role.to_string(),
                created_at: Utc::now(),
                created_by: format!("github:{github_id}"),
            })
            .await
            .unwrap();
        store
    }

    fn sample_tailnet_node(id: Uuid, preferred_derp: i32, seed: u8) -> TailnetNode {
        use codewire_tailnet::node::{DiscoPublic, NodePublic, prefix_from_uuid};

        TailnetNode {
            id,
            as_of: "2026-06-19T12:00:00Z".parse().unwrap(),
            key: NodePublic::from_raw([seed; 32]),
            disco_key: DiscoPublic::from_raw([seed.wrapping_add(1); 32]),
            preferred_derp,
            derp_latency: None,
            endpoints: vec![],
            addresses: vec![prefix_from_uuid(&id)],
        }
    }

    fn coordinate_request(
        addr: std::net::SocketAddr,
        token: Option<&str>,
        suffix: &str,
    ) -> tokio_tungstenite::tungstenite::handshake::client::Request {
        let mut request = format!("ws://{addr}/api/v1/tailnet/coordinate{suffix}")
            .into_client_request()
            .unwrap();
        request.headers_mut().insert(
            "Sec-WebSocket-Protocol",
            HeaderValue::from_static("coordinate"),
        );
        if let Some(token) = token {
            request.headers_mut().insert(
                AUTHORIZATION,
                HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
            );
        }
        request
    }

    async fn next_ws_json(ws: &mut WebSocketStream<MaybeTlsStream<TcpStream>>) -> JsonValue {
        let message = tokio::time::timeout(std::time::Duration::from_secs(2), ws.next())
            .await
            .expect("websocket frame")
            .expect("open websocket")
            .expect("valid websocket frame");
        match message {
            ClientMessage::Text(text) => serde_json::from_str(&text).unwrap(),
            other => panic!("expected websocket text JSON, got {other:?}"),
        }
    }

    #[test]
    fn load_or_create_mesh_host_key_reads_go_pkcs8_ed25519_pem() {
        let mut seed = [0_u8; 32];
        seed[31] = 42;
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let pem = signing_key
            .to_pkcs8_pem(Pkcs8LineEnding::LF)
            .expect("encode PKCS#8 PEM");

        let dir = std::env::temp_dir().join(format!(
            "codewire-mesh-host-key-pkcs8-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).expect("create test dir");
        let path = dir.join("ssh_host_ed25519");
        fs::write(&path, pem.as_bytes()).expect("write legacy host key");

        let loaded = load_or_create_mesh_host_key(&path).expect("load legacy host key");
        let expected = PrivateKey::from(Ed25519Keypair::from_seed(&seed));
        assert_eq!(loaded.algorithm(), Algorithm::Ed25519);
        assert_eq!(loaded.public_key(), expected.public_key());

        fs::remove_file(&path).expect("remove test key");
        fs::remove_dir(&dir).expect("remove test dir");
    }

    async fn seed_node(
        store: &MemoryStore,
        network_id: &str,
        name: &str,
        token: &str,
        peer_url: &str,
        last_seen_at: chrono::DateTime<Utc>,
    ) {
        store
            .node_register(NodeRecord {
                network_id: network_id.to_string(),
                name: name.to_string(),
                token: token.to_string(),
                peer_url: peer_url.to_string(),
                github_id: None,
                owner_subject: String::new(),
                authorized_by: String::new(),
                enrollment_id: String::new(),
                authorized_at: last_seen_at,
                last_seen_at,
            })
            .await
            .unwrap();
    }

    struct TaskSeed<'a> {
        event_id: &'a str,
        network_id: &'a str,
        node_name: &'a str,
        session_id: u32,
        session_name: &'a str,
        summary: &'a str,
        state: &'a str,
    }

    async fn seed_task_event(store: &MemoryStore, task: TaskSeed<'_>) {
        store
            .task_event_create(TaskEvent {
                event_id: task.event_id.to_string(),
                network_id: task.network_id.to_string(),
                node_name: task.node_name.to_string(),
                session_id: task.session_id,
                session_name: task.session_name.to_string(),
                summary: task.summary.to_string(),
                state: task.state.to_string(),
                timestamp: "2026-04-08T15:04:05Z".to_string(),
            })
            .await
            .unwrap();
    }

    async fn spawn_test_server(
        router: Router,
    ) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        (addr, handle)
    }

    struct AcceptAllKeys;

    impl client::Handler for AcceptAllKeys {
        type Error = russh::Error;

        async fn check_server_key(
            &mut self,
            _server_public_key: &russh::keys::ssh_key::PublicKey,
        ) -> Result<bool, Self::Error> {
            Ok(true)
        }
    }

    async fn spawn_test_mesh_ssh(
        state: AppState,
    ) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut config = mesh_ssh_server_config();
        config.keys.push(generate_mesh_host_key());
        let config = std::sync::Arc::new(config);
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let session = server::run_stream(config, stream, MeshSshHandler::new(state))
                .await
                .unwrap();
            let _ = session.await;
        });
        (addr, task)
    }

    fn mesh_ssh_client_config() -> std::sync::Arc<client::Config> {
        let mut config = client::Config::default();
        config.preferred.kex =
            Cow::Borrowed(&[kex::CURVE25519, kex::ECDH_SHA2_NISTP256, kex::DH_G14_SHA256]);
        std::sync::Arc::new(config)
    }

    async fn collect_ssh_channel_output(
        channel: &mut russh::Channel<client::Msg>,
    ) -> (Vec<u8>, Vec<u8>, Option<u32>) {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut exit = None;
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while let Some(message) = channel.wait().await {
                match message {
                    ChannelMsg::Data { data } => stdout.extend_from_slice(&data),
                    ChannelMsg::ExtendedData { data, ext: 1 } => stderr.extend_from_slice(&data),
                    ChannelMsg::ExitStatus { exit_status } => exit = Some(exit_status),
                    ChannelMsg::Close => break,
                    _ => {}
                }
            }
        })
        .await
        .expect("SSH channel output");
        (stdout, stderr, exit)
    }

    async fn wait_for_latest_task(
        store: &MemoryStore,
        network_id: &str,
        event_id: &str,
    ) -> LatestTaskValue {
        for _ in 0..40 {
            let tasks = store
                .task_latest_list(TaskFilter {
                    network_id: network_id.to_string(),
                    ..Default::default()
                })
                .await
                .unwrap();
            if let Some(task) = tasks.into_iter().find(|task| task.event_id == event_id) {
                return task;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        panic!("task {event_id} was not persisted");
    }

    #[tokio::test]
    async fn auth_config_matches_go_shape() {
        let response = router(test_config(AuthMode::Oidc))
            .oneshot(
                Request::builder()
                    .uri("/api/v1/auth/config")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let got: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(got, json!({"auth_mode": "oidc"}));
    }

    fn oidc_test_config(issuer: String) -> Config {
        let mut config = test_config(AuthMode::Oidc);
        config.oidc_issuer = Some(issuer);
        config.oidc_client_id = Some("test-client".to_string());
        config.oidc_client_secret = Some("test-secret".to_string());
        config
    }

    async fn mock_oidc_discovery(headers: HeaderMap) -> Json<serde_json::Value> {
        let host = headers
            .get("host")
            .and_then(|value| value.to_str().ok())
            .unwrap();
        let base = format!("http://{host}");
        Json(json!({
            "issuer": base,
            "authorization_endpoint": format!("{base}/authorize"),
            "token_endpoint": format!("{base}/token"),
            "userinfo_endpoint": format!("{base}/userinfo"),
            "device_authorization_endpoint": format!("{base}/device/auth"),
        }))
    }

    async fn mock_device_authorize() -> Json<serde_json::Value> {
        Json(json!({
            "device_code": "dex_device_code_123",
            "user_code": "ABCD-EFGH",
            "verification_uri": "https://auth.example.com/device",
            "expires_in": 300,
            "interval": 5,
        }))
    }

    async fn mock_device_pending_token() -> Json<serde_json::Value> {
        Json(json!({"error": "authorization_pending"}))
    }

    async fn mock_device_approved_token() -> Json<serde_json::Value> {
        Json(json!({
            "access_token": "dex_access_token_xyz",
            "token_type": "Bearer",
        }))
    }

    async fn mock_userinfo(headers: HeaderMap) -> Response {
        if headers
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            != Some("Bearer dex_access_token_xyz")
        {
            return plain_error(StatusCode::UNAUTHORIZED, "bad token");
        }
        Json(json!({
            "sub": "user_sub_abc",
            "preferred_username": "testuser",
            "groups": ["developers"],
        }))
        .into_response()
    }

    #[tokio::test]
    async fn oidc_login_redirects_to_provider_and_stores_state() {
        let oidc_router = Router::new().route(
            "/.well-known/openid-configuration",
            get(mock_oidc_discovery),
        );
        let (addr, handle) = spawn_test_server(oidc_router).await;
        let router = router(oidc_test_config(format!("http://{addr}")));

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/auth/oidc")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FOUND);
        let location = response.headers().get(LOCATION).unwrap().to_str().unwrap();
        let parsed = url::Url::parse(location).unwrap();
        assert_eq!(parsed.path(), "/authorize");
        let params = parsed.query_pairs().collect::<Vec<_>>();
        assert!(
            params
                .iter()
                .any(|(key, value)| key == "client_id" && value == "test-client")
        );
        assert!(params.iter().any(|(key, value)| {
            key == "redirect_uri" && value == "https://mesh.codewire.sh/auth/oidc/callback"
        }));
        assert!(
            params
                .iter()
                .any(|(key, value)| key == "response_type" && value == "code")
        );
        assert!(
            params
                .iter()
                .any(|(key, value)| { key == "scope" && value == "openid profile email groups" })
        );
        let state = params
            .iter()
            .find_map(|(key, value)| (key == "state").then_some(value.as_ref()))
            .unwrap();
        assert_eq!(state.len(), 32);
        assert!(state.chars().all(|ch| ch.is_ascii_hexdigit()));
        handle.abort();
    }

    #[tokio::test]
    async fn oidc_callback_sets_session_cookie_and_auth_session_returns_user() {
        let oidc_router = Router::new()
            .route(
                "/.well-known/openid-configuration",
                get(mock_oidc_discovery),
            )
            .route("/token", post(mock_device_approved_token))
            .route("/userinfo", get(mock_userinfo));
        let (addr, handle) = spawn_test_server(oidc_router).await;
        let store = MemoryStore::new();
        let router = router_with_store(
            oidc_test_config(format!("http://{addr}")),
            std::sync::Arc::new(store.clone()),
        );

        let login = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/auth/oidc")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let location = login.headers().get(LOCATION).unwrap().to_str().unwrap();
        let parsed = url::Url::parse(location).unwrap();
        let state = parsed
            .query_pairs()
            .find_map(|(key, value)| (key == "state").then_some(value.to_string()))
            .unwrap();

        let callback = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/auth/oidc/callback?state={state}&code=authcode123"
                    ))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(callback.status(), StatusCode::FOUND);
        assert_eq!(callback.headers().get(LOCATION).unwrap(), "/");
        let cookie = callback
            .headers()
            .get(SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert!(cookie.starts_with("cw_session=sess_"));
        assert!(cookie.contains("; Path=/; Max-Age=2592000; HttpOnly; Secure; SameSite=Lax"));
        let session_token = cookie
            .strip_prefix("cw_session=")
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string();
        assert_eq!(session_token.len(), "sess_".len() + 32);

        let session = store
            .oidc_session_get(&session_token)
            .await
            .unwrap()
            .expect("OIDC session");
        assert_eq!(session.sub, "user_sub_abc");
        let user = store
            .oidc_user_get_by_sub("user_sub_abc")
            .await
            .unwrap()
            .expect("OIDC user");
        assert_eq!(user.username, "testuser");

        let session_info = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/auth/session")
                    .header(COOKIE, format!("theme=dark; cw_session={session_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(session_info.status(), StatusCode::OK);
        let body = to_bytes(session_info.into_body(), usize::MAX)
            .await
            .unwrap();
        let got: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(got["sub"], "user_sub_abc");
        assert_eq!(got["username"], "testuser");
        assert!(got["expires_at"].as_str().is_some());

        let bearer_session = router
            .oneshot(
                Request::builder()
                    .uri("/auth/session")
                    .header(AUTHORIZATION, format!("Bearer {session_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(bearer_session.status(), StatusCode::OK);
        handle.abort();
    }

    #[tokio::test]
    async fn oidc_session_rejects_missing_session_like_go_relay() {
        let router = router(oidc_test_config("http://127.0.0.1:9".to_string()));
        let response = router
            .oneshot(
                Request::builder()
                    .uri("/auth/session")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(
            &body[..],
            br#"{"error":"unauthorized"}
"#
        );
    }

    #[tokio::test]
    async fn oidc_device_authorize_matches_go_relay_contract() {
        let oidc_router = Router::new()
            .route(
                "/.well-known/openid-configuration",
                get(mock_oidc_discovery),
            )
            .route("/device/auth", post(mock_device_authorize));
        let (addr, handle) = spawn_test_server(oidc_router).await;
        let store = MemoryStore::new();
        let router = router_with_store(
            oidc_test_config(format!("http://{addr}")),
            std::sync::Arc::new(store.clone()),
        );

        let response = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/device/authorize")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"node_name":"my-node","network_id":"project-alpha"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let got: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(
            got["poll_token"]
                .as_str()
                .is_some_and(|token| !token.is_empty())
        );
        assert_eq!(got["user_code"], "ABCD-EFGH");
        assert_eq!(got["verification_uri"], "https://auth.example.com/device");
        assert_eq!(got["expires_in"], 300);
        assert_eq!(got["interval"], 5);

        let flow = store
            .oidc_device_flow_get(got["poll_token"].as_str().unwrap())
            .await
            .unwrap()
            .expect("stored flow");
        assert_eq!(flow.device_code, "dex_device_code_123");
        assert_eq!(flow.network_id, "project-alpha");
        assert_eq!(flow.node_name, "my-node");
        handle.abort();
    }

    #[tokio::test]
    async fn oidc_device_poll_pending_matches_go_relay_contract() {
        let oidc_router = Router::new()
            .route(
                "/.well-known/openid-configuration",
                get(mock_oidc_discovery),
            )
            .route("/device/auth", post(mock_device_authorize))
            .route("/token", post(mock_device_pending_token));
        let (addr, handle) = spawn_test_server(oidc_router).await;
        let router = router(oidc_test_config(format!("http://{addr}")));

        let authorize = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/device/authorize")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"node_name":"pending-node","network_id":"project-alpha"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(authorize.status(), StatusCode::OK);
        let body = to_bytes(authorize.into_body(), usize::MAX).await.unwrap();
        let auth: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let poll_token = auth["poll_token"].as_str().unwrap();

        let poll = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/device/poll")
                    .header("content-type", "application/json")
                    .body(Body::from(format!(r#"{{"poll_token":"{poll_token}"}}"#)))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(poll.status(), StatusCode::ACCEPTED);
        let body = to_bytes(poll.into_body(), usize::MAX).await.unwrap();
        let got: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(got, json!({"status": "pending"}));
        handle.abort();
    }

    #[tokio::test]
    async fn oidc_device_poll_authorized_registers_node_like_go_relay() {
        let oidc_router = Router::new()
            .route(
                "/.well-known/openid-configuration",
                get(mock_oidc_discovery),
            )
            .route("/device/auth", post(mock_device_authorize))
            .route("/token", post(mock_device_approved_token))
            .route("/userinfo", get(mock_userinfo));
        let (addr, handle) = spawn_test_server(oidc_router).await;
        let store = MemoryStore::new();
        let router = router_with_store(
            oidc_test_config(format!("http://{addr}")),
            std::sync::Arc::new(store.clone()),
        );

        let authorize = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/device/authorize")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"node_name":"auth-node","network_id":"project-alpha"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(authorize.status(), StatusCode::OK);
        let body = to_bytes(authorize.into_body(), usize::MAX).await.unwrap();
        let auth: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let poll_token = auth["poll_token"].as_str().unwrap();

        let poll = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/device/poll")
                    .header("content-type", "application/json")
                    .body(Body::from(format!(r#"{{"poll_token":"{poll_token}"}}"#)))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(poll.status(), StatusCode::OK);
        let body = to_bytes(poll.into_body(), usize::MAX).await.unwrap();
        let got: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let node_token = got["node_token"].as_str().unwrap();
        assert_eq!(got["status"], "authorized");
        assert_eq!(got["node_name"], "auth-node");
        assert_eq!(got["network_id"], "project-alpha");
        assert!(!node_token.is_empty());

        let node = store
            .node_get_by_token(node_token)
            .await
            .unwrap()
            .expect("registered node");
        assert_eq!(node.name, "auth-node");
        assert_eq!(node.network_id, "project-alpha");
        assert_eq!(node.owner_subject, "oidc:user_sub_abc");
        assert_eq!(node.authorized_by, "oidc:user_sub_abc");
        assert!(!node.enrollment_id.is_empty());

        let user = store
            .oidc_user_get_by_sub("user_sub_abc")
            .await
            .unwrap()
            .expect("OIDC user");
        assert_eq!(user.username, "testuser");

        let cached = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/device/poll")
                    .header("content-type", "application/json")
                    .body(Body::from(format!(r#"{{"poll_token":"{poll_token}"}}"#)))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(cached.status(), StatusCode::OK);
        let body = to_bytes(cached.into_body(), usize::MAX).await.unwrap();
        let cached: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(cached["status"], "authorized");
        assert_eq!(cached["node_token"], node_token);
        assert_eq!(cached["node_name"], "auth-node");
        assert!(cached.get("network_id").is_none());
        handle.abort();
    }

    #[tokio::test]
    async fn healthz_matches_existing_relay_probe() {
        let response = router(test_config(AuthMode::None))
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&body[..], b"ok");
    }

    #[tokio::test]
    async fn auth_validate_accepts_go_compatible_bearer_admin_token() {
        let response = router(test_config(AuthMode::Token))
            .oneshot(
                Request::builder()
                    .uri("/api/v1/auth/validate")
                    .header(AUTHORIZATION, "Bearer relay-admin")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let got: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(got, json!({"status": "ok"}));
    }

    #[tokio::test]
    async fn auth_validate_accepts_store_backed_github_session_token() {
        let store = seeded_github_store("sess_member", 101, "member").await;
        let response = router_with_store(test_config(AuthMode::Token), std::sync::Arc::new(store))
            .oneshot(
                Request::builder()
                    .uri("/api/v1/auth/validate")
                    .header(AUTHORIZATION, "Bearer sess_member")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn auth_validate_accepts_go_compatible_session_cookie_admin_token() {
        let response = router(test_config(AuthMode::Token))
            .oneshot(
                Request::builder()
                    .uri("/api/v1/auth/validate")
                    .header(COOKIE, "theme=dark; cw_session=relay-admin")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let got: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(got, json!({"status": "ok"}));
    }

    #[tokio::test]
    async fn auth_validate_rejects_missing_auth_like_go_relay() {
        let response = router(test_config(AuthMode::Token))
            .oneshot(
                Request::builder()
                    .uri("/api/v1/auth/validate")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response
                .headers()
                .get("x-content-type-options")
                .and_then(|value| value.to_str().ok()),
            Some("nosniff")
        );
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&body[..], b"unauthorized\n");
    }

    #[tokio::test]
    async fn networks_can_be_created_and_listed_for_owner() {
        let store = seeded_github_store("sess_member", 101, "member").await;
        let router = router_with_store(test_config(AuthMode::Token), std::sync::Arc::new(store));

        let create = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/networks")
                    .header(AUTHORIZATION, "Bearer sess_member")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"network_id":"project-alpha"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(create.status(), StatusCode::OK);
        let body = to_bytes(create.into_body(), usize::MAX).await.unwrap();
        let got: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            got,
            json!({"status": "created", "network_id": "project-alpha"})
        );

        let list = router
            .oneshot(
                Request::builder()
                    .uri("/api/v1/networks")
                    .header(AUTHORIZATION, "Bearer sess_member")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(list.status(), StatusCode::OK);
        let body = to_bytes(list.into_body(), usize::MAX).await.unwrap();
        let got: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(got.as_array().unwrap().len(), 1);
        assert_eq!(got[0]["id"], "project-alpha");
        assert_eq!(got[0]["node_count"], 0);
        assert_eq!(got[0]["invite_count"], 0);
    }

    #[tokio::test]
    async fn network_list_scopes_non_admin_to_memberships() {
        let store = seeded_github_store("sess_member", 101, "member").await;
        store.network_ensure("network-a").await.unwrap();
        store.network_ensure("network-b").await.unwrap();
        store
            .network_member_upsert(NetworkMember {
                network_id: "network-a".to_string(),
                subject: "github:101".to_string(),
                role: NETWORK_ROLE_OWNER.to_string(),
                created_at: Utc::now(),
                created_by: "github:101".to_string(),
            })
            .await
            .unwrap();

        let response = router_with_store(test_config(AuthMode::Token), std::sync::Arc::new(store))
            .oneshot(
                Request::builder()
                    .uri("/api/v1/networks")
                    .header(AUTHORIZATION, "Bearer sess_member")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let got: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(got.as_array().unwrap().len(), 1);
        assert_eq!(got[0]["id"], "network-a");
    }

    #[tokio::test]
    async fn network_create_rejects_claimed_network_for_outsider() {
        let store = seeded_github_store("sess_owner", 101, "owner").await;
        store
            .upsert_github_session(
                "sess_outsider",
                202,
                "outsider",
                Utc::now() + Duration::hours(1),
            )
            .await;
        let router = router_with_store(test_config(AuthMode::Token), std::sync::Arc::new(store));

        let owner = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/networks")
                    .header(AUTHORIZATION, "Bearer sess_owner")
                    .body(Body::from(r#"{"network_id":"project-alpha"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(owner.status(), StatusCode::OK);

        let outsider = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/networks")
                    .header(AUTHORIZATION, "Bearer sess_outsider")
                    .body(Body::from(r#"{"network_id":"project-alpha"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(outsider.status(), StatusCode::CONFLICT);
        let body = to_bytes(outsider.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&body[..], b"network already claimed\n");
    }

    #[tokio::test]
    async fn invite_create_list_and_delete_require_owner() {
        let store = seeded_member_store(
            "sess_owner",
            101,
            "owner",
            "project-alpha",
            NETWORK_ROLE_OWNER,
        )
        .await;
        let router = router_with_store(
            test_config(AuthMode::Token),
            std::sync::Arc::new(store.clone()),
        );

        let create = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/invites")
                    .header(AUTHORIZATION, "Bearer sess_owner")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"network_id":"project-alpha","uses":3,"ttl":"30m"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(create.status(), StatusCode::OK);
        let body = to_bytes(create.into_body(), usize::MAX).await.unwrap();
        let invite: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let token = invite["token"].as_str().unwrap().to_string();
        assert_eq!(invite["network_id"], "project-alpha");
        assert_eq!(invite["created_by"], 101);
        assert_eq!(invite["uses_remaining"], 3);
        assert!(token.starts_with(INVITE_TOKEN_PREFIX));
        assert_eq!(token.len(), INVITE_TOKEN_PREFIX.len() + 24);

        let list = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/invites?network_id=project-alpha")
                    .header(AUTHORIZATION, "Bearer sess_owner")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(list.status(), StatusCode::OK);
        let body = to_bytes(list.into_body(), usize::MAX).await.unwrap();
        let got: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(got.as_array().unwrap().len(), 1);
        assert_eq!(got[0]["token"], token);

        let delete = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/api/v1/invites/{token}?network_id=project-alpha"))
                    .header(AUTHORIZATION, "Bearer sess_owner")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(delete.status(), StatusCode::NO_CONTENT);

        assert!(store.invite_get(&token).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn invite_create_defaults_invalid_uses_like_go_relay() {
        let store = seeded_member_store(
            "sess_owner",
            101,
            "owner",
            "project-alpha",
            NETWORK_ROLE_OWNER,
        )
        .await;

        let response = router_with_store(test_config(AuthMode::Token), std::sync::Arc::new(store))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/invites")
                    .header(AUTHORIZATION, "Bearer sess_owner")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"network_id":"project-alpha","uses":"bad"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let invite: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(invite["uses_remaining"], 1);
    }

    #[tokio::test]
    async fn invite_create_rejects_member_without_owner_role() {
        let store = seeded_member_store(
            "sess_member",
            101,
            "member",
            "project-alpha",
            NETWORK_ROLE_MEMBER,
        )
        .await;

        let response = router_with_store(test_config(AuthMode::Token), std::sync::Arc::new(store))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/invites")
                    .header(AUTHORIZATION, "Bearer sess_member")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"network_id":"project-alpha"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&body[..], b"owner access required\n");
    }

    #[tokio::test]
    async fn invite_create_rejects_invalid_ttl_like_go_relay() {
        let store = seeded_member_store(
            "sess_owner",
            101,
            "owner",
            "project-alpha",
            NETWORK_ROLE_OWNER,
        )
        .await;

        let response = router_with_store(test_config(AuthMode::Token), std::sync::Arc::new(store))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/invites")
                    .header(AUTHORIZATION, "Bearer sess_owner")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"network_id":"project-alpha","ttl":"soon"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&body[..], b"invalid ttl\n");
    }

    #[tokio::test]
    async fn kv_routes_are_network_scoped_and_require_membership_like_go_relay() {
        let store = seeded_github_store("sess_member", 101, "member").await;
        store
            .upsert_github_session(
                "sess_outsider",
                202,
                "outsider",
                Utc::now() + Duration::hours(1),
            )
            .await;
        store
            .network_member_upsert(NetworkMember {
                network_id: "network-a".to_string(),
                subject: "github:101".to_string(),
                role: NETWORK_ROLE_OWNER.to_string(),
                created_at: Utc::now(),
                created_by: "github:101".to_string(),
            })
            .await
            .unwrap();

        let router = router_with_store(
            test_config(AuthMode::Token),
            std::sync::Arc::new(store.clone()),
        );
        for (network_id, value) in [("network-a", "alpha"), ("network-b", "beta")] {
            let response = router
                .clone()
                .oneshot(
                    Request::builder()
                        .method("PUT")
                        .uri(format!("/api/v1/kv/tasks/build?network_id={network_id}"))
                        .header(AUTHORIZATION, "Bearer relay-admin")
                        .body(Body::from(value))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NO_CONTENT);
        }

        let unauthenticated = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/kv/tasks/build?network_id=network-a")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

        let member = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/kv/tasks/build?network_id=network-a")
                    .header(AUTHORIZATION, "Bearer sess_member")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(member.status(), StatusCode::OK);
        assert_eq!(
            member
                .headers()
                .get(CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("application/octet-stream")
        );
        let body = to_bytes(member.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&body[..], b"alpha");

        let outsider = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/kv/tasks/build?network_id=network-b")
                    .header(AUTHORIZATION, "Bearer sess_outsider")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(outsider.status(), StatusCode::FORBIDDEN);

        let wrong_network = router
            .oneshot(
                Request::builder()
                    .uri("/api/v1/kv/tasks/build?network_id=network-b")
                    .header(AUTHORIZATION, "Bearer sess_member")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(wrong_network.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn kv_list_filters_prefix_and_base64_encodes_values_like_go_relay() {
        let store = seeded_member_store(
            "sess_owner",
            101,
            "owner",
            "project-alpha",
            NETWORK_ROLE_OWNER,
        )
        .await;
        let router = router_with_store(test_config(AuthMode::Token), std::sync::Arc::new(store));

        for (key, value) in [
            ("build-a", "alpha"),
            ("build-b", "bravo"),
            ("deploy-a", "charlie"),
        ] {
            let response = router
                .clone()
                .oneshot(
                    Request::builder()
                        .method("PUT")
                        .uri(format!("/api/v1/kv/tasks/{key}?network_id=project-alpha"))
                        .header(AUTHORIZATION, "Bearer sess_owner")
                        .body(Body::from(value))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NO_CONTENT);
        }

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/api/v1/kv/tasks?network_id=project-alpha&prefix=build")
                    .header(AUTHORIZATION, "Bearer sess_owner")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let got: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            got,
            json!([
                {"key": "build-a", "value": "YWxwaGE="},
                {"key": "build-b", "value": "YnJhdm8="}
            ])
        );
    }

    #[tokio::test]
    async fn kv_ttl_expiry_and_invalid_ttl_match_go_relay() {
        let store = seeded_member_store(
            "sess_owner",
            101,
            "owner",
            "project-alpha",
            NETWORK_ROLE_OWNER,
        )
        .await;
        let router = router_with_store(test_config(AuthMode::Token), std::sync::Arc::new(store));

        let expired_set = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/v1/kv/tasks/expired?network_id=project-alpha")
                    .header(AUTHORIZATION, "Bearer sess_owner")
                    .header("x-ttl", "-1s")
                    .body(Body::from("gone"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(expired_set.status(), StatusCode::NO_CONTENT);

        let expired_get = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/kv/tasks/expired?network_id=project-alpha")
                    .header(AUTHORIZATION, "Bearer sess_owner")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(expired_get.status(), StatusCode::NOT_FOUND);
        let body = to_bytes(expired_get.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&body[..], b"not found\n");

        let invalid_ttl = router
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/v1/kv/tasks/bad?network_id=project-alpha")
                    .header(AUTHORIZATION, "Bearer sess_owner")
                    .header("x-ttl", "1d")
                    .body(Body::from("bad"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(invalid_ttl.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(invalid_ttl.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&body[..], b"invalid X-TTL header\n");
    }

    #[tokio::test]
    async fn kv_delete_requires_owner_and_removes_value_like_go_relay() {
        let store = seeded_member_store(
            "sess_owner",
            101,
            "owner",
            "project-alpha",
            NETWORK_ROLE_OWNER,
        )
        .await;
        store
            .upsert_github_session(
                "sess_member",
                202,
                "member",
                Utc::now() + Duration::hours(1),
            )
            .await;
        store
            .network_member_upsert(NetworkMember {
                network_id: "project-alpha".to_string(),
                subject: "github:202".to_string(),
                role: NETWORK_ROLE_MEMBER.to_string(),
                created_at: Utc::now(),
                created_by: "github:101".to_string(),
            })
            .await
            .unwrap();
        let router = router_with_store(test_config(AuthMode::Token), std::sync::Arc::new(store));

        let set = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/v1/kv/tasks/build?network_id=project-alpha")
                    .header(AUTHORIZATION, "Bearer sess_owner")
                    .body(Body::from("alpha"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(set.status(), StatusCode::NO_CONTENT);

        let member_delete = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/api/v1/kv/tasks/build?network_id=project-alpha")
                    .header(AUTHORIZATION, "Bearer sess_member")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(member_delete.status(), StatusCode::FORBIDDEN);
        let body = to_bytes(member_delete.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&body[..], b"owner access required\n");

        let owner_delete = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/api/v1/kv/tasks/build?network_id=project-alpha")
                    .header(AUTHORIZATION, "Bearer sess_owner")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(owner_delete.status(), StatusCode::NO_CONTENT);

        let get_deleted = router
            .oneshot(
                Request::builder()
                    .uri("/api/v1/kv/tasks/build?network_id=project-alpha")
                    .header(AUTHORIZATION, "Bearer sess_owner")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(get_deleted.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn kv_routes_require_network_id_like_go_relay() {
        let response = router(test_config(AuthMode::Token))
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/v1/kv/tasks/build")
                    .header(AUTHORIZATION, "Bearer relay-admin")
                    .body(Body::from("alpha"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&body[..], b"network_id required\n");
    }

    #[tokio::test]
    async fn group_lifecycle_requires_owner_and_persists_defaults_like_go_relay() {
        let store = seeded_member_store(
            "sess_owner",
            101,
            "owner",
            "project-alpha",
            NETWORK_ROLE_OWNER,
        )
        .await;
        store
            .upsert_github_session(
                "sess_outsider",
                202,
                "outsider",
                Utc::now() + Duration::hours(1),
            )
            .await;
        let router = router_with_store(
            test_config(AuthMode::Token),
            std::sync::Arc::new(store.clone()),
        );

        let outsider = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/groups")
                    .header(AUTHORIZATION, "Bearer sess_outsider")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"network_id":"project-alpha","name":"mesh"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(outsider.status(), StatusCode::FORBIDDEN);

        let create = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/groups")
                    .header(AUTHORIZATION, "Bearer sess_owner")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"network_id":"project-alpha","name":"mesh"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(create.status(), StatusCode::OK);
        let body = to_bytes(create.into_body(), usize::MAX).await.unwrap();
        let created: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(created["network_id"], "project-alpha");
        assert_eq!(created["name"], "mesh");
        assert_eq!(created["created_by"], "github:101");
        assert_eq!(
            created["policy"]["messages_policy"],
            GROUP_MESSAGES_INTERNAL_ONLY
        );
        assert_eq!(created["policy"]["debug_policy"], GROUP_DEBUG_OBSERVE_ONLY);

        let list = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/groups?network_id=project-alpha")
                    .header(AUTHORIZATION, "Bearer sess_owner")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(list.status(), StatusCode::OK);
        let body = to_bytes(list.into_body(), usize::MAX).await.unwrap();
        let groups: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(groups.as_array().unwrap().len(), 1);
        assert_eq!(groups[0]["name"], "mesh");
        assert!(groups[0].get("members").is_none());

        let add_member = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/groups/mesh/members")
                    .header(AUTHORIZATION, "Bearer sess_owner")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"network_id":"project-alpha","node_name":"node-a","session_name":"agent-1"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(add_member.status(), StatusCode::OK);

        let get = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/groups/mesh?network_id=project-alpha")
                    .header(AUTHORIZATION, "Bearer sess_owner")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(get.status(), StatusCode::OK);
        let body = to_bytes(get.into_body(), usize::MAX).await.unwrap();
        let group: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(group["members"].as_array().unwrap().len(), 1);
        assert_eq!(group["members"][0]["node_name"], "node-a");
        assert_eq!(group["members"][0]["session_name"], "agent-1");

        let set_policy = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/v1/groups/mesh/policy")
                    .header(AUTHORIZATION, "Bearer sess_owner")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"network_id":"project-alpha","messages_policy":"open","debug_policy":"none"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(set_policy.status(), StatusCode::OK);

        let updated = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/groups/mesh?network_id=project-alpha")
                    .header(AUTHORIZATION, "Bearer sess_owner")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(updated.status(), StatusCode::OK);
        let body = to_bytes(updated.into_body(), usize::MAX).await.unwrap();
        let group: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(group["policy"]["messages_policy"], GROUP_MESSAGES_OPEN);
        assert_eq!(group["policy"]["debug_policy"], GROUP_DEBUG_NONE);

        let remove = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/api/v1/groups/mesh/members?network_id=project-alpha&node_name=node-a&session_name=agent-1")
                    .header(AUTHORIZATION, "Bearer sess_owner")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(remove.status(), StatusCode::OK);

        let delete = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/api/v1/groups/mesh?network_id=project-alpha")
                    .header(AUTHORIZATION, "Bearer sess_owner")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(delete.status(), StatusCode::OK);
        assert!(
            store
                .group_get("project-alpha", "mesh")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn group_handlers_reject_invalid_policy_and_duplicate_create_like_go_relay() {
        let store = seeded_member_store(
            "sess_owner",
            101,
            "owner",
            "project-alpha",
            NETWORK_ROLE_OWNER,
        )
        .await;
        let router = router_with_store(test_config(AuthMode::Token), std::sync::Arc::new(store));

        for expected_status in [StatusCode::OK, StatusCode::CONFLICT] {
            let response = router
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/v1/groups")
                        .header(AUTHORIZATION, "Bearer sess_owner")
                        .header("content-type", "application/json")
                        .body(Body::from(
                            r#"{"network_id":"project-alpha","name":"mesh"}"#,
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), expected_status);
        }

        let invalid_policy = router
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/v1/groups/mesh/policy")
                    .header(AUTHORIZATION, "Bearer sess_owner")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"network_id":"project-alpha","messages_policy":"bad-value","debug_policy":"observe-only"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(invalid_policy.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(invalid_policy.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&body[..], b"invalid messages_policy\n");
    }

    #[tokio::test]
    async fn group_bindings_allow_node_scoped_lookup_like_go_relay() {
        let store = MemoryStore::new();
        seed_node(
            &store,
            "project-alpha",
            "node-a",
            "node-token",
            "",
            Utc::now(),
        )
        .await;
        store
            .group_create(Group {
                network_id: "project-alpha".to_string(),
                name: "mesh".to_string(),
                created_at: Utc::now(),
                created_by: String::new(),
            })
            .await
            .unwrap();
        store
            .group_member_add(GroupMember {
                network_id: "project-alpha".to_string(),
                group_name: "mesh".to_string(),
                node_name: "node-a".to_string(),
                session_name: "agent-1".to_string(),
                created_at: Utc::now(),
            })
            .await
            .unwrap();

        let router = router_with_store(test_config(AuthMode::Token), std::sync::Arc::new(store));
        let bindings = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/groups/bindings?session_name=agent-1")
                    .header(AUTHORIZATION, "Bearer node-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(bindings.status(), StatusCode::OK);
        let body = to_bytes(bindings.into_body(), usize::MAX).await.unwrap();
        let got: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(got.as_array().unwrap().len(), 1);
        assert_eq!(got[0]["group_name"], "mesh");
        assert_eq!(got[0]["messages_policy"], GROUP_MESSAGES_INTERNAL_ONLY);
        assert_eq!(got[0]["debug_policy"], GROUP_DEBUG_OBSERVE_ONLY);

        let forbidden = router
            .oneshot(
                Request::builder()
                    .uri("/api/v1/groups/bindings?node_name=node-b&session_name=agent-1")
                    .header(AUTHORIZATION, "Bearer node-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn group_member_handlers_allow_node_scoped_mutation_like_go_relay() {
        let store = MemoryStore::new();
        seed_node(
            &store,
            "project-alpha",
            "node-a",
            "node-token",
            "",
            Utc::now(),
        )
        .await;
        store
            .group_create(Group {
                network_id: "project-alpha".to_string(),
                name: "mesh".to_string(),
                created_at: Utc::now(),
                created_by: String::new(),
            })
            .await
            .unwrap();
        let router = router_with_store(
            test_config(AuthMode::Token),
            std::sync::Arc::new(store.clone()),
        );

        let add = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/groups/mesh/members")
                    .header(AUTHORIZATION, "Bearer node-token")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"session_name":"agent-1"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(add.status(), StatusCode::OK);
        let members = store
            .group_member_list("project-alpha", "mesh")
            .await
            .unwrap();
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].node_name, "node-a");
        assert_eq!(members[0].session_name, "agent-1");

        let remove = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/api/v1/groups/mesh/members?session_name=agent-1")
                    .header(AUTHORIZATION, "Bearer node-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(remove.status(), StatusCode::OK);
        assert!(
            store
                .group_member_list("project-alpha", "mesh")
                .await
                .unwrap()
                .is_empty()
        );

        let forbidden = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/groups/mesh/members")
                    .header(AUTHORIZATION, "Bearer node-token")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"node_name":"node-b","session_name":"agent-1"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn invite_list_requires_network_id_like_go_relay() {
        let response = router(test_config(AuthMode::Token))
            .oneshot(
                Request::builder()
                    .uri("/api/v1/invites")
                    .header(AUTHORIZATION, "Bearer relay-admin")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&body[..], b"network_id required\n");
    }

    #[test]
    fn go_duration_parser_accepts_common_relay_ttls() {
        assert_eq!(parse_go_duration("30m"), Some(Duration::minutes(30)));
        assert_eq!(parse_go_duration("1h30m"), Some(Duration::minutes(90)));
        assert_eq!(parse_go_duration("1.5h"), Some(Duration::minutes(90)));
        assert_eq!(
            parse_go_duration("250ms"),
            Some(Duration::milliseconds(250))
        );
        assert_eq!(parse_go_duration("1d"), None);
        assert_eq!(parse_go_duration(""), None);
    }

    async fn seed_invite(store: &MemoryStore, token: &str, network_id: &str, uses: i32) {
        let now = Utc::now();
        store
            .invite_create(Invite {
                network_id: network_id.to_string(),
                token: token.to_string(),
                created_by: None,
                uses_remaining: uses,
                expires_at: now + Duration::hours(1),
                created_at: now,
            })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn network_join_adds_authenticated_member() {
        let store = seeded_github_store("sess_member", 101, "member").await;
        seed_invite(&store, "CW-INV-TEST", "network-invite", 1).await;
        let router = router_with_store(
            test_config(AuthMode::Token),
            std::sync::Arc::new(store.clone()),
        );

        let response = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/networks/join")
                    .header(AUTHORIZATION, "Bearer sess_member")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"invite_token":"CW-INV-TEST"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let got: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            got,
            json!({"status": "joined", "network_id": "network-invite"})
        );

        let member = store
            .network_member_get("network-invite", "github:101")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(member.role, NETWORK_ROLE_MEMBER);
        assert_eq!(member.created_by, "CW-INV-TEST");
        assert!(store.invite_get("CW-INV-TEST").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn network_join_rejects_blank_invite_token_like_go_relay() {
        let store = seeded_github_store("sess_member", 101, "member").await;
        let response = router_with_store(test_config(AuthMode::Token), std::sync::Arc::new(store))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/networks/join")
                    .header(AUTHORIZATION, "Bearer sess_member")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"invite_token":"  "}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&body[..], b"invite_token required\n");
    }

    #[tokio::test]
    async fn network_join_rejects_invalid_invite_token_like_go_relay() {
        let store = seeded_github_store("sess_member", 101, "member").await;
        let response = router_with_store(test_config(AuthMode::Token), std::sync::Arc::new(store))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/networks/join")
                    .header(AUTHORIZATION, "Bearer sess_member")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"invite_token":"CW-INV-MISSING"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&body[..], b"invalid or expired invite\n");
    }

    #[tokio::test]
    async fn network_join_preserves_existing_owner_role() {
        let store = seeded_github_store("sess_owner", 101, "owner").await;
        store
            .network_member_upsert(NetworkMember {
                network_id: "network-invite".to_string(),
                subject: "github:101".to_string(),
                role: NETWORK_ROLE_OWNER.to_string(),
                created_at: Utc::now(),
                created_by: "github:101".to_string(),
            })
            .await
            .unwrap();
        seed_invite(&store, "CW-INV-OWNER", "network-invite", 1).await;

        let response = router_with_store(
            test_config(AuthMode::Token),
            std::sync::Arc::new(store.clone()),
        )
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/networks/join")
                .header(AUTHORIZATION, "Bearer sess_owner")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"invite_token":"CW-INV-OWNER"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let member = store
            .network_member_get("network-invite", "github:101")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(member.role, NETWORK_ROLE_OWNER);
        assert_eq!(member.created_by, "github:101");
    }

    #[tokio::test]
    async fn invite_join_bootstraps_node_via_enrollment_like_go_relay() {
        let store = MemoryStore::new();
        let now = Utc::now();
        store
            .invite_create(Invite {
                network_id: "network-invite".to_string(),
                token: "CW-INV-BOOTSTRAP".to_string(),
                created_by: Some(101),
                uses_remaining: 1,
                expires_at: now + Duration::hours(1),
                created_at: now,
            })
            .await
            .unwrap();
        let router = router_with_store(
            test_config(AuthMode::Token),
            std::sync::Arc::new(store.clone()),
        );

        let response = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/join")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"invite_token":"CW-INV-BOOTSTRAP","node_name":"bootstrap-node"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let node_token = result["node_token"].as_str().unwrap();
        assert_eq!(result["status"], "registered");
        assert_eq!(result["node_name"], "bootstrap-node");
        assert_eq!(result["network_id"], "network-invite");
        assert!(!result["enrollment_id"].as_str().unwrap().is_empty());

        let node = store
            .node_get_by_token(node_token)
            .await
            .unwrap()
            .expect("registered node");
        assert_eq!(node.name, "bootstrap-node");
        assert_eq!(node.network_id, "network-invite");
        assert_eq!(node.github_id, Some(101));
        assert_eq!(node.owner_subject, "github:101");
        assert_eq!(node.authorized_by, "github:101");
        assert!(!node.enrollment_id.is_empty());
        assert!(
            store
                .invite_get("CW-INV-BOOTSTRAP")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn invite_join_rejects_missing_fields_like_go_relay() {
        let response = router(test_config(AuthMode::Token))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/join")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"invite_token":"CW-INV-TEST"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&body[..], b"node_name and invite_token required\n");
    }

    #[tokio::test]
    async fn join_page_escapes_invite_and_base_url_like_go_relay() {
        let mut config = test_config(AuthMode::None);
        config.base_url = "https://mesh.example.com/?x=<y>&z".to_string();
        let response = router(config)
            .oneshot(
                Request::builder()
                    .uri("/join?invite=%3Cscript%3Ealert(1)%3C%2Fscript%3E")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("text/html; charset=utf-8")
        );
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(!body.contains("<script>alert(1)</script>"));
        assert!(body.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(!body.contains("x=<y>&z"));
        assert!(body.contains("x=&lt;y&gt;&amp;z"));
        assert!(body.contains("Join Codewire Mesh"));
        assert!(body.contains("cw login && cw network join --mesh-url"));
        assert!(!body.contains("--relay-url"));
        assert!(!body.contains("Join CodeWire Relay"));
    }

    #[tokio::test]
    async fn oidc_index_uses_mesh_wording() {
        let response = router(test_config(AuthMode::Oidc))
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("text/html; charset=utf-8")
        );
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(body.contains("Codewire Mesh"));
        assert!(body.contains("Mesh is running"));
        assert!(!body.contains("CodeWire Relay"));
        assert!(!body.contains("Relay is running"));
    }

    #[tokio::test]
    async fn node_enrollment_create_and_redeem_registers_node() {
        let store = seeded_member_store(
            "sess_member",
            101,
            "member",
            "network-a",
            NETWORK_ROLE_MEMBER,
        )
        .await;
        let router = router_with_store(
            test_config(AuthMode::Token),
            std::sync::Arc::new(store.clone()),
        );

        let create = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/node-enrollments")
                    .header(AUTHORIZATION, "Bearer sess_member")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"network_id":"network-a","node_name":"dev-1","uses":1,"ttl":"10m"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(create.status(), StatusCode::OK);
        let body = to_bytes(create.into_body(), usize::MAX).await.unwrap();
        let created: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let enrollment_id = created["id"].as_str().unwrap().to_string();
        let enrollment_token = created["enrollment_token"].as_str().unwrap().to_string();
        assert_eq!(created["network_id"], "network-a");
        assert_eq!(created["node_name"], "dev-1");
        assert_eq!(created["owner_subject"], "github:101");
        assert_eq!(created["issued_by"], "github:101");
        assert_eq!(created["uses_remaining"], 1);
        assert_eq!(enrollment_id.len(), 64);
        assert!(enrollment_token.starts_with("cw_enr_"));
        assert_eq!(enrollment_token.len(), "cw_enr_".len() + 64);

        let redeem = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/node-enrollments/redeem")
                    .header("content-type", "application/json")
                    .body(Body::from(format!(
                        r#"{{"enrollment_token":"{enrollment_token}","peer_url":"https://peer.dev"}}"#
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(redeem.status(), StatusCode::OK);
        let body = to_bytes(redeem.into_body(), usize::MAX).await.unwrap();
        let redeemed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let node_token = redeemed["node_token"].as_str().unwrap();
        assert_eq!(redeemed["status"], "registered");
        assert_eq!(redeemed["node_name"], "dev-1");
        assert_eq!(redeemed["network_id"], "network-a");
        assert_eq!(redeemed["enrollment_id"], enrollment_id);
        assert_eq!(node_token.len(), 64);

        let node = store
            .node_get_by_token(node_token)
            .await
            .unwrap()
            .expect("registered node");
        assert_eq!(node.network_id, "network-a");
        assert_eq!(node.name, "dev-1");
        assert_eq!(node.peer_url, "https://peer.dev");
        assert_eq!(node.owner_subject, "github:101");
        assert_eq!(node.authorized_by, "github:101");
        assert_eq!(node.enrollment_id, enrollment_id);

        let enrollment = store
            .node_enrollment_get_by_token_hash(&hash_enrollment_token(&enrollment_token))
            .await
            .unwrap()
            .expect("stored enrollment");
        assert_eq!(enrollment.uses_remaining, 0);
        assert!(enrollment.redeemed_at.is_some());
    }

    #[tokio::test]
    async fn node_enrollment_create_requires_membership_like_go_relay() {
        let store = seeded_github_store("sess_member", 101, "member").await;
        let response = router_with_store(test_config(AuthMode::Token), std::sync::Arc::new(store))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/node-enrollments")
                    .header(AUTHORIZATION, "Bearer sess_member")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"network_id":"network-a"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&body[..], b"membership required\n");
    }

    #[tokio::test]
    async fn node_enrollment_create_rejects_invalid_ttl_like_go_relay() {
        let store = seeded_member_store(
            "sess_member",
            101,
            "member",
            "network-a",
            NETWORK_ROLE_MEMBER,
        )
        .await;
        let response = router_with_store(test_config(AuthMode::Token), std::sync::Arc::new(store))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/node-enrollments")
                    .header(AUTHORIZATION, "Bearer sess_member")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"network_id":"network-a","ttl":"soon"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&body[..], b"invalid ttl\n");
    }

    #[tokio::test]
    async fn node_enrollment_redeem_rejects_missing_token_like_go_relay() {
        let response = router(test_config(AuthMode::Token))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/node-enrollments/redeem")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"node_name":"dev-1"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&body[..], b"enrollment_token required\n");
    }

    #[tokio::test]
    async fn node_enrollment_redeem_rejects_fixed_node_name_mismatch() {
        let store = seeded_member_store(
            "sess_member",
            101,
            "member",
            "network-a",
            NETWORK_ROLE_MEMBER,
        )
        .await;
        let (_, enrollment_token) = create_node_enrollment(
            &store,
            "network-a",
            "github:101",
            "github:101",
            "dev-1",
            1,
            Duration::minutes(10),
        )
        .await
        .unwrap();

        let response = router_with_store(test_config(AuthMode::Token), std::sync::Arc::new(store))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/node-enrollments/redeem")
                    .header("content-type", "application/json")
                    .body(Body::from(format!(
                        r#"{{"enrollment_token":"{enrollment_token}","node_name":"other"}}"#
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&body[..], b"node_name does not match enrollment\n");
    }

    #[tokio::test]
    async fn nodes_list_requires_membership_and_scopes_by_network_like_go_relay() {
        let store = MemoryStore::new();
        store
            .upsert_github_session(
                "sess_member",
                101,
                "member",
                Utc::now() + Duration::hours(1),
            )
            .await;
        store
            .upsert_github_session(
                "sess_outsider",
                202,
                "outsider",
                Utc::now() + Duration::hours(1),
            )
            .await;
        store
            .network_member_upsert(NetworkMember {
                network_id: "network-a".to_string(),
                subject: "github:101".to_string(),
                role: NETWORK_ROLE_OWNER.to_string(),
                created_at: Utc::now(),
                created_by: "github:101".to_string(),
            })
            .await
            .unwrap();
        seed_node(
            &store,
            "network-a",
            "shared-node",
            "token-network-a",
            "https://network-a.example/ws",
            Utc::now(),
        )
        .await;
        seed_node(
            &store,
            "network-b",
            "shared-node",
            "token-network-b",
            "https://network-b.example/ws",
            Utc::now(),
        )
        .await;
        let router = router_with_store(
            test_config(AuthMode::Token),
            std::sync::Arc::new(store.clone()),
        );

        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/nodes?network_id=network-a")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/nodes?network_id=network-a")
                    .header(AUTHORIZATION, "Bearer sess_outsider")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&body[..], b"membership required\n");

        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/nodes?network_id=network-a")
                    .header(AUTHORIZATION, "Bearer sess_member")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let nodes: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(nodes.as_array().unwrap().len(), 1);
        assert_eq!(nodes[0]["network_id"], "network-a");
        assert_eq!(nodes[0]["name"], "shared-node");
        assert_eq!(nodes[0]["peer_url"], "https://network-a.example/ws");
        assert_eq!(nodes[0]["connected"], true);

        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/nodes?all=true")
                    .header(AUTHORIZATION, "Bearer sess_member")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let nodes: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(nodes.as_array().unwrap().len(), 1);
        assert_eq!(nodes[0]["network_id"], "network-a");

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/api/v1/nodes?all=true")
                    .header(AUTHORIZATION, "Bearer relay-admin")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let nodes: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(nodes.as_array().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn nodes_list_accepts_node_token_like_go_relay() {
        let store = MemoryStore::new();
        seed_node(
            &store,
            "network-a",
            "builder",
            "node-token",
            "https://builder.example/ws",
            Utc::now(),
        )
        .await;
        seed_node(
            &store,
            "network-b",
            "other",
            "other-node-token",
            "https://other.example/ws",
            Utc::now(),
        )
        .await;

        let response = router_with_store(test_config(AuthMode::Token), std::sync::Arc::new(store))
            .oneshot(
                Request::builder()
                    .uri("/api/v1/nodes?network_id=network-b")
                    .header(AUTHORIZATION, "Bearer node-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let nodes: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(nodes.as_array().unwrap().len(), 1);
        assert_eq!(nodes[0]["network_id"], "network-a");
        assert_eq!(nodes[0]["name"], "builder");
    }

    #[tokio::test]
    async fn node_connect_rejects_missing_node_token_before_websocket_upgrade() {
        let response = router(test_config(AuthMode::Token))
            .oneshot(
                Request::builder()
                    .uri("/node/connect")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&body[..], b"unauthorized\n");
    }

    #[tokio::test]
    async fn node_connect_registers_hub_and_streams_messages_like_go_relay() {
        let store = MemoryStore::new();
        seed_node(
            &store,
            "network-a",
            "builder",
            "node-token",
            "https://builder.example/ws",
            Utc::now(),
        )
        .await;
        let state = test_state(AuthMode::Token, store);
        let router = router_from_state(state.clone());
        let (addr, server) = spawn_test_server(router).await;

        let mut request = format!("ws://{addr}/node/connect")
            .into_client_request()
            .unwrap();
        request
            .headers_mut()
            .insert("Authorization", "Bearer node-token".parse().unwrap());
        let (mut ws, response) = tokio_tungstenite::connect_async(request).await.unwrap();
        assert_eq!(response.status().as_u16(), 101);

        for _ in 0..40 {
            if state.node_hub.has("network-a", "builder") {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        assert!(state.node_hub.has("network-a", "builder"));

        state
            .node_hub
            .send(
                "network-a",
                "builder",
                HubMessage {
                    kind: "SSHRequest".to_string(),
                    session_id: "sess1".to_string(),
                    cols: 80,
                    rows: 24,
                },
            )
            .unwrap();

        let msg = tokio::time::timeout(std::time::Duration::from_secs(1), ws.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let ClientMessage::Text(text) = msg else {
            panic!("expected text hub message");
        };
        let body: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(body["type"], "SSHRequest");
        assert_eq!(body["session_id"], "sess1");
        assert_eq!(body["cols"], 80);
        assert_eq!(body["rows"], 24);

        let _ = ws.close(None).await;
        for _ in 0..40 {
            if !state.node_hub.has("network-a", "builder") {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        assert!(!state.node_hub.has("network-a", "builder"));
        server.abort();
    }

    #[tokio::test]
    async fn node_connect_publishes_task_report_like_go_relay() {
        let store = MemoryStore::new();
        let old_seen = Utc::now() - Duration::minutes(10);
        seed_node(
            &store,
            "network-a",
            "builder",
            "node-token",
            "https://old.example/ws",
            old_seen,
        )
        .await;
        let router = router_with_store(
            test_config(AuthMode::Token),
            std::sync::Arc::new(store.clone()),
        );
        let (addr, server) = spawn_test_server(router).await;

        let mut request = format!("ws://{addr}/node/connect")
            .into_client_request()
            .unwrap();
        request
            .headers_mut()
            .insert("Authorization", "Bearer node-token".parse().unwrap());
        request.headers_mut().insert(
            "X-CodeWire-Peer-URL",
            "https://builder.example/ws".parse().unwrap(),
        );
        let (mut ws, response) = tokio_tungstenite::connect_async(request).await.unwrap();
        assert_eq!(response.status().as_u16(), 101);

        ws.send(ClientMessage::Text(
            r#"{"type":"TaskReport","event_id":"task_ws","session_id":7,"session_name":"planner","summary":"ship rust ingest","state":"working","timestamp":"2026-04-08T15:04:05.123456789+02:00","network_id":"spoofed"}"#.into(),
        ))
        .await
        .unwrap();

        let latest = wait_for_latest_task(&store, "network-a", "task_ws").await;
        assert_eq!(latest.network_id, "network-a");
        assert_eq!(latest.node_name, "builder");
        assert_eq!(latest.session_id, 7);
        assert_eq!(latest.session_name, "planner");
        assert_eq!(latest.summary, "ship rust ingest");
        assert_eq!(latest.state, "working");
        assert_eq!(latest.timestamp, "2026-04-08T13:04:05.123456789Z");

        let node = store
            .node_get("network-a", "builder")
            .await
            .unwrap()
            .expect("node");
        assert_eq!(node.peer_url, "https://builder.example/ws");
        assert!(node.last_seen_at > old_seen);

        let _ = ws.close(None).await;
        server.abort();
    }

    #[tokio::test]
    async fn node_back_rejects_missing_node_token_before_websocket_upgrade() {
        let response = router(test_config(AuthMode::Token))
            .oneshot(
                Request::builder()
                    .uri("/node/back/sess1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&body[..], b"unauthorized\n");
    }

    #[tokio::test]
    async fn node_back_delivers_pending_session_like_go_relay() {
        let store = MemoryStore::new();
        seed_node(
            &store,
            "network-a",
            "builder",
            "node-token",
            "https://builder.example/ws",
            Utc::now(),
        )
        .await;
        let state = test_state(AuthMode::Token, store);
        let mut pending = state.pending_sessions.expect_for_test("sess1");
        let router = router_from_state(state.clone());
        let (addr, server) = spawn_test_server(router).await;

        let mut request = format!("ws://{addr}/node/back/sess1")
            .into_client_request()
            .unwrap();
        request
            .headers_mut()
            .insert("Authorization", "Bearer node-token".parse().unwrap());
        let (mut ws, response) = tokio_tungstenite::connect_async(request).await.unwrap();
        assert_eq!(response.status().as_u16(), 101);

        let conn = tokio::time::timeout(std::time::Duration::from_secs(1), pending.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(conn.network_id(), "network-a");
        assert_eq!(conn.node_name(), "builder");

        conn.close_no_waiter().await;
        let _ = ws.close(None).await;
        server.abort();
    }

    #[tokio::test]
    async fn mesh_ssh_listener_bridges_node_backchannel_like_go_relay() {
        let store = MemoryStore::new();
        seed_node(
            &store,
            "network-a",
            "builder",
            "node-token",
            "https://builder.example/ws",
            Utc::now(),
        )
        .await;
        let state = test_state(AuthMode::Token, store);
        let router = router_from_state(state.clone());
        let (http_addr, http_server) = spawn_test_server(router).await;
        let (ssh_addr, ssh_server) = spawn_test_mesh_ssh(state.clone()).await;

        let mut connect_request = format!("ws://{http_addr}/node/connect")
            .into_client_request()
            .unwrap();
        connect_request
            .headers_mut()
            .insert("Authorization", "Bearer node-token".parse().unwrap());
        let (mut node_ws, response) = tokio_tungstenite::connect_async(connect_request)
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), 101);

        for _ in 0..40 {
            if state.node_hub.has("network-a", "builder") {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        assert!(state.node_hub.has("network-a", "builder"));

        let node_task = tokio::spawn(async move {
            let msg = tokio::time::timeout(std::time::Duration::from_secs(2), node_ws.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            let ClientMessage::Text(text) = msg else {
                panic!("expected SSHRequest hub message");
            };
            let body: serde_json::Value = serde_json::from_str(&text).unwrap();
            assert_eq!(body["type"], "SSHRequest");
            assert_eq!(body["cols"], 100);
            assert_eq!(body["rows"], 30);
            let session_id = body["session_id"].as_str().unwrap();
            assert!(!session_id.is_empty());

            let mut back_request = format!("ws://{http_addr}/node/back/{session_id}")
                .into_client_request()
                .unwrap();
            back_request
                .headers_mut()
                .insert("Authorization", "Bearer node-token".parse().unwrap());
            let (mut back_ws, response) = tokio_tungstenite::connect_async(back_request)
                .await
                .unwrap();
            assert_eq!(response.status().as_u16(), 101);

            let stdin = tokio::time::timeout(std::time::Duration::from_secs(2), back_ws.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            let ClientMessage::Binary(stdin) = stdin else {
                panic!("expected SSH stdin over backchannel");
            };
            assert_eq!(&stdin[..], b"hello");

            back_ws
                .send(ClientMessage::Binary(
                    "echo:hello".as_bytes().to_vec().into(),
                ))
                .await
                .unwrap();

            let eof = tokio::time::timeout(std::time::Duration::from_secs(2), back_ws.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            let ClientMessage::Binary(eof) = eof else {
                panic!("expected SSH EOF marker over backchannel");
            };
            assert_eq!(&eof[..], &[0x04]);
            let _ = back_ws.close(None).await;
        });

        let mut client = client::connect(mesh_ssh_client_config(), ssh_addr, AcceptAllKeys)
            .await
            .unwrap();
        let authenticated = client
            .authenticate_password("network-a/builder", "node-token")
            .await
            .map(|result| matches!(result, client::AuthResult::Success))
            .unwrap_or(false);
        assert!(authenticated, "node token password auth should be accepted");

        let mut channel = client.channel_open_session().await.unwrap();
        channel
            .request_pty(true, "xterm-256color", 100, 30, 0, 0, &[])
            .await
            .unwrap();
        channel.request_shell(true).await.unwrap();
        channel.data_bytes(b"hello".to_vec()).await.unwrap();
        channel.eof().await.unwrap();

        let (stdout, stderr, exit) = collect_ssh_channel_output(&mut channel).await;
        assert_eq!(stdout, b"echo:hello");
        assert_eq!(stderr, b"");
        assert_eq!(exit, Some(0));

        node_task.await.unwrap();
        let _ = client
            .disconnect(russh::Disconnect::ByApplication, "", "en")
            .await;
        http_server.abort();
        ssh_server.abort();
    }

    #[tokio::test]
    async fn node_revoke_requires_owner_and_deletes_node_like_go_relay() {
        let store = MemoryStore::new();
        store
            .upsert_github_session("sess_owner", 101, "owner", Utc::now() + Duration::hours(1))
            .await;
        store
            .upsert_github_session(
                "sess_member",
                202,
                "member",
                Utc::now() + Duration::hours(1),
            )
            .await;
        store
            .network_member_upsert(NetworkMember {
                network_id: "network-a".to_string(),
                subject: "github:101".to_string(),
                role: NETWORK_ROLE_OWNER.to_string(),
                created_at: Utc::now(),
                created_by: "github:101".to_string(),
            })
            .await
            .unwrap();
        store
            .network_member_upsert(NetworkMember {
                network_id: "network-a".to_string(),
                subject: "github:202".to_string(),
                role: NETWORK_ROLE_MEMBER.to_string(),
                created_at: Utc::now(),
                created_by: "github:101".to_string(),
            })
            .await
            .unwrap();
        seed_node(
            &store,
            "network-a",
            "builder",
            "node-token",
            "",
            Utc::now() - Duration::minutes(5),
        )
        .await;
        let router = router_with_store(
            test_config(AuthMode::Token),
            std::sync::Arc::new(store.clone()),
        );

        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/api/v1/nodes/builder?network_id=network-a")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/api/v1/nodes/builder?network_id=network-a")
                    .header(AUTHORIZATION, "Bearer sess_member")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&body[..], b"owner access required\n");

        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/api/v1/nodes/missing?network_id=network-a")
                    .header(AUTHORIZATION, "Bearer sess_owner")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&body[..], b"node not found\n");

        let response = router
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/api/v1/nodes/builder?network_id=network-a")
                    .header(AUTHORIZATION, "Bearer sess_owner")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let revoked: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(revoked, json!({"status": "revoked", "node": "builder"}));
        assert!(
            store
                .node_get("network-a", "builder")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn tailnet_coordinate_rejects_missing_runtime_credential() {
        let router = router_with_store(
            test_config(AuthMode::Token),
            std::sync::Arc::new(MemoryStore::new()),
        );
        let (addr, server) = spawn_test_server(router).await;

        let err = tokio_tungstenite::connect_async(coordinate_request(addr, None, ""))
            .await
            .expect_err("missing runtime credential must reject websocket upgrade");
        match err {
            tokio_tungstenite::tungstenite::Error::Http(response) => {
                assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            }
            other => panic!("expected HTTP 401 websocket rejection, got {other:?}"),
        }
        server.abort();
    }

    #[tokio::test]
    async fn tailnet_coordinate_allows_runtime_credential_reconnect() {
        let store =
            seeded_member_store("sess_owner", 101, "owner", "network-a", NETWORK_ROLE_OWNER).await;
        let now = Utc::now();
        store
            .node_register(NodeRecord {
                network_id: "network-a".to_string(),
                name: "builder".to_string(),
                token: "node-token".to_string(),
                peer_url: "https://builder.example/ws".to_string(),
                github_id: None,
                owner_subject: "github:101".to_string(),
                authorized_by: "github:101".to_string(),
                enrollment_id: "enr_builder".to_string(),
                authorized_at: now,
                last_seen_at: now,
            })
            .await
            .unwrap();

        let state = test_state(AuthMode::Token, store);
        let issuer = load_or_create_issuer_state(&state, "network-a")
            .await
            .unwrap();
        let (node_token, _) = sign_runtime_credential(
            &issuer,
            SUBJECT_KIND_NODE,
            "builder",
            Utc::now(),
            DEFAULT_RUNTIME_TTL,
        )
        .unwrap();

        let router = router_from_state(state);
        let (addr, server) = spawn_test_server(router).await;

        let (mut first, _) =
            tokio_tungstenite::connect_async(coordinate_request(addr, Some(&node_token), ""))
                .await
                .unwrap();
        assert_eq!(next_ws_json(&mut first).await["type"], "derp_map");
        let _ = first.close(None).await;

        let (mut second, _) =
            tokio_tungstenite::connect_async(coordinate_request(addr, Some(&node_token), ""))
                .await
                .unwrap();
        assert_eq!(next_ws_json(&mut second).await["type"], "derp_map");
        let _ = second.close(None).await;
        server.abort();
    }

    #[tokio::test]
    async fn tailnet_coordinate_exchanges_node_peer_updates_like_go_relay() {
        let store =
            seeded_member_store("sess_owner", 101, "owner", "network-a", NETWORK_ROLE_OWNER).await;
        let now = Utc::now();
        store
            .node_register(NodeRecord {
                network_id: "network-a".to_string(),
                name: "builder".to_string(),
                token: "node-token".to_string(),
                peer_url: "https://builder.example/ws".to_string(),
                github_id: None,
                owner_subject: "github:101".to_string(),
                authorized_by: "github:101".to_string(),
                enrollment_id: "enr_builder".to_string(),
                authorized_at: now,
                last_seen_at: now,
            })
            .await
            .unwrap();

        let mut state = test_state(AuthMode::Token, store);
        state.config.derp_url = Some("http://127.0.0.1:18091".to_string());
        let issuer = load_or_create_issuer_state(&state, "network-a")
            .await
            .unwrap();
        let (node_token, _) = sign_runtime_credential(
            &issuer,
            SUBJECT_KIND_NODE,
            "builder",
            Utc::now(),
            DEFAULT_RUNTIME_TTL,
        )
        .unwrap();
        let (client_token, _) = sign_runtime_credential(
            &issuer,
            SUBJECT_KIND_CLIENT,
            "github:101",
            Utc::now(),
            DEFAULT_RUNTIME_TTL,
        )
        .unwrap();

        let router = router_from_state(state);
        let (addr, server) = spawn_test_server(router).await;

        let (mut node_ws, node_response) =
            tokio_tungstenite::connect_async(coordinate_request(addr, Some(&node_token), ""))
                .await
                .unwrap();
        assert_eq!(
            node_response
                .headers()
                .get("Sec-WebSocket-Protocol")
                .and_then(|value| value.to_str().ok()),
            Some("coordinate")
        );
        let node_derp = next_ws_json(&mut node_ws).await;
        assert_eq!(node_derp["type"], "derp_map");
        assert_eq!(
            node_derp["derp_map"]["Regions"]["1"]["Nodes"][0]["HostName"],
            "127.0.0.1"
        );
        assert_eq!(
            node_derp["derp_map"]["Regions"]["1"]["Nodes"][0]["DERPPort"],
            18091
        );
        assert_eq!(
            node_derp["derp_map"]["Regions"]["1"]["Nodes"][0]["InsecureForTests"],
            true
        );

        let builder_id = stable_principal_uuid("network-a", SUBJECT_KIND_NODE, "builder");
        let builder_node = sample_tailnet_node(builder_id, 1, 0x11);
        node_ws
            .send(ClientMessage::Text(
                json!({"type": "node", "node": builder_node})
                    .to_string()
                    .into(),
            ))
            .await
            .unwrap();

        let (mut client_ws, _) = tokio_tungstenite::connect_async(coordinate_request(
            addr,
            Some(&client_token),
            "?role=dial",
        ))
        .await
        .unwrap();
        let client_derp = next_ws_json(&mut client_ws).await;
        assert_eq!(client_derp["type"], "derp_map");
        client_ws
            .send(ClientMessage::Text(
                json!({"type": "subscribe", "target_node": "builder"})
                    .to_string()
                    .into(),
            ))
            .await
            .unwrap();

        let client_update = next_ws_json(&mut client_ws).await;
        assert_eq!(client_update["type"], "peer_update");
        assert_eq!(client_update["nodes"][0]["id"], builder_id.to_string());
        assert_eq!(client_update["nodes"][0]["preferred_derp"], 1);

        let client_id = Uuid::parse_str("00112233-4455-6677-8899-aabbccddeeff").unwrap();
        let client_node = sample_tailnet_node(client_id, 3, 0x22);
        client_ws
            .send(ClientMessage::Text(
                json!({"type": "node", "node": client_node})
                    .to_string()
                    .into(),
            ))
            .await
            .unwrap();

        let node_update = next_ws_json(&mut node_ws).await;
        assert_eq!(node_update["type"], "peer_update");
        assert_eq!(node_update["nodes"][0]["id"], client_id.to_string());
        assert_eq!(node_update["nodes"][0]["preferred_derp"], 3);

        let _ = client_ws.close(None).await;
        let _ = node_ws.close(None).await;
        server.abort();
    }

    #[tokio::test]
    async fn network_auth_client_runtime_credential_matches_go_relay_shape() {
        let store =
            seeded_member_store("sess_member", 101, "member", "project-alpha", "owner").await;
        let router = router_with_store(
            test_config(AuthMode::Token),
            std::sync::Arc::new(store.clone()),
        );

        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/network-auth/runtime/client?network_id=project-alpha")
                    .header(AUTHORIZATION, "Bearer sess_member")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let issued: RuntimeCredentialResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(issued.network_id, "project-alpha");
        assert_eq!(issued.subject_kind, SUBJECT_KIND_CLIENT);
        assert_eq!(issued.subject_id, "github:101");
        assert!(issued.credential.starts_with("cwrt1."));

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/api/v1/network-auth/bundle?network_id=project-alpha")
                    .header(AUTHORIZATION, "Bearer sess_member")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let bundle: VerifierBundle = serde_json::from_slice(&body).unwrap();
        assert_eq!(bundle.issuer, "mesh:project-alpha");
        let claims = verify_runtime_credential(&issued.credential, &bundle, Utc::now()).unwrap();
        assert_eq!(claims.subject_id, "github:101");
    }

    #[tokio::test]
    async fn network_auth_client_runtime_requires_membership_like_go_relay() {
        let store = MemoryStore::new();
        store
            .upsert_github_session(
                "sess_member",
                101,
                "member",
                Utc::now() + Duration::hours(1),
            )
            .await;
        store
            .upsert_github_session(
                "sess_outsider",
                202,
                "outsider",
                Utc::now() + Duration::hours(1),
            )
            .await;
        store
            .network_member_upsert(NetworkMember {
                network_id: "network-a".to_string(),
                subject: "github:101".to_string(),
                role: NETWORK_ROLE_OWNER.to_string(),
                created_at: Utc::now(),
                created_by: "github:101".to_string(),
            })
            .await
            .unwrap();

        let router = router_with_store(test_config(AuthMode::Token), std::sync::Arc::new(store));
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/network-auth/runtime/client?network_id=network-a")
                    .header(AUTHORIZATION, "Bearer sess_outsider")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&body[..], b"membership required\n");

        let response = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/network-auth/runtime/client?network_id=network-a")
                    .header(AUTHORIZATION, "Bearer sess_member")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn network_auth_node_runtime_and_bundle_use_node_token_like_go_relay() {
        let store = MemoryStore::new();
        seed_node(
            &store,
            "project-alpha",
            "dev-2",
            "node-token",
            "",
            Utc::now(),
        )
        .await;
        let router = router_with_store(
            test_config(AuthMode::Token),
            std::sync::Arc::new(store.clone()),
        );

        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/network-auth/runtime/node")
                    .header(AUTHORIZATION, "Bearer node-token")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let issued: RuntimeCredentialResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(issued.subject_kind, SUBJECT_KIND_NODE);
        assert_eq!(issued.subject_id, "dev-2");

        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/network-auth/bundle?network_id=other-network")
                    .header(AUTHORIZATION, "Bearer node-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&body[..], b"forbidden\n");

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/api/v1/network-auth/bundle?network_id=project-alpha")
                    .header(AUTHORIZATION, "Bearer node-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let bundle: VerifierBundle = serde_json::from_slice(&body).unwrap();
        assert_eq!(bundle.issuer, "mesh:project-alpha");
        let claims = verify_runtime_credential(&issued.credential, &bundle, Utc::now()).unwrap();
        assert_eq!(claims.subject_id, "dev-2");
    }

    #[tokio::test]
    async fn network_auth_node_sender_delegation_carries_session_groups_like_go_relay() {
        let store = MemoryStore::new();
        let now = Utc::now();
        seed_node(&store, "project-alpha", "dev-1", "node-token", "", now).await;
        store
            .group_create(Group {
                network_id: "project-alpha".to_string(),
                name: "mesh".to_string(),
                created_at: now,
                created_by: String::new(),
            })
            .await
            .unwrap();
        store
            .group_member_add(GroupMember {
                network_id: "project-alpha".to_string(),
                group_name: "mesh".to_string(),
                node_name: "dev-1".to_string(),
                session_name: "planner".to_string(),
                created_at: now,
            })
            .await
            .unwrap();
        let router = router_with_store(test_config(AuthMode::Token), std::sync::Arc::new(store));

        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/network-auth/delegation/node")
                    .header(AUTHORIZATION, "Bearer node-token")
                    .body(Body::from(
                        json!({
                            "source_node": "dev-1",
                            "from_session_id": 42,
                            "from_session_name": "planner",
                            "verbs": ["msg"],
                            "audience_node": "dev-2"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let issued: SenderDelegationResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(issued.source_node, "dev-1");
        assert_eq!(issued.from_session_name, "planner");
        assert_eq!(issued.source_groups, vec!["mesh"]);

        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/network-auth/bundle?network_id=project-alpha")
                    .header(AUTHORIZATION, "Bearer node-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let bundle: VerifierBundle = serde_json::from_slice(&body).unwrap();
        let claims = verify_sender_delegation(&issued.delegation, &bundle, Utc::now()).unwrap();
        assert_eq!(claims.audience_node, "dev-2");
        assert_eq!(claims.source_groups, vec!["mesh"]);

        let response = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/network-auth/delegation/node")
                    .header(AUTHORIZATION, "Bearer node-token")
                    .body(Body::from(
                        json!({
                            "source_node": "other-node",
                            "from_session_name": "planner",
                            "verbs": ["msg"]
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&body[..], b"source_node must match authenticated node\n");
    }

    #[tokio::test]
    async fn network_auth_user_sender_delegation_uses_network_scoped_source_node() {
        let store = seeded_member_store(
            "sess_member",
            101,
            "member",
            "project-alpha",
            NETWORK_ROLE_MEMBER,
        )
        .await;
        let now = Utc::now();
        seed_node(&store, "project-alpha", "dev-1", "alpha-token", "", now).await;
        seed_node(&store, "other-network", "dev-1", "other-token", "", now).await;
        store
            .group_create(Group {
                network_id: "project-alpha".to_string(),
                name: "mesh".to_string(),
                created_at: now,
                created_by: String::new(),
            })
            .await
            .unwrap();
        store
            .group_member_add(GroupMember {
                network_id: "project-alpha".to_string(),
                group_name: "mesh".to_string(),
                node_name: "dev-1".to_string(),
                session_name: "planner".to_string(),
                created_at: now,
            })
            .await
            .unwrap();
        let router = router_with_store(test_config(AuthMode::Token), std::sync::Arc::new(store));

        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/network-auth/delegation/node")
                    .header(AUTHORIZATION, "Bearer sess_member")
                    .body(Body::from(
                        json!({
                            "network_id": "project-alpha",
                            "source_node": "dev-1",
                            "from_session_name": "planner",
                            "verbs": ["request"],
                            "audience_node": "dev-2"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let issued: SenderDelegationResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(issued.network_id, "project-alpha");
        assert_eq!(issued.source_node, "dev-1");
        assert_eq!(issued.from_session_name, "planner");
        assert_eq!(issued.source_groups, vec!["mesh"]);

        let response = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/network-auth/delegation/node")
                    .header(AUTHORIZATION, "Bearer sess_member")
                    .body(Body::from(
                        json!({
                            "source_node": "dev-1",
                            "from_session_name": "planner",
                            "verbs": ["request"]
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&body[..], b"network_id is required\n");
    }

    #[tokio::test]
    async fn access_grant_lifecycle_requires_owner_and_persists_like_go_relay() {
        let store = seeded_member_store(
            "sess_owner",
            101,
            "owner",
            "project-alpha",
            NETWORK_ROLE_OWNER,
        )
        .await;
        store
            .upsert_github_session(
                "sess_member",
                202,
                "member",
                Utc::now() + Duration::hours(1),
            )
            .await;
        store
            .upsert_github_session(
                "sess_outsider",
                303,
                "outsider",
                Utc::now() + Duration::hours(1),
            )
            .await;
        store
            .network_member_upsert(NetworkMember {
                network_id: "project-alpha".to_string(),
                subject: "github:202".to_string(),
                role: NETWORK_ROLE_MEMBER.to_string(),
                created_at: Utc::now(),
                created_by: "github:101".to_string(),
            })
            .await
            .unwrap();
        let router = router_with_store(
            test_config(AuthMode::Token),
            std::sync::Arc::new(store.clone()),
        );

        let outsider = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/access-grants")
                    .header(AUTHORIZATION, "Bearer sess_outsider")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "network_id": "project-alpha",
                            "target_node": "builder",
                            "session_id": 7,
                            "audience": "member"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(outsider.status(), StatusCode::FORBIDDEN);

        let create = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/access-grants")
                    .header(AUTHORIZATION, "Bearer sess_owner")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "network_id": "project-alpha",
                            "target_node": "builder",
                            "session_id": 7,
                            "audience": "member",
                            "verbs": ["read", "listen"],
                            "ttl": "1m"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(create.status(), StatusCode::OK);
        let body = to_bytes(create.into_body(), usize::MAX).await.unwrap();
        let issued: ObserverDelegationResponse = serde_json::from_slice(&body).unwrap();
        assert!(issued.delegation.starts_with("cwog1."));
        assert_eq!(issued.network_id, "project-alpha");
        assert_eq!(issued.target_node, "builder");
        assert_eq!(issued.session_id, Some(7));
        assert_eq!(issued.audience_subject_kind, SUBJECT_KIND_CLIENT);
        assert_eq!(issued.audience_subject_id, "github:202");
        assert_eq!(issued.audience_display, "member");

        let bundle = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/network-auth/bundle?network_id=project-alpha")
                    .header(AUTHORIZATION, "Bearer sess_owner")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(bundle.status(), StatusCode::OK);
        let body = to_bytes(bundle.into_body(), usize::MAX).await.unwrap();
        let bundle: VerifierBundle = serde_json::from_slice(&body).unwrap();
        let claims = verify_observer_delegation(&issued.delegation, &bundle, Utc::now()).unwrap();
        assert_eq!(claims.jti, issued.grant_id);
        assert_eq!(claims.verbs, vec!["msg.read", "msg.listen"]);

        let owner_list = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/access-grants?network_id=project-alpha&active=true")
                    .header(AUTHORIZATION, "Bearer sess_owner")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(owner_list.status(), StatusCode::OK);
        let body = to_bytes(owner_list.into_body(), usize::MAX).await.unwrap();
        let grants: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(grants.as_array().unwrap().len(), 1);
        assert_eq!(grants[0]["id"], issued.grant_id);

        let mine = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/access-grants?network_id=project-alpha&mine=true")
                    .header(AUTHORIZATION, "Bearer sess_member")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(mine.status(), StatusCode::OK);
        let body = to_bytes(mine.into_body(), usize::MAX).await.unwrap();
        let grants: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(grants.as_array().unwrap().len(), 1);
        assert_eq!(grants[0]["audience_subject_id"], "github:202");

        let get = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/api/v1/access-grants/{}?network_id=project-alpha",
                        issued.grant_id
                    ))
                    .header(AUTHORIZATION, "Bearer sess_member")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(get.status(), StatusCode::OK);

        let revoke = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!(
                        "/api/v1/access-grants/{}?network_id=project-alpha",
                        issued.grant_id
                    ))
                    .header(AUTHORIZATION, "Bearer sess_owner")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(revoke.status(), StatusCode::OK);
        let body = to_bytes(revoke.into_body(), usize::MAX).await.unwrap();
        let revoked: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            revoked,
            json!({"status": "revoked", "grant_id": issued.grant_id})
        );

        let active_after_revoke = router
            .oneshot(
                Request::builder()
                    .uri("/api/v1/access-grants?network_id=project-alpha&active=true")
                    .header(AUTHORIZATION, "Bearer sess_owner")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(active_after_revoke.status(), StatusCode::OK);
        let body = to_bytes(active_after_revoke.into_body(), usize::MAX)
            .await
            .unwrap();
        let grants: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(grants.as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn access_grant_create_rejects_ambiguous_audience_like_go_relay() {
        let store = seeded_member_store(
            "sess_owner",
            101,
            "owner",
            "project-alpha",
            NETWORK_ROLE_OWNER,
        )
        .await;
        store
            .upsert_github_session(
                "sess_shared",
                202,
                "shared",
                Utc::now() + Duration::hours(1),
            )
            .await;
        store
            .upsert_oidc_session(
                "sess_oidc",
                "user-202",
                "shared",
                Utc::now() + Duration::hours(1),
            )
            .await;
        let router = router_with_store(test_config(AuthMode::Token), std::sync::Arc::new(store));

        let response = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/access-grants")
                    .header(AUTHORIZATION, "Bearer sess_owner")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "network_id": "project-alpha",
                            "target_node": "builder",
                            "session_name": "planner",
                            "audience": "shared"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(
            &body[..],
            b"principal is ambiguous; use an explicit subject like github:<id> or oidc:<sub>\n"
        );
    }

    #[tokio::test]
    async fn task_list_returns_latest_snapshot_with_filters_like_go_relay() {
        let store = seeded_member_store(
            "sess_owner",
            101,
            "owner",
            "project-alpha",
            NETWORK_ROLE_OWNER,
        )
        .await;
        seed_task_event(
            &store,
            TaskSeed {
                event_id: "task_old",
                network_id: "project-alpha",
                node_name: "builder",
                session_id: 7,
                session_name: "planner",
                summary: "ship task route",
                state: "working",
            },
        )
        .await;
        seed_task_event(
            &store,
            TaskSeed {
                event_id: "task_new",
                network_id: "project-alpha",
                node_name: "builder",
                session_id: 7,
                session_name: "planner",
                summary: "ship task route",
                state: "complete",
            },
        )
        .await;
        seed_task_event(
            &store,
            TaskSeed {
                event_id: "task_other",
                network_id: "project-alpha",
                node_name: "runner",
                session_id: 8,
                session_name: "builder",
                summary: "unrelated task",
                state: "working",
            },
        )
        .await;

        let response = router_with_store(test_config(AuthMode::Token), std::sync::Arc::new(store))
            .oneshot(
                Request::builder()
                    .uri("/api/v1/tasks?network_id=project-alpha&node=builder&state=complete")
                    .header(AUTHORIZATION, "Bearer sess_owner")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let tasks: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(tasks.as_array().unwrap().len(), 1);
        assert_eq!(tasks[0]["event_id"], "task_new");
        assert_eq!(tasks[0]["stream_seq"], 2);
        assert_eq!(tasks[0]["session_name"], "planner");
        assert_eq!(tasks[0]["state"], "complete");
    }

    #[tokio::test]
    async fn task_list_requires_membership_like_go_relay() {
        let store = seeded_github_store("sess_outsider", 202, "outsider").await;
        let router = router_with_store(test_config(AuthMode::Token), std::sync::Arc::new(store));

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/api/v1/tasks?network_id=project-alpha")
                    .header(AUTHORIZATION, "Bearer sess_outsider")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&body[..], b"membership required\n");
    }

    #[tokio::test]
    async fn direct_node_registration_is_disabled_like_go_relay() {
        let response = router(test_config(AuthMode::Token))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/nodes")
                    .header(AUTHORIZATION, "Bearer relay-admin")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::GONE);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(
            &body[..],
            b"direct node registration is disabled; use /api/v1/node-enrollments and /api/v1/node-enrollments/redeem\n"
        );
    }
}
