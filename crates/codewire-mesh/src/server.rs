use std::future::Future;
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::header::{
    ACCEPT, AUTHORIZATION, CONTENT_TYPE, COOKIE, HeaderName, HeaderValue, LOCATION, SET_COOKIE,
};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use chrono::{DateTime, Duration, Utc};
use codewire_server_core::AppError;
use codewire_server_core::http::AppBuilder;
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tokio::sync::OnceCell;

use crate::mesh_authorization::{
    ForwardedMeshCredential, MeshAuthorizationAdapter, forwarded_mesh_credential,
};
use crate::product::{KeyValueWrite, MeshProductService};
use crate::store::{
    Group, GroupMember, GroupPolicy, NodeRecord, OAuthState, OidcSession, OidcUser, SharedStore,
    store_from_config,
};
use crate::{AuthMode, Config};

const ALPHANUMERIC: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const MAX_KV_VALUE_BYTES: usize = 1 << 20;
#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) config: Config,
    pub(crate) store: SharedStore,
    pub(crate) product: MeshProductService,
    pub(crate) mesh_coordinate: crate::mesh_coordinate::MeshCoordinateState,
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
}

#[derive(Deserialize)]
struct OidcDiscoveryDocument {
    authorization_endpoint: String,
    token_endpoint: String,
    userinfo_endpoint: String,
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

    tracing::info!(
        listen_addr = %http_addr,
        base_url = %config.base_url,
        auth_mode = config.auth_mode.as_str(),
        "codewire mesh service listening"
    );

    let store = store_from_config(&config)
        .await
        .context("initialize codewire-mesh store")?;
    let state = AppState::new(config, store);
    let router = router_from_state(state.clone());
    axum::serve(http_listener, router)
        .with_graceful_shutdown(shutdown)
        .await
        .context("serve codewire-mesh HTTP")
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
        let mesh_authorization = MeshAuthorizationAdapter::from_config(
            config.mesh_authorization.as_ref(),
            config.local_authorization.as_ref(),
        );
        let product = MeshProductService::new(store.clone(), mesh_authorization);
        Self {
            config,
            store,
            product,
            mesh_coordinate: crate::mesh_coordinate::MeshCoordinateState::new(),
            oidc_client: OidcClient::new(),
        }
    }
}

fn router_from_state(state: AppState) -> Router {
    let mut public_routes = Router::new()
        .route("/api/v1/nodes", get(node_list))
        .route("/join", get(join_page))
        // The temporary REST spelling is a primary-authenticated ownership
        // bridge. It must not pass through Mesh's retired cookie/admin
        // middleware: that would let the two identity systems diverge.
        .route("/api/v1/networks", get(network_list).post(network_create))
        .route(
            "/api/v1/groups/{name}/members",
            post(group_member_add).delete(group_member_remove),
        )
        .route("/api/v1/groups", get(group_list).post(group_create))
        .route("/api/v1/groups/{name}", get(group_get).delete(group_delete))
        .route("/api/v1/groups/{name}/policy", put(group_policy_set))
        .route("/api/v1/invites", get(invite_list).post(invite_create))
        .route("/api/v1/invites/{invite_id}", delete(invite_delete))
        .route("/api/v1/kv/{namespace}", get(kv_list))
        .route(
            "/api/v1/kv/{namespace}/{key}",
            get(kv_get).put(kv_set).delete(kv_delete),
        )
        .route("/api/v1/node-enrollments", post(node_enrollment_create))
        .route("/api/v1/nodes/{name}", delete(node_revoke))
        .route("/api/v1/networks/join", post(network_join));

    if state.config.auth_mode == AuthMode::Oidc {
        public_routes = public_routes
            .route("/", get(oidc_index))
            .route("/auth/oidc", get(oidc_login))
            .route("/auth/oidc/callback", get(oidc_callback))
            .route("/auth/session", get(oidc_session_info));
    }

    let public_routes = public_routes.with_state(state.clone());

    AppBuilder::new("mesh")
        .with_health()
        .with_connect_routes(crate::connect::router(state.clone()))
        .with_connect_routes_and_protocol_policy(
            crate::mesh_coordinate::router(state),
            codewire_server_core::connect::ProtocolPolicy::ConnectAndGrpc,
        )
        .with_routes(public_routes)
        .into_router()
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
        Err(error) => return error.into_response(),
    };
    let claims = match fetch_oidc_userinfo(&state, &endpoints, &access_token).await {
        Ok(claims) => claims,
        Err(error) => return error.into_response(),
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
struct OidcTokenResponse {
    #[serde(default)]
    access_token: String,
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
struct NetworkResponse {
    id: String,
    org_id: String,
    created_at: chrono::DateTime<Utc>,
    node_count: i64,
    invite_count: i64,
}

async fn network_list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<NetworkListQuery>,
) -> Response {
    let Some(org_id) = required_org_id(query.org_id) else {
        return plain_error(StatusCode::BAD_REQUEST, "org_id required");
    };
    let credential = match product_credential(&headers) {
        Ok(credential) => credential,
        Err(error) => return error.into_response(),
    };
    match state.product.list_networks(&org_id, credential).await {
        Ok(networks) => {
            let body = networks
                .into_iter()
                .map(|network| NetworkResponse {
                    id: network.id,
                    org_id: network.organization_id,
                    created_at: network.created_at,
                    node_count: network.node_count,
                    invite_count: network.invite_count,
                })
                .collect::<Vec<_>>();
            Json(body).into_response()
        }
        Err(error) => error.into_response(),
    }
}

#[derive(Deserialize)]
struct NetworkCreateRequest {
    org_id: Option<String>,
    network_id: Option<String>,
}

#[derive(Deserialize)]
struct NetworkListQuery {
    org_id: Option<String>,
}

async fn network_create(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let req = match serde_json::from_slice::<NetworkCreateRequest>(&body) {
        Ok(req) => req,
        Err(_) => return plain_error(StatusCode::BAD_REQUEST, "network_id required"),
    };
    let Some(org_id) = required_org_id(req.org_id) else {
        return plain_error(StatusCode::BAD_REQUEST, "org_id required");
    };
    let network_id = req.network_id.unwrap_or_default().trim().to_string();
    if let Err(message) = validate_network_id(&network_id) {
        return plain_error(StatusCode::BAD_REQUEST, message);
    }

    let credential = match product_credential(&headers) {
        Ok(credential) => credential,
        Err(error) => return error.into_response(),
    };
    match state
        .product
        .create_network(&org_id, &network_id, credential)
        .await
    {
        Ok(network) => Json(NetworkCreateResponse::created(network.id)).into_response(),
        Err(error) => error.into_response(),
    }
}

fn required_org_id(org_id: Option<String>) -> Option<String> {
    org_id
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn product_credential(
    headers: &HeaderMap,
) -> codewire_server_core::AppResult<ForwardedMeshCredential> {
    forwarded_mesh_credential(headers).map_err(|_| AppError::Unauthorized)
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

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct InviteCreateRequest {
    network_id: Option<String>,
    ttl: Option<String>,
}

#[derive(Deserialize)]
struct NetworkIDQuery {
    network_id: Option<String>,
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
#[serde(deny_unknown_fields)]
struct NodeEnrollmentCreateRequest {
    network_id: Option<String>,
    node_name: Option<String>,
    ttl: Option<String>,
}

#[derive(Serialize)]
struct NodeEnrollmentCreateResponse {
    enrollment: NodeEnrollmentResponse,
    enrollment_code: String,
}

#[derive(Serialize)]
struct NodeEnrollmentResponse {
    id: String,
    org_id: String,
    network_id: String,
    node_name: String,
    owner_user_id: String,
    issued_by_user_id: String,
    expires_at: chrono::DateTime<Utc>,
    created_at: chrono::DateTime<Utc>,
}

#[derive(Deserialize)]
struct NodesListQuery {
    network_id: Option<String>,
}

#[derive(Serialize)]
struct NodeResponse {
    network_id: String,
    name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    peer_url: String,
    connected: bool,
}

#[derive(Serialize)]
struct NodeRevokeResponse<'a> {
    status: &'static str,
    node: &'a str,
}

async fn node_enrollment_create(
    State(state): State<AppState>,
    headers: HeaderMap,
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
    let ttl = match req.ttl.as_deref() {
        None => Duration::minutes(10),
        Some(raw) if raw.trim().is_empty() => Duration::minutes(10),
        Some(raw) => match parse_go_duration(raw) {
            Some(ttl) => ttl,
            None => return plain_error(StatusCode::BAD_REQUEST, "invalid ttl"),
        },
    };
    let organization_id = match state.product.organization_for_network(&network_id).await {
        Ok(organization_id) => organization_id,
        Err(error) => return error.into_response(),
    };
    let credential = match product_credential(&headers) {
        Ok(credential) => credential,
        Err(error) => return error.into_response(),
    };
    match state
        .product
        .create_node_enrollment(
            &organization_id,
            &network_id,
            req.node_name.as_deref().unwrap_or_default(),
            credential,
            ttl,
        )
        .await
    {
        Ok(created) => Json(NodeEnrollmentCreateResponse {
            enrollment: NodeEnrollmentResponse {
                id: created.enrollment.id,
                org_id: organization_id,
                network_id: created.enrollment.network_id,
                node_name: created.enrollment.node_name,
                owner_user_id: created.enrollment.owner_subject,
                issued_by_user_id: created.enrollment.issued_by,
                expires_at: created.enrollment.expires_at,
                created_at: created.enrollment.created_at,
            },
            enrollment_code: created.enrollment_code,
        })
        .into_response(),
        Err(error) => error.into_response(),
    }
}

async fn kv_set(
    State(state): State<AppState>,
    Path((namespace, key)): Path<(String, String)>,
    Query(query): Query<NetworkIDQuery>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let network_id = match required_network_id(query.network_id.as_deref()) {
        Ok(network_id) => network_id,
        Err(message) => return plain_error(StatusCode::BAD_REQUEST, message),
    };
    let ttl = match parse_xttl_header(&headers) {
        Ok(ttl) => ttl,
        Err(message) => return plain_error(StatusCode::BAD_REQUEST, message),
    };
    let value = body
        .iter()
        .take(MAX_KV_VALUE_BYTES)
        .copied()
        .collect::<Vec<_>>();
    let organization_id = match state.product.organization_for_network(&network_id).await {
        Ok(organization_id) => organization_id,
        Err(error) => return error.into_response(),
    };
    let credential = match product_credential(&headers) {
        Ok(credential) => credential,
        Err(error) => return error.into_response(),
    };
    match state
        .product
        .set_key_value(
            KeyValueWrite {
                organization_id: &organization_id,
                network_id: &network_id,
                namespace: &namespace,
                key: &key,
                value,
                ttl,
            },
            credential,
        )
        .await
    {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => error.into_response(),
    }
}

async fn kv_get(
    State(state): State<AppState>,
    Path((namespace, key)): Path<(String, String)>,
    Query(query): Query<NetworkIDQuery>,
    headers: HeaderMap,
) -> Response {
    let network_id = match required_network_id(query.network_id.as_deref()) {
        Ok(network_id) => network_id,
        Err(message) => return plain_error(StatusCode::BAD_REQUEST, message),
    };
    let organization_id = match state.product.organization_for_network(&network_id).await {
        Ok(organization_id) => organization_id,
        Err(error) => return error.into_response(),
    };
    let credential = match product_credential(&headers) {
        Ok(credential) => credential,
        Err(error) => return error.into_response(),
    };
    match state
        .product
        .get_key_value(&organization_id, &network_id, &namespace, &key, credential)
        .await
    {
        Ok(entry) => (
            StatusCode::OK,
            [(
                CONTENT_TYPE,
                HeaderValue::from_static("application/octet-stream"),
            )],
            entry.value,
        )
            .into_response(),
        Err(error) => error.into_response(),
    }
}

async fn kv_delete(
    State(state): State<AppState>,
    Path((namespace, key)): Path<(String, String)>,
    Query(query): Query<NetworkIDQuery>,
    headers: HeaderMap,
) -> Response {
    let network_id = match required_network_id(query.network_id.as_deref()) {
        Ok(network_id) => network_id,
        Err(message) => return plain_error(StatusCode::BAD_REQUEST, message),
    };
    let organization_id = match state.product.organization_for_network(&network_id).await {
        Ok(organization_id) => organization_id,
        Err(error) => return error.into_response(),
    };
    let credential = match product_credential(&headers) {
        Ok(credential) => credential,
        Err(error) => return error.into_response(),
    };
    match state
        .product
        .delete_key_value(&organization_id, &network_id, &namespace, &key, credential)
        .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => error.into_response(),
    }
}

async fn kv_list(
    State(state): State<AppState>,
    Path(namespace): Path<String>,
    Query(query): Query<KVListQuery>,
    headers: HeaderMap,
) -> Response {
    let network_id = match required_network_id(query.network_id.as_deref()) {
        Ok(network_id) => network_id,
        Err(message) => return plain_error(StatusCode::BAD_REQUEST, message),
    };
    let organization_id = match state.product.organization_for_network(&network_id).await {
        Ok(organization_id) => organization_id,
        Err(error) => return error.into_response(),
    };
    let credential = match product_credential(&headers) {
        Ok(credential) => credential,
        Err(error) => return error.into_response(),
    };
    match state
        .product
        .list_key_values(
            &organization_id,
            &network_id,
            &namespace,
            query.prefix.as_deref().unwrap_or_default(),
            credential,
        )
        .await
    {
        Ok(entries) => Json(entries).into_response(),
        Err(error) => error.into_response(),
    }
}

async fn group_create(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
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
    let organization_id = match state.product.organization_for_network(&network_id).await {
        Ok(organization_id) => organization_id,
        Err(error) => return error.into_response(),
    };
    let credential = match product_credential(&headers) {
        Ok(credential) => credential,
        Err(error) => return error.into_response(),
    };
    match state
        .product
        .create_group(&organization_id, &network_id, &group_name, credential)
        .await
    {
        Ok(view) => Json(group_response(view.group, view.members, view.policy)).into_response(),
        Err(error) => error.into_response(),
    }
}

async fn group_list(
    State(state): State<AppState>,
    Query(query): Query<NetworkIDQuery>,
    headers: HeaderMap,
) -> Response {
    let network_id = match required_network_id(query.network_id.as_deref()) {
        Ok(network_id) => network_id,
        Err(message) => return plain_error(StatusCode::BAD_REQUEST, message),
    };
    let organization_id = match state.product.organization_for_network(&network_id).await {
        Ok(organization_id) => organization_id,
        Err(error) => return error.into_response(),
    };
    let credential = match product_credential(&headers) {
        Ok(credential) => credential,
        Err(error) => return error.into_response(),
    };
    match state
        .product
        .list_groups(&organization_id, &network_id, credential)
        .await
    {
        Ok(groups) => Json(
            groups
                .into_iter()
                .map(|view| group_response(view.group, view.members, view.policy))
                .collect::<Vec<_>>(),
        )
        .into_response(),
        Err(error) => error.into_response(),
    }
}

async fn group_get(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Query(query): Query<NetworkIDQuery>,
    headers: HeaderMap,
) -> Response {
    let network_id = match required_network_id(query.network_id.as_deref()) {
        Ok(network_id) => network_id,
        Err(message) => return plain_error(StatusCode::BAD_REQUEST, message),
    };
    let group_name = match validate_group_name(&name) {
        Ok(group_name) => group_name,
        Err(message) => return plain_error(StatusCode::BAD_REQUEST, message),
    };
    let organization_id = match state.product.organization_for_network(&network_id).await {
        Ok(organization_id) => organization_id,
        Err(error) => return error.into_response(),
    };
    let credential = match product_credential(&headers) {
        Ok(credential) => credential,
        Err(error) => return error.into_response(),
    };
    match state
        .product
        .get_group(&organization_id, &network_id, &group_name, credential)
        .await
    {
        Ok(view) => Json(group_response(view.group, view.members, view.policy)).into_response(),
        Err(error) => error.into_response(),
    }
}

async fn group_delete(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Query(query): Query<NetworkIDQuery>,
    headers: HeaderMap,
) -> Response {
    let network_id = match required_network_id(query.network_id.as_deref()) {
        Ok(network_id) => network_id,
        Err(message) => return plain_error(StatusCode::BAD_REQUEST, message),
    };
    let group_name = match validate_group_name(&name) {
        Ok(group_name) => group_name,
        Err(message) => return plain_error(StatusCode::BAD_REQUEST, message),
    };
    let organization_id = match state.product.organization_for_network(&network_id).await {
        Ok(organization_id) => organization_id,
        Err(error) => return error.into_response(),
    };
    let credential = match product_credential(&headers) {
        Ok(credential) => credential,
        Err(error) => return error.into_response(),
    };
    match state
        .product
        .delete_group(&organization_id, &network_id, &group_name, credential)
        .await
    {
        Ok(()) => Json(GroupDeleteResponse {
            status: "deleted",
            network_id,
            name: group_name,
        })
        .into_response(),
        Err(error) => error.into_response(),
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
    let organization_id = match state.product.organization_for_network(&network_id).await {
        Ok(organization_id) => organization_id,
        Err(error) => return error.into_response(),
    };
    let credential = match product_credential(&headers) {
        Ok(credential) => credential,
        Err(error) => return error.into_response(),
    };
    match state
        .product
        .add_group_member(
            &organization_id,
            &network_id,
            &group_name,
            &node_name,
            &session_name,
            credential,
        )
        .await
    {
        Ok(member) => Json(member).into_response(),
        Err(error) => error.into_response(),
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
    let network_id = match required_network_id(query.network_id.as_deref()) {
        Ok(network_id) => network_id,
        Err(message) => return plain_error(StatusCode::BAD_REQUEST, message),
    };
    let node_name = query.node_name.as_deref().unwrap_or_default();
    let session_name = query.session_name.as_deref().unwrap_or_default();
    let organization_id = match state.product.organization_for_network(&network_id).await {
        Ok(organization_id) => organization_id,
        Err(error) => return error.into_response(),
    };
    let credential = match product_credential(&headers) {
        Ok(credential) => credential,
        Err(error) => return error.into_response(),
    };
    match state
        .product
        .remove_group_member(
            &organization_id,
            &network_id,
            &group_name,
            node_name,
            session_name,
            credential,
        )
        .await
    {
        Ok(()) => Json(GroupMemberRemoveResponse {
            status: "removed",
            network_id,
            group_name,
            node_name: node_name.trim().to_owned(),
            session_name: session_name.trim().to_owned(),
        })
        .into_response(),
        Err(error) => error.into_response(),
    }
}

async fn group_policy_set(
    State(state): State<AppState>,
    Path(name): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let req = match serde_json::from_slice::<GroupPolicyRequest>(&body) {
        Ok(req) => req,
        Err(_) => return plain_error(StatusCode::BAD_REQUEST, "bad request"),
    };
    let network_id = match required_network_id(req.network_id.as_deref()) {
        Ok(network_id) => network_id,
        Err(message) => return plain_error(StatusCode::BAD_REQUEST, message),
    };
    let organization_id = match state.product.organization_for_network(&network_id).await {
        Ok(organization_id) => organization_id,
        Err(error) => return error.into_response(),
    };
    let credential = match product_credential(&headers) {
        Ok(credential) => credential,
        Err(error) => return error.into_response(),
    };
    match state
        .product
        .set_group_policy(
            &organization_id,
            &network_id,
            &name,
            req.messages_policy.as_deref().unwrap_or_default(),
            req.debug_policy.as_deref().unwrap_or_default(),
            credential,
        )
        .await
    {
        Ok(policy) => Json(policy).into_response(),
        Err(error) => error.into_response(),
    }
}

async fn node_list(
    State(state): State<AppState>,
    Query(query): Query<NodesListQuery>,
    headers: HeaderMap,
) -> Response {
    let network_id = match required_network_id(query.network_id.as_deref()) {
        Ok(network_id) => network_id,
        Err(message) => return plain_error(StatusCode::BAD_REQUEST, message),
    };
    let organization_id = match state.product.organization_for_network(&network_id).await {
        Ok(organization_id) => organization_id,
        Err(error) => return error.into_response(),
    };
    let credential = match product_credential(&headers) {
        Ok(credential) => credential,
        Err(error) => return error.into_response(),
    };
    match state
        .product
        .list_nodes(&organization_id, &network_id, credential)
        .await
    {
        Ok(nodes) => Json(node_responses(nodes)).into_response(),
        Err(error) => error.into_response(),
    }
}

async fn node_revoke(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Query(query): Query<NodesListQuery>,
    headers: HeaderMap,
) -> Response {
    let network_id = match required_network_id(query.network_id.as_deref()) {
        Ok(network_id) => network_id,
        Err(message) => return plain_error(StatusCode::BAD_REQUEST, message),
    };
    let organization_id = match state.product.organization_for_network(&network_id).await {
        Ok(organization_id) => organization_id,
        Err(error) => return error.into_response(),
    };
    let credential = match product_credential(&headers) {
        Ok(credential) => credential,
        Err(error) => return error.into_response(),
    };
    match state
        .product
        .revoke_node(&organization_id, &network_id, &name, credential)
        .await
    {
        Ok(()) => Json(NodeRevokeResponse {
            status: "revoked",
            node: &name,
        })
        .into_response(),
        Err(error) => error.into_response(),
    }
}

async fn invite_create(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    let req = match serde_json::from_slice::<InviteCreateRequest>(&body) {
        Ok(req) => req,
        Err(_) => return AppError::BadRequest("bad request".into()).into_response(),
    };
    let network_id = match required_network_id(req.network_id.as_deref()) {
        Ok(network_id) => network_id,
        Err(message) => return plain_error(StatusCode::BAD_REQUEST, message),
    };
    let ttl = match req.ttl.as_deref() {
        None | Some("") => Duration::hours(1),
        Some(raw) => match parse_go_duration(raw) {
            Some(ttl) => ttl,
            None => return AppError::BadRequest("invalid ttl".into()).into_response(),
        },
    };
    let organization_id = match state.product.organization_for_network(&network_id).await {
        Ok(organization_id) => organization_id,
        Err(error) => return error.into_response(),
    };
    let credential = match product_credential(&headers) {
        Ok(credential) => credential,
        Err(error) => return error.into_response(),
    };
    match state
        .product
        .create_invite(&organization_id, &network_id, credential, ttl)
        .await
    {
        Ok(created) => Json(InviteCreateResponse {
            invite: InviteResponse::from(created.invite),
            invite_code: created.invite_code,
        })
        .into_response(),
        Err(error) => error.into_response(),
    }
}

#[derive(Serialize)]
struct InviteResponse {
    id: String,
    org_id: String,
    network_id: String,
    created_by_user_id: String,
    expires_at: DateTime<Utc>,
    created_at: DateTime<Utc>,
}

impl From<crate::store::Invite> for InviteResponse {
    fn from(invite: crate::store::Invite) -> Self {
        Self {
            id: invite.id,
            org_id: invite.organization_id,
            network_id: invite.network_id,
            created_by_user_id: invite.created_by_user_id,
            expires_at: invite.expires_at,
            created_at: invite.created_at,
        }
    }
}

#[derive(Serialize)]
struct InviteCreateResponse {
    invite: InviteResponse,
    invite_code: String,
}

async fn invite_list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<NetworkIDQuery>,
) -> Response {
    let network_id = match required_network_id(query.network_id.as_deref()) {
        Ok(network_id) => network_id,
        Err(message) => return plain_error(StatusCode::BAD_REQUEST, message),
    };
    let organization_id = match state.product.organization_for_network(&network_id).await {
        Ok(organization_id) => organization_id,
        Err(error) => return error.into_response(),
    };
    let credential = match product_credential(&headers) {
        Ok(credential) => credential,
        Err(error) => return error.into_response(),
    };
    match state
        .product
        .list_invites(&organization_id, &network_id, credential)
        .await
    {
        Ok(invites) => Json(
            invites
                .into_iter()
                .map(InviteResponse::from)
                .collect::<Vec<_>>(),
        )
        .into_response(),
        Err(error) => error.into_response(),
    }
}

async fn invite_delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(invite_id): Path<String>,
    Query(query): Query<NetworkIDQuery>,
) -> Response {
    let network_id = match required_network_id(query.network_id.as_deref()) {
        Ok(network_id) => network_id,
        Err(message) => return plain_error(StatusCode::BAD_REQUEST, message),
    };
    let organization_id = match state.product.organization_for_network(&network_id).await {
        Ok(organization_id) => organization_id,
        Err(error) => return error.into_response(),
    };
    let credential = match product_credential(&headers) {
        Ok(credential) => credential,
        Err(error) => return error.into_response(),
    };
    match state
        .product
        .delete_invite(&organization_id, &network_id, &invite_id, credential)
        .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => error.into_response(),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkJoinRequest {
    invite_code: Option<String>,
}

#[derive(Serialize)]
struct NetworkJoinResponse {
    status: &'static str,
    network_id: String,
}

#[derive(Deserialize)]
struct JoinPageQuery {
    invite: Option<String>,
}

async fn network_join(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    let req = match serde_json::from_slice::<NetworkJoinRequest>(&body) {
        Ok(req) => req,
        Err(_) => return plain_error(StatusCode::BAD_REQUEST, "bad request"),
    };
    let credential = match product_credential(&headers) {
        Ok(credential) => credential,
        Err(error) => return error.into_response(),
    };
    match state
        .product
        .join_network(req.invite_code.as_deref().unwrap_or_default(), credential)
        .await
    {
        Ok(network) => Json(NetworkJoinResponse {
            status: "joined",
            network_id: network.id,
        })
        .into_response(),
        Err(error) => error.into_response(),
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
    use axum::http::{Request, StatusCode};
    use chrono::{Duration, Utc};
    use serde_json::json;
    use tower::ServiceExt;

    use super::*;
    use crate::AuthMode;
    use crate::store::{
        GROUP_DEBUG_NONE, GROUP_DEBUG_OBSERVE_ONLY, GROUP_MESSAGES_INTERNAL_ONLY,
        GROUP_MESSAGES_OPEN, NETWORK_ROLE_MEMBER, NETWORK_ROLE_OWNER, NetworkMember,
    };
    use crate::{Invite, MemoryStore, MeshStore};

    fn test_config(auth_mode: AuthMode) -> Config {
        Config {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            base_url: "https://mesh.codewire.sh".to_string(),
            auth_mode,
            auth_token: Some("relay-admin".to_string()),
            derp_url: None,
            oidc_issuer: None,
            oidc_client_id: None,
            oidc_client_secret: None,
            oidc_allowed_groups: Vec::new(),
            database_url: None,
            mesh_authorization: None,
            local_authorization: Some(crate::LocalMeshAuthorizationConfig {
                organization_id: "local-test-org".to_string(),
                api_key_hash: codewire_server_core::auth::hash_api_key("cw_local-test"),
                environment_id: "local-test-environment".to_string(),
                environment_token_hash: crate::mesh_authorization::hash_local_environment_token(
                    "local-test-environment-token",
                ),
            }),
        }
    }

    async fn seeded_github_store(token: &str, github_id: i64, username: &str) -> MemoryStore {
        let store = MemoryStore::new();
        store
            .upsert_github_session(token, github_id, username, Utc::now() + Duration::hours(1))
            .await;
        store
    }

    async fn seed_network(store: &MemoryStore, network_id: &str) {
        store
            .network_create_owned(network_id, "local-test-org")
            .await
            .unwrap();
    }

    async fn seeded_member_store(
        token: &str,
        github_id: i64,
        username: &str,
        network_id: &str,
        role: &str,
    ) -> MemoryStore {
        let store = seeded_github_store(token, github_id, username).await;
        seed_network(&store, network_id).await;
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

    async fn seed_node(
        store: &MemoryStore,
        network_id: &str,
        name: &str,
        peer_url: &str,
        last_seen_at: chrono::DateTime<Utc>,
    ) {
        seed_network(store, network_id).await;
        store
            .node_register(NodeRecord {
                network_id: network_id.to_string(),
                name: name.to_string(),
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

    async fn mock_oidc_token() -> Json<serde_json::Value> {
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
            .route("/token", post(mock_oidc_token))
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
    async fn networks_can_be_created_and_listed_for_owner() {
        let store = seeded_github_store("sess_member", 101, "member").await;
        let router = router_with_store(test_config(AuthMode::Token), std::sync::Arc::new(store));

        let create = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/networks")
                    .header(AUTHORIZATION, "Bearer cw_local-test")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"org_id":"local-test-org","network_id":"project-alpha"}"#,
                    ))
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
                    .uri("/api/v1/networks?org_id=local-test-org")
                    .header(AUTHORIZATION, "Bearer cw_local-test")
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
    async fn network_list_requires_explicit_authorized_organization() {
        let store = seeded_github_store("sess_member", 101, "member").await;
        seed_network(&store, "network-a").await;
        seed_network(&store, "network-b").await;

        let response = router_with_store(test_config(AuthMode::Token), std::sync::Arc::new(store))
            .oneshot(
                Request::builder()
                    .uri("/api/v1/networks?org_id=local-test-org")
                    .header(AUTHORIZATION, "Bearer cw_local-test")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let got: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(got.as_array().unwrap().len(), 2);
        assert_eq!(got[0]["id"], "network-a");
        assert_eq!(got[0]["org_id"], "local-test-org");

        let denied = router_with_store(
            test_config(AuthMode::Token),
            std::sync::Arc::new(MemoryStore::new()),
        )
        .oneshot(
            Request::builder()
                .uri("/api/v1/networks?org_id=other-org")
                .header(AUTHORIZATION, "Bearer cw_local-test")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn network_create_is_explicitly_owned_and_rejects_cross_organization() {
        let store = MemoryStore::new();
        let router = router_with_store(test_config(AuthMode::Token), std::sync::Arc::new(store));

        let owner = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/networks")
                    .header(AUTHORIZATION, "Bearer cw_local-test")
                    .body(Body::from(
                        r#"{"org_id":"local-test-org","network_id":"project-alpha"}"#,
                    ))
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
                    .header(AUTHORIZATION, "Bearer cw_local-test")
                    .body(Body::from(
                        r#"{"org_id":"other-org","network_id":"project-alpha"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(outsider.status(), StatusCode::FORBIDDEN);
        let body = to_bytes(outsider.into_body(), usize::MAX).await.unwrap();
        let error: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(error["detail"], "forbidden");
    }

    #[tokio::test]
    async fn network_management_rejects_the_local_environment_identity() {
        let router = router_with_store(
            test_config(AuthMode::Token),
            std::sync::Arc::new(MemoryStore::new()),
        );

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/api/v1/networks?org_id=local-test-org")
                    .header(AUTHORIZATION, "Bearer local-test-environment-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
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
                    .header(AUTHORIZATION, "Bearer cw_local-test")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"network_id":"project-alpha","ttl":"30m"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(create.status(), StatusCode::OK);
        let body = to_bytes(create.into_body(), usize::MAX).await.unwrap();
        let invite: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let invite_id = invite["invite"]["id"].as_str().unwrap().to_string();
        let invite_code = invite["invite_code"].as_str().unwrap().to_string();
        assert_eq!(invite["invite"]["org_id"], "local-test-org");
        assert_eq!(invite["invite"]["network_id"], "project-alpha");
        assert_eq!(
            invite["invite"]["created_by_user_id"],
            "local-machine:local-test-environment"
        );
        assert!(invite_code.starts_with("cw_inv_"));
        assert_eq!(invite_code.len(), "cw_inv_".len() + 64);
        assert!(invite["invite"].get("code_hash").is_none());
        assert!(invite["invite"].get("token").is_none());
        assert!(invite["invite"].get("uses_remaining").is_none());

        let list = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/invites?network_id=project-alpha")
                    .header(AUTHORIZATION, "Bearer cw_local-test")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(list.status(), StatusCode::OK);
        let body = to_bytes(list.into_body(), usize::MAX).await.unwrap();
        let got: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(got.as_array().unwrap().len(), 1);
        assert_eq!(got[0]["id"], invite_id);
        assert!(got[0].get("invite_code").is_none());
        assert!(got[0].get("code_hash").is_none());

        let delete = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!(
                        "/api/v1/invites/{invite_id}?network_id=project-alpha"
                    ))
                    .header(AUTHORIZATION, "Bearer cw_local-test")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(delete.status(), StatusCode::NO_CONTENT);

        assert!(
            store
                .invite_get_by_id("project-alpha", &invite_id)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn invite_create_rejects_legacy_uses_field() {
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
                    .header(AUTHORIZATION, "Bearer cw_local-test")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"network_id":"project-alpha","uses":"bad"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
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
                    .header(AUTHORIZATION, "Bearer local-test-environment-token")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"network_id":"project-alpha"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn invite_create_rejects_invalid_ttl() {
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
                    .header(AUTHORIZATION, "Bearer cw_local-test")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"network_id":"project-alpha","ttl":"soon"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let error: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(error["detail"], "invalid ttl");
    }

    #[tokio::test]
    async fn kv_routes_are_network_scoped_and_require_primary_product_auth() {
        let store = seeded_github_store("sess_member", 101, "member").await;
        seed_network(&store, "network-a").await;
        seed_network(&store, "network-b").await;
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
                        .header(AUTHORIZATION, "Bearer cw_local-test")
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
                    .header(AUTHORIZATION, "Bearer cw_local-test")
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
                    .header(AUTHORIZATION, "Bearer local-test-environment-token")
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
                    .header(AUTHORIZATION, "Bearer local-test-environment-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(wrong_network.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn kv_list_filters_prefix_and_base64_encodes_values() {
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
                        .header(AUTHORIZATION, "Bearer cw_local-test")
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
                    .header(AUTHORIZATION, "Bearer cw_local-test")
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
    async fn kv_ttl_expiry_and_invalid_ttl_are_enforced() {
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
                    .header(AUTHORIZATION, "Bearer cw_local-test")
                    .header("x-ttl", "1ms")
                    .body(Body::from("gone"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(expired_set.status(), StatusCode::NO_CONTENT);
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;

        let expired_get = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/kv/tasks/expired?network_id=project-alpha")
                    .header(AUTHORIZATION, "Bearer cw_local-test")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(expired_get.status(), StatusCode::NOT_FOUND);

        let invalid_ttl = router
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/v1/kv/tasks/bad?network_id=project-alpha")
                    .header(AUTHORIZATION, "Bearer cw_local-test")
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
    async fn kv_delete_requires_owner_and_removes_value() {
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
                    .header(AUTHORIZATION, "Bearer cw_local-test")
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
                    .header(AUTHORIZATION, "Bearer local-test-environment-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(member_delete.status(), StatusCode::FORBIDDEN);

        let owner_delete = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/api/v1/kv/tasks/build?network_id=project-alpha")
                    .header(AUTHORIZATION, "Bearer cw_local-test")
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
                    .header(AUTHORIZATION, "Bearer cw_local-test")
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
    async fn group_lifecycle_requires_primary_owner_and_persists_defaults() {
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
                    .header(AUTHORIZATION, "Bearer local-test-environment-token")
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
                    .header(AUTHORIZATION, "Bearer cw_local-test")
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
        assert_eq!(
            created["created_by"],
            "local-machine:local-test-environment"
        );
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
                    .header(AUTHORIZATION, "Bearer cw_local-test")
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
                    .header(AUTHORIZATION, "Bearer cw_local-test")
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
                    .header(AUTHORIZATION, "Bearer cw_local-test")
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
                    .header(AUTHORIZATION, "Bearer cw_local-test")
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
                    .header(AUTHORIZATION, "Bearer cw_local-test")
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
                    .header(AUTHORIZATION, "Bearer cw_local-test")
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
                    .header(AUTHORIZATION, "Bearer cw_local-test")
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
    async fn group_handlers_reject_invalid_policy_and_duplicate_create() {
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
                        .header(AUTHORIZATION, "Bearer cw_local-test")
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
                    .header(AUTHORIZATION, "Bearer cw_local-test")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"network_id":"project-alpha","messages_policy":"bad-value","debug_policy":"observe-only"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(invalid_policy.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn group_member_handlers_reject_node_bearer_and_accept_primary_owner() {
        let store = MemoryStore::new();
        seed_node(&store, "project-alpha", "node-a", "", Utc::now()).await;
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

        let legacy_node_bearer = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/groups/mesh/members")
                    .header(AUTHORIZATION, "Bearer node-token")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"network_id":"project-alpha","node_name":"node-a","session_name":"agent-1"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(legacy_node_bearer.status(), StatusCode::UNAUTHORIZED);

        let add = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/groups/mesh/members")
                    .header(AUTHORIZATION, "Bearer cw_local-test")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"network_id":"project-alpha","node_name":"node-a","session_name":"agent-1"}"#,
                    ))
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
                    .uri(
                        "/api/v1/groups/mesh/members?network_id=project-alpha&node_name=node-a&session_name=agent-1",
                    )
                    .header(AUTHORIZATION, "Bearer cw_local-test")
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

        let incomplete = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/groups/mesh/members")
                    .header(AUTHORIZATION, "Bearer cw_local-test")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"node_name":"node-b","session_name":"agent-1"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(incomplete.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn invite_list_requires_network_id() {
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

    async fn seed_invite(store: &MemoryStore, code: &str, network_id: &str, invite_id: &str) {
        let now = Utc::now();
        seed_network(store, network_id).await;
        store
            .invite_create(Invite {
                id: invite_id.to_owned(),
                network_id: network_id.to_string(),
                organization_id: "local-test-org".to_string(),
                created_by_user_id: "creator-primary-id".to_string(),
                code_hash: crate::product::hash_invite_code(code),
                expires_at: now + Duration::hours(1),
                created_at: now,
            })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn network_join_adds_authenticated_member() {
        let store = MemoryStore::new();
        seed_invite(&store, "cw_inv_test", "network-invite", "invite-test-id").await;
        let router = router_with_store(
            test_config(AuthMode::Token),
            std::sync::Arc::new(store.clone()),
        );

        let response = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/networks/join")
                    .header(AUTHORIZATION, "Bearer cw_local-test")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"invite_code":"cw_inv_test"}"#))
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
            .network_member_get("network-invite", "local-machine:local-test-environment")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(member.role, NETWORK_ROLE_MEMBER);
        assert_eq!(member.created_by, "invite:invite-test-id");
        assert!(
            store
                .invite_get_by_id("network-invite", "invite-test-id")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn network_join_rejects_blank_invite_code() {
        let store = MemoryStore::new();
        let response = router_with_store(test_config(AuthMode::Token), std::sync::Arc::new(store))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/networks/join")
                    .header(AUTHORIZATION, "Bearer cw_local-test")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"invite_code":"  "}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn network_join_rejects_legacy_invite_token_field() {
        let response = router_with_store(
            test_config(AuthMode::Token),
            std::sync::Arc::new(MemoryStore::new()),
        )
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/networks/join")
                .header(AUTHORIZATION, "Bearer cw_local-test")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"invite_token":"legacy-is-not-supported"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn network_join_rejects_invalid_invite_code() {
        let store = MemoryStore::new();
        let response = router_with_store(test_config(AuthMode::Token), std::sync::Arc::new(store))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/networks/join")
                    .header(AUTHORIZATION, "Bearer cw_local-test")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"invite_code":"cw_inv_missing"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn network_join_preserves_existing_owner_role() {
        let store = MemoryStore::new();
        seed_network(&store, "network-invite").await;
        store
            .network_member_upsert(NetworkMember {
                network_id: "network-invite".to_string(),
                subject: "local-machine:local-test-environment".to_string(),
                role: NETWORK_ROLE_OWNER.to_string(),
                created_at: Utc::now(),
                created_by: "local-machine:local-test-environment".to_string(),
            })
            .await
            .unwrap();
        seed_invite(&store, "cw_inv_owner", "network-invite", "invite-owner-id").await;

        let response = router_with_store(
            test_config(AuthMode::Token),
            std::sync::Arc::new(store.clone()),
        )
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/networks/join")
                .header(AUTHORIZATION, "Bearer cw_local-test")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"invite_code":"cw_inv_owner"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let member = store
            .network_member_get("network-invite", "local-machine:local-test-environment")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(member.role, NETWORK_ROLE_OWNER);
        assert_eq!(member.created_by, "local-machine:local-test-environment");
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
    async fn retired_coordinate_and_network_auth_routes_are_absent() {
        let router = router(test_config(AuthMode::Token));
        for (method, path) in [
            ("POST", "/api/v1/node-enrollments/redeem"),
            ("POST", "/api/v1/network-auth/runtime/node"),
            ("GET", "/api/v1/network-auth/bundle"),
            ("POST", "/api/v1/network-auth/delegation/node"),
            ("POST", "/api/v1/network-auth/runtime/client"),
            ("GET", "/api/v1/tailnet/coordinate"),
        ] {
            let response = router
                .clone()
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(path)
                        .header("content-type", "application/json")
                        .body(Body::from("{}"))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
        }
    }

    #[tokio::test]
    async fn node_enrollment_create_rejects_environment_credential() {
        let store = MemoryStore::new();
        seed_network(&store, "network-a").await;
        let response = router_with_store(test_config(AuthMode::Token), std::sync::Arc::new(store))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/node-enrollments")
                    .header(AUTHORIZATION, "Bearer local-test-environment-token")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"network_id":"network-a"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn node_enrollment_create_rejects_invalid_ttl() {
        let store = MemoryStore::new();
        seed_network(&store, "network-a").await;
        let response = router_with_store(test_config(AuthMode::Token), std::sync::Arc::new(store))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/node-enrollments")
                    .header(AUTHORIZATION, "Bearer cw_local-test")
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
    async fn nodes_list_requires_primary_auth_and_explicit_network_scope() {
        let store = MemoryStore::new();
        seed_network(&store, "network-a").await;
        seed_network(&store, "network-b").await;
        seed_node(
            &store,
            "network-a",
            "shared-node",
            "https://network-a.example/ws",
            Utc::now(),
        )
        .await;
        seed_node(
            &store,
            "network-b",
            "shared-node",
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
                    .header(AUTHORIZATION, "Bearer local-test-environment-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/nodes?network_id=network-a")
                    .header(AUTHORIZATION, "Bearer cw_local-test")
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
                    .header(AUTHORIZATION, "Bearer cw_local-test")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn nodes_list_rejects_legacy_node_bearer() {
        let store = MemoryStore::new();
        seed_network(&store, "network-a").await;
        seed_network(&store, "network-b").await;
        seed_node(
            &store,
            "network-a",
            "builder",
            "https://builder.example/ws",
            Utc::now(),
        )
        .await;
        seed_node(
            &store,
            "network-b",
            "other",
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

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn node_revoke_requires_primary_owner_and_deletes_node() {
        let store = MemoryStore::new();
        seed_network(&store, "network-a").await;
        seed_node(
            &store,
            "network-a",
            "builder",
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
                    .header(AUTHORIZATION, "Bearer local-test-environment-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/api/v1/nodes/missing?network_id=network-a")
                    .header(AUTHORIZATION, "Bearer cw_local-test")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let response = router
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/api/v1/nodes/builder?network_id=network-a")
                    .header(AUTHORIZATION, "Bearer cw_local-test")
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
}
