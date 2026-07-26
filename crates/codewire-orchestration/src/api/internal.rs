//! Internal sidecar endpoints (#140).
//!
//! These are the endpoints the in-pod gateway sidecar (and warm pods)
//! call to fetch their binding + credentials. They are authenticated by
//! the environment's `auth_token` (a Bearer token), NOT a user session
//! cookie — except `gateway/binding`, which is keyed by the requesting
//! pod's `(pod, ns)` and issues a coordinate-scoped sidecar token.
//!
//! Routes (mirroring the Go registration):
//! - `GET /api/v1/internal/gateway/binding`      — `gatewayBindingHandler`
//! - `GET /api/v1/internal/credentials/github`   — `handleInternalGitHubCredentials`
//! - `GET /api/v1/internal/credentials/git`      — `handleInternalGitCredentials`
//!
//! Wire-parity notes:
//! - The binding handler is a RAW chi handler in Go: 400/500 are
//!   `http.Error` text/plain bodies; 404 is a bare `WriteHeader(404)`
//!   (no body); the 200 is `json.NewEncoder` JSON with a trailing `\n`.
//! - The credentials handlers route every response through `respondJSON`
//!   (`Content-Type: application/json`, trailing `\n`); errors are
//!   `{"error": msg}`.

use axum::body::Body;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::Response;
use codewire_server_core::{AppError, AppResult};
use k8s_openapi::api::core::v1::{Node, Pod};
use kube::Api;
use serde::Deserialize;
use serde_json::{Map, Value, json};

use crate::runtime_transport::{
    RUNTIME_REGION_LABEL, RuntimeTransportBinding, TRANSPORT_ZONE_LABEL, load_enabled_zone,
};
use crate::worker::gatewayauth::{SCOPE_COORDINATE, issue_token};
use crate::worker::github::{get_github_token_for_user, get_github_username_for_user};

use super::ApiState;
use super::detect::{resolve_forge_token, user_secret_path};
use super::prepare::{json_response, read_bearer};

/// `http.Error` parity: text/plain with a trailing newline and the
/// nosniff header chi's `http.Error` sets.
fn text_error(status: StatusCode, body: &str) -> Response {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header("X-Content-Type-Options", "nosniff")
        .body(Body::from(format!("{body}\n")))
        .expect("static response")
}

/// `respondJSONError` parity: `{"error": msg}` JSON via `respondJSON`.
fn json_error(status: StatusCode, msg: &str) -> Response {
    json_response(status, &serde_json::json!({ "error": msg }))
}

// ── GET /api/v1/internal/gateway/binding ───────────────────────────────

#[derive(Debug, Deserialize)]
pub struct BindingQuery {
    #[serde(default)]
    pod: String,
    #[serde(default)]
    ns: String,
}

#[derive(Debug)]
struct BindingTarget {
    env_id: String,
    node_name: Option<String>,
    workspace_pod_ip: Option<String>,
}

/// Shared service-layer result for the raw REST handler and
/// `GatewayBindingService`. Keep this independent of either wire shape so the
/// temporary dual serve cannot diverge.
#[derive(Debug, Clone)]
pub struct GatewayBinding {
    pub environment_id: String,
    pub sidecar_token: String,
    pub workspace_pod_ip: Option<String>,
    pub app_ports: Vec<i32>,
    pub runtime_transport: Option<RuntimeTransportBinding>,
}

/// Shared service-layer result for the raw credential handlers and
/// `EnvironmentCredentialService`.
#[derive(Debug, Clone)]
pub struct IssuedCredentials {
    pub token: String,
    pub username: String,
    pub host: String,
}

/// Mirrors `gatewayBindingHandler`. Keyed by the requesting pod's
/// `(pod, ns)` — looks up the bound environment and issues a
/// coordinate-scoped sidecar token for it.
pub async fn gateway_binding(
    State(state): State<ApiState>,
    Query(q): Query<BindingQuery>,
) -> Response {
    match issue_gateway_binding_core(&state, &q.pod, &q.ns).await {
        Ok(binding) => json_response(StatusCode::OK, &gateway_binding_json(binding)),
        Err(AppError::BadRequest(detail)) => text_error(StatusCode::BAD_REQUEST, &detail),
        Err(AppError::NotFound(_)) => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::empty())
            .expect("static response"),
        Err(error) => {
            tracing::error!(pod = %q.pod, namespace = %q.ns, error = %error, "gateway binding failed");
            text_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
        }
    }
}

/// Resolves a gateway pod binding and issues its coordinate-scoped token.
/// Both the raw REST endpoint and the internal Connect command delegate here.
pub async fn issue_gateway_binding_core(
    state: &ApiState,
    pod: &str,
    namespace: &str,
) -> AppResult<GatewayBinding> {
    if pod.is_empty() || namespace.is_empty() {
        return Err(AppError::BadRequest(
            "pod and ns query params required".into(),
        ));
    }

    let target = resolve_binding_target(state, pod, namespace)
        .await
        .map_err(|error| {
            tracing::error!(pod, namespace, error = %error, "gateway binding lookup failed");
            AppError::from(error)
        })?
        .ok_or_else(|| AppError::NotFound("gateway binding not ready".into()))?;

    let env_id = target.env_id;
    let workspace_pod_ip = target.workspace_pod_ip;
    let app_ports = match binding_app_ports(state, &env_id).await {
        Ok(ports) => ports,
        Err(e) => {
            tracing::warn!(env = %env_id, error = %e, "gateway binding app-port lookup failed");
            Vec::new()
        }
    };

    let runtime_transport = match target.node_name.as_deref() {
        Some(node_name) => match runtime_transport_for_node(state, node_name).await {
            Ok(transport) => transport,
            Err(e) => {
                tracing::warn!(
                    env = %env_id,
                    node = %node_name,
                    error = %e,
                    "gateway binding runtime transport selection failed"
                );
                None
            }
        },
        None => None,
    };

    if let Some(transport) = runtime_transport.as_ref() {
        tracing::info!(
            env = %env_id,
            runtime_region = %transport.runtime_region,
            transport_zone = %transport.transport_zone,
            peer_relay_endpoints = ?transport.peer_relay.as_ref().map(|relay| &relay.public_endpoints),
            "gateway binding selected runtime transport zone"
        );
    }

    let sidecar_token =
        issue_token(&state.session_secret, &env_id, SCOPE_COORDINATE).map_err(|error| {
            tracing::error!(env = %env_id, error = %error, "sidecar binding: issue token");
            AppError::from(error)
        })?;

    Ok(GatewayBinding {
        environment_id: env_id,
        sidecar_token,
        workspace_pod_ip,
        app_ports,
        runtime_transport,
    })
}

fn gateway_binding_json(binding: GatewayBinding) -> Value {
    let mut body = Map::new();
    body.insert("environment_id".to_string(), json!(binding.environment_id));
    body.insert("sidecar_token".to_string(), json!(binding.sidecar_token));
    if let Some(pod_ip) = binding.workspace_pod_ip {
        body.insert("workspace_pod_ip".to_string(), json!(pod_ip));
    }
    if !binding.app_ports.is_empty() {
        body.insert("app_ports".to_string(), json!(binding.app_ports));
    }
    if let Some(runtime_transport) = binding.runtime_transport {
        body.insert(
            "runtime_transport".to_string(),
            serde_json::to_value(runtime_transport)
                .expect("runtime transport binding serializes to JSON"),
        );
    }

    Value::Object(body)
}

async fn resolve_binding_target(
    state: &ApiState,
    pod: &str,
    namespace: &str,
) -> anyhow::Result<Option<BindingTarget>> {
    let mut pod_node_name = None;
    if let Some(client) = state.kube.as_ref() {
        let pods: Api<Pod> = Api::namespaced(client.clone(), namespace);
        match pods.get(pod).await {
            Ok(pod_obj) => {
                pod_node_name = pod_obj
                    .spec
                    .as_ref()
                    .and_then(|spec| spec.node_name.clone());
                let env_id = pod_obj
                    .metadata
                    .labels
                    .as_ref()
                    .and_then(|labels| labels.get("codewire.sh/environment-id"))
                    .filter(|env_id| !env_id.trim().is_empty())
                    .cloned();
                match env_id {
                    Some(env_id) if environment_is_active(state, &env_id).await? => {
                        let workspace_pod_ip = binding_workspace_pod_ip(state, &env_id).await?;
                        return Ok(Some(BindingTarget {
                            env_id,
                            node_name: pod_node_name,
                            workspace_pod_ip,
                        }));
                    }
                    _ => {}
                }
            }
            Err(kube::Error::Api(e)) if e.code == 404 => {}
            Err(e) => {
                tracing::warn!(
                    pod,
                    namespace,
                    error = %e,
                    "gateway binding could not read requesting pod; falling back to backend lookup"
                );
            }
        }
    }

    let backend: Option<(String, Option<String>)> = sqlx::query_as(
        r#"SELECT b.environment_id, b.pod_ip
           FROM sandbox_environment_backend b
           JOIN environments e ON e.id = b.environment_id
           WHERE b.pod_name = $1 AND b.namespace = $2
             AND e.state NOT IN ('destroyed', 'destroying')"#,
    )
    .bind(pod)
    .bind(namespace)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| anyhow::anyhow!("query backend binding: {e}"))?;

    Ok(backend.map(|(env_id, workspace_pod_ip)| BindingTarget {
        env_id,
        node_name: pod_node_name,
        workspace_pod_ip: workspace_pod_ip
            .map(|pod_ip| pod_ip.trim().to_string())
            .filter(|pod_ip| !pod_ip.is_empty()),
    }))
}

async fn binding_workspace_pod_ip(
    state: &ApiState,
    env_id: &str,
) -> anyhow::Result<Option<String>> {
    let pod_ip: Option<Option<String>> = sqlx::query_scalar(
        r#"SELECT pod_ip
           FROM sandbox_environment_backend
           WHERE environment_id = $1"#,
    )
    .bind(env_id)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| anyhow::anyhow!("query binding workspace pod IP: {e}"))?;

    Ok(pod_ip
        .flatten()
        .map(|pod_ip| pod_ip.trim().to_string())
        .filter(|pod_ip| !pod_ip.is_empty()))
}

async fn binding_app_ports(state: &ApiState, env_id: &str) -> anyhow::Result<Vec<i32>> {
    let rows: Vec<(i32,)> = sqlx::query_as(
        r#"SELECT DISTINCT port
           FROM environment_ports
           WHERE environment_id = $1
             AND port BETWEEN 1 AND 65535
           ORDER BY port"#,
    )
    .bind(env_id)
    .fetch_all(&state.pool)
    .await
    .map_err(|e| anyhow::anyhow!("query binding app ports: {e}"))?;

    Ok(rows.into_iter().map(|(port,)| port).collect())
}

async fn environment_is_active(state: &ApiState, env_id: &str) -> anyhow::Result<bool> {
    sqlx::query_scalar(
        r#"SELECT EXISTS(
             SELECT 1
             FROM environments
             WHERE id = $1 AND state NOT IN ('destroyed', 'destroying')
           )"#,
    )
    .bind(env_id)
    .fetch_one(&state.pool)
    .await
    .map_err(|e| anyhow::anyhow!("query environment binding state: {e}"))
}

async fn runtime_transport_for_node(
    state: &ApiState,
    node_name: &str,
) -> anyhow::Result<Option<RuntimeTransportBinding>> {
    let Some(client) = state.kube.as_ref() else {
        return Ok(None);
    };
    let nodes: Api<Node> = Api::all(client.clone());
    let node = nodes
        .get(node_name)
        .await
        .map_err(|e| anyhow::anyhow!("get node {node_name}: {e}"))?;
    let labels = node.metadata.labels.unwrap_or_default();
    let Some(zone_name) = labels
        .get(TRANSPORT_ZONE_LABEL)
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
    else {
        tracing::warn!(
            node = node_name,
            label = TRANSPORT_ZONE_LABEL,
            "runtime node has no transport-zone label"
        );
        return Ok(None);
    };
    let zone = match load_enabled_zone(&state.pool, zone_name).await? {
        Some(zone) => zone,
        None => {
            tracing::warn!(
                node = node_name,
                transport_zone = zone_name,
                "runtime node references unknown or disabled transport zone"
            );
            return Ok(None);
        }
    };
    let mismatched_node_region = labels
        .get(RUNTIME_REGION_LABEL)
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .filter(|node_region| *node_region != zone.runtime_region.as_str());
    if let Some(node_region) = mismatched_node_region {
        tracing::warn!(
            node = node_name,
            node_runtime_region = node_region,
            zone_runtime_region = %zone.runtime_region,
            transport_zone = %zone.name,
            "runtime node region label differs from transport-zone registry"
        );
    }
    Ok(Some(zone.binding()))
}

// ── GET /api/v1/internal/credentials/github ────────────────────────────

/// Mirrors `handleInternalGitHubCredentials`. Returns the GitHub token
/// for the user who owns the environment identified by the Bearer
/// `auth_token`.
pub async fn internal_github_credentials(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> Response {
    let auth_token = match read_bearer(&headers) {
        Some(t) => t,
        None => return json_error(StatusCode::UNAUTHORIZED, "missing bearer token"),
    };

    let user_id = match environment_owner(&state, &auth_token).await {
        Some(id) => id,
        None => {
            return json_error(StatusCode::UNAUTHORIZED, "invalid or expired auth token");
        }
    };

    credentials_response(issue_github_credentials_core(&state, &user_id).await)
}

// ── GET /api/v1/internal/credentials/git ───────────────────────────────

#[derive(Debug, Deserialize)]
pub struct GitCredentialsQuery {
    #[serde(default)]
    host: String,
}

/// Mirrors `handleInternalGitCredentials`. Returns a forge token for the
/// user who owns the environment identified by the Bearer `auth_token`;
/// the target forge host comes from the `host` query param (default
/// `github.com`).
pub async fn internal_git_credentials(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Query(q): Query<GitCredentialsQuery>,
) -> Response {
    let auth_token = match read_bearer(&headers) {
        Some(t) => t,
        None => return json_error(StatusCode::UNAUTHORIZED, "missing bearer token"),
    };

    let user_id = match environment_owner(&state, &auth_token).await {
        Some(id) => id,
        None => {
            return json_error(StatusCode::UNAUTHORIZED, "invalid or expired auth token");
        }
    };

    credentials_response(issue_git_credentials_core(&state, &user_id, &q.host).await)
}

/// Issues the caller's GitHub credential through the service layer shared by
/// REST and Connect. The underlying GitHub lookup may refresh stored tokens.
pub async fn issue_github_credentials_core(
    state: &ApiState,
    user_id: &str,
) -> AppResult<IssuedCredentials> {
    let token = get_github_token_for_user(&state.pool, &state.github_cfg, user_id).await;
    if token.is_empty() {
        return Err(AppError::NotFound("no GitHub token linked".into()));
    }
    Ok(IssuedCredentials {
        token,
        username: get_github_username_for_user(&state.pool, user_id).await,
        host: "github.com".to_string(),
    })
}

/// Issues a credential for one forge host through the service layer shared by
/// REST and Connect. An empty host keeps the raw endpoint's github.com default.
pub async fn issue_git_credentials_core(
    state: &ApiState,
    user_id: &str,
    host: &str,
) -> AppResult<IssuedCredentials> {
    let host = if host.is_empty() {
        "github.com".to_string()
    } else {
        host.to_string()
    };
    let token = resolve_forge_token(
        &state.pool,
        &state.github_cfg,
        state.secrets.as_ref(),
        user_id,
        &host,
    )
    .await;
    if token.is_empty() {
        return Err(AppError::NotFound("no token for host".into()));
    }

    // Resolve username for the host.
    let username = if host == "github.com" {
        get_github_username_for_user(&state.pool, user_id).await
    } else {
        let mut username = resolve_git_credential_username(&state.pool, user_id, &host).await;
        // Fall back to legacy Infisical GITEA_USERNAME.
        if username.is_empty()
            && let Ok(secrets) = state
                .secrets
                .get_all_secrets_at_path(&user_secret_path(user_id))
                .await
        {
            username = secrets.get("GITEA_USERNAME").cloned().unwrap_or_default();
        }
        username
    };

    Ok(IssuedCredentials {
        token,
        username,
        host,
    })
}

fn credentials_response(result: AppResult<IssuedCredentials>) -> Response {
    match result {
        Ok(credentials) => json_response(
            StatusCode::OK,
            &serde_json::json!({
                "token": credentials.token,
                "username": credentials.username,
                "host": credentials.host,
            }),
        ),
        Err(AppError::NotFound(detail)) => json_error(StatusCode::NOT_FOUND, &detail),
        Err(error) => {
            tracing::error!(error = %error, "internal credential issue failed");
            json_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
        }
    }
}

// ── helpers ────────────────────────────────────────────────────────────

/// Look up the `created_by` of the active environment owning `auth_token`.
/// Mirrors the shared lookup in both credentials handlers.
async fn environment_owner(state: &ApiState, auth_token: &str) -> Option<String> {
    let row: Option<(String,)> = sqlx::query_as(
        r#"SELECT created_by FROM environments
           WHERE auth_token = $1 AND state NOT IN ('destroyed', 'destroying')"#,
    )
    .bind(auth_token)
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten();
    row.map(|(id,)| id)
}

/// Mirrors `resolveGitCredentialUsername`: stored username for a host
/// from `user_git_credentials`.
async fn resolve_git_credential_username(pool: &sqlx::PgPool, user_id: &str, host: &str) -> String {
    let row: Option<(Option<String>,)> = sqlx::query_as(
        "SELECT username FROM user_git_credentials WHERE user_id = $1 AND host = $2",
    )
    .bind(user_id)
    .bind(host)
    .fetch_optional(pool)
    .await
    .unwrap_or(None);
    row.and_then(|(u,)| u).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use axum::http::header::CONTENT_TYPE;

    async fn body_string(resp: Response) -> String {
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn text_error_mirrors_http_error_wire() {
        // chi's http.Error: text/plain + nosniff + trailing newline.
        let resp = text_error(StatusCode::BAD_REQUEST, "pod and ns query params required");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            resp.headers().get(CONTENT_TYPE).unwrap(),
            "text/plain; charset=utf-8"
        );
        assert_eq!(
            resp.headers().get("X-Content-Type-Options").unwrap(),
            "nosniff"
        );
        assert_eq!(
            body_string(resp).await,
            "pod and ns query params required\n"
        );
    }

    #[tokio::test]
    async fn json_error_mirrors_respond_json_error() {
        // respondJSONError: application/json {"error":…} + trailing \n.
        let resp = json_error(StatusCode::UNAUTHORIZED, "missing bearer token");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            resp.headers().get(CONTENT_TYPE).unwrap(),
            "application/json"
        );
        assert_eq!(
            body_string(resp).await,
            "{\"error\":\"missing bearer token\"}\n"
        );
    }

    #[tokio::test]
    async fn binding_success_body_matches_go() {
        // The 200 path: json.NewEncoder of {environment_id, sidecar_token}.
        let token = issue_token("parity-secret", "env-parity-1", SCOPE_COORDINATE).unwrap();
        let resp = json_response(
            StatusCode::OK,
            &serde_json::json!({
                "environment_id": "env-parity-1",
                "sidecar_token": token,
            }),
        );
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get(CONTENT_TYPE).unwrap(),
            "application/json"
        );
        let v: serde_json::Value =
            serde_json::from_str(body_string(resp).await.trim_end()).unwrap();
        assert_eq!(v["environment_id"], "env-parity-1");
        assert_eq!(v["sidecar_token"].as_str().unwrap(), token);
    }

    #[tokio::test]
    async fn credentials_success_shape_matches_go() {
        // handleInternal*Credentials 200 shape: {token, username, host}.
        let resp = json_response(
            StatusCode::OK,
            &serde_json::json!({
                "token": "gho_abc",
                "username": "octocat",
                "host": "github.com",
            }),
        );
        let v: serde_json::Value =
            serde_json::from_str(body_string(resp).await.trim_end()).unwrap();
        assert_eq!(v["token"], "gho_abc");
        assert_eq!(v["username"], "octocat");
        assert_eq!(v["host"], "github.com");
    }

    #[test]
    fn read_bearer_extracts_and_rejects() {
        use axum::http::HeaderValue;
        // Accept: strips the "Bearer " prefix.
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer tok-123"),
        );
        assert_eq!(read_bearer(&headers).as_deref(), Some("tok-123"));

        // Reject: non-bearer scheme.
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, HeaderValue::from_static("Basic xyz"));
        assert_eq!(read_bearer(&headers), None);

        // Reject: absent header.
        assert_eq!(read_bearer(&HeaderMap::new()), None);
    }
}
