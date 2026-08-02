//! Internal sidecar service logic (#140).
//!
//! These are the endpoints the in-pod gateway sidecar (and warm pods)
//! call to fetch their binding + credentials. They are authenticated by
//! the environment's `auth_token` (a Bearer token), NOT a user session
//! cookie — except `gateway/binding`, which is keyed by the requesting
//! pod's `(pod, ns)` and issues a coordinate-scoped sidecar token.
//!
//! Connect-RPC owns the binding and credential wire contracts. The shared
//! functions below stay transport-neutral so that policy, persistence, and
//! token issuance remain in one service layer.

use codewire_server_core::{AppError, AppResult};
use k8s_openapi::api::core::v1::{Node, Pod};
use kube::Api;

use crate::runtime_transport::{
    RUNTIME_REGION_LABEL, RuntimeTransportBinding, TRANSPORT_ZONE_LABEL, load_enabled_zone,
};
use crate::worker::gatewayauth::{SCOPE_COORDINATE, issue_token};
use crate::worker::github::{get_github_token_for_user, get_github_username_for_user};

use super::ApiState;
use super::detect::{resolve_forge_token, user_secret_path};

#[derive(Debug)]
struct BindingTarget {
    env_id: String,
    node_name: Option<String>,
    workspace_pod_ip: Option<String>,
}

/// Shared service-layer result for `GatewayBindingService`.
#[derive(Debug, Clone)]
pub struct GatewayBinding {
    pub environment_id: String,
    pub sidecar_token: String,
    pub workspace_pod_ip: Option<String>,
    pub app_ports: Vec<i32>,
    pub runtime_transport: Option<RuntimeTransportBinding>,
}

/// Shared service-layer result for `EnvironmentCredentialService`.
#[derive(Debug, Clone)]
pub struct IssuedCredentials {
    pub token: String,
    pub username: String,
    pub host: String,
}

/// Resolves a gateway pod binding and issues its coordinate-scoped token.
/// The internal Connect command delegates here.
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

/// Issues the caller's GitHub credential through the Connect service layer.
/// The underlying GitHub lookup may refresh stored tokens.
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

/// Issues a credential for one forge host through the Connect service layer.
/// An empty host defaults to github.com.
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
