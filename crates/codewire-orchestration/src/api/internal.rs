//! Internal sidecar service logic (#140).
//!
//! The in-pod gateway calls this service to fetch its binding. The gateway
//! binding is keyed by the Pod identity derived from an exact-audience
//! Kubernetes TokenReview and issues a coordinate-scoped sidecar token.
//!
//! Connect-RPC owns the binding wire contract. The shared functions below stay
//! transport-neutral so that policy and token issuance remain in one service
//! layer.

use codewire_gateway_proto::GATEWAY_BINDING_SERVICE_ACCOUNT;
use codewire_server_core::{AppError, AppResult};
use k8s_openapi::api::core::v1::{Node, Pod};
use kube::Api;
use uuid::Uuid;

use crate::gateway_binding_identity::GatewayPodIdentity;
use crate::runtime_transport::{
    RUNTIME_REGION_LABEL, RuntimeTransportBinding, TRANSPORT_ZONE_LABEL, load_enabled_zone,
};
use crate::sandbox::client::{ProbeResult, SandboxClient};
use crate::sandbox::{LABEL_ENV_ID, LABEL_TYPE};
use crate::worker::gatewayauth::{SCOPE_COORDINATE, issue_token};

use super::ApiState;

#[derive(Debug)]
struct BindingTarget {
    env_id: String,
    node_name: Option<String>,
    workspace_pod_ip: Option<String>,
}

#[derive(Debug)]
struct BindingRuntime {
    env_id: String,
    namespace: String,
    pod_name: String,
    pod_ip: String,
}

type BindingRuntimeRow = (String, String, String, String, String, String);

/// Shared service-layer result for `GatewayBindingService`.
#[derive(Clone)]
pub struct GatewayBinding {
    pub environment_id: String,
    pub sidecar_token: String,
    pub workspace_pod_ip: Option<String>,
    pub app_ports: Vec<i32>,
    pub runtime_transport: Option<RuntimeTransportBinding>,
}

impl std::fmt::Debug for GatewayBinding {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GatewayBinding")
            .field("environment_id", &self.environment_id)
            .field("sidecar_token", &"[REDACTED]")
            .field("workspace_pod_ip", &self.workspace_pod_ip)
            .field("app_ports", &self.app_ports)
            .field("runtime_transport", &self.runtime_transport)
            .finish()
    }
}

/// Resolves a gateway pod binding and issues its coordinate-scoped token.
/// The internal Connect command delegates here.
pub(crate) async fn issue_gateway_binding_core(
    state: &ApiState,
    identity: &GatewayPodIdentity,
) -> AppResult<GatewayBinding> {
    let target = resolve_binding_target(state, identity)
        .await
        .map_err(|error| {
            tracing::error!(
                pod = %identity.pod_name(),
                namespace = %identity.namespace(),
                error = %error,
                "gateway binding lookup failed"
            );
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
    identity: &GatewayPodIdentity,
) -> anyhow::Result<Option<BindingTarget>> {
    let Some(client) = state.kube.as_ref() else {
        return Ok(None);
    };
    let pods: Api<Pod> = Api::namespaced(client.clone(), identity.namespace());
    let pod_obj = match pods.get(identity.pod_name()).await {
        Ok(pod_obj) => pod_obj,
        Err(kube::Error::Api(error)) if error.code == 404 => return Ok(None),
        Err(error) => {
            return Err(anyhow::anyhow!(
                "get authenticated gateway Pod {}/{}: {error}",
                identity.namespace(),
                identity.pod_name(),
            ));
        }
    };
    let Some(env_id) = authenticated_gateway_environment(&pod_obj, identity) else {
        return Ok(None);
    };
    let pod_node_name = pod_obj
        .spec
        .as_ref()
        .and_then(|spec| spec.node_name.clone());
    let runtime = binding_runtime_for_environment(state, &env_id).await?;
    let Some(runtime) = runtime else {
        return Ok(None);
    };
    if runtime.namespace != identity.namespace() {
        return Ok(None);
    }

    let probe = SandboxClient::new(client.clone(), &runtime.namespace)
        .probe_environment(&runtime.env_id)
        .await
        .map_err(|error| {
            anyhow::anyhow!(
                "probe workspace Pod for gateway binding {}: {error}",
                runtime.env_id
            )
        })?;
    if !binding_runtime_is_current(&runtime, &probe) {
        return Ok(None);
    }

    Ok(Some(BindingTarget {
        env_id: runtime.env_id,
        node_name: pod_node_name,
        workspace_pod_ip: Some(probe.pod_ip),
    }))
}

fn authenticated_gateway_environment(pod: &Pod, identity: &GatewayPodIdentity) -> Option<String> {
    if pod.metadata.name.as_deref() != Some(identity.pod_name())
        || pod.metadata.namespace.as_deref() != Some(identity.namespace())
        || pod.metadata.uid.as_deref() != Some(identity.pod_uid())
        || pod.metadata.deletion_timestamp.is_some()
        || pod
            .spec
            .as_ref()
            .and_then(|spec| spec.service_account_name.as_deref())
            != Some(GATEWAY_BINDING_SERVICE_ACCOUNT)
    {
        return None;
    }
    let labels = pod.metadata.labels.as_ref()?;
    if labels.get(LABEL_TYPE).map(String::as_str) != Some("gateway") {
        return None;
    }
    let environment_id = labels.get(LABEL_ENV_ID)?;
    let parsed = Uuid::parse_str(environment_id).ok()?;
    (parsed.to_string() == *environment_id).then(|| environment_id.clone())
}

async fn binding_runtime_for_environment(
    state: &ApiState,
    env_id: &str,
) -> anyhow::Result<Option<BindingRuntime>> {
    let row: Option<BindingRuntimeRow> = sqlx::query_as(
        r#"SELECT b.environment_id,
                  b.namespace,
                  COALESCE(b.pod_name, ''),
                  COALESCE(b.pod_ip, ''),
                  e.state,
                  e.desired_state
             FROM sandbox_environment_backend b
             JOIN environments e ON e.id = b.environment_id
            WHERE b.environment_id = $1"#,
    )
    .bind(env_id)
    .fetch_optional(&state.pool)
    .await
    .map_err(|error| anyhow::anyhow!("query environment gateway binding: {error}"))?;

    Ok(row.and_then(binding_runtime_from_row))
}

fn binding_runtime_from_row(
    (env_id, namespace, pod_name, pod_ip, state, desired_state): BindingRuntimeRow,
) -> Option<BindingRuntime> {
    if state != "running" || desired_state != "started" {
        return None;
    }
    Some(BindingRuntime {
        env_id,
        namespace,
        pod_name,
        pod_ip,
    })
}

fn binding_runtime_is_current(runtime: &BindingRuntime, probe: &ProbeResult) -> bool {
    probe.claim_exists
        && probe.claim_ready
        && probe.pod_exists
        && probe.pod_phase == "Running"
        && !probe.pod_name.is_empty()
        && !probe.pod_uid.is_empty()
        && !probe.pod_ip.is_empty()
        && runtime.pod_name == probe.pod_name
        && runtime.pod_ip == probe.pod_ip
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

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::api::core::v1::PodSpec;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::{ObjectMeta, Time};

    const ENVIRONMENT_ID: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn gateway_identity() -> GatewayPodIdentity {
        GatewayPodIdentity::for_test(
            "runtime",
            "cw-gateway-current",
            "7e7b20f6-0bd2-4f11-8b16-9c239851eb52",
        )
    }

    fn gateway_pod() -> Pod {
        let identity = gateway_identity();
        Pod {
            metadata: ObjectMeta {
                name: Some(identity.pod_name().to_owned()),
                namespace: Some(identity.namespace().to_owned()),
                uid: Some(identity.pod_uid().to_owned()),
                labels: Some(std::collections::BTreeMap::from([
                    (LABEL_TYPE.into(), "gateway".into()),
                    (LABEL_ENV_ID.into(), ENVIRONMENT_ID.into()),
                ])),
                ..Default::default()
            },
            spec: Some(PodSpec {
                service_account_name: Some(GATEWAY_BINDING_SERVICE_ACCOUNT.into()),
                containers: Vec::new(),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn current_runtime() -> BindingRuntime {
        BindingRuntime {
            env_id: "env-current".into(),
            namespace: "runtime".into(),
            pod_name: "workspace-current".into(),
            pod_ip: "10.0.0.9".into(),
        }
    }

    fn current_probe() -> ProbeResult {
        ProbeResult {
            claim_exists: true,
            claim_ready: true,
            pod_exists: true,
            pod_phase: "Running".into(),
            pod_name: "workspace-current".into(),
            pod_uid: "workspace-uid-current".into(),
            pod_ip: "10.0.0.9".into(),
            ..Default::default()
        }
    }

    fn runtime_row(state: &str, desired_state: &str) -> BindingRuntimeRow {
        (
            "env-current".into(),
            "runtime".into(),
            "workspace-current".into(),
            "10.0.0.9".into(),
            state.into(),
            desired_state.into(),
        )
    }

    #[test]
    fn gateway_binding_requires_running_started_environment() {
        assert!(binding_runtime_from_row(runtime_row("running", "started")).is_some());
        assert!(binding_runtime_from_row(runtime_row("starting", "started")).is_none());
        assert!(binding_runtime_from_row(runtime_row("running", "stopped")).is_none());
    }

    #[test]
    fn gateway_binding_requires_current_ready_workspace_runtime() {
        let runtime = current_runtime();
        let current = current_probe();
        assert!(binding_runtime_is_current(&runtime, &current));

        let mut replacement = current.clone();
        replacement.pod_uid.clear();
        assert!(!binding_runtime_is_current(&runtime, &replacement));

        let mut wrong_name = current.clone();
        wrong_name.pod_name = "workspace-replacement".into();
        assert!(!binding_runtime_is_current(&runtime, &wrong_name));

        let mut wrong_ip = current.clone();
        wrong_ip.pod_ip = "10.0.0.10".into();
        assert!(!binding_runtime_is_current(&runtime, &wrong_ip));

        let mut not_ready = current;
        not_ready.claim_ready = false;
        assert!(!binding_runtime_is_current(&runtime, &not_ready));
    }

    #[test]
    fn gateway_environment_requires_exact_reviewed_uid_service_account_and_labels() {
        let identity = gateway_identity();
        assert_eq!(
            authenticated_gateway_environment(&gateway_pod(), &identity).as_deref(),
            Some(ENVIRONMENT_ID)
        );

        let replacement = GatewayPodIdentity::for_test(
            identity.namespace(),
            identity.pod_name(),
            "a1560db3-8899-40c9-b521-500f223b04fb",
        );
        assert!(authenticated_gateway_environment(&gateway_pod(), &replacement).is_none());

        let mut wrong_service_account = gateway_pod();
        wrong_service_account
            .spec
            .as_mut()
            .unwrap()
            .service_account_name = Some("other-service-account".into());
        assert!(authenticated_gateway_environment(&wrong_service_account, &identity).is_none());

        let mut wrong_type = gateway_pod();
        wrong_type
            .metadata
            .labels
            .as_mut()
            .unwrap()
            .insert(LABEL_TYPE.into(), "workspace".into());
        assert!(authenticated_gateway_environment(&wrong_type, &identity).is_none());

        let mut missing_environment = gateway_pod();
        missing_environment
            .metadata
            .labels
            .as_mut()
            .unwrap()
            .remove(LABEL_ENV_ID);
        assert!(authenticated_gateway_environment(&missing_environment, &identity).is_none());

        let mut noncanonical_environment = gateway_pod();
        noncanonical_environment
            .metadata
            .labels
            .as_mut()
            .unwrap()
            .insert(LABEL_ENV_ID.into(), ENVIRONMENT_ID.to_ascii_uppercase());
        assert!(authenticated_gateway_environment(&noncanonical_environment, &identity).is_none());
    }

    #[test]
    fn terminating_or_cross_scope_gateway_pods_are_rejected() {
        let identity = gateway_identity();

        let mut terminating = gateway_pod();
        terminating.metadata.deletion_timestamp = Some(Time(k8s_openapi::jiff::Timestamp::now()));
        assert!(authenticated_gateway_environment(&terminating, &identity).is_none());

        let other_namespace =
            GatewayPodIdentity::for_test("other-runtime", identity.pod_name(), identity.pod_uid());
        assert!(authenticated_gateway_environment(&gateway_pod(), &other_namespace).is_none());

        let other_name = GatewayPodIdentity::for_test(
            identity.namespace(),
            "cw-gateway-other",
            identity.pod_uid(),
        );
        assert!(authenticated_gateway_environment(&gateway_pod(), &other_name).is_none());
    }
}
