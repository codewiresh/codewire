//! Internal sidecar service logic (#140).
//!
//! The in-pod gateway calls this service to fetch its binding. The gateway
//! binding is keyed by the Pod identity derived from an exact-audience
//! Kubernetes TokenReview and issues a coordinate-scoped sidecar token. Both
//! gateway RPCs authorize the reviewed Pod by the same ownership rule
//! (`codewire_server_core::gateway_authority`): its live Pod → ReplicaSet →
//! `cw-gateway-<env>` Deployment chain at the current operation generation.
//!
//! Connect-RPC owns the binding wire contract. The shared functions below stay
//! transport-neutral so that policy and token issuance remain in one service
//! layer.

use codewire_gateway_proto::GATEWAY_BINDING_SERVICE_ACCOUNT;
use codewire_server_core::gateway_authority::{self, GatewayChain, GatewayEnvironment};
use codewire_server_core::{AppError, AppResult};
use k8s_openapi::api::apps::v1::{Deployment, ReplicaSet};
use k8s_openapi::api::core::v1::{Node, Pod};
use kube::Api;

use crate::gateway_binding_identity::GatewayPodIdentity;
use crate::runtime_transport::{
    RUNTIME_REGION_LABEL, RuntimeTransportBinding, TRANSPORT_ZONE_LABEL, load_enabled_zone,
};
use crate::sandbox::client::{ProbeResult, SandboxClient};
use crate::worker::gatewayauth::{
    SCOPE_COORDINATE, WorkspaceCredentialScope, daemon_credential_for, issue_token,
};

use super::ApiState;

#[derive(Debug)]
pub(crate) struct BindingTarget {
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
    /// The environment facts the gateway's chain is checked against, from the
    /// same read.
    gateway: GatewayEnvironment,
}

/// `(environment, namespace, workspace Pod name, workspace Pod IP, state,
/// desired state, organization, operation generation)`.
type BindingRuntimeRow = (String, String, String, String, String, String, String, i64);

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

/// Service-layer result for `GatewayBindingService.IssueGatewayDaemonCredential`.
#[derive(Clone)]
pub struct GatewayDaemonCredential {
    pub daemon_credential: String,
    pub workspace_pod_uid: String,
}

impl std::fmt::Debug for GatewayDaemonCredential {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GatewayDaemonCredential")
            .field("daemon_credential", &"[REDACTED]")
            .field("workspace_pod_uid", &self.workspace_pod_uid)
            .finish()
    }
}

/// The environment facts a gateway's ownership chain is checked against,
/// with its live workspace binding when one is recorded.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct GatewayDaemonAuthority {
    pub(crate) environment_id: String,
    pub(crate) organization_id: String,
    pub(crate) operation_generation: i64,
    pub(crate) namespace: String,
    pub(crate) binding: Option<GatewayDaemonBinding>,
}

impl GatewayDaemonAuthority {
    fn gateway_environment(&self) -> GatewayEnvironment {
        GatewayEnvironment {
            environment_id: self.environment_id.clone(),
            organization_id: self.organization_id.clone(),
            operation_generation: self.operation_generation,
            namespace: self.namespace.clone(),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct GatewayDaemonBinding {
    pub(crate) pod_uid: String,
    pub(crate) credential_scope: WorkspaceCredentialScope,
}

type GatewayDaemonAuthorityRow = (String, String, i64, String, Option<String>, Option<String>);

fn gateway_daemon_not_ready() -> AppError {
    AppError::NotFound("gateway daemon credential not ready".into())
}

fn gateway_daemon_unavailable() -> AppError {
    AppError::ServiceUnavailable("gateway daemon credential unavailable".into())
}

/// Issues the daemon credential of the environment's currently bound workspace
/// Pod to that environment's gateway (design §3.2). It deliberately has no
/// `running` gate: the gateway becomes ready only after it reaches the
/// daemon, which listens only once bound. Because the credential is issued
/// before `running`, labels and the service account are not enough: the
/// reviewed gateway Pod must be the live Pod of the environment's own
/// ReplicaSet → Deployment chain, matched by UID, at the environment's current
/// operation generation (`codewire_server_core::gateway_authority`).
/// Deployment availability is intentionally not required; requiring it would
/// reintroduce the deadlock.
pub(crate) async fn issue_gateway_daemon_credential_core(
    state: &ApiState,
    identity: &GatewayPodIdentity,
) -> AppResult<GatewayDaemonCredential> {
    if identity.namespace() != state.sandbox_cfg.sandbox_namespace {
        return Err(AppError::Forbidden);
    }
    let client = state.kube.as_ref().ok_or_else(gateway_daemon_unavailable)?;
    issue_gateway_daemon_credential_in(client, &state.pool, &state.session_secret, identity).await
}

/// [`issue_gateway_daemon_credential_core`] after its namespace and client
/// checks.
pub(crate) async fn issue_gateway_daemon_credential_in(
    client: &kube::Client,
    pool: &sqlx::PgPool,
    session_secret: &str,
    identity: &GatewayPodIdentity,
) -> AppResult<GatewayDaemonCredential> {
    let namespace = identity.namespace();
    let (environment_id, objects) = match read_gateway_objects(client, identity)
        .await
        .map_err(|_| gateway_daemon_unavailable())?
    {
        GatewayRead::Missing => return Err(gateway_daemon_not_ready()),
        GatewayRead::Refused => return Err(AppError::Forbidden),
        GatewayRead::Found {
            environment_id,
            objects,
        } => (environment_id, objects),
    };
    let authority = gateway_daemon_authority(pool, &environment_id)
        .await?
        .ok_or_else(gateway_daemon_not_ready)?;
    if authority.namespace != namespace {
        return Err(AppError::Forbidden);
    }
    let chain = objects.chain(namespace).ok_or(AppError::Forbidden)?;
    gateway_authority::authorize(&chain, &authority.gateway_environment())
        .map_err(|_| AppError::Forbidden)?;
    let binding = authority.binding.ok_or_else(gateway_daemon_not_ready)?;
    let daemon_credential = daemon_credential_for(
        session_secret,
        &environment_id,
        &binding.pod_uid,
        binding.credential_scope,
    )
    .map_err(|_| gateway_daemon_unavailable())?;
    Ok(GatewayDaemonCredential {
        daemon_credential,
        workspace_pod_uid: binding.pod_uid,
    })
}

pub(crate) async fn gateway_daemon_authority(
    pool: &sqlx::PgPool,
    environment_id: &str,
) -> AppResult<Option<GatewayDaemonAuthority>> {
    let row: Option<GatewayDaemonAuthorityRow> = sqlx::query_as(
        r#"SELECT e.org_id,
                  b.environment_id,
                  e.environment_operation_generation,
                  b.namespace,
                  w.pod_uid,
                  w.credential_scope
             FROM environments e
             JOIN sandbox_environment_backend b ON b.environment_id = e.id
             LEFT JOIN sandbox_workspace_bindings w
               ON w.environment_id = b.environment_id
              AND w.pod_uid = b.pod_uid
              AND w.released_at IS NULL
            WHERE e.id = $1
              AND e.type = 'sandbox'
              AND e.state IN ('pending', 'creating', 'starting', 'running', 'resizing')
              AND (e.desired_state = 'started'
                   OR (e.state = 'resizing' AND e.desired_state = 'resized'))
              AND e.deletion_requested_at IS NULL"#,
    )
    .bind(environment_id)
    .fetch_optional(pool)
    .await
    .map_err(|error| {
        tracing::warn!(env = %environment_id, error = %error, "gateway daemon credential lookup failed");
        gateway_daemon_unavailable()
    })?;
    row.map(gateway_daemon_authority_from_row).transpose()
}

fn gateway_daemon_authority_from_row(
    (organization_id, environment_id, operation_generation, namespace, pod_uid, scope): GatewayDaemonAuthorityRow,
) -> AppResult<GatewayDaemonAuthority> {
    let binding = match (pod_uid, scope) {
        (None, None) => None,
        (Some(pod_uid), Some(scope)) => Some(GatewayDaemonBinding {
            pod_uid,
            credential_scope: WorkspaceCredentialScope::parse(&scope)
                .ok_or_else(gateway_daemon_unavailable)?,
        }),
        _ => return Err(gateway_daemon_unavailable()),
    };
    // Gateways are rendered only under an operation generation.
    if operation_generation <= 0 {
        return Err(AppError::Forbidden);
    }
    Ok(GatewayDaemonAuthority {
        environment_id,
        organization_id,
        operation_generation,
        namespace,
        binding,
    })
}

/// The reviewed gateway Pod and the ReplicaSet and Deployment its controller
/// references name, read by those names. [`GatewayObjects::chain`] then
/// matches them by UID.
struct GatewayObjects {
    pod: Pod,
    replica_set: ReplicaSet,
    deployment: Deployment,
}

impl GatewayObjects {
    fn chain<'a>(&'a self, namespace: &'a str) -> Option<GatewayChain<'a>> {
        GatewayChain::verify(namespace, &self.pod, &self.replica_set, &self.deployment)
    }
}

enum GatewayRead {
    /// The reviewed Pod no longer exists.
    Missing,
    /// The Pod is not the reviewed live gateway Pod, names no environment, or
    /// a controller it names is missing.
    Refused,
    Found {
        /// The environment the Pod's labels name, which the shared rule then
        /// checks against the whole chain.
        environment_id: String,
        objects: Box<GatewayObjects>,
    },
}

/// Reads the reviewed gateway Pod and, only when it is the reviewed live
/// gateway Pod naming an environment, the ReplicaSet and Deployment its
/// controller references name.
async fn read_gateway_objects(
    client: &kube::Client,
    identity: &GatewayPodIdentity,
) -> anyhow::Result<GatewayRead> {
    let namespace = identity.namespace();
    let Some(pod) = Api::<Pod>::namespaced(client.clone(), namespace)
        .get_opt(identity.pod_name())
        .await?
    else {
        return Ok(GatewayRead::Missing);
    };
    let Some(environment_id) = authenticated_gateway_environment(&pod, identity) else {
        return Ok(GatewayRead::Refused);
    };
    let Some(replica_set_name) = GatewayChain::controlling_replica_set(&pod) else {
        return Ok(GatewayRead::Refused);
    };
    let Some(replica_set) = Api::<ReplicaSet>::namespaced(client.clone(), namespace)
        .get_opt(replica_set_name)
        .await?
    else {
        return Ok(GatewayRead::Refused);
    };
    let Some(deployment_name) = GatewayChain::controlling_deployment(&replica_set) else {
        return Ok(GatewayRead::Refused);
    };
    let Some(deployment) = Api::<Deployment>::namespaced(client.clone(), namespace)
        .get_opt(deployment_name)
        .await?
    else {
        return Ok(GatewayRead::Refused);
    };
    Ok(GatewayRead::Found {
        environment_id,
        objects: Box::new(GatewayObjects {
            pod,
            replica_set,
            deployment,
        }),
    })
}

async fn resolve_binding_target(
    state: &ApiState,
    identity: &GatewayPodIdentity,
) -> anyhow::Result<Option<BindingTarget>> {
    let Some(client) = state.kube.as_ref() else {
        return Ok(None);
    };
    resolve_binding_target_in(client, &state.pool, identity).await
}

/// [`resolve_binding_target`] with its client. The binding requires the same
/// ownership chain as the daemon credential; a gateway the shared rule refuses
/// gets no binding (NotFound, so it keeps polling) and reads nothing of the
/// workspace.
pub(crate) async fn resolve_binding_target_in(
    client: &kube::Client,
    pool: &sqlx::PgPool,
    identity: &GatewayPodIdentity,
) -> anyhow::Result<Option<BindingTarget>> {
    let (env_id, objects) = match read_gateway_objects(client, identity)
        .await
        .map_err(|error| {
            anyhow::anyhow!(
                "read authenticated gateway {}/{}: {error}",
                identity.namespace(),
                identity.pod_name(),
            )
        })? {
        GatewayRead::Found {
            environment_id,
            objects,
        } => (environment_id, objects),
        GatewayRead::Missing | GatewayRead::Refused => return Ok(None),
    };
    let runtime = binding_runtime_for_environment(pool, &env_id).await?;
    let Some(runtime) = runtime else {
        return Ok(None);
    };
    if runtime.namespace != identity.namespace() {
        return Ok(None);
    }
    let authorized = objects
        .chain(identity.namespace())
        .is_some_and(|chain| gateway_authority::authorize(&chain, &runtime.gateway).is_ok());
    if !authorized {
        tracing::info!(
            env = %env_id,
            pod = %identity.pod_name(),
            "gateway binding refused: not the environment's current gateway chain"
        );
        return Ok(None);
    }
    let pod_node_name = objects
        .pod
        .spec
        .as_ref()
        .and_then(|spec| spec.node_name.clone());

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
    gateway_authority::labelled_environment(pod)
}

async fn binding_runtime_for_environment(
    pool: &sqlx::PgPool,
    env_id: &str,
) -> anyhow::Result<Option<BindingRuntime>> {
    let row: Option<BindingRuntimeRow> = sqlx::query_as(
        r#"SELECT b.environment_id,
                  b.namespace,
                  COALESCE(b.pod_name, ''),
                  COALESCE(b.pod_ip, ''),
                  e.state,
                  e.desired_state,
                  e.org_id,
                  e.environment_operation_generation
             FROM sandbox_environment_backend b
             JOIN environments e ON e.id = b.environment_id
            WHERE b.environment_id = $1"#,
    )
    .bind(env_id)
    .fetch_optional(pool)
    .await
    .map_err(|error| anyhow::anyhow!("query environment gateway binding: {error}"))?;

    Ok(row.and_then(binding_runtime_from_row))
}

fn binding_runtime_from_row(
    (
        env_id,
        namespace,
        pod_name,
        pod_ip,
        state,
        desired_state,
        organization_id,
        operation_generation,
    ): BindingRuntimeRow,
) -> Option<BindingRuntime> {
    if state != "running" || desired_state != "started" {
        return None;
    }
    let gateway = GatewayEnvironment {
        environment_id: env_id.clone(),
        organization_id,
        operation_generation,
        namespace: namespace.clone(),
    };
    Some(BindingRuntime {
        env_id,
        namespace,
        pod_name,
        pod_ip,
        gateway,
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
mod database_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::api::core::v1::PodSpec;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::{ObjectMeta, Time};

    use crate::sandbox::{LABEL_ENV_ID, LABEL_TYPE};

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
            gateway: GatewayEnvironment {
                environment_id: "env-current".into(),
                organization_id: ORGANIZATION_ID.into(),
                operation_generation: 4,
                namespace: "runtime".into(),
            },
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
            ORGANIZATION_ID.into(),
            4,
        )
    }

    #[test]
    fn gateway_binding_requires_running_started_environment() {
        let runtime = binding_runtime_from_row(runtime_row("running", "started"))
            .expect("running environment");
        // The binding checks the gateway chain against the same read.
        assert_eq!(runtime.gateway, current_runtime().gateway);
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

    const ORGANIZATION_ID: &str = "org-chain";
    const REPLICA_SET_UID: &str = "3f2b1c0d-1111-4a2b-8c3d-4e5f6a7b8c9d";

    #[test]
    fn gateway_daemon_authority_rows_are_coherent() {
        let row = |pod: Option<&str>, scope: Option<&str>, generation: i64| {
            gateway_daemon_authority_from_row((
                ORGANIZATION_ID.into(),
                ENVIRONMENT_ID.into(),
                generation,
                "runtime".into(),
                pod.map(str::to_owned),
                scope.map(str::to_owned),
            ))
        };
        assert_eq!(row(None, None, 4).unwrap().binding, None);
        assert_eq!(
            row(Some(REPLICA_SET_UID), Some("pod"), 4).unwrap().binding,
            Some(GatewayDaemonBinding {
                pod_uid: REPLICA_SET_UID.into(),
                credential_scope: WorkspaceCredentialScope::Pod,
            })
        );
        assert!(row(Some(REPLICA_SET_UID), None, 4).is_err());
        assert!(row(Some(REPLICA_SET_UID), Some("node"), 4).is_err());
        assert!(matches!(row(None, None, 0), Err(AppError::Forbidden)));
    }

    #[test]
    fn gateway_daemon_credential_debug_is_redacted() {
        const MARKER: &str = "synthetic-daemon-credential-canary";
        let credential = GatewayDaemonCredential {
            daemon_credential: MARKER.into(),
            workspace_pod_uid: REPLICA_SET_UID.into(),
        };
        let debug = format!("{credential:?}");
        assert!(debug.contains("[REDACTED]") && !debug.contains(MARKER));
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
