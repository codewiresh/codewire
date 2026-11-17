//! The binding service's reads (#3628 PR 5b, design §4), moved unchanged
//! from `workspace_binding::service` and `access`: the incarnation by the
//! reviewed name, its runtime by name, its node's transport zone, and the
//! environment's direct-UDP Service. Each returns raw facts; the service
//! decides.

use std::net::IpAddr;

use k8s_openapi::api::core::v1::{Node, Pod, Service};
use k8s_openapi::api::networking::v1::{NetworkPolicy, NetworkPolicySpec};
use kube::Api;
use kube::api::{ApiResource, DynamicObject, GroupVersionKind};
use serde_json::Value;

use super::super::observation::{MemberFacts, NetworkPolicyFacts, RuntimeFacts};
use super::observation::{member_facts, runtime_facts};
use crate::runtime_transport::TRANSPORT_ZONE_LABEL;
use crate::sandbox::{CRD_VERSION, SANDBOX_GROUP};

pub(super) async fn member(
    client: &kube::Client,
    namespace: &str,
    name: &str,
) -> anyhow::Result<Option<MemberFacts>> {
    let pods: Api<Pod> = Api::namespaced(client.clone(), namespace);
    pods.get_opt(name)
        .await?
        .as_ref()
        .map(member_facts)
        .transpose()
}

pub(super) async fn network_policy(
    client: &kube::Client,
    namespace: &str,
    name: &str,
) -> anyhow::Result<Option<NetworkPolicyFacts>> {
    let policies: Api<NetworkPolicy> = Api::namespaced(client.clone(), namespace);
    policies
        .get_opt(name)
        .await?
        .map(|policy| network_policy_facts(&policy.spec.unwrap_or_default()))
        .transpose()
}

/// The policy a rendered manifest applies, in the form one read back has.
pub(super) fn rendered_network_policy(manifest: Value) -> anyhow::Result<NetworkPolicyFacts> {
    let policy: NetworkPolicy = serde_json::from_value(manifest)?;
    network_policy_facts(&policy.spec.unwrap_or_default())
}

fn network_policy_facts(spec: &NetworkPolicySpec) -> anyhow::Result<NetworkPolicyFacts> {
    let mut spec = serde_json::to_value(spec)?;
    drop_absent(&mut spec);
    Ok(NetworkPolicyFacts { spec })
}

/// Removes what Kubernetes reads as an absent field: a null and an empty
/// list. An empty object stays: `{}` as a rule, a peer or a selector means
/// everything, so dropping it would hide an allow-all.
///
/// Nothing here fills in a default the API server adds on write, such as a
/// port's `protocol` or `policyTypes`. So the rendered policy must spell out
/// every field the server defaults, or the policy read back differs from the
/// rendering and every bound guest is refused.
fn drop_absent(value: &mut Value) {
    match value {
        Value::Object(fields) => {
            fields.retain(|_, field| match field {
                Value::Null => false,
                Value::Array(items) => !items.is_empty(),
                _ => true,
            });
            fields.values_mut().for_each(drop_absent);
        }
        Value::Array(items) => items.iter_mut().for_each(drop_absent),
        _ => {}
    }
}

pub(super) async fn runtime(
    client: &kube::Client,
    namespace: &str,
    name: &str,
) -> anyhow::Result<Option<RuntimeFacts>> {
    let gvk = GroupVersionKind::gvk(SANDBOX_GROUP, CRD_VERSION, "Sandbox");
    let resource = ApiResource::from_gvk_with_plural(&gvk, "sandboxes");
    let sandboxes: Api<DynamicObject> = Api::namespaced_with(client.clone(), namespace, &resource);
    sandboxes
        .get_opt(name)
        .await?
        .as_ref()
        .map(runtime_facts)
        .transpose()
}

/// The zone label of the incarnation's node; `None` when it has no node, the
/// node is gone, or the label is empty.
pub(super) async fn transport_zone(
    client: &kube::Client,
    member: &MemberFacts,
) -> anyhow::Result<Option<String>> {
    let Some(node_name) = member.node_name.as_deref().filter(|name| !name.is_empty()) else {
        return Ok(None);
    };
    let nodes: Api<Node> = Api::all(client.clone());
    let node = nodes.get_opt(node_name).await?;
    Ok(node
        .as_ref()
        .and_then(|node| node.metadata.labels.as_ref())
        .and_then(|labels| labels.get(TRANSPORT_ZONE_LABEL))
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(str::to_owned))
}

/// The environment's direct-UDP endpoints: its own LoadBalancer Service's
/// address and port. Empty when none is provisioned or it has no address.
pub(super) async fn direct_udp_endpoints(
    client: &kube::Client,
    namespace: &str,
    environment_id: &str,
) -> Vec<String> {
    let services: Api<Service> = Api::namespaced(client.clone(), namespace);
    let name = crate::sandbox::template::direct_udp_service_name(environment_id);
    let Ok(Some(service)) = services.get_opt(&name).await else {
        return Vec::new();
    };
    let ip = service
        .status
        .as_ref()
        .and_then(|status| status.load_balancer.as_ref())
        .and_then(|load_balancer| load_balancer.ingress.as_ref())
        .and_then(|ingress| ingress.iter().find_map(|entry| entry.ip.clone()))
        .or_else(|| {
            service
                .spec
                .as_ref()
                .and_then(|spec| spec.load_balancer_ip.clone())
        })
        .and_then(|ip| ip.parse::<IpAddr>().ok());
    let port = service
        .spec
        .as_ref()
        .and_then(|spec| spec.ports.as_ref())
        .and_then(|ports| ports.first())
        .map(|port| port.port)
        .filter(|port| (1..=65535).contains(port));
    match (ip, port) {
        (Some(ip), Some(port)) => vec![std::net::SocketAddr::new(ip, port as u16).to_string()],
        _ => Vec::new(),
    }
}
