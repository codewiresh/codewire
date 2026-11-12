//! What a member shows of where and how it runs, for the trust report
//! (#3628 PR 8a): the workspace Pod and its node, read as the report read
//! them before, with the same label keys. The report keeps deciding what the
//! runtime means.

use std::collections::BTreeMap;

use k8s_openapi::api::core::v1::{Node, Pod};
use kube::Api;

use super::super::MemberEvidence;
use crate::sandbox::template::{DAEMON_INIT_CONTAINER, DAEMON_VOLUME};

/// The member's evidence; `None` when its Pod can't be read.
pub(super) async fn member(
    client: &kube::Client,
    namespace: &str,
    member_name: &str,
) -> Option<MemberEvidence> {
    let pods: Api<Pod> = Api::namespaced(client.clone(), namespace);
    let pod = match pods.get(member_name).await {
        Ok(pod) => pod,
        Err(err) => {
            tracing::debug!(%err, namespace, pod_name = member_name, "trust report live pod lookup failed");
            return None;
        }
    };
    let mut evidence = of_pod(&pod);
    if let Some(node_name) = evidence
        .host
        .as_deref()
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
    {
        let nodes: Api<Node> = Api::all(client.clone());
        match nodes.get(&node_name).await {
            Ok(node) => {
                let labels = node.metadata.labels.unwrap_or_default();
                evidence.zone = first_label(
                    &labels,
                    &[
                        "topology.kubernetes.io/zone",
                        "failure-domain.beta.kubernetes.io/zone",
                    ],
                );
                evidence.region = first_label(
                    &labels,
                    &[
                        "topology.kubernetes.io/region",
                        "failure-domain.beta.kubernetes.io/region",
                    ],
                );
            }
            Err(err) => {
                tracing::debug!(%err, node_name, "trust report node lookup failed");
            }
        }
    }
    Some(evidence)
}

/// Everything the Pod itself shows.
pub(super) fn of_pod(pod: &Pod) -> MemberEvidence {
    let mut evidence = MemberEvidence::default();
    if let Some(spec) = pod.spec.as_ref() {
        evidence.runtime = spec.runtime_class_name.clone();
        evidence.host = spec.node_name.clone();
        evidence.workspace_image = spec_container_image(pod, "workspace");
        evidence.dind_image = spec_container_image(pod, "dind");
        evidence.daemon_init_image = spec_init_container_image(pod, DAEMON_INIT_CONTAINER)
            .or_else(|| spec_daemon_volume_image(pod));
    }
    if let Some(status) = pod.status.as_ref() {
        evidence.address = status.pod_ip.clone();
    }
    evidence.workspace_image_id = status_container_image_id(pod, "workspace");
    evidence.dind_image_id = status_container_image_id(pod, "dind");
    // An image-volume daemon has no init status; its digest-pinned reference
    // is the daemon image above.
    evidence.daemon_init_image_id = status_init_container_image_id(pod, DAEMON_INIT_CONTAINER);
    evidence
}

fn first_label(labels: &BTreeMap<String, String>, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| labels.get(*key).cloned())
        .and_then(trimmed_optional)
}

fn spec_container_image(pod: &Pod, name: &str) -> Option<String> {
    pod.spec
        .as_ref()?
        .containers
        .iter()
        .find(|container| container.name == name)
        .and_then(|container| container.image.clone())
        .and_then(trimmed_optional)
}

fn spec_init_container_image(pod: &Pod, name: &str) -> Option<String> {
    pod.spec
        .as_ref()?
        .init_containers
        .as_ref()?
        .iter()
        .find(|container| container.name == name)
        .and_then(|container| container.image.clone())
        .and_then(trimmed_optional)
}

/// The support image a commodity workspace mounts its daemon from.
fn spec_daemon_volume_image(pod: &Pod) -> Option<String> {
    pod.spec
        .as_ref()?
        .volumes
        .as_ref()?
        .iter()
        .find(|volume| volume.name == DAEMON_VOLUME)?
        .image
        .as_ref()?
        .reference
        .clone()
        .and_then(trimmed_optional)
}

fn status_container_image_id(pod: &Pod, name: &str) -> Option<String> {
    pod.status
        .as_ref()?
        .container_statuses
        .as_ref()?
        .iter()
        .find(|status| status.name == name)
        .map(|status| status.image_id.clone())
        .and_then(trimmed_optional)
}

fn status_init_container_image_id(pod: &Pod, name: &str) -> Option<String> {
    pod.status
        .as_ref()?
        .init_container_statuses
        .as_ref()?
        .iter()
        .find(|status| status.name == name)
        .map(|status| status.image_id.clone())
        .and_then(trimmed_optional)
}

fn trimmed_optional(value: String) -> Option<String> {
    let trimmed = value.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn daemon_image_is_reported_from_either_delivery_route() {
        let observe = |spec: serde_json::Value, status: serde_json::Value| {
            let pod: Pod = serde_json::from_value(serde_json::json!({
                "metadata": {"name": "workspace"},
                "spec": spec,
                "status": status,
            }))
            .unwrap();
            let evidence = of_pod(&pod);
            (evidence.daemon_init_image, evidence.daemon_init_image_id)
        };
        let image = "registry.example/codewire/support@sha256:1111";
        let workspace = serde_json::json!({"name": "workspace", "image": "workspace"});
        assert_eq!(
            observe(
                serde_json::json!({
                    "containers": [workspace],
                    "volumes": [{"name": "codewire-bin", "image": {"reference": image}}],
                }),
                serde_json::json!({}),
            ),
            (Some(image.to_owned()), None)
        );
        assert_eq!(
            observe(
                serde_json::json!({
                    "containers": [workspace],
                    "initContainers": [{"name": "codewire-daemon-init", "image": image}],
                    "volumes": [{"name": "codewire-bin", "emptyDir": {}}],
                }),
                serde_json::json!({"initContainerStatuses": [{
                    "name": "codewire-daemon-init", "image": image, "imageID": "sha256:2222",
                    "ready": false, "restartCount": 0,
                }]}),
            ),
            (Some(image.to_owned()), Some("sha256:2222".to_owned()))
        );
    }

    /// Every field the trust report read off the Pod, each where it was.
    #[test]
    fn a_pods_evidence_is_each_field_as_it_was_read() {
        let pod: Pod = serde_json::from_value(serde_json::json!({
            "metadata": {"name": "sandbox-env-1"},
            "spec": {
                "runtimeClassName": "commodity",
                "nodeName": "node-a",
                "containers": [
                    {"name": "workspace", "image": " registry.example/workspace@sha256:1 "},
                    {"name": "dind", "image": "docker:29-dind"},
                ],
            },
            "status": {
                "podIP": "10.0.0.9",
                "containerStatuses": [
                    {"name": "workspace", "image": "w", "imageID": "sha256:aa", "ready": true, "restartCount": 0},
                    {"name": "dind", "image": "d", "imageID": "sha256:bb", "ready": true, "restartCount": 0},
                ],
            },
        }))
        .unwrap();
        assert_eq!(
            of_pod(&pod),
            MemberEvidence {
                runtime: Some("commodity".into()),
                host: Some("node-a".into()),
                address: Some("10.0.0.9".into()),
                zone: None,
                region: None,
                workspace_image: Some("registry.example/workspace@sha256:1".into()),
                workspace_image_id: Some("sha256:aa".into()),
                dind_image: Some("docker:29-dind".into()),
                dind_image_id: Some("sha256:bb".into()),
                daemon_init_image: None,
                daemon_init_image_id: None,
            }
        );
    }
}
